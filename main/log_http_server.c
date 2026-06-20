#include "log_http_server.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_err.h"
#include "esp_flash.h"
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_image_format.h"
#include "esp_mac.h"
#include "esp_mesh.h"
#include "esp_ota_ops.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "nvs.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/portmacro.h"
#include "freertos/semphr.h"

#include "mesh_proto.h"
#include "mesh_v2_link.h"
#include "stack_monitor.h"

static const char *TAG = "log_http";

extern const unsigned char node0_https_servercert_pem_start[] asm("_binary_node0_https_servercert_pem_start");
extern const unsigned char node0_https_servercert_pem_end[] asm("_binary_node0_https_servercert_pem_end");
extern const unsigned char node0_https_prvtkey_pem_start[] asm("_binary_node0_https_prvtkey_pem_start");
extern const unsigned char node0_https_prvtkey_pem_end[] asm("_binary_node0_https_prvtkey_pem_end");

/* ----------------- Configuration ----------------- */

#ifndef LOG_HTTP_LINES
	#define LOG_HTTP_LINES			220
#endif

#ifndef LOG_HTTP_LINE_MAX
	#define LOG_HTTP_LINE_MAX		256
#endif

#ifndef LOG_HTTP_STACK_TMP
	#define LOG_HTTP_STACK_TMP		LOG_HTTP_LINE_MAX
#endif

#ifndef WEB_POLL_MS
	#define WEB_POLL_MS			2000
#endif

#ifndef LOG_HTTP_MAX_NODES
	#define LOG_HTTP_MAX_NODES		24
#endif

#ifndef CONFIG_NODE0_OTA_PIN
	#define CONFIG_NODE0_OTA_PIN		""
#endif

#define NODE0_OTA_BUF_SIZE		4096U
#define NODE0_OTA_RECV_TIMEOUT_RETRIES	3
#define REMOTE_OTA_ACK_TIMEOUT_MS	8000U
#define REMOTE_OTA_SEND_RETRIES		3
#define REMOTE_OTA_RETRY_DELAY_MS	120U
#define REMOTE_REBOOT_ACK_TIMEOUT_MS	7000U
#define REMOTE_REBOOT_SEND_RETRIES	3
#define REMOTE_REBOOT_RETRY_DELAY_MS	150U
#define REMOTE_REBOOT_DELAY_MS		1200U
#define LOG_STREAM_TASK_STACK		4096U
#define LOG_STREAM_HEARTBEAT_MS		10000U
#define MESH_STREAM_TASK_STACK		6144U
#define MESH_STREAM_HEARTBEAT_MS	15000U
#define UI_STREAM_TASK_STACK		4096U
#define UI_STREAM_HEARTBEAT_MS		5000U
#define LOG_LEASE_TASK_STACK		3572U
#define HTTPS_MAX_OPEN_SOCKETS		4
#define UI_STATUS_JSON_MAX		12288U
#define MESH_STATUS_JSON_MAX		12288U
#define UI_CONTROL_POLL_MS		15000
#define TASKS_FAST_POLL_MS		2000
#define REMOTE_LOG_RETRY_MS		5000U
#define REMOTE_LOG_READY_REARM_MS	30000U
#define NODEINFO_STALE_MS		75000U
#define STREAM_SID_MAX			32
#define NODE_OFFLINE_MS		180000U

#ifndef LOG_HTTP_ENABLE_MESH_STREAM
#define LOG_HTTP_ENABLE_MESH_STREAM	0
#endif

#define STR_HELPER(x)	#x
#define STR(x)		STR_HELPER(x)

/* ----------------- State ----------------- */

static httpd_handle_t s_http_server = NULL;

static portMUX_TYPE s_log_lock = portMUX_INITIALIZER_UNLOCKED;
static char s_lines[LOG_HTTP_LINES][LOG_HTTP_LINE_MAX];
static uint32_t s_write_idx = 0;	// absolute line cursor
static uint32_t s_total_lines = 0;
static uint8_t s_http_wire_drop_budget = 0;

typedef struct {
	httpd_req_t *req;
	uint32_t cursor;
	bool headers_sent;
	bool client_close;
	char sid[STREAM_SID_MAX];
} log_stream_state_t;

static SemaphoreHandle_t s_log_stream_mutex = NULL;
static TaskHandle_t s_log_stream_task = NULL;
static log_stream_state_t s_log_stream = {0};

typedef struct {
	httpd_req_t *req;
	uint32_t seq;
	bool headers_sent;
	bool client_close;
	char sid[STREAM_SID_MAX];
} mesh_stream_state_t;

static SemaphoreHandle_t s_mesh_stream_mutex = NULL;
static TaskHandle_t s_mesh_stream_task = NULL;
static mesh_stream_state_t s_mesh_stream = {0};
static uint32_t s_mesh_stream_seq = 1;

typedef struct {
	httpd_req_t *req;
	uint32_t seq;
	bool headers_sent;
	bool client_close;
	char sid[STREAM_SID_MAX];
} ui_stream_state_t;

static SemaphoreHandle_t s_ui_stream_mutex = NULL;
static TaskHandle_t s_ui_stream_task = NULL;
static ui_stream_state_t s_ui_stream = {0};
static uint32_t s_ui_stream_seq = 1;
static TaskHandle_t s_stream_lease_task = NULL;

typedef int (*vprintf_like_t)(const char *fmt, va_list ap);
static vprintf_like_t s_orig_vprintf = NULL;

// Local node.
static uint8_t s_local_mac[6] = {0};
static char s_local_tag[16] = "node0";

// Selected stream, local by default.
static uint8_t s_sel_mac[6] = {0};
static char s_sel_tag[16] = "node0";

// Currently active remote stream; used to disable the previous one.
static uint8_t s_stream_mac[6] = {0};
static bool s_stream_active = false;
static bool s_stream_ready = false;
static uint32_t s_stream_selected_ms = 0;
static uint32_t s_stream_last_line_ms = 0;
static uint8_t s_last_rearm_mac[6] = {0};
static uint32_t s_last_rearm_ms = 0;
static uint32_t s_last_log_ctrl_ms = 0;
static esp_err_t s_last_log_ctrl_err = ESP_OK;
static uint32_t s_task_request_id = 1;

// Known node list.
typedef struct {
	uint8_t mac[6];
	char tag[16];
	uint32_t last_seen_ms;
	uint32_t last_route_ms;
	uint32_t topology_seen_ms;
	uint8_t parent_mac[6];
	uint8_t root_mac[6];
	uint16_t layer;
	uint16_t max_layer;
	int8_t parent_rssi;
	uint8_t child_count;
	uint32_t capabilities;
	uint32_t v1_ok_age_ms;
	uint32_t v2_ack_age_ms;
	int32_t last_send_err;
	uint8_t recovery_phase;
	bool log_stream_enabled;
	char ota_running_label[MESH_OTA_SLOT_LABEL_MAX];
	char ota_update_label[MESH_OTA_SLOT_LABEL_MAX];
	uint32_t ota_running_size;
	uint32_t ota_update_size;
	bool uptime_valid;
	uint32_t uptime_s;
	uint32_t uptime_seen_ms;
} node_ent_t;

typedef struct {
	bool valid;
	uint32_t free_bytes;
	uint32_t min_free_bytes;
	uint32_t total_bytes;
	bool internal_valid;
	uint32_t internal_free_bytes;
	uint32_t internal_min_free_bytes;
	uint32_t internal_total_bytes;
	bool psram_valid;
	uint32_t psram_free_bytes;
	uint32_t psram_min_free_bytes;
	uint32_t psram_total_bytes;
} ram_status_t;

typedef struct {
	bool flash_valid;
	uint32_t flash_chip_bytes;
	uint32_t app_used_bytes;
	uint32_t app_partition_bytes;
	bool nvs_valid;
	uint32_t nvs_used_entries;
	uint32_t nvs_free_entries;
	uint32_t nvs_available_entries;
	uint32_t nvs_total_entries;
} persistent_status_t;

static node_ent_t s_nodes[LOG_HTTP_MAX_NODES];
static uint32_t s_nodes_count = 0;
static portMUX_TYPE s_nodes_lock = portMUX_INITIALIZER_UNLOCKED;
static portMUX_TYPE s_selection_lock = portMUX_INITIALIZER_UNLOCKED;

typedef struct {
	uint8_t mac[6];
	char tag[16];
	bool used;
	bool valid;
	bool staging_active;
	int slot_count;
	uint32_t last_request_id;
	ram_status_t ram;
	persistent_status_t persistent;
	stack_monitor_snapshot_t current;
	stack_monitor_snapshot_t staging;
} taskmon_ent_t;

static taskmon_ent_t s_taskmon[LOG_HTTP_MAX_NODES];
static portMUX_TYPE s_taskmon_lock = portMUX_INITIALIZER_UNLOCKED;

static taskmon_ent_t *taskmon_find_locked(const uint8_t mac[6], bool create);
static size_t append_fmt(char *out, size_t cap, size_t pos, const char *fmt, ...);
static size_t append_json_string(char *out, size_t cap, size_t pos, const char *s);
static void log_stream_notify(void);
static void mesh_stream_notify(void);
static void ui_stream_notify(void);
static bool parse_mac_hex(const char *s, uint8_t mac[6]);
static void copy_tag(char *dst, size_t dst_sz, const char *tag);
static void copy_packet_text(char *dst, size_t dst_sz, const char *src, size_t src_sz);
static size_t append_nodes_json(char *out, size_t cap, size_t pos);
static size_t append_node_v2_json_fields(char *out, size_t cap, size_t pos,
                                         const uint8_t mac[6], uint32_t now);
static size_t append_node_topology_json_fields(char *out, size_t cap, size_t pos,
                                               const node_ent_t *node,
                                               uint32_t now);
static size_t append_tasks_json_for_mac(char *out, size_t cap, size_t pos,
                                        const uint8_t mac[6]);
static size_t append_local_ota_json(char *out, size_t cap, size_t pos);
static size_t append_remote_ota_json_for_mac(char *out, size_t cap, size_t pos,
                                             const uint8_t mac[6]);
static void remote_ota_slot_snapshot(const uint8_t mac[6],
                                     char running_label[MESH_OTA_SLOT_LABEL_MAX],
                                     char update_label[MESH_OTA_SLOT_LABEL_MAX],
                                     uint32_t *running_size,
                                     uint32_t *update_size);
static bool query_bool_value(const char *q, const char *key);
static void stream_sid_from_req(httpd_req_t *req, char *sid, size_t sid_sz);
static size_t append_ui_status_json_for_mac(char *out, size_t cap, size_t pos,
                                            const uint8_t mac[6],
                                            bool include_tasks,
                                            bool include_ota);
static void remote_ota_note_node_seen(const uint8_t mac[6], bool uptime_valid,
                                      uint32_t uptime_s);
static esp_err_t mesh_send_log_ctrl(const uint8_t to_mac[6], bool enable);
static bool selected_remote_stream_needs_rearm(const uint8_t mac[6]);
static void selected_remote_stream_note_rearm(const uint8_t mac[6], esp_err_t err);
static esp_err_t remote_stream_rearm_for_mac(const uint8_t mac[6], bool force);
static bool stream_sid_matches(const char stored[STREAM_SID_MAX], const char *sid);

typedef enum {
	NODE0_OTA_IDLE = 0,
	NODE0_OTA_UPDATING,
	NODE0_OTA_SUCCESS,
	NODE0_OTA_FAILED,
	NODE0_OTA_REBOOTING,
} node0_ota_state_t;

typedef struct {
	node0_ota_state_t state;
	uint32_t total_bytes;
	uint32_t written_bytes;
	uint32_t started_ms;
	uint32_t finished_ms;
	char last_error[96];
	char last_result[96];
} node0_ota_status_t;

static SemaphoreHandle_t s_ota_mutex = NULL;
static portMUX_TYPE s_ota_state_lock = portMUX_INITIALIZER_UNLOCKED;
static node0_ota_status_t s_ota_status = {
	.state = NODE0_OTA_IDLE,
};

typedef struct {
	bool waiting;
	uint8_t mac[6];
	uint8_t op;
	uint16_t seq;
	mesh_ota_status_packet_t ack;
} remote_ota_wait_t;

typedef struct {
	node0_ota_state_t state;
	bool target_valid;
	uint8_t target_mac[6];
	char target_tag[16];
	uint32_t total_bytes;
	uint32_t written_bytes;
	uint32_t started_ms;
	uint32_t finished_ms;
	char running_label[MESH_OTA_SLOT_LABEL_MAX];
	char update_label[MESH_OTA_SLOT_LABEL_MAX];
	uint32_t running_size;
	uint32_t update_size;
	char last_error[96];
	char last_result[96];
	char remote_message[MESH_OTA_STATUS_MSG_MAX];
} remote_ota_status_t;

static SemaphoreHandle_t s_remote_ota_ack_sem = NULL;
static portMUX_TYPE s_remote_ota_lock = portMUX_INITIALIZER_UNLOCKED;
static remote_ota_wait_t s_remote_ota_wait = {0};
static remote_ota_status_t s_remote_ota_status = {
	.state = NODE0_OTA_IDLE,
};

typedef struct {
	bool waiting;
	uint8_t mac[6];
	uint16_t seq;
	mesh_reboot_status_packet_t ack;
} remote_reboot_wait_t;

static SemaphoreHandle_t s_remote_reboot_ack_sem = NULL;
static portMUX_TYPE s_remote_reboot_lock = portMUX_INITIALIZER_UNLOCKED;
static remote_reboot_wait_t s_remote_reboot_wait = {0};

/* ----------------- Helpers ----------------- */

static uint32_t ms_now(void)
{
	return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

static uint32_t local_uptime_s(void)
{
	return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

static void log_stream_notify(void)
{
	TaskHandle_t task = s_log_stream_task;
	if (task) {
		xTaskNotifyGive(task);
	}
}

static void mesh_stream_notify(void)
{
	TaskHandle_t task = s_mesh_stream_task;
	if (task) {
		xTaskNotifyGive(task);
	}
}

static void ui_stream_notify(void)
{
	TaskHandle_t task = s_ui_stream_task;
	if (task) {
		xTaskNotifyGive(task);
	}
}

static void mesh_stream_mark_changed(void)
{
	s_mesh_stream_seq++;
	s_ui_stream_seq++;
	mesh_stream_notify();
	ui_stream_notify();
}

static bool mac_eq(const uint8_t a[6], const uint8_t b[6])
{
	return memcmp(a, b, 6) == 0;
}

static void mac_copy(uint8_t dst[6], const uint8_t src[6])
{
	memcpy(dst, src, 6);
}

static bool mac_list_contains(const uint8_t list[][6], uint32_t count, const uint8_t mac[6])
{
	if (!mac) return false;

	for (uint32_t i = 0; i < count; i++) {
		if (mac_eq(list[i], mac)) return true;
	}

	return false;
}

static bool route_table_contains(const mesh_addr_t routes[], int route_count,
                                 const uint8_t mac[6])
{
	if (!routes || !mac) return false;

	for (int i = 0; i < route_count; i++) {
		if (mac_eq(routes[i].addr, mac)) return true;
	}

	return false;
}

static void note_route_table_nodes(const mesh_addr_t routes[], int route_count,
                                   uint32_t now)
{
	if (!routes || route_count <= 0) return;

	bool changed = false;
	portENTER_CRITICAL(&s_nodes_lock);
	{
		for (int i = 0; i < route_count; i++) {
			const uint8_t *mac = routes[i].addr;
			bool found = false;

			if (mac_eq(mac, s_local_mac)) {
				continue;
			}

			for (uint32_t n = 0; n < s_nodes_count; n++) {
				if (mac_eq(s_nodes[n].mac, mac)) {
					if (s_nodes[n].last_route_ms == 0 ||
					    (uint32_t)(now - s_nodes[n].last_route_ms) > NODEINFO_STALE_MS) {
						changed = true;
					}
					s_nodes[n].last_route_ms = now;
					found = true;
					break;
				}
			}

			if (!found && s_nodes_count < LOG_HTTP_MAX_NODES) {
				node_ent_t *ent = &s_nodes[s_nodes_count++];
				memset(ent, 0, sizeof(*ent));
				mac_copy(ent->mac, mac);
				copy_tag(ent->tag, sizeof(ent->tag), "mesh");
				ent->last_route_ms = now;
				changed = true;
			}
		}
	}
	portEXIT_CRITICAL(&s_nodes_lock);
	if (changed) {
		mesh_stream_mark_changed();
	}

	for (int i = 0; i < route_count; i++) {
		const uint8_t *mac = routes[i].addr;
		if (!mac_eq(mac, s_local_mac) && selected_remote_stream_needs_rearm(mac)) {
			esp_err_t err = mesh_send_log_ctrl(mac, true);
			selected_remote_stream_note_rearm(mac, err);
			if (err != ESP_OK) {
				ESP_LOGD(TAG, "LOG_CTRL route retry failed: %s",
				         esp_err_to_name(err));
			}
		}
	}
}

void log_http_server_refresh_routes(void)
{
	mesh_addr_t routes[LOG_HTTP_MAX_NODES];
	int route_count = 0;

	if (esp_mesh_get_routing_table(routes, sizeof(routes), &route_count) != ESP_OK) {
		return;
	}
	if (route_count > LOG_HTTP_MAX_NODES) route_count = LOG_HTTP_MAX_NODES;

	note_route_table_nodes(routes, route_count, ms_now());
}

void log_http_server_mesh_state_changed(void)
{
	mesh_stream_mark_changed();
}

static bool node_route_current(const uint8_t mac[6])
{
	if (!mac) return false;
	if (mac_eq(mac, s_local_mac)) return true;

	mesh_addr_t routes[LOG_HTTP_MAX_NODES];
	int route_count = 0;
	if (esp_mesh_get_routing_table(routes, sizeof(routes), &route_count) != ESP_OK) {
		return false;
	}
	if (route_count > LOG_HTTP_MAX_NODES) route_count = LOG_HTTP_MAX_NODES;
	return route_table_contains(routes, route_count, mac);
}

static uint32_t max_ms_value(uint32_t a, uint32_t b)
{
	return (a > b) ? a : b;
}

static uint32_t node_last_app_ms(const uint8_t mac[6])
{
	uint32_t last_ms = 0;

	if (!mac) return 0;
	if (mac_eq(mac, s_local_mac)) return ms_now();

	mesh_v2_root_stats_t v2;
	if (mesh_v2_root_stats_for_mac(mac, &v2)) {
		last_ms = max_ms_value(last_ms, v2.last_v2_ms);
		last_ms = max_ms_value(last_ms, v2.last_tunnel_ms);
	}

	portENTER_CRITICAL(&s_nodes_lock);
	{
		for (uint32_t i = 0; i < s_nodes_count; i++) {
			if (mac_eq(s_nodes[i].mac, mac)) {
				last_ms = max_ms_value(last_ms, s_nodes[i].last_seen_ms);
				last_ms = max_ms_value(last_ms, s_nodes[i].topology_seen_ms);
				break;
			}
		}
	}
	portEXIT_CRITICAL(&s_nodes_lock);

	portENTER_CRITICAL(&s_taskmon_lock);
	{
		taskmon_ent_t *ent = taskmon_find_locked(mac, false);
		if (ent && ent->valid) {
			last_ms = max_ms_value(last_ms, ent->current.updated_ms);
		}
	}
	portEXIT_CRITICAL(&s_taskmon_lock);

	portENTER_CRITICAL(&s_selection_lock);
	{
		if (s_stream_active && mac_eq(mac, s_stream_mac)) {
			last_ms = max_ms_value(last_ms, s_stream_last_line_ms);
		}
	}
	portEXIT_CRITICAL(&s_selection_lock);

	return last_ms;
}

static long node_app_age_ms_at(const uint8_t mac[6], uint32_t now)
{
	uint32_t last_ms = node_last_app_ms(mac);
	if (last_ms == 0) return -1;
	return (long)(uint32_t)(now - last_ms);
}

static bool node_has_fresh_telemetry(const uint8_t mac[6], uint32_t max_age_ms)
{
	if (!mac || mac_eq(mac, s_local_mac)) return true;

	uint32_t now = ms_now();
	long age_ms = node_app_age_ms_at(mac, now);
	return age_ms >= 0 && (uint32_t)age_ms <= max_age_ms;
}

static void mac_to_hex(const uint8_t mac[6], char out[13])
{
	snprintf(out, 13, "%02x%02x%02x%02x%02x%02x",
	         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void copy_tag(char *dst, size_t dst_sz, const char *tag)
{
	if (!dst || dst_sz == 0) return;

	const char *src = (tag && tag[0]) ? tag : "node";
	size_t pos = 0;
	while (src[pos] && pos < dst_sz - 1) {
		unsigned char c = (unsigned char)src[pos];
		dst[pos] = (c < 32 || c == '"' || c == '\\') ? '_' : (char)c;
		pos++;
	}
	dst[pos] = '\0';
}

static void copy_packet_text(char *dst, size_t dst_sz, const char *src, size_t src_sz)
{
	size_t n = 0;

	if (!dst || dst_sz == 0) {
		return;
	}

	if (src && src_sz > 0) {
		n = strnlen(src, src_sz);
		if (n >= dst_sz) {
			n = dst_sz - 1;
		}
		memcpy(dst, src, n);
	}
	dst[n] = '\0';
}

static void selection_snapshot(uint8_t mac[6], char *tag, size_t tag_sz)
{
	portENTER_CRITICAL(&s_selection_lock);
	{
		if (mac) {
			mac_copy(mac, s_sel_mac);
		}
		if (tag && tag_sz > 0) {
			copy_tag(tag, tag_sz, s_sel_tag);
		}
	}
	portEXIT_CRITICAL(&s_selection_lock);
}

static bool selection_is_local(void)
{
	uint8_t selected[6];
	selection_snapshot(selected, NULL, 0);
	return mac_eq(selected, s_local_mac);
}

static uint32_t uptime_advanced_s(uint32_t uptime_s, uint32_t uptime_seen_ms, uint32_t now_ms)
{
	return uptime_s + ((uint32_t)(now_ms - uptime_seen_ms) / 1000U);
}

static bool node_uptime_for_mac(const uint8_t mac[6], uint32_t *uptime_s)
{
	if (!mac || !uptime_s) return false;

	if (mac_eq(mac, s_local_mac)) {
		*uptime_s = local_uptime_s();
		return true;
	}

	bool valid = false;
	uint32_t value = 0;
	uint32_t now = ms_now();

	portENTER_CRITICAL(&s_nodes_lock);
	{
		for (uint32_t i = 0; i < s_nodes_count; i++) {
			if (mac_eq(s_nodes[i].mac, mac) && s_nodes[i].uptime_valid) {
				valid = true;
				value = uptime_advanced_s(s_nodes[i].uptime_s, s_nodes[i].uptime_seen_ms, now);
				break;
			}
		}
	}
	portEXIT_CRITICAL(&s_nodes_lock);

	if (valid) {
		*uptime_s = value;
	}
	return valid;
}

static ram_status_t ram_status_for_mac(const uint8_t mac[6])
{
	ram_status_t ram = {0};

	if (mac && mac_eq(mac, s_local_mac)) {
		ram.valid = true;
		ram.free_bytes = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_8BIT);
		ram.min_free_bytes = (uint32_t)heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
		ram.total_bytes = (uint32_t)heap_caps_get_total_size(MALLOC_CAP_8BIT);
		ram.internal_total_bytes = (uint32_t)heap_caps_get_total_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
		ram.internal_free_bytes = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
		ram.internal_min_free_bytes = (uint32_t)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
		ram.internal_valid = ram.internal_total_bytes > 0;
		ram.psram_total_bytes = (uint32_t)heap_caps_get_total_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
		ram.psram_free_bytes = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
		ram.psram_min_free_bytes = (uint32_t)heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
		ram.psram_valid = ram.psram_total_bytes > 0;
	}
	else if (mac) {
		portENTER_CRITICAL(&s_taskmon_lock);
		{
			taskmon_ent_t *ent = taskmon_find_locked(mac, false);
			if (ent && ent->ram.valid) {
				ram = ent->ram;
			}
		}
		portEXIT_CRITICAL(&s_taskmon_lock);
	}

	return ram;
}

static persistent_status_t persistent_status_for_mac(const uint8_t mac[6])
{
	persistent_status_t status = {0};

	if (!mac) {
		return status;
	}

	if (!mac_eq(mac, s_local_mac)) {
		portENTER_CRITICAL(&s_taskmon_lock);
		{
			taskmon_ent_t *ent = taskmon_find_locked(mac, false);
			if (ent && (ent->persistent.flash_valid || ent->persistent.nvs_valid)) {
				status = ent->persistent;
			}
		}
		portEXIT_CRITICAL(&s_taskmon_lock);
		return status;
	}

	uint32_t flash_size = 0;
	const esp_partition_t *app_partition = esp_ota_get_running_partition();
	if (esp_flash_get_size(NULL, &flash_size) == ESP_OK && app_partition) {
		status.flash_valid = true;
		status.flash_chip_bytes = flash_size;
		status.app_partition_bytes = app_partition->size;

		esp_partition_pos_t app_pos = {
			.offset = app_partition->address,
			.size = app_partition->size,
		};
		esp_image_metadata_t app_meta = {0};
		if (esp_image_get_metadata(&app_pos, &app_meta) == ESP_OK) {
			status.app_used_bytes = app_meta.image_len;
		}
	}

	nvs_stats_t nvs_stats = {0};
	if (nvs_get_stats(NULL, &nvs_stats) == ESP_OK) {
		status.nvs_valid = true;
		status.nvs_used_entries = (uint32_t)nvs_stats.used_entries;
		status.nvs_free_entries = (uint32_t)nvs_stats.free_entries;
		status.nvs_available_entries = (uint32_t)nvs_stats.available_entries;
		status.nvs_total_entries = (uint32_t)nvs_stats.total_entries;
	}

	return status;
}

static int taskmon_slot_count_for_mac(const uint8_t mac[6])
{
	int slot_count = -1;

	if (!mac) return slot_count;

	portENTER_CRITICAL(&s_taskmon_lock);
	{
		taskmon_ent_t *ent = taskmon_find_locked(mac, false);
		if (ent && ent->slot_count >= 0) {
			slot_count = ent->slot_count;
		}
	}
	portEXIT_CRITICAL(&s_taskmon_lock);

	return slot_count;
}

static uint32_t next_task_request_id(void)
{
	uint32_t id = 0;

	portENTER_CRITICAL(&s_selection_lock);
	id = s_task_request_id++;
	if (s_task_request_id == 0) {
		s_task_request_id = 1;
	}
	portEXIT_CRITICAL(&s_selection_lock);

	return id;
}

static uint32_t request_fresh_tasks_for_mac(const uint8_t mac[6])
{
	if (!mac) {
		return 0;
	}

	if (mac_eq(mac, s_local_mac)) {
		stack_monitor_snapshot_t snapshot;
		(void)stack_monitor_sample_now(&snapshot);
		return 0;
	}

	bool telemetry_fresh = node_has_fresh_telemetry(mac, NODEINFO_STALE_MS);
	(void)remote_stream_rearm_for_mac(mac, !telemetry_fresh);

	uint32_t request_id = next_task_request_id();
	esp_err_t last_err = ESP_ERR_INVALID_STATE;
	for (uint32_t attempt = 0; attempt < 3; attempt++) {
		last_err = mesh_v2_root_send_task_request(mac, request_id);
		if (last_err == ESP_OK) {
			return request_id;
		}
		(void)remote_stream_rearm_for_mac(mac, true);
		vTaskDelay(pdMS_TO_TICKS(120));
	}
	ESP_LOGD(TAG, "fresh task request failed for " MACSTR ": %s",
	         MAC2STR(mac), esp_err_to_name(last_err));
	return 0;
}

static bool taskmon_request_ready(const uint8_t mac[6], uint32_t request_id)
{
	bool ready = false;

	if (!mac || request_id == 0) {
		return false;
	}

	portENTER_CRITICAL(&s_taskmon_lock);
	{
		taskmon_ent_t *ent = taskmon_find_locked(mac, false);
		ready = ent && ent->valid && ent->last_request_id == request_id;
	}
	portEXIT_CRITICAL(&s_taskmon_lock);

	return ready;
}

static void wait_for_task_request(const uint8_t mac[6], uint32_t request_id,
                                  uint32_t timeout_ms)
{
	if (!mac || request_id == 0 || timeout_ms == 0) {
		return;
	}

	uint32_t start = ms_now();
	while ((uint32_t)(ms_now() - start) < timeout_ms) {
		if (taskmon_request_ready(mac, request_id)) {
			return;
		}
		vTaskDelay(pdMS_TO_TICKS(50));
	}
}

static taskmon_ent_t *taskmon_find_locked(const uint8_t mac[6], bool create)
{
	taskmon_ent_t *empty = NULL;

	for (uint32_t i = 0; i < LOG_HTTP_MAX_NODES; i++) {
		if (s_taskmon[i].used && mac_eq(s_taskmon[i].mac, mac)) {
			return &s_taskmon[i];
		}
		if (!s_taskmon[i].used && !empty) {
			empty = &s_taskmon[i];
		}
	}

	if (!create || !empty) {
		return NULL;
	}

	memset(empty, 0, sizeof(*empty));
	empty->used = true;
	empty->slot_count = -1;
	mac_copy(empty->mac, mac);
	copy_tag(empty->tag, sizeof(empty->tag), "node");
	return empty;
}

static void taskmon_update_tag_locked(taskmon_ent_t *ent, const char *tag)
{
	if (ent && tag && tag[0]) {
		copy_tag(ent->tag, sizeof(ent->tag), tag);
	}
}

static void taskmon_start_locked(taskmon_ent_t *ent, const uint8_t mac[6], const char *tag)
{
	if (!ent) return;

	memset(&ent->staging, 0, sizeof(ent->staging));
	ent->staging.updated_ms = ms_now();
	ent->staging.count = 0;
	ent->staging.cpu_valid = false;
	ent->slot_count = -1;
	ent->ram.valid = false;
	ent->persistent.flash_valid = false;
	ent->persistent.nvs_valid = false;
	ent->staging_active = true;
	mac_copy(ent->mac, mac);
	taskmon_update_tag_locked(ent, tag);
}

static void taskmon_publish_locked(taskmon_ent_t *ent)
{
	if (!ent || !ent->staging_active) return;

	ent->staging.updated_ms = ms_now();
	ent->current = ent->staging;
	ent->valid = true;
	ent->staging_active = false;
}

static void taskmon_add_task_locked(taskmon_ent_t *ent, const uint8_t mac[6],
                                    const char *tag, const stack_monitor_task_info_t *task)
{
	if (!ent || !task) return;

	if (!ent->staging_active) {
		taskmon_start_locked(ent, mac, tag);
	}

	if (ent->staging.count >= STACK_MONITOR_MAX_TASKS) {
		return;
	}

	ent->staging.tasks[ent->staging.count++] = *task;
	taskmon_update_tag_locked(ent, tag);
}

static void taskmon_set_cpu_locked(taskmon_ent_t *ent, const uint8_t mac[6],
                                   const char *tag, uint32_t cpu_load_x10)
{
	if (!ent) return;

	if (!ent->staging_active) {
		taskmon_start_locked(ent, mac, tag);
	}

	ent->staging.cpu_valid = true;
	ent->staging.cpu_load_x10 = cpu_load_x10;
	taskmon_update_tag_locked(ent, tag);
}

static void taskmon_set_slot_count_locked(taskmon_ent_t *ent, const uint8_t mac[6],
                                          const char *tag, int slot_count)
{
	if (!ent || slot_count < 0) return;

	mac_copy(ent->mac, mac);
	taskmon_update_tag_locked(ent, tag);
	ent->slot_count = slot_count;
}

static void taskmon_set_ram_locked(taskmon_ent_t *ent, const uint8_t mac[6],
                                   const char *tag, const ram_status_t *ram)
{
	if (!ent || !ram || !ram->valid) return;

	mac_copy(ent->mac, mac);
	taskmon_update_tag_locked(ent, tag);
	ent->ram = *ram;
}

static void taskmon_set_persistent_locked(taskmon_ent_t *ent, const uint8_t mac[6],
                                          const char *tag, const persistent_status_t *persistent)
{
	if (!ent || !persistent ||
	    (!persistent->flash_valid && !persistent->nvs_valid)) {
		return;
	}

	mac_copy(ent->mac, mac);
	taskmon_update_tag_locked(ent, tag);
	ent->persistent = *persistent;
}

static bool taskmon_get_snapshot(const uint8_t mac[6], stack_monitor_snapshot_t *out,
                                 char *tag, size_t tag_sz)
{
	bool ok = false;

	if (tag && tag_sz > 0) {
		tag[0] = '\0';
	}

	if (mac && mac_eq(mac, s_local_mac)) {
		if (tag && tag_sz > 0) {
			copy_tag(tag, tag_sz, s_local_tag);
		}
		return out ? stack_monitor_get_snapshot(out) : false;
	}

	portENTER_CRITICAL(&s_taskmon_lock);
	{
		taskmon_ent_t *ent = taskmon_find_locked(mac, false);
		if (ent) {
			if (tag && tag_sz > 0) {
				copy_tag(tag, tag_sz, ent->tag);
			}
			if (ent->valid && out) {
				*out = ent->current;
				ok = true;
			}
		}
	}
	portEXIT_CRITICAL(&s_taskmon_lock);

	return ok;
}

static bool lookup_node_tag(const uint8_t mac[6], char *tag, size_t tag_sz)
{
	if (!tag || tag_sz == 0) return false;

	if (mac_eq(mac, s_local_mac)) {
		copy_tag(tag, tag_sz, s_local_tag);
		return true;
	}

	bool found = false;
	portENTER_CRITICAL(&s_nodes_lock);
	{
		for (uint32_t i = 0; i < s_nodes_count; i++) {
			if (mac_eq(s_nodes[i].mac, mac)) {
				copy_tag(tag, tag_sz, s_nodes[i].tag);
				found = true;
				break;
			}
		}
	}
	portEXIT_CRITICAL(&s_nodes_lock);

	if (found) {
		return true;
	}

	uint8_t selected_mac[6];
	char selected_tag[16];
	selection_snapshot(selected_mac, selected_tag, sizeof(selected_tag));
	if (mac_eq(mac, selected_mac)) {
		copy_tag(tag, tag_sz, selected_tag);
		return true;
	}

	return false;
}

static const char *body_after_marker(const char *line, const char *marker)
{
	const char *p = strstr(line, marker);
	if (!p) return NULL;

	p += strlen(marker);
	if (*p == ':') p++;
	while (*p == ' ') p++;
	return p;
}

static bool parse_taskmon_task(const char *line, stack_monitor_task_info_t *task)
{
	if (!line || !task) return false;

	memset(task, 0, sizeof(*task));
	task->cpu_x10 = -1;

	const char *body = body_after_marker(line, "[STACKMON]");
	if (body && body[0] == '"') {
		char name[STACK_MONITOR_TASK_NAME_MAX] = {0};
		unsigned prio = 0;
		unsigned free_words = 0;
		unsigned free_bytes = 0;
		char cpu_token[16] = {0};
		float cpu_pct = 0.0f;

		if (sscanf(body,
		           "\"%15[^\"]\" prio=%u free=%u words (%u bytes), cpu=%15s",
		           name, &prio, &free_words, &free_bytes, cpu_token) == 5) {
			copy_tag(task->name, sizeof(task->name), name);
			task->priority = prio;
			task->free_words = free_words;
			task->free_bytes = free_bytes;
			task->cpu_x10 = (cpu_token[0] == '?') ? -1 : (int32_t)(strtof(cpu_token, NULL) * 10.0f + 0.5f);
			return true;
		}

		if (sscanf(body,
		           "\"%15[^\"]\" prio=%u free=%u words, cpu=%f%%",
		           name, &prio, &free_words, &cpu_pct) == 4) {
			copy_tag(task->name, sizeof(task->name), name);
			task->priority = prio;
			task->free_words = free_words;
			task->free_bytes = free_words * sizeof(StackType_t);
			task->cpu_x10 = (int32_t)(cpu_pct * 10.0f + 0.5f);
			return true;
		}
	}

	body = body_after_marker(line, "[STACK] task=");
	if (body && body[0] == '"') {
		char name[STACK_MONITOR_TASK_NAME_MAX] = {0};
		unsigned prio = 0;
		unsigned free_words = 0;
		unsigned free_bytes = 0;

		if (sscanf(body,
		           "\"%15[^\"]\" prio=%u free=%u words (%u bytes)",
		           name, &prio, &free_words, &free_bytes) == 4) {
			copy_tag(task->name, sizeof(task->name), name);
			task->priority = prio;
			task->free_words = free_words;
			task->free_bytes = free_bytes;
			task->cpu_x10 = -1;
			return true;
		}
	}

	return false;
}

static bool parse_taskmon_cpu(const char *line, uint32_t *cpu_load_x10)
{
	if (!line || !cpu_load_x10) return false;

	const char *p = strstr(line, "CPU: CPU load ~");
	if (!p) return false;

	float cpu_pct = 0.0f;
	if (sscanf(p, "CPU: CPU load ~ %f%%", &cpu_pct) != 1) {
		return false;
	}

	*cpu_load_x10 = (uint32_t)(cpu_pct * 10.0f + 0.5f);
	return true;
}

static bool parse_taskmon_slots(const char *line, int *slot_count)
{
	if (!line || !slot_count) return false;

	const char *p = strstr(line, "===== STACK MONITOR");
	if (!p) return false;

	p = strstr(p, "slots=");
	if (!p) return false;
	p += strlen("slots=");

	char *end = NULL;
	long value = strtol(p, &end, 10);
	if (end == p || value < 0 || value > 1024) {
		return false;
	}

	*slot_count = (int)value;
	return true;
}

static bool parse_taskmon_ram(const char *line, ram_status_t *ram)
{
	if (!line || !ram) return false;

	const char *body = body_after_marker(line, "[STACKMON]");
	const char *p = body ? body : line;
	while (*p == ' ') p++;
	if (strncmp(p, "RAM:", 4) != 0) return false;

	unsigned free_bytes = 0;
	unsigned min_free_bytes = 0;
	unsigned total_bytes = 0;
	if (sscanf(p, "RAM: free=%u min=%u total=%u bytes",
	           &free_bytes, &min_free_bytes, &total_bytes) != 3) {
		return false;
	}

	memset(ram, 0, sizeof(*ram));
	ram->valid = true;
	ram->free_bytes = free_bytes;
	ram->min_free_bytes = min_free_bytes;
	ram->total_bytes = total_bytes;
	return true;
}

static bool parse_taskmon_persistent(const char *line, persistent_status_t *persistent)
{
	if (!line || !persistent) return false;

	const char *body = body_after_marker(line, "[STACKMON]");
	const char *p = body ? body : line;
	while (*p == ' ') p++;
	if (strncmp(p, "FLASH:", 6) != 0) return false;

	unsigned chip = 0;
	unsigned app_used = 0;
	unsigned app_slot = 0;
	unsigned nvs_used = 0;
	unsigned nvs_free = 0;
	unsigned nvs_avail = 0;
	unsigned nvs_total = 0;
	if (sscanf(p,
	           "FLASH: chip=%u app_used=%u app_slot=%u nvs_used=%u nvs_free=%u nvs_avail=%u nvs_total=%u",
	           &chip, &app_used, &app_slot, &nvs_used, &nvs_free, &nvs_avail, &nvs_total) != 7) {
		return false;
	}

	memset(persistent, 0, sizeof(*persistent));
	persistent->flash_valid = true;
	persistent->flash_chip_bytes = chip;
	persistent->app_used_bytes = app_used;
	persistent->app_partition_bytes = app_slot;
	persistent->nvs_valid = true;
	persistent->nvs_used_entries = nvs_used;
	persistent->nvs_free_entries = nvs_free;
	persistent->nvs_available_entries = nvs_avail;
	persistent->nvs_total_entries = nvs_total;
	return true;
}

static bool taskmon_ingest_line(const uint8_t mac[6], const char *tag, const char *line)
{
	if (!mac || !line) return false;

	stack_monitor_task_info_t task;
	uint32_t cpu_load_x10 = 0;
	ram_status_t ram;
	persistent_status_t persistent;
	int slot_count = -1;
	bool is_end = strstr(line, "===== END STACK MONITOR") != NULL;
	bool is_start = !is_end && strstr(line, "===== STACK MONITOR") != NULL;
	bool has_task = parse_taskmon_task(line, &task);
	bool has_cpu = parse_taskmon_cpu(line, &cpu_load_x10);
	bool has_slots = parse_taskmon_slots(line, &slot_count);
	bool has_ram = parse_taskmon_ram(line, &ram);
	bool has_persistent = parse_taskmon_persistent(line, &persistent);

	if (!is_start && !is_end && !has_task && !has_cpu && !has_slots &&
	    !has_ram && !has_persistent) {
		return false;
	}

	portENTER_CRITICAL(&s_taskmon_lock);
	{
		taskmon_ent_t *ent = taskmon_find_locked(mac, true);
		if (ent) {
			taskmon_update_tag_locked(ent, tag);

			if (is_start) {
				taskmon_start_locked(ent, mac, tag);
			}
			if (has_slots) {
				taskmon_set_slot_count_locked(ent, mac, tag, slot_count);
			}
			if (has_task) {
				taskmon_add_task_locked(ent, mac, tag, &task);
			}
			if (has_cpu) {
				taskmon_set_cpu_locked(ent, mac, tag, cpu_load_x10);
			}
			if (has_ram) {
				taskmon_set_ram_locked(ent, mac, tag, &ram);
			}
			if (has_persistent) {
				taskmon_set_persistent_locked(ent, mac, tag, &persistent);
			}
			if (is_end) {
				taskmon_publish_locked(ent);
			}
		}
	}
	portEXIT_CRITICAL(&s_taskmon_lock);

	return true;
}

static bool starts_with_len(const char *s, size_t len, const char *prefix)
{
	size_t plen = strlen(prefix);
	return s && len >= plen && memcmp(s, prefix, plen) == 0;
}

static const char *log_payload_start(const char *line, size_t len, size_t *out_len)
{
	const char *p = line;
	size_t l = len;

	while (l > 0 && (*p == ' ' || *p == '\t')) {
		p++;
		l--;
	}

	if (l > 2 && p[0] == '[') {
		for (size_t i = 1; i < l && i < 40; i++) {
			if (p[i] == ']') {
				size_t skip = i + 1;
				if (skip < l && p[skip] == ' ') {
					skip++;
				}
				p += skip;
				l -= skip;
				while (l > 0 && (*p == ' ' || *p == '\t')) {
					p++;
					l--;
				}
				break;
			}
		}
	}

	if (out_len) {
		*out_len = l;
	}
	return p;
}

static bool log_http_wire_status_line(const char *line, size_t len)
{
	return starts_with_len(line, len, "HTTP/1.0 ") ||
	       starts_with_len(line, len, "HTTP/1.1 ");
}

static bool log_http_wire_header_line(const char *line, size_t len)
{
	static const char *const prefixes[] = {
		"Content-Type:",
		"Content-Length:",
		"Transfer-Encoding:",
		"X-Log-Next:",
		"X-Log-Reset:",
		"Cache-Control:",
		"Connection:",
		"Server:",
		"Date:",
	};

	for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
		if (starts_with_len(line, len, prefixes[i])) {
			return true;
		}
	}
	return false;
}

static bool log_http_wire_chunk_end(const char *line, size_t len)
{
	return len == 1 && line[0] == '0';
}

static void log_buffer_clear(void)
{
	portENTER_CRITICAL(&s_log_lock);
	{
		s_write_idx = 0;
		s_total_lines = 0;
		s_http_wire_drop_budget = 0;
		memset(s_lines, 0, sizeof(s_lines));
	}
	portEXIT_CRITICAL(&s_log_lock);
	log_stream_notify();
}

static void log_buffer_append_line(const char *line, size_t len)
{
	if (!line || len == 0) return;

	// Trim trailing CR/LF.
	while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
		len--;
	}

	// Skip lines that became empty after trimming.
	if (len == 0) return;

	portENTER_CRITICAL(&s_log_lock);
	{
		size_t payload_len = 0;
		const char *payload = log_payload_start(line, len, &payload_len);
		bool drop_line = false;

		if (log_http_wire_status_line(payload, payload_len)) {
			s_http_wire_drop_budget = 10;
			drop_line = true;
		} else if (s_http_wire_drop_budget > 0 &&
		           (log_http_wire_header_line(payload, payload_len) ||
		            log_http_wire_chunk_end(payload, payload_len))) {
			s_http_wire_drop_budget--;
			drop_line = true;
		} else if (s_http_wire_drop_budget > 0) {
			s_http_wire_drop_budget = 0;
		}

		if (drop_line) {
			portEXIT_CRITICAL(&s_log_lock);
			return;
		}

		uint32_t idx = s_write_idx % LOG_HTTP_LINES;

		size_t copy_len = (len >= (LOG_HTTP_LINE_MAX - 1)) ? (LOG_HTTP_LINE_MAX - 1) : len;
		memcpy(s_lines[idx], line, copy_len);
		s_lines[idx][copy_len] = '\0';

		s_write_idx++;
		if (s_total_lines < LOG_HTTP_LINES) s_total_lines++;
	}
	portEXIT_CRITICAL(&s_log_lock);
	log_stream_notify();
}


static void log_buffer_stream_range(uint32_t from, uint32_t *out_start,
                                    uint32_t *out_next, bool *out_reset)
{
	uint32_t next = 0;
	uint32_t total = 0;
	uint32_t earliest = 0;
	bool reset = false;

	portENTER_CRITICAL(&s_log_lock);
	{
		next = s_write_idx;
		total = s_total_lines;
		earliest = (next >= total) ? (next - total) : 0;
	}
	portEXIT_CRITICAL(&s_log_lock);

	if (from < earliest || from > next) {
		reset = true;
		from = earliest;
	}

	if (out_start) *out_start = from;
	if (out_next) *out_next = next;
	if (out_reset) *out_reset = reset;
}

static uint32_t log_buffer_next_cursor(void)
{
	uint32_t next = 0;

	portENTER_CRITICAL(&s_log_lock);
	next = s_write_idx;
	portEXIT_CRITICAL(&s_log_lock);

	return next;
}

static bool log_buffer_copy_abs_line(uint32_t abs_i, char *out, size_t out_sz,
                                     size_t *out_len)
{
	if (!out || out_sz == 0) return false;

	bool ok = false;
	size_t pos = 0;

	portENTER_CRITICAL(&s_log_lock);
	{
		uint32_t next = s_write_idx;
		uint32_t total = s_total_lines;
		uint32_t earliest = (next >= total) ? (next - total) : 0;

		if (abs_i >= earliest && abs_i < next) {
			uint32_t idx = abs_i % LOG_HTTP_LINES;
			const char *line = s_lines[idx];
			size_t l = strnlen(line, LOG_HTTP_LINE_MAX);
			size_t copy_len = (l < out_sz - 1) ? l : (out_sz - 1);

			memcpy(out, line, copy_len);
			pos = copy_len;

			if (pos < out_sz - 1 && (pos == 0 || out[pos - 1] != '\n')) {
				out[pos++] = '\n';
			}
			ok = true;
		}
	}
	portEXIT_CRITICAL(&s_log_lock);

	out[pos] = '\0';
	if (out_len) *out_len = pos;
	return ok;
}

static bool build_time_prefix(char *out, size_t out_sz)
{
	if (!out || out_sz == 0) return false;

	time_t now = time(NULL);
	if (now <= 0) {
		snprintf(out, out_sz, "[no-time] ");
		return true;
	}

	struct tm tm_now;
	if (!localtime_r(&now, &tm_now)) {
		snprintf(out, out_sz, "[no-time] ");
		return true;
	}

	size_t n = strftime(out, out_sz, "[%Y-%m-%d %H:%M:%S] ", &tm_now);
	if (n == 0) snprintf(out, out_sz, "[no-time] ");
	return true;
}

/* ----------------- Mesh CTRL (root -> node) ----------------- */

static esp_err_t mesh_send_log_ctrl(const uint8_t to_mac[6], bool enable)
{
	if (!to_mac) {
		return ESP_ERR_INVALID_ARG;
	}

	esp_err_t v2_err = mesh_v2_root_send_log_ctrl(to_mac, enable);

	mesh_log_ctrl_packet_t p;
	memset(&p, 0, sizeof(p));

	p.h.magic = MESH_PKT_MAGIC;
	p.h.version = MESH_PKT_VERSION;
	p.h.type = MESH_LOG_TYPE_CTRL;
	p.h.counter = ms_now();
	esp_wifi_get_mac(WIFI_IF_STA, p.h.src_mac);

	p.enable = enable ? 1 : 0;

	mesh_data_t data;
	memset(&data, 0, sizeof(data));
	data.data = (uint8_t *)&p;
	data.size = sizeof(p);
	data.proto = MESH_PROTO_BIN;
	data.tos = MESH_TOS_P2P;

	mesh_addr_t dest;
	memset(&dest, 0, sizeof(dest));
	memcpy(dest.addr, to_mac, 6);

	esp_err_t v1_err = esp_mesh_send(&dest, &data, MESH_DATA_P2P, NULL, 0);
	if (v2_err == ESP_OK || v1_err == ESP_OK) {
		return ESP_OK;
	}
	return v1_err != ESP_OK ? v1_err : v2_err;
}

static void select_stream_node(const uint8_t mac[6], const char *tag)
{
	if (!mac) return;

	char clean_tag[16];
	copy_tag(clean_tag, sizeof(clean_tag), tag);

	uint8_t old_stream_mac[6] = {0};
	uint8_t new_stream_mac[6] = {0};
	bool disable_old_stream = false;
	bool enable_new_stream = false;
	bool enable_local_stream = false;

	portENTER_CRITICAL(&s_selection_lock);
	{
		if (mac_eq(mac, s_sel_mac)) {
			copy_tag(s_sel_tag, sizeof(s_sel_tag), clean_tag);
			if (mac_eq(mac, s_local_mac)) {
				portEXIT_CRITICAL(&s_selection_lock);
				return;
			}
			s_stream_active = true;
			mac_copy(s_stream_mac, mac);
			mac_copy(new_stream_mac, mac);
			s_stream_ready = false;
			s_stream_selected_ms = ms_now();
			s_stream_last_line_ms = 0;
			enable_new_stream = true;
			portEXIT_CRITICAL(&s_selection_lock);
			goto selected;
		}

		if (s_stream_active) {
			disable_old_stream = true;
			mac_copy(old_stream_mac, s_stream_mac);
		}

		mac_copy(s_sel_mac, mac);
		copy_tag(s_sel_tag, sizeof(s_sel_tag), clean_tag);

		if (mac_eq(mac, s_local_mac)) {
			s_stream_active = false;
			s_stream_ready = false;
			s_stream_selected_ms = 0;
			s_stream_last_line_ms = 0;
			memset(s_stream_mac, 0, sizeof(s_stream_mac));
			memset(s_last_rearm_mac, 0, sizeof(s_last_rearm_mac));
			s_last_rearm_ms = 0;
			enable_local_stream = true;
		} else {
			s_stream_active = true;
			mac_copy(s_stream_mac, mac);
			mac_copy(new_stream_mac, mac);
			s_stream_ready = false;
			s_stream_selected_ms = ms_now();
			s_stream_last_line_ms = 0;
			enable_new_stream = true;
		}
	}
	portEXIT_CRITICAL(&s_selection_lock);

selected:
	if (disable_old_stream) {
		(void)mesh_send_log_ctrl(old_stream_mac, false);
	}

	log_buffer_clear();

	if (enable_local_stream) {
		char tprefix[40];
		char line[LOG_HTTP_LINE_MAX];
		build_time_prefix(tprefix, sizeof(tprefix));
		snprintf(line, sizeof(line),
		         "%sI (0) log_http: selected %s [%02x%02x%02x%02x%02x%02x], local log stream active",
		         tprefix,
		         clean_tag,
		         s_local_mac[0], s_local_mac[1], s_local_mac[2],
		         s_local_mac[3], s_local_mac[4], s_local_mac[5]);
		log_buffer_append_line(line, strnlen(line, sizeof(line)));
	}

	if (enable_new_stream) {
		char tprefix[40];
		char line[LOG_HTTP_LINE_MAX];
		bool route_current = node_route_current(new_stream_mac);
		bool app_fresh = node_has_fresh_telemetry(new_stream_mac, NODEINFO_STALE_MS);
		const char *reason = route_current
			? (app_fresh ? "waiting for log stream" : "route alive, telemetry stale")
			: (app_fresh ? "waiting for log stream" : "waiting for node route");
		build_time_prefix(tprefix, sizeof(tprefix));
		snprintf(line, sizeof(line),
		         "%sI (0) log_http: selected %s [%02x%02x%02x%02x%02x%02x], %s",
		         tprefix,
		         clean_tag,
		         new_stream_mac[0], new_stream_mac[1], new_stream_mac[2],
		         new_stream_mac[3], new_stream_mac[4], new_stream_mac[5],
		         reason);
		log_buffer_append_line(line, strnlen(line, sizeof(line)));
		esp_err_t err = mesh_send_log_ctrl(new_stream_mac, true);
		selected_remote_stream_note_rearm(new_stream_mac, err);
	}

	mesh_stream_mark_changed();
}

static bool selected_remote_stream_needs_rearm(const uint8_t mac[6])
{
	bool rearm = false;
	uint32_t now = ms_now();

	if (!mac) return false;
	bool app_fresh = node_has_fresh_telemetry(mac, NODEINFO_STALE_MS);

	portENTER_CRITICAL(&s_selection_lock);
	{
		if (s_stream_active &&
		    mac_eq(mac, s_sel_mac) &&
		    mac_eq(mac, s_stream_mac) &&
		    !mac_eq(mac, s_local_mac)) {
			if (s_stream_ready && !app_fresh) {
				s_stream_ready = false;
			}
			uint32_t min_ms = s_stream_ready ? REMOTE_LOG_READY_REARM_MS :
			                  REMOTE_LOG_RETRY_MS;
			bool same_mac = mac_eq(mac, s_last_rearm_mac);
			bool throttled = same_mac &&
			                 (uint32_t)(now - s_last_rearm_ms) < min_ms;
			if (!throttled) {
				rearm = true;
			}
		}
	}
	portEXIT_CRITICAL(&s_selection_lock);

	return rearm;
}

static void selected_remote_stream_note_rearm(const uint8_t mac[6], esp_err_t err)
{
	if (!mac) return;

	portENTER_CRITICAL(&s_selection_lock);
	{
		uint32_t now = ms_now();
		s_last_log_ctrl_ms = now;
		s_last_log_ctrl_err = err;
		if (err == ESP_OK) {
			mac_copy(s_last_rearm_mac, mac);
			s_last_rearm_ms = now;
		} else if (s_stream_active && mac_eq(mac, s_stream_mac)) {
			s_stream_ready = false;
		}
	}
	portEXIT_CRITICAL(&s_selection_lock);
}

static esp_err_t remote_stream_rearm_for_mac(const uint8_t mac[6], bool force)
{
	if (!mac || mac_eq(mac, s_local_mac)) {
		return ESP_ERR_INVALID_ARG;
	}

	uint32_t now = ms_now();
	bool send = force;
	if (!send) {
		portENTER_CRITICAL(&s_selection_lock);
		{
			bool same_mac = mac_eq(mac, s_last_rearm_mac);
			bool throttled = same_mac &&
			                 (uint32_t)(now - s_last_rearm_ms) < REMOTE_LOG_RETRY_MS;
			send = !throttled;
		}
		portEXIT_CRITICAL(&s_selection_lock);
	}
	if (!send) {
		return ESP_OK;
	}

	esp_err_t err = mesh_send_log_ctrl(mac, true);
	selected_remote_stream_note_rearm(mac, err);
	return err;
}

static void stream_lease_task(void *arg)
{
	(void)arg;

	for (;;) {
		vTaskDelay(pdMS_TO_TICKS(1000));

		uint8_t mac[6] = {0};
		bool active = false;
		portENTER_CRITICAL(&s_selection_lock);
		{
			active = s_stream_active && !mac_eq(s_stream_mac, s_local_mac);
			if (active) {
				mac_copy(mac, s_stream_mac);
			}
		}
		portEXIT_CRITICAL(&s_selection_lock);

		if (!active) {
			continue;
		}

		if (selected_remote_stream_needs_rearm(mac)) {
			esp_err_t err = mesh_send_log_ctrl(mac, true);
			selected_remote_stream_note_rearm(mac, err);
			if (err != ESP_OK) {
				ESP_LOGD(TAG, "LOG_CTRL retry failed: %s", esp_err_to_name(err));
			}
		}
	}
}

/* ----------------- vprintf hook for the selected local node ----------------- */

static int log_http_vprintf(const char *fmt, va_list ap)
{
	int ret = 0;

	// 1) UART
	if (s_orig_vprintf) {
		va_list ap_copy;
		va_copy(ap_copy, ap);
		ret = s_orig_vprintf(fmt, ap_copy);
		va_end(ap_copy);
	}

	// 2) Buffer local logs only while the local node is selected.
	if (!selection_is_local()) {
		return ret;
	}

	char tprefix[40];
	build_time_prefix(tprefix, sizeof(tprefix));
	size_t tlen = strnlen(tprefix, sizeof(tprefix));

	char stack_buf[LOG_HTTP_STACK_TMP];
	size_t cap = sizeof(stack_buf);

	size_t copy_t = (tlen < (cap - 1)) ? tlen : (cap - 1);
	memcpy(stack_buf, tprefix, copy_t);
	stack_buf[copy_t] = '\0';

	va_list ap_copy2;
	va_copy(ap_copy2, ap);
	int w = vsnprintf(stack_buf + copy_t, cap - copy_t, fmt, ap_copy2);
	va_end(ap_copy2);

	if (w < 0) {
		if (!taskmon_ingest_line(s_local_mac, s_local_tag, stack_buf)) {
			log_buffer_append_line(stack_buf, strnlen(stack_buf, cap));
		}
		return ret;
	}

	if ((size_t)w < (cap - copy_t)) {
		if (!taskmon_ingest_line(s_local_mac, s_local_tag, stack_buf)) {
			log_buffer_append_line(stack_buf, copy_t + (size_t)w);
		}
		return ret;
	}

	if (!taskmon_ingest_line(s_local_mac, s_local_tag, stack_buf)) {
		log_buffer_append_line(stack_buf, strnlen(stack_buf, cap));
	}
	return ret;
}

/* ----------------- Public API called from mesh RX ----------------- */

void log_http_server_node_seen_uptime(const uint8_t mac[6], const char *tag,
                                      bool uptime_valid, uint32_t uptime_s)
{
	if (!mac) return;

	uint32_t now = ms_now();
	bool recorded = false;

	portENTER_CRITICAL(&s_nodes_lock);
	{
		for (uint32_t i = 0; i < s_nodes_count; i++) {
			if (mac_eq(s_nodes[i].mac, mac)) {
				if (tag && tag[0]) {
					copy_tag(s_nodes[i].tag, sizeof(s_nodes[i].tag), tag);
				}
				s_nodes[i].last_seen_ms = now;
				if (uptime_valid) {
					s_nodes[i].uptime_valid = true;
					s_nodes[i].uptime_s = uptime_s;
					s_nodes[i].uptime_seen_ms = now;
				}
				recorded = true;
				break;
			}
		}

		if (!recorded && s_nodes_count < LOG_HTTP_MAX_NODES) {
			mac_copy(s_nodes[s_nodes_count].mac, mac);
			copy_tag(s_nodes[s_nodes_count].tag, sizeof(s_nodes[s_nodes_count].tag), tag);
			s_nodes[s_nodes_count].last_seen_ms = now;
			s_nodes[s_nodes_count].uptime_valid = uptime_valid;
			s_nodes[s_nodes_count].uptime_s = uptime_valid ? uptime_s : 0;
			s_nodes[s_nodes_count].uptime_seen_ms = now;
			s_nodes_count++;
			recorded = true;
		}
	}
	portEXIT_CRITICAL(&s_nodes_lock);

	if (uptime_valid && selected_remote_stream_needs_rearm(mac)) {
		esp_err_t err = mesh_send_log_ctrl(mac, true);
		selected_remote_stream_note_rearm(mac, err);
	}

	remote_ota_note_node_seen(mac, uptime_valid, uptime_s);
	mesh_stream_mark_changed();
}

void log_http_server_node_seen(const uint8_t mac[6], const char *tag)
{
	log_http_server_node_seen_uptime(mac, tag, false, 0);
}

void log_http_server_node_topology(const uint8_t mac[6],
                                   const mesh_v2_topology_payload_t *topology,
                                   size_t topology_len)
{
	if (!mac || !topology) return;

	uint32_t now = ms_now();
	bool recorded = false;
	char tag[MESH_V2_TAG_MAX + 1];
	copy_packet_text(tag, sizeof(tag), topology->tag, sizeof(topology->tag));
	bool has_ota_slots = topology_len >= sizeof(mesh_v2_topology_v2_payload_t);
	char ota_running_label[MESH_OTA_SLOT_LABEL_MAX] = {0};
	char ota_update_label[MESH_OTA_SLOT_LABEL_MAX] = {0};
	uint32_t ota_running_size = 0;
	uint32_t ota_update_size = 0;

	if (has_ota_slots) {
		const mesh_v2_topology_v2_payload_t *v2 =
			(const mesh_v2_topology_v2_payload_t *)topology;
		copy_packet_text(ota_running_label, sizeof(ota_running_label),
		                 v2->ota_running_label, sizeof(v2->ota_running_label));
		copy_packet_text(ota_update_label, sizeof(ota_update_label),
		                 v2->ota_update_label, sizeof(v2->ota_update_label));
		ota_running_size = v2->ota_running_size;
		ota_update_size = v2->ota_update_size;
	}

	portENTER_CRITICAL(&s_nodes_lock);
	{
		for (uint32_t i = 0; i < s_nodes_count; i++) {
			if (mac_eq(s_nodes[i].mac, mac)) {
				if (tag[0]) {
					copy_tag(s_nodes[i].tag, sizeof(s_nodes[i].tag), tag);
				}
				s_nodes[i].last_seen_ms = now;
				s_nodes[i].topology_seen_ms = now;
				mac_copy(s_nodes[i].parent_mac, topology->parent_mac);
				mac_copy(s_nodes[i].root_mac, topology->root_mac);
				s_nodes[i].layer = topology->layer;
				s_nodes[i].max_layer = topology->max_layer;
				s_nodes[i].parent_rssi = topology->parent_rssi;
				s_nodes[i].child_count = topology->child_count;
				s_nodes[i].capabilities = topology->capabilities;
				s_nodes[i].v1_ok_age_ms = topology->v1_ok_age_ms;
				s_nodes[i].v2_ack_age_ms = topology->v2_ack_age_ms;
				s_nodes[i].last_send_err = topology->last_send_err;
				s_nodes[i].recovery_phase = topology->recovery_phase;
				s_nodes[i].log_stream_enabled = topology->log_stream_enabled != 0;
				if (has_ota_slots) {
					copy_packet_text(s_nodes[i].ota_running_label,
					                 sizeof(s_nodes[i].ota_running_label),
					                 ota_running_label, sizeof(ota_running_label));
					copy_packet_text(s_nodes[i].ota_update_label,
					                 sizeof(s_nodes[i].ota_update_label),
					                 ota_update_label, sizeof(ota_update_label));
					s_nodes[i].ota_running_size = ota_running_size;
					s_nodes[i].ota_update_size = ota_update_size;
				}
				s_nodes[i].uptime_valid = true;
				s_nodes[i].uptime_s = topology->uptime_s;
				s_nodes[i].uptime_seen_ms = now;
				recorded = true;
				break;
			}
		}

		if (!recorded && s_nodes_count < LOG_HTTP_MAX_NODES) {
			node_ent_t *ent = &s_nodes[s_nodes_count++];
			memset(ent, 0, sizeof(*ent));
			mac_copy(ent->mac, mac);
			copy_tag(ent->tag, sizeof(ent->tag), tag);
			ent->last_seen_ms = now;
			ent->topology_seen_ms = now;
			mac_copy(ent->parent_mac, topology->parent_mac);
			mac_copy(ent->root_mac, topology->root_mac);
			ent->layer = topology->layer;
			ent->max_layer = topology->max_layer;
			ent->parent_rssi = topology->parent_rssi;
			ent->child_count = topology->child_count;
			ent->capabilities = topology->capabilities;
			ent->v1_ok_age_ms = topology->v1_ok_age_ms;
			ent->v2_ack_age_ms = topology->v2_ack_age_ms;
			ent->last_send_err = topology->last_send_err;
			ent->recovery_phase = topology->recovery_phase;
			ent->log_stream_enabled = topology->log_stream_enabled != 0;
			if (has_ota_slots) {
				copy_packet_text(ent->ota_running_label,
				                 sizeof(ent->ota_running_label),
				                 ota_running_label, sizeof(ota_running_label));
				copy_packet_text(ent->ota_update_label,
				                 sizeof(ent->ota_update_label),
				                 ota_update_label, sizeof(ota_update_label));
				ent->ota_running_size = ota_running_size;
				ent->ota_update_size = ota_update_size;
			}
			ent->uptime_valid = true;
			ent->uptime_s = topology->uptime_s;
			ent->uptime_seen_ms = now;
		}
	}
	portEXIT_CRITICAL(&s_nodes_lock);

	mesh_stream_mark_changed();
}

void log_http_server_task_snapshot_v2(const uint8_t mac[6],
                                      const mesh_v2_task_snapshot_payload_t *snapshot)
{
	if (!mac || !snapshot) return;

	uint32_t now = ms_now();
	char tag[MESH_V2_TAG_MAX + 1];
	copy_packet_text(tag, sizeof(tag), snapshot->tag, sizeof(snapshot->tag));
	log_http_server_node_seen_uptime(mac, tag, true, snapshot->uptime_s);

	uint16_t total = snapshot->task_total;
	if (total > STACK_MONITOR_MAX_TASKS) {
		total = STACK_MONITOR_MAX_TASKS;
	}

	portENTER_CRITICAL(&s_taskmon_lock);
	{
		taskmon_ent_t *ent = taskmon_find_locked(mac, true);
		if (ent) {
			taskmon_update_tag_locked(ent, tag);
			ent->slot_count = snapshot->slot_count;

			if (snapshot->task_index == 0 || !ent->staging_active) {
				memset(&ent->staging, 0, sizeof(ent->staging));
				ent->staging.updated_ms = now;
				ent->staging.cpu_valid = snapshot->cpu_valid != 0;
				ent->staging.cpu_load_x10 = snapshot->cpu_load_x10;
				ent->staging.count = total;
				ent->staging_active = true;
			}

			for (uint8_t i = 0; i < snapshot->task_count; i++) {
				uint16_t idx = (uint16_t)(snapshot->task_index + i);
				if (idx >= STACK_MONITOR_MAX_TASKS || idx >= total) {
					continue;
				}
				const mesh_v2_task_entry_t *src = &snapshot->tasks[i];
				stack_monitor_task_info_t *dst = &ent->staging.tasks[idx];
				copy_packet_text(dst->name, sizeof(dst->name), src->name, sizeof(src->name));
				dst->priority = src->priority;
				dst->free_words = src->free_words;
				dst->free_bytes = src->free_words * sizeof(StackType_t);
				dst->cpu_x10 = src->cpu_x10;
			}

			if ((snapshot->flags & MESH_V2_TASK_SNAPSHOT_FLAG_LAST) ||
			    snapshot->task_index + snapshot->task_count >= total) {
				ent->current = ent->staging;
				ent->valid = true;
				ent->staging_active = false;
				ent->last_request_id = snapshot->request_id;
			}
		}
	}
	portEXIT_CRITICAL(&s_taskmon_lock);
	ui_stream_notify();
}

void log_http_server_remote_line(const uint8_t mac[6], const char *tag, const char *line)
{
	if (!mac || !line) return;
	uint8_t selected_mac[6];
	selection_snapshot(selected_mac, NULL, 0);
	if (!mac_eq(mac, selected_mac)) return;

	portENTER_CRITICAL(&s_selection_lock);
	{
		if (s_stream_active && mac_eq(mac, s_stream_mac)) {
			s_stream_ready = true;
			s_stream_last_line_ms = ms_now();
		}
	}
	portEXIT_CRITICAL(&s_selection_lock);

	if (!taskmon_ingest_line(mac, tag, line)) {
		log_buffer_append_line(line, strnlen(line, 2048));
	}
	mesh_stream_mark_changed();
}

void log_http_server_remote_ota_status(const uint8_t mac[6],
                                       const mesh_ota_status_packet_t *status,
                                       size_t status_len)
{
	if (!mac || !status) return;

	bool give_ack = false;
	bool has_slot_info = status_len >= sizeof(mesh_ota_status_v2_packet_t);
	char running_label[MESH_OTA_SLOT_LABEL_MAX] = {0};
	char update_label[MESH_OTA_SLOT_LABEL_MAX] = {0};
	uint32_t running_size = 0;
	uint32_t update_size = 0;

	if (has_slot_info) {
		const mesh_ota_status_v2_packet_t *v2 =
			(const mesh_ota_status_v2_packet_t *)status;
		copy_packet_text(running_label, sizeof(running_label),
		                 v2->running_label, sizeof(v2->running_label));
		copy_packet_text(update_label, sizeof(update_label),
		                 v2->update_label, sizeof(v2->update_label));
		running_size = v2->running_size;
		update_size = v2->update_size;
		has_slot_info = running_label[0] || update_label[0] ||
		                running_size != 0 || update_size != 0;
	}

	portENTER_CRITICAL(&s_remote_ota_lock);
	{
		if (s_remote_ota_status.target_valid &&
		    mac_eq(mac, s_remote_ota_status.target_mac)) {
			if (status->total > 0) {
				s_remote_ota_status.total_bytes = status->total;
			}
			s_remote_ota_status.written_bytes = status->offset;
			if (has_slot_info) {
				copy_packet_text(s_remote_ota_status.running_label,
				                 sizeof(s_remote_ota_status.running_label),
				                 running_label, sizeof(running_label));
				copy_packet_text(s_remote_ota_status.update_label,
				                 sizeof(s_remote_ota_status.update_label),
				                 update_label, sizeof(update_label));
				s_remote_ota_status.running_size = running_size;
				s_remote_ota_status.update_size = update_size;
			}

			if (status->op != MESH_OTA_OP_DATA ||
			    status->code != MESH_OTA_STATUS_OK) {
				copy_packet_text(s_remote_ota_status.remote_message,
				                 sizeof(s_remote_ota_status.remote_message),
				                 status->message, sizeof(status->message));
			}

			if (status->code != MESH_OTA_STATUS_OK) {
				s_remote_ota_status.state = NODE0_OTA_FAILED;
				copy_packet_text(s_remote_ota_status.last_error,
				                 sizeof(s_remote_ota_status.last_error),
				                 status->message, sizeof(status->message));
			}
		}

		if (s_remote_ota_wait.waiting &&
		    mac_eq(mac, s_remote_ota_wait.mac) &&
		    status->op == s_remote_ota_wait.op &&
		    status->seq == s_remote_ota_wait.seq) {
			s_remote_ota_wait.ack = *status;
			s_remote_ota_wait.waiting = false;
			give_ack = true;
		}
	}
	portEXIT_CRITICAL(&s_remote_ota_lock);

	if (give_ack && s_remote_ota_ack_sem) {
		xSemaphoreGive(s_remote_ota_ack_sem);
	}

	if (status->op != MESH_OTA_OP_DATA || status->code != MESH_OTA_STATUS_OK) {
		char msg[MESH_OTA_STATUS_MSG_MAX + 1];
		copy_packet_text(msg, sizeof(msg), status->message, sizeof(status->message));
		ESP_LOGI(TAG, "remote OTA status from " MACSTR ": op=%u code=%u seq=%u %s",
		         MAC2STR(mac), (unsigned)status->op, (unsigned)status->code,
		         (unsigned)status->seq, msg);
	}
}

void log_http_server_remote_reboot_status(const uint8_t mac[6],
                                          const mesh_reboot_status_packet_t *status)
{
	if (!mac || !status) return;

	bool give_ack = false;

	portENTER_CRITICAL(&s_remote_reboot_lock);
	{
		if (s_remote_reboot_wait.waiting &&
		    mac_eq(mac, s_remote_reboot_wait.mac) &&
		    status->seq == s_remote_reboot_wait.seq) {
			s_remote_reboot_wait.ack = *status;
			s_remote_reboot_wait.waiting = false;
			give_ack = true;
		}
	}
	portEXIT_CRITICAL(&s_remote_reboot_lock);

	if (give_ack && s_remote_reboot_ack_sem) {
		xSemaphoreGive(s_remote_reboot_ack_sem);
	}

	char msg[MESH_REBOOT_STATUS_MSG_MAX + 1];
	copy_packet_text(msg, sizeof(msg), status->message, sizeof(status->message));
	ESP_LOGI(TAG, "remote reboot status from " MACSTR ": code=%u seq=%u %s",
	         MAC2STR(mac), (unsigned)status->code, (unsigned)status->seq, msg);
}

/* ----------------- HTTP handlers ----------------- */

static esp_err_t http_nodes_get(httpd_req_t *req)
{
	enum { NODES_JSON_MAX = 8192 };
	char *out = (char *)malloc(NODES_JSON_MAX);
	if (!out) {
		return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
		                           "no memory for nodes");
	}
	out[0] = '\0';

	size_t pos = append_nodes_json(out, NODES_JSON_MAX, 0);
	if (pos >= NODES_JSON_MAX - 2) {
		free(out);
		return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
		                           "nodes JSON truncated");
	}

	httpd_resp_set_type(req, "application/json");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	esp_err_t err = httpd_resp_send(req, out, HTTPD_RESP_USE_STRLEN);
	free(out);
	return err;
}

static bool parse_mac_hex(const char *s, uint8_t mac[6])
{
	if (!s) return false;
	if (strlen(s) != 12) return false;

	for (int i = 0; i < 12; i++) {
		if (!isxdigit((unsigned char)s[i])) return false;
	}

	for (int i = 0; i < 6; i++) {
		unsigned v = 0;
		if (sscanf(s + i * 2, "%2x", &v) != 1) return false;
		mac[i] = (uint8_t)v;
	}
	return true;
}

static esp_err_t http_select_get(httpd_req_t *req)
{
	char mac_str[64] = {0};

	if (httpd_req_get_url_query_str(req, mac_str, sizeof(mac_str)) == ESP_OK) {
		char val[32] = {0};
		if (httpd_query_key_value(mac_str, "mac", val, sizeof(val)) == ESP_OK) {
			uint8_t mac[6];
			if (parse_mac_hex(val, mac)) {
				char tag[16] = "node";

				if (mac_eq(mac, s_local_mac)) {
					copy_tag(tag, sizeof(tag), s_local_tag);
				} else {
					portENTER_CRITICAL(&s_nodes_lock);
					for (uint32_t i = 0; i < s_nodes_count; i++) {
						if (mac_eq(s_nodes[i].mac, mac)) {
							copy_tag(tag, sizeof(tag), s_nodes[i].tag);
							break;
						}
					}
					portEXIT_CRITICAL(&s_nodes_lock);
				}

				select_stream_node(mac, tag);
			}
		}
	}

	httpd_resp_set_type(req, "text/plain");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	return httpd_resp_send(req, "OK\n", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t http_clear_get(httpd_req_t *req)
{
	log_buffer_clear();
	httpd_resp_set_type(req, "text/plain");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	return httpd_resp_send(req, "OK\n", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t http_log_get(httpd_req_t *req)
{
	// /log?from=123
	char q[64] = {0};
	uint32_t from = 0;

	if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
		char v[32] = {0};
		if (httpd_query_key_value(q, "from", v, sizeof(v)) == ESP_OK) {
			from = (uint32_t)strtoul(v, NULL, 10);
		}
	}

	uint32_t start = 0;
	uint32_t next = 0;
	bool reset = false;
	log_buffer_stream_range(from, &start, &next, &reset);

	char hdr_next[32];
	snprintf(hdr_next, sizeof(hdr_next), "%lu", (unsigned long)next);
	httpd_resp_set_hdr(req, "X-Log-Next", hdr_next);
	httpd_resp_set_hdr(req, "X-Log-Reset", reset ? "1" : "0");

	httpd_resp_set_type(req, "text/plain");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");

	char line[LOG_HTTP_LINE_MAX + 2];
	for (uint32_t abs_i = start; abs_i < next; abs_i++) {
		size_t len = 0;
		if (!log_buffer_copy_abs_line(abs_i, line, sizeof(line), &len) || len == 0) {
			continue;
		}

		esp_err_t err = httpd_resp_send_chunk(req, line, len);
		if (err != ESP_OK) {
			return err;
		}
	}

	return httpd_resp_send_chunk(req, NULL, 0);
}

static uint32_t http_log_cursor_from_query(httpd_req_t *req, uint32_t fallback)
{
	char q[64] = {0};
	uint32_t from = fallback;

	if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
		char v[32] = {0};
		if (httpd_query_key_value(q, "from", v, sizeof(v)) == ESP_OK) {
			from = (uint32_t)strtoul(v, NULL, 10);
		}
	}

	return from;
}

static uint32_t http_log_stream_cursor(httpd_req_t *req)
{
	uint32_t from = http_log_cursor_from_query(req, log_buffer_next_cursor());
	char last_id[32] = {0};
	size_t last_id_len = httpd_req_get_hdr_value_len(req, "Last-Event-ID");

	if (last_id_len > 0 && last_id_len < sizeof(last_id) &&
	    httpd_req_get_hdr_value_str(req, "Last-Event-ID", last_id, sizeof(last_id)) == ESP_OK) {
		uint32_t last = (uint32_t)strtoul(last_id, NULL, 10);
		if (last > from) {
			from = last;
		}
	}

	return from;
}

static esp_err_t http_log_stream_busy(httpd_req_t *req)
{
	httpd_resp_set_status(req, "503 Stream Busy");
	httpd_resp_set_type(req, "text/plain");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	return httpd_resp_send(req, "log stream busy\n", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t log_stream_send_preamble(httpd_req_t *req)
{
	static const char preamble[] = ": node0 log stream\n\n";
	httpd_resp_set_type(req, "text/event-stream");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	httpd_resp_set_hdr(req, "Connection", "keep-alive");
	return httpd_resp_send_chunk(req, preamble, sizeof(preamble) - 1);
}

static esp_err_t log_stream_send_reset(httpd_req_t *req, uint32_t cursor)
{
	char msg[80];
	int n = snprintf(msg, sizeof(msg),
	                 "event: reset\nid: %lu\ndata: reset\n\n",
	                 (unsigned long)cursor);
	if (n < 0) {
		return ESP_FAIL;
	}
	size_t len = ((size_t)n < sizeof(msg)) ? (size_t)n : (sizeof(msg) - 1);
	return httpd_resp_send_chunk(req, msg, len);
}

static esp_err_t log_stream_send_heartbeat(httpd_req_t *req)
{
	static const char heartbeat[] = ": ping\n\n";
	return httpd_resp_send_chunk(req, heartbeat, sizeof(heartbeat) - 1);
}

static esp_err_t log_stream_send_line(httpd_req_t *req, uint32_t next_cursor,
                                      const char *line, size_t len)
{
	char out[LOG_HTTP_LINE_MAX + 80];
	int n = snprintf(out, sizeof(out), "id: %lu\ndata: ",
	                 (unsigned long)next_cursor);

	if (n < 0) {
		return ESP_FAIL;
	}

	size_t pos = ((size_t)n < sizeof(out)) ? (size_t)n : (sizeof(out) - 1);

	while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
		len--;
	}

	for (size_t i = 0; i < len && pos < sizeof(out) - 3; i++) {
		char c = line[i];
		if (c == '\n' || c == '\r') {
			c = ' ';
		}
		out[pos++] = c;
	}

	out[pos++] = '\n';
	out[pos++] = '\n';
	out[pos] = '\0';

	return httpd_resp_send_chunk(req, out, pos);
}

static void log_stream_complete(httpd_req_t *req)
{
	if (!req) {
		return;
	}

	esp_err_t err = httpd_req_async_handler_complete(req);
	if (err != ESP_OK) {
		ESP_LOGD(TAG, "log stream async complete failed: %s", esp_err_to_name(err));
	}
}

static void log_stream_request_close(const char *sid)
{
	if (!s_log_stream_mutex || !s_log_stream_task) {
		return;
	}

	bool notify = false;
	if (xSemaphoreTake(s_log_stream_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
		if (s_log_stream.req && stream_sid_matches(s_log_stream.sid, sid)) {
			s_log_stream.client_close = true;
			notify = true;
		}
		xSemaphoreGive(s_log_stream_mutex);
	}

	if (notify) {
		xTaskNotifyGive(s_log_stream_task);
	}
}

static bool log_stream_wait_idle(uint32_t timeout_ms)
{
	uint32_t start = ms_now();

	for (;;) {
		bool idle = true;
		if (xSemaphoreTake(s_log_stream_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
			return false;
		}
		if (s_log_stream.req) {
			s_log_stream.client_close = true;
			idle = false;
		}
		xSemaphoreGive(s_log_stream_mutex);

		if (idle) {
			return true;
		}
		log_stream_notify();
		if ((uint32_t)(ms_now() - start) >= timeout_ms) {
			return false;
		}
		vTaskDelay(pdMS_TO_TICKS(40));
	}
}

static void log_stream_task(void *arg)
{
	(void)arg;
	char line[LOG_HTTP_LINE_MAX + 2];

	for (;;) {
		ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(LOG_STREAM_HEARTBEAT_MS));

		httpd_req_t *req = NULL;
		uint32_t cursor = 0;
		bool headers_sent = false;
		bool client_close = false;

		if (!s_log_stream_mutex ||
		    xSemaphoreTake(s_log_stream_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
			continue;
		}

		req = s_log_stream.req;
		cursor = s_log_stream.cursor;
		headers_sent = s_log_stream.headers_sent;
		client_close = s_log_stream.client_close;
		xSemaphoreGive(s_log_stream_mutex);

		if (!req) {
			continue;
		}

		if (client_close) {
			if (xSemaphoreTake(s_log_stream_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
				if (s_log_stream.req == req) {
					memset(&s_log_stream, 0, sizeof(s_log_stream));
				}
				xSemaphoreGive(s_log_stream_mutex);
			}
			log_stream_complete(req);
			continue;
		}

		esp_err_t err = ESP_OK;

		if (!headers_sent) {
			err = log_stream_send_preamble(req);
			if (err == ESP_OK &&
			    xSemaphoreTake(s_log_stream_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
				if (s_log_stream.req == req) {
					s_log_stream.headers_sent = true;
				}
				xSemaphoreGive(s_log_stream_mutex);
			}
		}

		uint32_t start = 0;
		uint32_t next = 0;
		bool reset = false;

		if (err == ESP_OK) {
			log_buffer_stream_range(cursor, &start, &next, &reset);
			if (reset) {
				err = log_stream_send_reset(req, start);
			}
		}

		if (err == ESP_OK) {
			for (uint32_t abs_i = start; abs_i < next; abs_i++) {
				size_t len = 0;
				if (!log_buffer_copy_abs_line(abs_i, line, sizeof(line), &len) || len == 0) {
					continue;
				}

				err = log_stream_send_line(req, abs_i + 1, line, len);
				if (err != ESP_OK) {
					break;
				}
			}
		}

		if (err == ESP_OK && start == next && !reset) {
			err = log_stream_send_heartbeat(req);
		}

		if (err == ESP_OK) {
			if (xSemaphoreTake(s_log_stream_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
				if (s_log_stream.req == req) {
					s_log_stream.cursor = next;
				}
				xSemaphoreGive(s_log_stream_mutex);
			}
			continue;
		}

		if (xSemaphoreTake(s_log_stream_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
			if (s_log_stream.req == req) {
				memset(&s_log_stream, 0, sizeof(s_log_stream));
			}
			xSemaphoreGive(s_log_stream_mutex);
		}
		log_stream_complete(req);
	}
}

static esp_err_t http_log_stream_get(httpd_req_t *req)
{
	if (!s_log_stream_mutex || !s_log_stream_task) {
		httpd_resp_set_status(req, "503 Stream Unavailable");
		httpd_resp_set_type(req, "text/plain");
		httpd_resp_set_hdr(req, "Cache-Control", "no-store");
		return httpd_resp_send(req, "log stream unavailable\n", HTTPD_RESP_USE_STRLEN);
	}

	uint32_t from = http_log_stream_cursor(req);
	char sid[STREAM_SID_MAX];
	stream_sid_from_req(req, sid, sizeof(sid));

	if (!log_stream_wait_idle(1400)) {
		return http_log_stream_busy(req);
	}

	httpd_req_t *async_req = NULL;
	esp_err_t err = httpd_req_async_handler_begin(req, &async_req);
	if (err != ESP_OK) {
		return err;
	}

	if (xSemaphoreTake(s_log_stream_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
		log_stream_complete(async_req);
		return ESP_FAIL;
	}

	if (s_log_stream.req != NULL) {
		xSemaphoreGive(s_log_stream_mutex);
		httpd_resp_set_status(async_req, "503 Stream Busy");
		httpd_resp_set_type(async_req, "text/plain");
		httpd_resp_set_hdr(async_req, "Cache-Control", "no-store");
		(void)httpd_resp_send(async_req, "log stream busy\n", HTTPD_RESP_USE_STRLEN);
		log_stream_complete(async_req);
		return ESP_OK;
	}

	s_log_stream.req = async_req;
	s_log_stream.cursor = from;
	s_log_stream.headers_sent = false;
	s_log_stream.client_close = false;
	copy_packet_text(s_log_stream.sid, sizeof(s_log_stream.sid), sid, sizeof(sid));
	xSemaphoreGive(s_log_stream_mutex);

	log_stream_notify();
	return ESP_OK;
}

static size_t append_fmt(char *out, size_t cap, size_t pos, const char *fmt, ...)
{
	if (!out || cap == 0 || pos >= cap) return pos;

	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(out + pos, cap - pos, fmt, ap);
	va_end(ap);

	if (n < 0) return pos;
	if ((size_t)n >= cap - pos) return cap - 1;
	return pos + (size_t)n;
}

static size_t append_json_string(char *out, size_t cap, size_t pos, const char *s)
{
	if (!out || cap == 0 || pos >= cap) return pos;

	if (pos < cap - 1) out[pos++] = '"';
	for (const char *p = s ? s : ""; *p && pos < cap - 1; p++) {
		unsigned char c = (unsigned char)*p;
		if (c == '"' || c == '\\') {
			if (pos + 2 >= cap) break;
			out[pos++] = '\\';
			out[pos++] = (char)c;
		} else if (c < 32) {
			out[pos++] = ' ';
		} else {
			out[pos++] = (char)c;
		}
	}
	if (pos < cap - 1) out[pos++] = '"';
	out[pos] = '\0';
	return pos;
}

static const char *ota_state_name(node0_ota_state_t state)
{
	switch (state) {
	case NODE0_OTA_IDLE: return "idle";
	case NODE0_OTA_UPDATING: return "updating";
	case NODE0_OTA_SUCCESS: return "success";
	case NODE0_OTA_FAILED: return "failed";
	case NODE0_OTA_REBOOTING: return "rebooting";
	default: return "unknown";
	}
}

static const char *ota_img_state_name(esp_ota_img_states_t state)
{
	switch (state) {
	case ESP_OTA_IMG_NEW: return "new";
	case ESP_OTA_IMG_PENDING_VERIFY: return "pending_verify";
	case ESP_OTA_IMG_VALID: return "valid";
	case ESP_OTA_IMG_INVALID: return "invalid";
	case ESP_OTA_IMG_ABORTED: return "aborted";
	case ESP_OTA_IMG_UNDEFINED: return "undefined";
	default: return "unknown";
	}
}

static bool ota_enabled(void)
{
	return CONFIG_NODE0_OTA_PIN[0] != '\0';
}

static void ota_status_begin(uint32_t total_bytes)
{
	node0_ota_status_t status = {0};
	status.state = NODE0_OTA_UPDATING;
	status.total_bytes = total_bytes;
	status.started_ms = ms_now();
	strncpy(status.last_result, "upload started", sizeof(status.last_result) - 1);

	portENTER_CRITICAL(&s_ota_state_lock);
	s_ota_status = status;
	portEXIT_CRITICAL(&s_ota_state_lock);
}

static void ota_status_progress(uint32_t written_bytes)
{
	portENTER_CRITICAL(&s_ota_state_lock);
	s_ota_status.written_bytes = written_bytes;
	portEXIT_CRITICAL(&s_ota_state_lock);
}

static void ota_status_finish(node0_ota_state_t state, const char *msg)
{
	portENTER_CRITICAL(&s_ota_state_lock);
	s_ota_status.state = state;
	s_ota_status.finished_ms = ms_now();
	if (state == NODE0_OTA_FAILED) {
		strncpy(s_ota_status.last_error, msg ? msg : "OTA failed",
		        sizeof(s_ota_status.last_error) - 1);
		s_ota_status.last_error[sizeof(s_ota_status.last_error) - 1] = '\0';
	} else {
		strncpy(s_ota_status.last_result, msg ? msg : "OK",
		        sizeof(s_ota_status.last_result) - 1);
		s_ota_status.last_result[sizeof(s_ota_status.last_result) - 1] = '\0';
	}
	portEXIT_CRITICAL(&s_ota_state_lock);
}

static bool remote_ota_supported_tag(const char *tag)
{
	return tag && strcmp(tag, "choinka") == 0;
}

static bool remote_ota_is_choinka_mac(const uint8_t mac[6])
{
	static const uint8_t choinka_mac[6] = {
		0x08, 0xa6, 0xf7, 0x65, 0xce, 0xa0
	};

	return mac && mac_eq(mac, choinka_mac);
}

static void remote_ota_normalize_tag_for_mac(const uint8_t mac[6],
                                             char *tag,
                                             size_t tag_sz)
{
	if (!tag || tag_sz == 0) return;
	if (!remote_ota_supported_tag(tag) && remote_ota_is_choinka_mac(mac)) {
		copy_tag(tag, tag_sz, "choinka");
	}
}

static void remote_ota_status_begin(const uint8_t mac[6], const char *tag,
                                    uint32_t total_bytes)
{
	remote_ota_status_t status;
	memset(&status, 0, sizeof(status));
	status.state = NODE0_OTA_UPDATING;
	status.target_valid = true;
	mac_copy(status.target_mac, mac);
	copy_tag(status.target_tag, sizeof(status.target_tag), tag);
	status.total_bytes = total_bytes;
	status.started_ms = ms_now();
	strncpy(status.last_result, "remote upload started",
	        sizeof(status.last_result) - 1);

	portENTER_CRITICAL(&s_remote_ota_lock);
	s_remote_ota_status = status;
	portEXIT_CRITICAL(&s_remote_ota_lock);
}

static void remote_ota_status_progress(uint32_t written_bytes)
{
	portENTER_CRITICAL(&s_remote_ota_lock);
	s_remote_ota_status.written_bytes = written_bytes;
	portEXIT_CRITICAL(&s_remote_ota_lock);
}

static void remote_ota_status_finish(node0_ota_state_t state, const char *msg)
{
	portENTER_CRITICAL(&s_remote_ota_lock);
	s_remote_ota_status.state = state;
	s_remote_ota_status.finished_ms = ms_now();
	if (state == NODE0_OTA_FAILED) {
		strncpy(s_remote_ota_status.last_error, msg ? msg : "remote OTA failed",
		        sizeof(s_remote_ota_status.last_error) - 1);
		s_remote_ota_status.last_error[sizeof(s_remote_ota_status.last_error) - 1] = '\0';
	} else {
		strncpy(s_remote_ota_status.last_result, msg ? msg : "OK",
		        sizeof(s_remote_ota_status.last_result) - 1);
		s_remote_ota_status.last_result[sizeof(s_remote_ota_status.last_result) - 1] = '\0';
	}
	portEXIT_CRITICAL(&s_remote_ota_lock);
}

static void remote_ota_note_node_seen(const uint8_t mac[6], bool uptime_valid,
                                      uint32_t uptime_s)
{
	if (!mac || !uptime_valid) {
		return;
	}

	char result[96];
	snprintf(result, sizeof(result),
	         "remote OTA booted, uptime %lus",
	         (unsigned long)uptime_s);

	portENTER_CRITICAL(&s_remote_ota_lock);
	if (s_remote_ota_status.target_valid &&
	    mac_eq(mac, s_remote_ota_status.target_mac) &&
	    s_remote_ota_status.state == NODE0_OTA_REBOOTING) {
		s_remote_ota_status.state = NODE0_OTA_SUCCESS;
		s_remote_ota_status.finished_ms = ms_now();
		strncpy(s_remote_ota_status.last_result, result,
		        sizeof(s_remote_ota_status.last_result) - 1);
		s_remote_ota_status.last_result[sizeof(s_remote_ota_status.last_result) - 1] = '\0';
		s_remote_ota_status.last_error[0] = '\0';
	}
	portEXIT_CRITICAL(&s_remote_ota_lock);
}

static size_t append_node_v2_json_fields(char *out, size_t cap, size_t pos,
                                         const uint8_t mac[6], uint32_t now)
{
	mesh_v2_root_stats_t st;
	bool has_v2 = mac && mesh_v2_root_stats_for_mac(mac, &st);
	long v2_age_ms = -1;

	pos = append_fmt(out, cap, pos, ",\"proto\":");
	if (mac && mac_eq(mac, s_local_mac)) {
		pos = append_json_string(out, cap, pos, "local");
	} else {
		pos = append_json_string(out, cap, pos,
		                         (has_v2 && st.tunnel_seen) ? "tunnel" :
		                         (has_v2 ? "v2" : "v1"));
	}

	if (!has_v2) {
		return append_fmt(out, cap, pos,
		                  ",\"v2_session\":0,\"expected_seq\":0,"
		                  "\"gap_count\":0,\"replay_count\":0,"
		                  "\"lost_count\":0,\"last_v2_ms\":0,"
		                  "\"last_tunnel_ms\":0,\"v2_age_ms\":-1,\"v2_ack_age_ms\":-1,"
		                  "\"tunnel_age_ms\":-1,\"has_gap\":false");
	}

	if (st.last_v2_ms != 0) {
		v2_age_ms = (long)(uint32_t)(now - st.last_v2_ms);
	}
	long tunnel_age_ms = st.last_tunnel_ms != 0
		? (long)(uint32_t)(now - st.last_tunnel_ms)
		: -1;

	return append_fmt(out, cap, pos,
	                  ",\"v2_session\":%lu,\"expected_seq\":%lu,"
	                  "\"gap_count\":%lu,\"replay_count\":%lu,"
	                  "\"lost_count\":%lu,\"last_v2_ms\":%lu,"
	                  "\"last_tunnel_ms\":%lu,\"v2_age_ms\":%ld,\"v2_ack_age_ms\":%ld,"
	                  "\"tunnel_age_ms\":%ld,\"has_gap\":%s",
	                  (unsigned long)st.session_id,
	                  (unsigned long)st.expected_seq,
	                  (unsigned long)st.gap_count,
	                  (unsigned long)st.replay_count,
	                  (unsigned long)st.lost_count,
	                  (unsigned long)st.last_v2_ms,
	                  (unsigned long)st.last_tunnel_ms,
	                  v2_age_ms,
	                  v2_age_ms,
	                  tunnel_age_ms,
	                  st.has_gap ? "true" : "false");
}

static size_t append_node_health_json_fields(char *out, size_t cap, size_t pos,
                                             const uint8_t mac[6],
                                             bool route_seen,
                                             uint32_t last_route_ms,
                                             uint32_t last_nodeinfo_ms,
                                             uint32_t now)
{
	mesh_v2_root_stats_t v2;
	bool has_v2 = mac && mesh_v2_root_stats_for_mac(mac, &v2);
	bool remote = mac && !mac_eq(mac, s_local_mac);
	bool has_nodeinfo = last_nodeinfo_ms != 0;
	bool has_route_history = last_route_ms != 0;
	uint32_t app_last_ms = node_last_app_ms(mac);
	long route_age_ms = has_route_history ? (long)(uint32_t)(now - last_route_ms) : -1;
	long nodeinfo_age_ms = has_nodeinfo ? (long)(uint32_t)(now - last_nodeinfo_ms) : -1;
	long telemetry_age_ms = app_last_ms ? (long)(uint32_t)(now - app_last_ms) : -1;

	bool fresh_telemetry = remote
		? (telemetry_age_ms >= 0 && (uint32_t)telemetry_age_ms <= NODEINFO_STALE_MS)
		: true;
	bool app_stale = remote && !fresh_telemetry;
	bool stale = app_stale;
	bool link_seen = route_seen || fresh_telemetry;
	bool offline = remote && !link_seen && stale &&
		(!has_route_history || (uint32_t)route_age_ms > NODE_OFFLINE_MS);
	const char *stream_state = remote ? "idle" : "local";
	long log_ctrl_age_ms = -1;
	long remote_line_age_ms = -1;
	long last_remote_app_ms = app_last_ms ? (long)app_last_ms : -1;
	int last_log_ctrl_err = 0;
	int32_t last_send_err = 0;
	uint8_t recovery_phase = 0;

	if (remote) {
		portENTER_CRITICAL(&s_nodes_lock);
		{
			for (uint32_t i = 0; i < s_nodes_count; i++) {
				if (mac_eq(mac, s_nodes[i].mac)) {
					last_send_err = s_nodes[i].last_send_err;
					recovery_phase = s_nodes[i].recovery_phase;
					break;
				}
			}
		}
		portEXIT_CRITICAL(&s_nodes_lock);

		portENTER_CRITICAL(&s_selection_lock);
		{
			if (s_stream_active && mac_eq(mac, s_stream_mac)) {
				stream_state = (s_stream_ready && !app_stale) ? "ready" :
				               route_seen ? "telemetry_stale" :
				               fresh_telemetry ? "waiting_log" :
				               "waiting_route";
				log_ctrl_age_ms = s_last_log_ctrl_ms ?
					(long)(uint32_t)(now - s_last_log_ctrl_ms) : -1;
				remote_line_age_ms = s_stream_last_line_ms ?
					(long)(uint32_t)(now - s_stream_last_line_ms) : -1;
				last_log_ctrl_err = (int)s_last_log_ctrl_err;
			}
		}
		portEXIT_CRITICAL(&s_selection_lock);
	}

	const char *node_source = "selected";
	if (!remote) {
		node_source = "local";
	} else if (route_seen && has_v2) {
		node_source = "route+v2";
	} else if (route_seen && has_nodeinfo) {
		node_source = "route+nodeinfo";
	} else if (route_seen) {
		node_source = "route";
	} else if (has_v2) {
		node_source = "v2";
	} else if (has_nodeinfo) {
		node_source = "nodeinfo";
	}

	pos = append_fmt(out, cap, pos,
	                  ",\"route_seen\":%s,\"route_table_seen\":%s,\"link_seen\":%s,"
	                  "\"route_age_ms\":%ld,\"nodeinfo_age_ms\":%ld,"
	                  "\"telemetry_fresh\":%s,\"telemetry_age_ms\":%ld,"
	                  "\"app_stale\":%s,\"last_remote_app_ms\":%ld,\"node_source\":",
	                  route_seen ? "true" : "false",
	                  route_seen ? "true" : "false",
	                  link_seen ? "true" : "false",
	                  route_age_ms,
	                  nodeinfo_age_ms,
	                  fresh_telemetry ? "true" : "false",
	                  telemetry_age_ms,
	                  app_stale ? "true" : "false",
	                  last_remote_app_ms);
	pos = append_json_string(out, cap, pos, node_source);
	pos = append_fmt(out, cap, pos,
	                  ",\"stream_state\":");
	pos = append_json_string(out, cap, pos, stream_state);
	return append_fmt(out, cap, pos,
	                  ",\"log_ctrl_age_ms\":%ld,\"remote_line_age_ms\":%ld,"
	                  "\"last_log_ctrl_err\":%d,\"last_send_err\":%ld,\"recovery_phase\":%u,"
	                  "\"stale\":%s,\"offline\":%s",
	                  log_ctrl_age_ms,
	                  remote_line_age_ms,
	                  last_log_ctrl_err,
	                  (long)last_send_err,
	                  (unsigned)recovery_phase,
	                  stale ? "true" : "false",
	                  offline ? "true" : "false");
}

static size_t append_node_topology_json_fields(char *out, size_t cap, size_t pos,
                                               const node_ent_t *node,
                                               uint32_t now)
{
	if (!node || node->topology_seen_ms == 0) {
		return append_fmt(out, cap, pos,
		                  ",\"topology_valid\":false,\"topology_age_ms\":-1,"
		                  "\"parent_mac\":\"\",\"root_mac\":\"\","
		                  "\"layer\":0,\"max_layer\":0,\"parent_rssi\":-127,"
		                  "\"child_count\":0,\"capabilities\":0,"
		                  "\"v1_ok_age_ms\":-1,\"v2_ack_age_ms\":-1,"
		                  "\"last_remote_send_err\":0,\"remote_recovery_phase\":0,"
		                  "\"remote_log_stream_enabled\":false,"
		                  "\"ota_running_label\":\"\",\"ota_update_label\":\"\","
		                  "\"ota_running_size\":0,\"ota_update_size\":0");
	}

	long age_ms = (long)(uint32_t)(now - node->topology_seen_ms);
	pos = append_fmt(out, cap, pos,
	                 ",\"topology_valid\":true,\"topology_age_ms\":%ld,"
	                 "\"parent_mac\":\"%02x%02x%02x%02x%02x%02x\","
	                 "\"root_mac\":\"%02x%02x%02x%02x%02x%02x\","
	                 "\"layer\":%u,\"max_layer\":%u,\"parent_rssi\":%d,"
	                 "\"child_count\":%u,\"capabilities\":%lu,"
	                 "\"v1_ok_age_ms\":%ld,\"v2_ack_age_ms\":%ld,"
	                 "\"last_remote_send_err\":%ld,\"remote_recovery_phase\":%u,"
	                 "\"remote_log_stream_enabled\":%s,"
	                 "\"ota_running_label\":",
	                 age_ms,
	                 node->parent_mac[0], node->parent_mac[1], node->parent_mac[2],
	                 node->parent_mac[3], node->parent_mac[4], node->parent_mac[5],
	                 node->root_mac[0], node->root_mac[1], node->root_mac[2],
	                 node->root_mac[3], node->root_mac[4], node->root_mac[5],
	                 (unsigned)node->layer,
	                 (unsigned)node->max_layer,
	                 (int)node->parent_rssi,
	                 (unsigned)node->child_count,
	                 (unsigned long)node->capabilities,
	                 node->v1_ok_age_ms == UINT32_MAX ? -1L : (long)node->v1_ok_age_ms,
	                 node->v2_ack_age_ms == UINT32_MAX ? -1L : (long)node->v2_ack_age_ms,
	                 (long)node->last_send_err,
	                 (unsigned)node->recovery_phase,
	                 node->log_stream_enabled ? "true" : "false");
	pos = append_json_string(out, cap, pos, node->ota_running_label);
	pos = append_fmt(out, cap, pos, ",\"ota_update_label\":");
	pos = append_json_string(out, cap, pos, node->ota_update_label);
	return append_fmt(out, cap, pos,
	                  ",\"ota_running_size\":%lu,\"ota_update_size\":%lu",
	                  (unsigned long)node->ota_running_size,
	                  (unsigned long)node->ota_update_size);
}

static size_t append_nodes_json(char *out, size_t cap, size_t pos)
{
	enum { NODE_JSON_MARGIN = 512 };
	uint32_t local_uptime = local_uptime_s();
	uint8_t selected_mac[6];
	char selected_tag[16];
	static const uint8_t zero_mac[6] = {0};
	uint8_t emitted[LOG_HTTP_MAX_NODES + 2][6];
	uint32_t emitted_count = 0;
	mesh_addr_t routes[LOG_HTTP_MAX_NODES];
	int route_count = 0;
	uint32_t now = ms_now();

	selection_snapshot(selected_mac, selected_tag, sizeof(selected_tag));

	if (esp_mesh_get_routing_table(routes, sizeof(routes), &route_count) != ESP_OK) {
		route_count = 0;
	}
	if (route_count > LOG_HTTP_MAX_NODES) route_count = LOG_HTTP_MAX_NODES;
	note_route_table_nodes(routes, route_count, now);

	pos = append_fmt(out, cap, pos,
	                 "{\"selected_mac\":\"%02x%02x%02x%02x%02x%02x\",\"selected_tag\":",
	                 selected_mac[0], selected_mac[1], selected_mac[2],
	                 selected_mac[3], selected_mac[4], selected_mac[5]);
	pos = append_json_string(out, cap, pos, selected_tag);
	pos = append_fmt(out, cap, pos,
	                 ",\"local_mac\":\"%02x%02x%02x%02x%02x%02x\","
	                 "\"route_table_count\":%d,\"nodes\":[",
	                 s_local_mac[0], s_local_mac[1], s_local_mac[2],
	                 s_local_mac[3], s_local_mac[4], s_local_mac[5],
	                 route_count);

	pos = append_fmt(out, cap, pos,
	                 "{\"mac\":\"%02x%02x%02x%02x%02x%02x\",\"tag\":",
	                 s_local_mac[0], s_local_mac[1], s_local_mac[2],
	                 s_local_mac[3], s_local_mac[4], s_local_mac[5]);
	pos = append_json_string(out, cap, pos, s_local_tag);
	pos = append_fmt(out, cap, pos,
	                 ",\"uptime_valid\":true,\"uptime_s\":%lu",
	                 (unsigned long)local_uptime);
	pos = append_node_v2_json_fields(out, cap, pos, s_local_mac, now);
	node_ent_t local_node;
	memset(&local_node, 0, sizeof(local_node));
	mac_copy(local_node.mac, s_local_mac);
	copy_tag(local_node.tag, sizeof(local_node.tag), s_local_tag);
	local_node.topology_seen_ms = now;
	local_node.layer = 1;
	local_node.max_layer = CONFIG_MESH_MAX_LAYER;
	local_node.parent_rssi = 0;
	local_node.capabilities = MESH_V2_CAP_TUNNEL | MESH_V2_CAP_RELAY | MESH_V2_CAP_TOPOLOGY;
	pos = append_node_topology_json_fields(out, cap, pos, &local_node, now);
	pos = append_node_health_json_fields(out, cap, pos, s_local_mac,
	                                     true, now, now, now);
	pos = append_fmt(out, cap, pos, "}");
	mac_copy(emitted[emitted_count++], s_local_mac);

	bool sel_in_list = mac_eq(selected_mac, s_local_mac);

	portENTER_CRITICAL(&s_nodes_lock);
	{
		for (uint32_t i = 0; i < s_nodes_count; i++) {
			if (pos + NODE_JSON_MARGIN >= cap) break;
			if (mac_eq(s_nodes[i].mac, s_local_mac)) continue;
			if (mac_list_contains(emitted, emitted_count, s_nodes[i].mac)) continue;

			if (mac_eq(s_nodes[i].mac, selected_mac)) sel_in_list = true;

			bool uptime_valid = s_nodes[i].uptime_valid;
			uint32_t uptime_s = uptime_valid
				? uptime_advanced_s(s_nodes[i].uptime_s, s_nodes[i].uptime_seen_ms, now)
				: 0;
			bool route_seen = route_table_contains(routes, route_count, s_nodes[i].mac);

			pos = append_fmt(out, cap, pos,
			                 ",{\"mac\":\"%02x%02x%02x%02x%02x%02x\",\"tag\":",
			                 s_nodes[i].mac[0], s_nodes[i].mac[1], s_nodes[i].mac[2],
			                 s_nodes[i].mac[3], s_nodes[i].mac[4], s_nodes[i].mac[5]);
			pos = append_json_string(out, cap, pos, s_nodes[i].tag);
			pos = append_fmt(out, cap, pos,
			                 ",\"uptime_valid\":%s,\"uptime_s\":%lu",
			                 uptime_valid ? "true" : "false",
			                 (unsigned long)uptime_s);
			pos = append_node_v2_json_fields(out, cap, pos, s_nodes[i].mac, now);
			pos = append_node_topology_json_fields(out, cap, pos, &s_nodes[i], now);
			pos = append_node_health_json_fields(out, cap, pos, s_nodes[i].mac,
			                                     route_seen,
			                                     s_nodes[i].last_route_ms,
			                                     s_nodes[i].last_seen_ms,
			                                     now);
			pos = append_fmt(out, cap, pos, "}");
			if (emitted_count < LOG_HTTP_MAX_NODES + 2) {
				mac_copy(emitted[emitted_count++], s_nodes[i].mac);
			}
		}
	}
	portEXIT_CRITICAL(&s_nodes_lock);

	if (!sel_in_list && !mac_eq(selected_mac, zero_mac) && pos + NODE_JSON_MARGIN < cap) {
		bool route_seen = route_table_contains(routes, route_count, selected_mac);
		pos = append_fmt(out, cap, pos,
		                 ",{\"mac\":\"%02x%02x%02x%02x%02x%02x\",\"tag\":",
		                 selected_mac[0], selected_mac[1], selected_mac[2],
		                 selected_mac[3], selected_mac[4], selected_mac[5]);
		pos = append_json_string(out, cap, pos, selected_tag);
		pos = append_fmt(out, cap, pos,
		                 ",\"uptime_valid\":false,\"uptime_s\":0");
		pos = append_node_v2_json_fields(out, cap, pos, selected_mac, now);
		pos = append_node_topology_json_fields(out, cap, pos, NULL, now);
		pos = append_node_health_json_fields(out, cap, pos, selected_mac,
		                                     route_seen, 0, 0, now);
		pos = append_fmt(out, cap, pos, "}");
	}

	return append_fmt(out, cap, pos, "]}");
}

static size_t append_local_ota_json(char *out, size_t cap, size_t pos)
{
	node0_ota_status_t status;

	portENTER_CRITICAL(&s_ota_state_lock);
	status = s_ota_status;
	portEXIT_CRITICAL(&s_ota_state_lock);

	const esp_partition_t *running = esp_ota_get_running_partition();
	const esp_partition_t *update = esp_ota_get_next_update_partition(NULL);
	const esp_app_desc_t *app = esp_app_get_description();

	esp_ota_img_states_t img_state = ESP_OTA_IMG_UNDEFINED;
	bool img_state_valid = running &&
		esp_ota_get_state_partition(running, &img_state) == ESP_OK;

	pos = append_fmt(out, cap, pos,
	                 "{\"enabled\":%s,\"busy\":%s,\"state\":\"%s\","
	                 "\"written_bytes\":%lu,\"total_bytes\":%lu,"
	                 "\"running_label\":",
	                 ota_enabled() ? "true" : "false",
	                 status.state == NODE0_OTA_UPDATING ? "true" : "false",
	                 ota_state_name(status.state),
	                 (unsigned long)status.written_bytes,
	                 (unsigned long)status.total_bytes);
	pos = append_json_string(out, cap, pos, running ? running->label : "");
	pos = append_fmt(out, cap, pos,
	                 ",\"running_address\":%lu,\"running_size\":%lu,"
	                 "\"update_label\":",
	                 (unsigned long)(running ? running->address : 0),
	                 (unsigned long)(running ? running->size : 0));
	pos = append_json_string(out, cap, pos, update ? update->label : "");
	pos = append_fmt(out, cap, pos,
	                 ",\"update_size\":%lu,\"rollback_state\":",
	                 (unsigned long)(update ? update->size : 0));
	pos = append_json_string(out, cap, pos,
	                         img_state_valid ? ota_img_state_name(img_state) : "unknown");
	pos = append_fmt(out, cap, pos, ",\"project_name\":");
	pos = append_json_string(out, cap, pos, app ? app->project_name : "");
	pos = append_fmt(out, cap, pos, ",\"version\":");
	pos = append_json_string(out, cap, pos, app ? app->version : "");
	pos = append_fmt(out, cap, pos, ",\"last_result\":");
	pos = append_json_string(out, cap, pos, status.last_result);
	pos = append_fmt(out, cap, pos, ",\"last_error\":");
	pos = append_json_string(out, cap, pos, status.last_error);
	return append_fmt(out, cap, pos, "}");
}

static void remote_ota_slot_snapshot(const uint8_t mac[6],
                                     char running_label[MESH_OTA_SLOT_LABEL_MAX],
                                     char update_label[MESH_OTA_SLOT_LABEL_MAX],
                                     uint32_t *running_size,
                                     uint32_t *update_size)
{
	if (running_label) memset(running_label, 0, MESH_OTA_SLOT_LABEL_MAX);
	if (update_label) memset(update_label, 0, MESH_OTA_SLOT_LABEL_MAX);
	if (running_size) *running_size = 0;
	if (update_size) *update_size = 0;
	if (!mac) return;

	bool found_node_slots = false;
	remote_ota_status_t status;

	portENTER_CRITICAL(&s_nodes_lock);
	{
		for (uint32_t i = 0; i < s_nodes_count; i++) {
			if (!mac_eq(mac, s_nodes[i].mac)) continue;
			found_node_slots = s_nodes[i].ota_running_label[0] ||
			                   s_nodes[i].ota_update_label[0] ||
			                   s_nodes[i].ota_running_size != 0 ||
			                   s_nodes[i].ota_update_size != 0;
			if (running_label) {
				copy_packet_text(running_label, MESH_OTA_SLOT_LABEL_MAX,
				                 s_nodes[i].ota_running_label,
				                 sizeof(s_nodes[i].ota_running_label));
			}
			if (update_label) {
				copy_packet_text(update_label, MESH_OTA_SLOT_LABEL_MAX,
				                 s_nodes[i].ota_update_label,
				                 sizeof(s_nodes[i].ota_update_label));
			}
			if (running_size) *running_size = s_nodes[i].ota_running_size;
			if (update_size) *update_size = s_nodes[i].ota_update_size;
			break;
		}
	}
	portEXIT_CRITICAL(&s_nodes_lock);

	if (found_node_slots) {
		return;
	}

	portENTER_CRITICAL(&s_remote_ota_lock);
	status = s_remote_ota_status;
	portEXIT_CRITICAL(&s_remote_ota_lock);

	if (status.target_valid && mac_eq(mac, status.target_mac) &&
	    (status.running_label[0] || status.update_label[0] ||
	     status.running_size != 0 || status.update_size != 0)) {
		if (running_label) {
			copy_packet_text(running_label, MESH_OTA_SLOT_LABEL_MAX,
			                 status.running_label, sizeof(status.running_label));
		}
		if (update_label) {
			copy_packet_text(update_label, MESH_OTA_SLOT_LABEL_MAX,
			                 status.update_label, sizeof(status.update_label));
		}
		if (running_size) *running_size = status.running_size;
		if (update_size) *update_size = status.update_size;
	}
}

static size_t append_remote_ota_json_for_mac(char *out, size_t cap, size_t pos,
                                             const uint8_t mac[6])
{
	uint8_t target_mac[6] = {0};
	char tag[16] = "node";
	char target_err[96] = "target node is unknown";

	if (mac) {
		mac_copy(target_mac, mac);
	}

	bool target_ok = !mac_eq(target_mac, s_local_mac) &&
	                 lookup_node_tag(target_mac, tag, sizeof(tag));
	if (!target_ok && mac_eq(target_mac, s_local_mac)) {
		strncpy(target_err, "target is local node0", sizeof(target_err) - 1);
		target_err[sizeof(target_err) - 1] = '\0';
	}
	if (target_ok) {
		remote_ota_normalize_tag_for_mac(target_mac, tag, sizeof(tag));
	}
	bool target_supported = target_ok && remote_ota_supported_tag(tag);
	bool route_ready = target_supported && node_route_current(target_mac);
	bool telemetry_ready = target_supported &&
	                       node_has_fresh_telemetry(target_mac, NODEINFO_STALE_MS);
	bool supported = target_supported && route_ready;
	if (target_ok && target_supported && !route_ready) {
		strncpy(target_err, "target route not ready", sizeof(target_err) - 1);
		target_err[sizeof(target_err) - 1] = '\0';
	} else if (target_ok && target_supported && !telemetry_ready) {
		strncpy(target_err, "target telemetry stale, resyncing", sizeof(target_err) - 1);
		target_err[sizeof(target_err) - 1] = '\0';
	}

	char mac_hex[13] = {0};
	mac_to_hex(target_mac, mac_hex);

	remote_ota_status_t status;
	portENTER_CRITICAL(&s_remote_ota_lock);
	status = s_remote_ota_status;
	portEXIT_CRITICAL(&s_remote_ota_lock);

	bool target_match = target_ok &&
	                    status.target_valid &&
	                    mac_eq(target_mac, status.target_mac);
	node0_ota_state_t state = target_match ? status.state : NODE0_OTA_IDLE;
	uint32_t total = target_match ? status.total_bytes : 0;
	uint32_t written = target_match ? status.written_bytes : 0;
	const char *last_result = target_match ? status.last_result : "";
	const char *last_error = target_match ? status.last_error : "";
	const char *remote_message = target_match ? status.remote_message : "";
	char running_label[MESH_OTA_SLOT_LABEL_MAX] = {0};
	char update_label[MESH_OTA_SLOT_LABEL_MAX] = {0};
	uint32_t running_size = 0;
	uint32_t update_size = 0;
	remote_ota_slot_snapshot(target_mac, running_label, update_label,
	                         &running_size, &update_size);

	pos = append_fmt(out, cap, pos,
	                 "{\"enabled\":%s,\"supported\":%s,\"busy\":%s,"
	                 "\"state\":\"%s\",\"written_bytes\":%lu,\"total_bytes\":%lu,"
	                 "\"target_mac\":\"%s\",\"route_ready\":%s,"
	                 "\"telemetry_ready\":%s,\"target_tag\":",
	                 ota_enabled() ? "true" : "false",
	                 supported ? "true" : "false",
	                 state == NODE0_OTA_UPDATING ? "true" : "false",
	                 ota_state_name(state),
	                 (unsigned long)written,
	                 (unsigned long)total,
	                 mac_hex,
	                 route_ready ? "true" : "false",
	                 telemetry_ready ? "true" : "false");
	pos = append_json_string(out, cap, pos, target_ok ? tag : "");
	pos = append_fmt(out, cap, pos, ",\"running_label\":");
	pos = append_json_string(out, cap, pos, running_label);
	pos = append_fmt(out, cap, pos,
	                 ",\"running_size\":%lu,\"update_label\":",
	                 (unsigned long)running_size);
	pos = append_json_string(out, cap, pos, update_label);
	pos = append_fmt(out, cap, pos,
	                 ",\"update_size\":%lu,\"last_result\":",
	                 (unsigned long)update_size);
	pos = append_json_string(out, cap, pos, last_result);
	pos = append_fmt(out, cap, pos, ",\"last_error\":");
	pos = append_json_string(out, cap, pos, target_ok ? last_error : target_err);
	pos = append_fmt(out, cap, pos, ",\"remote_message\":");
	pos = append_json_string(out, cap, pos, remote_message);
	return append_fmt(out, cap, pos, "}");
}

static size_t append_ram_json_fields(char *out, size_t cap, size_t pos,
                                     const ram_status_t *ram)
{
	ram_status_t empty = {0};
	if (!ram) ram = &empty;

	return append_fmt(out, cap, pos,
	                  "\"ram_valid\":%s,"
	                  "\"ram_free_bytes\":%lu,\"ram_min_free_bytes\":%lu,"
	                  "\"ram_total_bytes\":%lu,"
	                  "\"ram_internal_valid\":%s,"
	                  "\"ram_internal_free_bytes\":%lu,"
	                  "\"ram_internal_min_free_bytes\":%lu,"
	                  "\"ram_internal_total_bytes\":%lu,"
	                  "\"ram_psram_valid\":%s,"
	                  "\"ram_psram_free_bytes\":%lu,"
	                  "\"ram_psram_min_free_bytes\":%lu,"
	                  "\"ram_psram_total_bytes\":%lu",
	                  ram->valid ? "true" : "false",
	                  (unsigned long)ram->free_bytes,
	                  (unsigned long)ram->min_free_bytes,
	                  (unsigned long)ram->total_bytes,
	                  ram->internal_valid ? "true" : "false",
	                  (unsigned long)ram->internal_free_bytes,
	                  (unsigned long)ram->internal_min_free_bytes,
	                  (unsigned long)ram->internal_total_bytes,
	                  ram->psram_valid ? "true" : "false",
	                  (unsigned long)ram->psram_free_bytes,
	                  (unsigned long)ram->psram_min_free_bytes,
	                  (unsigned long)ram->psram_total_bytes);
}

static size_t append_tasks_json_for_mac(char *out, size_t cap, size_t pos,
                                        const uint8_t mac[6])
{
	uint8_t target_mac[6];
	if (mac) {
		mac_copy(target_mac, mac);
	} else {
		selection_snapshot(target_mac, NULL, 0);
	}

	stack_monitor_snapshot_t snap;
	char tag[16] = {0};
	bool valid = taskmon_get_snapshot(target_mac, &snap, tag, sizeof(tag));
	if (tag[0] == '\0' && !lookup_node_tag(target_mac, tag, sizeof(tag))) {
		copy_tag(tag, sizeof(tag), "node");
	}

	char mac_hex[13];
	mac_to_hex(target_mac, mac_hex);
	int slot_count = mac_eq(target_mac, s_local_mac)
		? STACK_MONITOR_MAX_TASKS
		: taskmon_slot_count_for_mac(target_mac);
	uint32_t uptime_s = 0;
	bool uptime_valid = node_uptime_for_mac(target_mac, &uptime_s);
	ram_status_t ram = ram_status_for_mac(target_mac);
	persistent_status_t persistent = persistent_status_for_mac(target_mac);

	if (!valid) {
		pos = append_fmt(out, cap, pos,
		                 "{\"valid\":false,\"mac\":\"%s\",\"tag\":",
		                 mac_hex);
		pos = append_json_string(out, cap, pos, tag);
		pos = append_fmt(out, cap, pos,
		                 ",\"updated_ms\":0,\"age_ms\":0,"
		                 "\"cpu_valid\":false,\"cpu_load_x10\":0,"
		                 "\"slot_count\":%d,\"uptime_valid\":%s,"
		                 "\"uptime_s\":%lu,",
		                 slot_count,
		                 uptime_valid ? "true" : "false",
		                 (unsigned long)uptime_s);
		pos = append_ram_json_fields(out, cap, pos, &ram);
		return append_fmt(out, cap, pos,
		                  ",\"flash_valid\":%s,"
		                  "\"flash_chip_bytes\":%lu,\"app_used_bytes\":%lu,"
		                  "\"app_partition_bytes\":%lu,"
		                  "\"nvs_valid\":%s,\"nvs_used_entries\":%lu,"
		                  "\"nvs_free_entries\":%lu,\"nvs_available_entries\":%lu,"
		                  "\"nvs_total_entries\":%lu,\"tasks\":[]}",
		                  persistent.flash_valid ? "true" : "false",
		                  (unsigned long)persistent.flash_chip_bytes,
		                  (unsigned long)persistent.app_used_bytes,
		                  (unsigned long)persistent.app_partition_bytes,
		                  persistent.nvs_valid ? "true" : "false",
		                  (unsigned long)persistent.nvs_used_entries,
		                  (unsigned long)persistent.nvs_free_entries,
		                  (unsigned long)persistent.nvs_available_entries,
		                  (unsigned long)persistent.nvs_total_entries);
	}

	uint32_t now = ms_now();
	uint32_t age_ms = (now >= snap.updated_ms) ? (now - snap.updated_ms) : 0;

	pos = append_fmt(out, cap, pos,
	                 "{\"valid\":true,\"mac\":\"%s\",\"tag\":",
	                 mac_hex);
	pos = append_json_string(out, cap, pos, tag);
	pos = append_fmt(out, cap, pos,
	                 ",\"updated_ms\":%lu,\"age_ms\":%lu,"
	                 "\"cpu_valid\":%s,\"cpu_load_x10\":%lu,"
	                 "\"slot_count\":%d,\"uptime_valid\":%s,"
	                 "\"uptime_s\":%lu,",
	                 (unsigned long)snap.updated_ms,
	                 (unsigned long)age_ms,
	                 snap.cpu_valid ? "true" : "false",
	                 (unsigned long)snap.cpu_load_x10,
	                 slot_count,
	                 uptime_valid ? "true" : "false",
	                 (unsigned long)uptime_s);
	pos = append_ram_json_fields(out, cap, pos, &ram);
	pos = append_fmt(out, cap, pos,
	                 ",\"flash_valid\":%s,"
	                 "\"flash_chip_bytes\":%lu,\"app_used_bytes\":%lu,"
	                 "\"app_partition_bytes\":%lu,"
	                 "\"nvs_valid\":%s,\"nvs_used_entries\":%lu,"
	                 "\"nvs_free_entries\":%lu,\"nvs_available_entries\":%lu,"
	                 "\"nvs_total_entries\":%lu,\"tasks\":[",
	                 persistent.flash_valid ? "true" : "false",
	                 (unsigned long)persistent.flash_chip_bytes,
	                 (unsigned long)persistent.app_used_bytes,
	                 (unsigned long)persistent.app_partition_bytes,
	                 persistent.nvs_valid ? "true" : "false",
	                 (unsigned long)persistent.nvs_used_entries,
	                 (unsigned long)persistent.nvs_free_entries,
	                 (unsigned long)persistent.nvs_available_entries,
	                 (unsigned long)persistent.nvs_total_entries);

	for (uint32_t i = 0; i < snap.count && i < STACK_MONITOR_MAX_TASKS; i++) {
		const stack_monitor_task_info_t *t = &snap.tasks[i];
		if (i > 0) pos = append_fmt(out, cap, pos, ",");
		pos = append_fmt(out, cap, pos, "{\"name\":");
		pos = append_json_string(out, cap, pos, t->name);
		pos = append_fmt(out, cap, pos,
		                 ",\"prio\":%lu,\"free_words\":%lu,\"cpu_x10\":%ld}",
		                 (unsigned long)t->priority,
		                 (unsigned long)t->free_words,
		                 (long)t->cpu_x10);
	}

	return append_fmt(out, cap, pos, "]}");
}

static bool remote_ota_target_from_req(httpd_req_t *req, uint8_t mac[6],
                                       char *tag, size_t tag_sz,
                                       char *err, size_t err_sz)
{
	if (!mac || !tag || tag_sz == 0) {
		snprintf(err, err_sz, "bad target");
		return false;
	}

	selection_snapshot(mac, tag, tag_sz);

	char q[80] = {0};
	if (req && httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
		char v[32] = {0};
		if (httpd_query_key_value(q, "mac", v, sizeof(v)) == ESP_OK) {
			uint8_t parsed[6];
			if (!parse_mac_hex(v, parsed)) {
				snprintf(err, err_sz, "bad target MAC");
				return false;
			}
			mac_copy(mac, parsed);
			if (!lookup_node_tag(mac, tag, tag_sz)) {
				copy_tag(tag, tag_sz, "node");
			}
		}
	}

	if (mac_eq(mac, s_local_mac)) {
		snprintf(err, err_sz, "target is local node0");
		return false;
	}

	if (!lookup_node_tag(mac, tag, tag_sz)) {
		snprintf(err, err_sz, "target node is unknown");
		return false;
	}

	return true;
}

static uint16_t remote_ota_next_seq(void)
{
	static uint16_t seq = 0;
	seq++;
	if (seq == 0) {
		seq = 1;
	}
	return seq;
}

static void mesh_ota_fill_header(mesh_pkt_hdr_t *h, uint8_t type)
{
	if (!h) return;

	memset(h, 0, sizeof(*h));
	h->magic = MESH_PKT_MAGIC;
	h->version = MESH_PKT_VERSION;
	h->type = type;
	h->counter = ms_now();
	esp_wifi_get_mac(WIFI_IF_STA, h->src_mac);
}

static esp_err_t mesh_ota_send_to(const uint8_t to_mac[6], const void *pkt, size_t pkt_len)
{
	if (!to_mac || !pkt || pkt_len == 0) {
		return ESP_ERR_INVALID_ARG;
	}

	mesh_data_t data;
	memset(&data, 0, sizeof(data));
	data.data = (uint8_t *)pkt;
	data.size = pkt_len;
	data.proto = MESH_PROTO_BIN;
	data.tos = MESH_TOS_P2P;

	mesh_addr_t dest;
	memset(&dest, 0, sizeof(dest));
	memcpy(dest.addr, to_mac, 6);

	return esp_mesh_send(&dest, &data, MESH_DATA_P2P, NULL, 0);
}

static void remote_ota_clear_wait(void)
{
	portENTER_CRITICAL(&s_remote_ota_lock);
	s_remote_ota_wait.waiting = false;
	portEXIT_CRITICAL(&s_remote_ota_lock);
}

static esp_err_t remote_ota_send_wait(const uint8_t mac[6], const void *pkt,
                                      size_t pkt_len, uint8_t op, uint16_t seq,
                                      mesh_ota_status_packet_t *ack,
                                      char *err, size_t err_sz)
{
	if (!s_remote_ota_ack_sem) {
		snprintf(err, err_sz, "remote OTA ACK semaphore unavailable");
		return ESP_ERR_INVALID_STATE;
	}

	esp_err_t last_err = ESP_ERR_TIMEOUT;

	for (uint32_t attempt = 1; attempt <= REMOTE_OTA_SEND_RETRIES; attempt++) {
		while (xSemaphoreTake(s_remote_ota_ack_sem, 0) == pdTRUE) {
		}

		portENTER_CRITICAL(&s_remote_ota_lock);
		memset(&s_remote_ota_wait, 0, sizeof(s_remote_ota_wait));
		s_remote_ota_wait.waiting = true;
		mac_copy(s_remote_ota_wait.mac, mac);
		s_remote_ota_wait.op = op;
		s_remote_ota_wait.seq = seq;
		portEXIT_CRITICAL(&s_remote_ota_lock);

		esp_err_t send_err = mesh_ota_send_to(mac, pkt, pkt_len);
		if (send_err != ESP_OK) {
			remote_ota_clear_wait();
			last_err = send_err;
			snprintf(err, err_sz, "mesh send failed: %s", esp_err_to_name(send_err));
			vTaskDelay(pdMS_TO_TICKS(REMOTE_OTA_RETRY_DELAY_MS));
			continue;
		}

		if (xSemaphoreTake(s_remote_ota_ack_sem,
		                   pdMS_TO_TICKS(REMOTE_OTA_ACK_TIMEOUT_MS)) == pdTRUE) {
			last_err = ESP_OK;
			break;
		}

		remote_ota_clear_wait();
		last_err = ESP_ERR_TIMEOUT;
		snprintf(err, err_sz, "remote OTA ACK timeout op=%u seq=%u try=%lu/%u",
		         (unsigned)op, (unsigned)seq, (unsigned long)attempt,
		         (unsigned)REMOTE_OTA_SEND_RETRIES);
		vTaskDelay(pdMS_TO_TICKS(REMOTE_OTA_RETRY_DELAY_MS));
	}

	if (last_err != ESP_OK) {
		return last_err;
	}

	mesh_ota_status_packet_t got;
	portENTER_CRITICAL(&s_remote_ota_lock);
	got = s_remote_ota_wait.ack;
	portEXIT_CRITICAL(&s_remote_ota_lock);

	if (ack) {
		*ack = got;
	}

	if (got.code != MESH_OTA_STATUS_OK) {
		char msg[MESH_OTA_STATUS_MSG_MAX + 1];
		copy_packet_text(msg, sizeof(msg), got.message, sizeof(got.message));
		snprintf(err, err_sz, "remote OTA error: %s", msg[0] ? msg : "unknown");
		return ESP_FAIL;
	}

	return ESP_OK;
}

static uint16_t remote_reboot_next_seq(void)
{
	static uint16_t seq = 0;
	seq++;
	if (seq == 0) {
		seq = 1;
	}
	return seq;
}

static void remote_reboot_clear_wait(void)
{
	portENTER_CRITICAL(&s_remote_reboot_lock);
	s_remote_reboot_wait.waiting = false;
	portEXIT_CRITICAL(&s_remote_reboot_lock);
}

static esp_err_t remote_reboot_send_wait(const uint8_t mac[6],
                                         const mesh_reboot_request_packet_t *pkt,
                                         mesh_reboot_status_packet_t *ack,
                                         char *err, size_t err_sz)
{
	if (!s_remote_reboot_ack_sem) {
		snprintf(err, err_sz, "remote reboot ACK semaphore unavailable");
		return ESP_ERR_INVALID_STATE;
	}
	if (!mac || !pkt) {
		snprintf(err, err_sz, "bad remote reboot request");
		return ESP_ERR_INVALID_ARG;
	}

	esp_err_t last_err = ESP_ERR_TIMEOUT;

	for (uint32_t attempt = 1; attempt <= REMOTE_REBOOT_SEND_RETRIES; attempt++) {
		while (xSemaphoreTake(s_remote_reboot_ack_sem, 0) == pdTRUE) {
		}

		portENTER_CRITICAL(&s_remote_reboot_lock);
		memset(&s_remote_reboot_wait, 0, sizeof(s_remote_reboot_wait));
		s_remote_reboot_wait.waiting = true;
		mac_copy(s_remote_reboot_wait.mac, mac);
		s_remote_reboot_wait.seq = pkt->seq;
		portEXIT_CRITICAL(&s_remote_reboot_lock);

		esp_err_t send_err = mesh_ota_send_to(mac, pkt, sizeof(*pkt));
		if (send_err != ESP_OK) {
			remote_reboot_clear_wait();
			last_err = send_err;
			snprintf(err, err_sz, "mesh send failed: %s", esp_err_to_name(send_err));
			vTaskDelay(pdMS_TO_TICKS(REMOTE_REBOOT_RETRY_DELAY_MS));
			continue;
		}

		if (xSemaphoreTake(s_remote_reboot_ack_sem,
		                   pdMS_TO_TICKS(REMOTE_REBOOT_ACK_TIMEOUT_MS)) == pdTRUE) {
			last_err = ESP_OK;
			break;
		}

		remote_reboot_clear_wait();
		last_err = ESP_ERR_TIMEOUT;
		snprintf(err, err_sz, "remote reboot ACK timeout seq=%u try=%lu/%u",
		         (unsigned)pkt->seq, (unsigned long)attempt,
		         (unsigned)REMOTE_REBOOT_SEND_RETRIES);
		vTaskDelay(pdMS_TO_TICKS(REMOTE_REBOOT_RETRY_DELAY_MS));
	}

	if (last_err != ESP_OK) {
		return last_err;
	}

	mesh_reboot_status_packet_t got;
	portENTER_CRITICAL(&s_remote_reboot_lock);
	got = s_remote_reboot_wait.ack;
	portEXIT_CRITICAL(&s_remote_reboot_lock);

	if (ack) {
		*ack = got;
	}

	if (got.code != MESH_REBOOT_STATUS_OK) {
		char msg[MESH_REBOOT_STATUS_MSG_MAX + 1];
		copy_packet_text(msg, sizeof(msg), got.message, sizeof(got.message));
		snprintf(err, err_sz, "remote reboot error: %s", msg[0] ? msg : "unknown");
		return ESP_FAIL;
	}

	return ESP_OK;
}

static void remote_ota_send_abort(const uint8_t mac[6], const char *reason)
{
	mesh_ota_abort_packet_t p;
	memset(&p, 0, sizeof(p));

	mesh_ota_fill_header(&p.h, MESH_OTA_TYPE_ABORT);
	p.seq = remote_ota_next_seq();
	if (reason) {
		strncpy(p.reason, reason, sizeof(p.reason) - 1);
		p.reason[sizeof(p.reason) - 1] = '\0';
	}

	mesh_ota_send_to(mac, &p, sizeof(p));
}

static esp_err_t http_json_error(httpd_req_t *req, const char *status, const char *msg)
{
	char out[192];
	size_t pos = append_fmt(out, sizeof(out), 0, "{\"ok\":false,\"error\":");
	pos = append_json_string(out, sizeof(out), pos, msg ? msg : "error");
	pos = append_fmt(out, sizeof(out), pos, "}");

	httpd_resp_set_status(req, status ? status : "500 Internal Server Error");
	httpd_resp_set_type(req, "application/json");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	return httpd_resp_send(req, out, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t http_json_ok(httpd_req_t *req, const char *msg)
{
	char out[192];
	size_t pos = append_fmt(out, sizeof(out), 0, "{\"ok\":true,\"message\":");
	pos = append_json_string(out, sizeof(out), pos, msg ? msg : "OK");
	pos = append_fmt(out, sizeof(out), pos, "}");

	httpd_resp_set_type(req, "application/json");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	return httpd_resp_send(req, out, HTTPD_RESP_USE_STRLEN);
}

static bool ota_check_pin(httpd_req_t *req)
{
	char pin[64] = {0};
	if (!ota_enabled()) {
		return false;
	}
	if (httpd_req_get_hdr_value_str(req, "X-OTA-PIN", pin, sizeof(pin)) != ESP_OK) {
		return false;
	}
	return strcmp(pin, CONFIG_NODE0_OTA_PIN) == 0;
}

static int ota_recv_retry(httpd_req_t *req, uint8_t *buf, size_t len)
{
	if (!req || !buf || len == 0) {
		return -1;
	}

	for (int tries = 0; tries < NODE0_OTA_RECV_TIMEOUT_RETRIES; tries++) {
		int r = httpd_req_recv(req, (char *)buf, len);
		if (r != HTTPD_SOCK_ERR_TIMEOUT) {
			return r;
		}
	}

	return HTTPD_SOCK_ERR_TIMEOUT;
}

static bool ota_validate_first_chunk(const uint8_t *data, size_t len,
                                     esp_app_desc_t *new_desc,
                                     const char *expected_project,
                                     char *err, size_t err_len)
{
	if (!data || !new_desc) {
		snprintf(err, err_len, "missing OTA data");
		return false;
	}

	if (len < sizeof(esp_image_header_t)) {
		snprintf(err, err_len, "image too small");
		return false;
	}

	const esp_image_header_t *image_header = (const esp_image_header_t *)data;
	if (image_header->magic != ESP_IMAGE_HEADER_MAGIC) {
		snprintf(err, err_len, "invalid ESP image magic");
		return false;
	}

	const size_t desc_off = sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t);
	if (len < desc_off + sizeof(esp_app_desc_t)) {
		snprintf(err, err_len, "image descriptor missing");
		return false;
	}

	memcpy(new_desc, data + desc_off, sizeof(*new_desc));
	if (new_desc->magic_word != ESP_APP_DESC_MAGIC_WORD) {
		snprintf(err, err_len, "invalid app descriptor");
		return false;
	}

	const esp_app_desc_t *running = esp_app_get_description();
	if (!expected_project || expected_project[0] == '\0') {
		expected_project = running ? running->project_name : "";
	}
	if (strncmp(new_desc->project_name, expected_project,
	            sizeof(new_desc->project_name)) != 0) {
		char got[33] = {0};
		char expected[33] = {0};
		memcpy(got, new_desc->project_name, sizeof(new_desc->project_name));
		strncpy(expected, expected_project[0] ? expected_project : "unknown",
		        sizeof(expected) - 1);
		snprintf(err, err_len, "wrong project: %s, expected %s", got, expected);
		return false;
	}

	return true;
}

static void ota_restart_task(void *arg)
{
	(void)arg;
	vTaskDelay(pdMS_TO_TICKS(1200));
	esp_restart();
}

static esp_err_t http_reboot_post(httpd_req_t *req)
{
	if (!ota_enabled()) {
		return http_json_error(req, "403 Forbidden",
		                       "reboot disabled: set CONFIG_NODE0_OTA_PIN");
	}

	if (!ota_check_pin(req)) {
		return http_json_error(req, "403 Forbidden", "bad OTA PIN");
	}

	if (s_ota_mutex && xSemaphoreTake(s_ota_mutex, 0) != pdTRUE) {
		return http_json_error(req, "409 Conflict", "OTA already running");
	}
	if (s_ota_mutex) {
		xSemaphoreGive(s_ota_mutex);
	}

	ESP_LOGW(TAG, "manual reboot requested from web UI");
	BaseType_t task_ok = xTaskCreate(ota_restart_task, "web_reboot", 2048, NULL, 5, NULL);
	if (task_ok != pdPASS) {
		return http_json_error(req, "500 Internal Server Error",
		                       "failed to create reboot task");
	}

	return http_json_ok(req, "rebooting node0");
}

static esp_err_t http_reboot_remote_post(httpd_req_t *req)
{
	if (!ota_enabled()) {
		return http_json_error(req, "403 Forbidden",
		                       "reboot disabled: set CONFIG_NODE0_OTA_PIN");
	}

	if (!ota_check_pin(req)) {
		return http_json_error(req, "403 Forbidden", "bad OTA PIN");
	}

	if (!s_ota_mutex) {
		return http_json_error(req, "500 Internal Server Error", "OTA mutex unavailable");
	}
	if (xSemaphoreTake(s_ota_mutex, 0) != pdTRUE) {
		return http_json_error(req, "409 Conflict", "OTA/reboot already running");
	}

	uint8_t target_mac[6] = {0};
	char target_tag[16] = "node";
	char err_msg[96] = "remote reboot failed";
	esp_err_t result = ESP_FAIL;

	do {
		if (!remote_ota_target_from_req(req, target_mac, target_tag,
		                                sizeof(target_tag), err_msg,
		                                sizeof(err_msg))) {
			break;
		}
		remote_ota_normalize_tag_for_mac(target_mac, target_tag,
		                                 sizeof(target_tag));
		if (!remote_ota_supported_tag(target_tag)) {
			snprintf(err_msg, sizeof(err_msg), "remote reboot unsupported for %s",
			         target_tag);
			break;
		}
		if (!node_route_current(target_mac)) {
			snprintf(err_msg, sizeof(err_msg), "target route not ready");
			break;
		}
		if (!node_has_fresh_telemetry(target_mac, NODEINFO_STALE_MS)) {
			(void)remote_stream_rearm_for_mac(target_mac, true);
		}

		mesh_reboot_request_packet_t p;
		memset(&p, 0, sizeof(p));
		mesh_ota_fill_header(&p.h, MESH_REBOOT_TYPE_REQUEST);
		p.seq = remote_reboot_next_seq();
		p.delay_ms = REMOTE_REBOOT_DELAY_MS;
		strncpy(p.reason, "manual web reboot", sizeof(p.reason) - 1);
		p.reason[sizeof(p.reason) - 1] = '\0';

		ESP_LOGW(TAG, "manual remote reboot requested -> " MACSTR " tag=%s seq=%u",
		         MAC2STR(target_mac), target_tag, (unsigned)p.seq);

		mesh_reboot_status_packet_t ack;
		result = remote_reboot_send_wait(target_mac, &p, &ack,
		                                 err_msg, sizeof(err_msg));
		if (result != ESP_OK) {
			break;
		}

		char remote_msg[MESH_REBOOT_STATUS_MSG_MAX + 1];
		copy_packet_text(remote_msg, sizeof(remote_msg),
		                 ack.message, sizeof(ack.message));
		snprintf(err_msg, sizeof(err_msg), "remote reboot accepted, %s rebooting",
		         target_tag);
		ESP_LOGI(TAG, "%s: %s", err_msg,
		         remote_msg[0] ? remote_msg : "OK");

		xSemaphoreGive(s_ota_mutex);
		return http_json_ok(req, err_msg);
	} while (0);

	ESP_LOGW(TAG, "remote reboot failed: %s", err_msg);
	xSemaphoreGive(s_ota_mutex);
	return http_json_error(req, "400 Bad Request", err_msg);
}

static esp_err_t http_ota_status_get(httpd_req_t *req)
{
	enum { OTA_STATUS_JSON_MAX = 1024 };
	char out[OTA_STATUS_JSON_MAX];
	node0_ota_status_t status;

	portENTER_CRITICAL(&s_ota_state_lock);
	status = s_ota_status;
	portEXIT_CRITICAL(&s_ota_state_lock);

	const esp_partition_t *running = esp_ota_get_running_partition();
	const esp_partition_t *update = esp_ota_get_next_update_partition(NULL);
	const esp_app_desc_t *app = esp_app_get_description();

	esp_ota_img_states_t img_state = ESP_OTA_IMG_UNDEFINED;
	bool img_state_valid = running &&
		esp_ota_get_state_partition(running, &img_state) == ESP_OK;

	size_t pos = 0;
	pos = append_fmt(out, sizeof(out), pos,
	                 "{\"enabled\":%s,\"busy\":%s,\"state\":\"%s\","
	                 "\"written_bytes\":%lu,\"total_bytes\":%lu,"
	                 "\"running_label\":",
	                 ota_enabled() ? "true" : "false",
	                 status.state == NODE0_OTA_UPDATING ? "true" : "false",
	                 ota_state_name(status.state),
	                 (unsigned long)status.written_bytes,
	                 (unsigned long)status.total_bytes);
	pos = append_json_string(out, sizeof(out), pos, running ? running->label : "");
	pos = append_fmt(out, sizeof(out), pos,
	                 ",\"running_address\":%lu,\"running_size\":%lu,"
	                 "\"update_label\":",
	                 (unsigned long)(running ? running->address : 0),
	                 (unsigned long)(running ? running->size : 0));
	pos = append_json_string(out, sizeof(out), pos, update ? update->label : "");
	pos = append_fmt(out, sizeof(out), pos,
	                 ",\"update_size\":%lu,\"rollback_state\":",
	                 (unsigned long)(update ? update->size : 0));
	pos = append_json_string(out, sizeof(out), pos,
	                         img_state_valid ? ota_img_state_name(img_state) : "unknown");
	pos = append_fmt(out, sizeof(out), pos, ",\"project_name\":");
	pos = append_json_string(out, sizeof(out), pos, app ? app->project_name : "");
	pos = append_fmt(out, sizeof(out), pos, ",\"version\":");
	pos = append_json_string(out, sizeof(out), pos, app ? app->version : "");
	pos = append_fmt(out, sizeof(out), pos, ",\"last_result\":");
	pos = append_json_string(out, sizeof(out), pos, status.last_result);
	pos = append_fmt(out, sizeof(out), pos, ",\"last_error\":");
	pos = append_json_string(out, sizeof(out), pos, status.last_error);
	pos = append_fmt(out, sizeof(out), pos, "}");

	httpd_resp_set_type(req, "application/json");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	return httpd_resp_send(req, out, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t http_ota_post(httpd_req_t *req)
{
	if (!ota_enabled()) {
		ota_status_finish(NODE0_OTA_FAILED, "OTA disabled: set CONFIG_NODE0_OTA_PIN");
		return http_json_error(req, "403 Forbidden", "OTA disabled: set CONFIG_NODE0_OTA_PIN");
	}

	if (!ota_check_pin(req)) {
		ota_status_finish(NODE0_OTA_FAILED, "bad OTA PIN");
		return http_json_error(req, "403 Forbidden", "bad OTA PIN");
	}

	if (!s_ota_mutex) {
		return http_json_error(req, "500 Internal Server Error", "OTA mutex unavailable");
	}
	if (xSemaphoreTake(s_ota_mutex, 0) != pdTRUE) {
		return http_json_error(req, "409 Conflict", "OTA already running");
	}

	esp_ota_handle_t ota_handle = 0;
	const esp_partition_t *update_partition = NULL;
	uint8_t *buf = NULL;
	bool ota_started = false;
	esp_err_t result = ESP_FAIL;
	char err_msg[96] = "OTA failed";

	do {
		size_t total_len = req->content_len;
		if (total_len == 0) {
			snprintf(err_msg, sizeof(err_msg), "missing Content-Length");
			break;
		}

		update_partition = esp_ota_get_next_update_partition(NULL);
		if (!update_partition) {
			snprintf(err_msg, sizeof(err_msg), "no OTA update partition");
			break;
		}
		if (total_len > update_partition->size) {
			snprintf(err_msg, sizeof(err_msg), "image too large for %s", update_partition->label);
			break;
		}

		buf = (uint8_t *)malloc(NODE0_OTA_BUF_SIZE);
		if (!buf) {
			snprintf(err_msg, sizeof(err_msg), "no memory for OTA buffer");
			break;
		}

		const size_t validate_need =
			sizeof(esp_image_header_t) +
			sizeof(esp_image_segment_header_t) +
			sizeof(esp_app_desc_t);
		size_t first_want = total_len < NODE0_OTA_BUF_SIZE ? total_len : NODE0_OTA_BUF_SIZE;
		size_t first_have = 0;
		while (first_have < first_want && first_have < validate_need) {
			int r = ota_recv_retry(req, buf + first_have, first_want - first_have);
			if (r <= 0) {
				break;
			}
			first_have += (size_t)r;
		}
		if (first_have == 0) {
			snprintf(err_msg, sizeof(err_msg), "failed to read OTA image");
			break;
		}

		esp_app_desc_t new_desc = {0};
		if (!ota_validate_first_chunk(buf, first_have, &new_desc, NULL,
		                              err_msg, sizeof(err_msg))) {
			break;
		}

		ESP_LOGI(TAG, "OTA upload: project=%s version=%s size=%lu target=%s",
		         new_desc.project_name, new_desc.version,
		         (unsigned long)total_len, update_partition->label);

		ota_status_begin((uint32_t)total_len);

		result = esp_ota_begin(update_partition, total_len, &ota_handle);
		if (result != ESP_OK) {
			snprintf(err_msg, sizeof(err_msg), "esp_ota_begin: %s", esp_err_to_name(result));
			break;
		}
		ota_started = true;

		result = esp_ota_write(ota_handle, buf, first_have);
		if (result != ESP_OK) {
			snprintf(err_msg, sizeof(err_msg), "esp_ota_write: %s", esp_err_to_name(result));
			break;
		}

		size_t written = first_have;
		ota_status_progress((uint32_t)written);

		while (written < total_len) {
			size_t to_read = total_len - written;
			if (to_read > NODE0_OTA_BUF_SIZE) to_read = NODE0_OTA_BUF_SIZE;

			int r = ota_recv_retry(req, buf, to_read);
			if (r <= 0) {
				snprintf(err_msg, sizeof(err_msg), "OTA upload interrupted");
				break;
			}

			result = esp_ota_write(ota_handle, buf, r);
			if (result != ESP_OK) {
				snprintf(err_msg, sizeof(err_msg), "esp_ota_write: %s", esp_err_to_name(result));
				break;
			}

			written += (size_t)r;
			ota_status_progress((uint32_t)written);
		}

		if (written != total_len) {
			result = ESP_FAIL;
			break;
		}

		result = esp_ota_end(ota_handle);
		ota_started = false;
		ota_handle = 0;
		if (result != ESP_OK) {
			snprintf(err_msg, sizeof(err_msg), "esp_ota_end: %s", esp_err_to_name(result));
			break;
		}

		result = esp_ota_set_boot_partition(update_partition);
		if (result != ESP_OK) {
			snprintf(err_msg, sizeof(err_msg), "set boot partition: %s", esp_err_to_name(result));
			break;
		}

		snprintf(err_msg, sizeof(err_msg), "OTA OK, rebooting into %s", update_partition->label);
		ota_status_finish(NODE0_OTA_REBOOTING, err_msg);
		ESP_LOGI(TAG, "%s", err_msg);

		BaseType_t task_ok = xTaskCreate(ota_restart_task, "ota_reboot", 2048, NULL, 5, NULL);
		if (task_ok != pdPASS) {
			ESP_LOGW(TAG, "failed to create OTA reboot task; reboot manually");
		}

		free(buf);
		xSemaphoreGive(s_ota_mutex);
		return http_json_ok(req, err_msg);
	} while (0);

	if (ota_started) {
		esp_ota_abort(ota_handle);
	}
	if (buf) {
		free(buf);
	}

	ota_status_finish(NODE0_OTA_FAILED, err_msg);
	ESP_LOGW(TAG, "OTA failed: %s", err_msg);
	xSemaphoreGive(s_ota_mutex);
	return http_json_error(req, "400 Bad Request", err_msg);
}

static esp_err_t remote_ota_send_chunks_from_buffer(const uint8_t mac[6],
                                                    const uint8_t *buf,
                                                    size_t len,
                                                    uint32_t total_len,
                                                    uint32_t *written,
                                                    char *err, size_t err_sz)
{
	if (!buf || !written) {
		snprintf(err, err_sz, "bad remote OTA chunk buffer");
		return ESP_ERR_INVALID_ARG;
	}

	size_t pos = 0;
	while (pos < len) {
		size_t remain = len - pos;
		uint16_t chunk_len = (uint16_t)(remain > MESH_OTA_CHUNK_MAX
		                                ? MESH_OTA_CHUNK_MAX
		                                : remain);
		if ((uint32_t)chunk_len > total_len - *written) {
			snprintf(err, err_sz, "remote OTA chunk exceeds image size");
			return ESP_ERR_INVALID_SIZE;
		}

		mesh_ota_data_packet_t p;
		memset(&p, 0, sizeof(p));
		mesh_ota_fill_header(&p.h, MESH_OTA_TYPE_DATA);
		p.seq = remote_ota_next_seq();
		p.len = chunk_len;
		p.offset = *written;
		memcpy(p.data, buf + pos, chunk_len);

		mesh_ota_status_packet_t ack;
		esp_err_t result = remote_ota_send_wait(
			mac,
			&p,
			offsetof(mesh_ota_data_packet_t, data) + chunk_len,
			MESH_OTA_OP_DATA,
			p.seq,
			&ack,
			err,
			err_sz);
		if (result != ESP_OK) {
			return result;
		}

		uint32_t expected = *written + chunk_len;
		if (ack.offset != expected) {
			snprintf(err, err_sz, "remote OTA offset mismatch %lu/%lu",
			         (unsigned long)ack.offset, (unsigned long)expected);
			return ESP_FAIL;
		}

		*written = ack.offset;
		remote_ota_status_progress(*written);
		pos += chunk_len;
	}

	return ESP_OK;
}

static esp_err_t http_ota_remote_status_get(httpd_req_t *req)
{
	enum { OTA_STATUS_JSON_MAX = 1024 };
	char out[OTA_STATUS_JSON_MAX];
	char target_err[96] = {0};
	uint8_t mac[6] = {0};
	char tag[16] = "node";
	bool target_ok = remote_ota_target_from_req(req, mac, tag, sizeof(tag),
	                                            target_err, sizeof(target_err));
	if (target_ok) {
		remote_ota_normalize_tag_for_mac(mac, tag, sizeof(tag));
	}
	bool target_supported = target_ok && remote_ota_supported_tag(tag);
	bool route_ready = target_supported && node_route_current(mac);
	bool telemetry_ready = target_supported &&
	                       node_has_fresh_telemetry(mac, NODEINFO_STALE_MS);
	bool supported = target_supported && route_ready;
	if (target_ok && target_supported && !route_ready) {
		strncpy(target_err, "target route not ready", sizeof(target_err) - 1);
		target_err[sizeof(target_err) - 1] = '\0';
	} else if (target_ok && target_supported && !telemetry_ready) {
		strncpy(target_err, "target telemetry stale, resyncing", sizeof(target_err) - 1);
		target_err[sizeof(target_err) - 1] = '\0';
	}

	char mac_hex[13] = {0};
	mac_to_hex(mac, mac_hex);

	remote_ota_status_t status;
	portENTER_CRITICAL(&s_remote_ota_lock);
	status = s_remote_ota_status;
	portEXIT_CRITICAL(&s_remote_ota_lock);

	bool target_match = target_ok &&
	                    status.target_valid &&
	                    mac_eq(mac, status.target_mac);
	node0_ota_state_t state = target_match ? status.state : NODE0_OTA_IDLE;
	uint32_t total = target_match ? status.total_bytes : 0;
	uint32_t written = target_match ? status.written_bytes : 0;
	const char *last_result = target_match ? status.last_result : "";
	const char *last_error = target_match ? status.last_error : "";
	const char *remote_message = target_match ? status.remote_message : "";
	char running_label[MESH_OTA_SLOT_LABEL_MAX] = {0};
	char update_label[MESH_OTA_SLOT_LABEL_MAX] = {0};
	uint32_t running_size = 0;
	uint32_t update_size = 0;
	remote_ota_slot_snapshot(mac, running_label, update_label,
	                         &running_size, &update_size);

	size_t pos = 0;
	pos = append_fmt(out, sizeof(out), pos,
	                 "{\"enabled\":%s,\"supported\":%s,\"busy\":%s,"
	                 "\"state\":\"%s\",\"written_bytes\":%lu,\"total_bytes\":%lu,"
	                 "\"target_mac\":\"%s\",\"route_ready\":%s,"
	                 "\"telemetry_ready\":%s,\"target_tag\":",
	                 ota_enabled() ? "true" : "false",
	                 supported ? "true" : "false",
	                 state == NODE0_OTA_UPDATING ? "true" : "false",
	                 ota_state_name(state),
	                 (unsigned long)written,
	                 (unsigned long)total,
	                 mac_hex,
	                 route_ready ? "true" : "false",
	                 telemetry_ready ? "true" : "false");
	pos = append_json_string(out, sizeof(out), pos, target_ok ? tag : "");
	pos = append_fmt(out, sizeof(out), pos, ",\"running_label\":");
	pos = append_json_string(out, sizeof(out), pos, running_label);
	pos = append_fmt(out, sizeof(out), pos,
	                 ",\"running_size\":%lu,\"update_label\":",
	                 (unsigned long)running_size);
	pos = append_json_string(out, sizeof(out), pos, update_label);
	pos = append_fmt(out, sizeof(out), pos,
	                 ",\"update_size\":%lu,\"last_result\":",
	                 (unsigned long)update_size);
	pos = append_json_string(out, sizeof(out), pos, last_result);
	pos = append_fmt(out, sizeof(out), pos, ",\"last_error\":");
	pos = append_json_string(out, sizeof(out), pos,
	                         target_ok ? last_error : target_err);
	pos = append_fmt(out, sizeof(out), pos, ",\"remote_message\":");
	pos = append_json_string(out, sizeof(out), pos, remote_message);
	pos = append_fmt(out, sizeof(out), pos, "}");

	httpd_resp_set_type(req, "application/json");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	return httpd_resp_send(req, out, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t http_ota_remote_post(httpd_req_t *req)
{
	if (!ota_enabled()) {
		remote_ota_status_finish(NODE0_OTA_FAILED,
		                         "OTA disabled: set CONFIG_NODE0_OTA_PIN");
		return http_json_error(req, "403 Forbidden",
		                       "OTA disabled: set CONFIG_NODE0_OTA_PIN");
	}

	if (!ota_check_pin(req)) {
		remote_ota_status_finish(NODE0_OTA_FAILED, "bad OTA PIN");
		return http_json_error(req, "403 Forbidden", "bad OTA PIN");
	}

	if (!s_ota_mutex) {
		return http_json_error(req, "500 Internal Server Error", "OTA mutex unavailable");
	}
	if (xSemaphoreTake(s_ota_mutex, 0) != pdTRUE) {
		return http_json_error(req, "409 Conflict", "OTA already running");
	}

	uint8_t target_mac[6] = {0};
	char target_tag[16] = "node";
	char err_msg[96] = "remote OTA failed";
	uint8_t *buf = NULL;
	bool remote_started = false;
	esp_err_t result = ESP_FAIL;

	do {
		if (!remote_ota_target_from_req(req, target_mac, target_tag, sizeof(target_tag),
		                                err_msg, sizeof(err_msg))) {
			break;
		}
		remote_ota_normalize_tag_for_mac(target_mac, target_tag,
		                                 sizeof(target_tag));
		if (!remote_ota_supported_tag(target_tag)) {
			snprintf(err_msg, sizeof(err_msg), "remote OTA unsupported for %s", target_tag);
			break;
		}
		if (!node_route_current(target_mac)) {
			snprintf(err_msg, sizeof(err_msg), "target route not ready");
			break;
		}
		if (!node_has_fresh_telemetry(target_mac, NODEINFO_STALE_MS)) {
			(void)remote_stream_rearm_for_mac(target_mac, true);
		}

		size_t total_len = req->content_len;
		if (total_len == 0 || total_len > UINT32_MAX) {
			snprintf(err_msg, sizeof(err_msg), "bad Content-Length");
			break;
		}

		buf = (uint8_t *)malloc(NODE0_OTA_BUF_SIZE);
		if (!buf) {
			snprintf(err_msg, sizeof(err_msg), "no memory for OTA buffer");
			break;
		}

		const size_t validate_need =
			sizeof(esp_image_header_t) +
			sizeof(esp_image_segment_header_t) +
			sizeof(esp_app_desc_t);
		size_t first_want = total_len < NODE0_OTA_BUF_SIZE ? total_len : NODE0_OTA_BUF_SIZE;
		size_t first_have = 0;
		while (first_have < first_want && first_have < validate_need) {
			int r = ota_recv_retry(req, buf + first_have, first_want - first_have);
			if (r <= 0) {
				break;
			}
			first_have += (size_t)r;
		}
		if (first_have == 0) {
			snprintf(err_msg, sizeof(err_msg), "failed to read OTA image");
			break;
		}

		esp_app_desc_t new_desc = {0};
		if (!ota_validate_first_chunk(buf, first_have, &new_desc, target_tag,
		                              err_msg, sizeof(err_msg))) {
			break;
		}

		ESP_LOGI(TAG, "remote OTA upload -> " MACSTR " tag=%s project=%s version=%s size=%lu",
		         MAC2STR(target_mac), target_tag, new_desc.project_name,
		         new_desc.version, (unsigned long)total_len);

		remote_ota_status_begin(target_mac, target_tag, (uint32_t)total_len);

		mesh_ota_begin_packet_t begin;
		memset(&begin, 0, sizeof(begin));
		mesh_ota_fill_header(&begin.h, MESH_OTA_TYPE_BEGIN);
		begin.seq = remote_ota_next_seq();
		begin.chunk_size = MESH_OTA_CHUNK_MAX;
		begin.image_size = (uint32_t)total_len;
		copy_packet_text(begin.project_name, sizeof(begin.project_name),
		                 new_desc.project_name, sizeof(new_desc.project_name));
		copy_packet_text(begin.version, sizeof(begin.version),
		                 new_desc.version, sizeof(new_desc.version));

		mesh_ota_status_packet_t ack;
		remote_started = true;
		result = remote_ota_send_wait(target_mac, &begin, sizeof(begin),
		                              MESH_OTA_OP_BEGIN, begin.seq,
		                              &ack, err_msg, sizeof(err_msg));
		if (result != ESP_OK) {
			break;
		}

		uint32_t written = 0;
		result = remote_ota_send_chunks_from_buffer(target_mac, buf, first_have,
		                                            (uint32_t)total_len, &written,
		                                            err_msg, sizeof(err_msg));
		if (result != ESP_OK) {
			break;
		}

		while (written < total_len) {
			size_t to_read = total_len - written;
			if (to_read > NODE0_OTA_BUF_SIZE) to_read = NODE0_OTA_BUF_SIZE;

			int r = ota_recv_retry(req, buf, to_read);
			if (r <= 0) {
				snprintf(err_msg, sizeof(err_msg), "OTA upload interrupted");
				result = ESP_FAIL;
				break;
			}

			result = remote_ota_send_chunks_from_buffer(target_mac, buf, (size_t)r,
			                                            (uint32_t)total_len, &written,
			                                            err_msg, sizeof(err_msg));
			if (result != ESP_OK) {
				break;
			}
		}
		if (result != ESP_OK) {
			break;
		}

		mesh_ota_end_packet_t end;
		memset(&end, 0, sizeof(end));
		mesh_ota_fill_header(&end.h, MESH_OTA_TYPE_END);
		end.seq = remote_ota_next_seq();
		end.image_size = (uint32_t)total_len;

		result = remote_ota_send_wait(target_mac, &end, sizeof(end),
		                              MESH_OTA_OP_END, end.seq,
		                              &ack, err_msg, sizeof(err_msg));
		if (result != ESP_OK) {
			break;
		}

		snprintf(err_msg, sizeof(err_msg), "remote OTA OK, %s rebooting", target_tag);
		remote_ota_status_finish(NODE0_OTA_REBOOTING, err_msg);
		ESP_LOGI(TAG, "%s", err_msg);

		free(buf);
		xSemaphoreGive(s_ota_mutex);
		return http_json_ok(req, err_msg);
	} while (0);

	if (remote_started) {
		remote_ota_send_abort(target_mac, err_msg);
	}
	if (buf) {
		free(buf);
	}

	remote_ota_status_finish(NODE0_OTA_FAILED, err_msg);
	ESP_LOGW(TAG, "remote OTA failed: %s", err_msg);
	xSemaphoreGive(s_ota_mutex);
	return http_json_error(req, "400 Bad Request", err_msg);
}

static void ota_mark_running_app_valid_if_pending(void)
{
#ifdef CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
	const esp_partition_t *running = esp_ota_get_running_partition();
	esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;

	if (!running) return;
	if (esp_ota_get_state_partition(running, &state) != ESP_OK) return;
	if (state != ESP_OTA_IMG_PENDING_VERIFY) return;

	esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
	if (err == ESP_OK) {
		ESP_LOGI(TAG, "OTA rollback: running app marked valid");
	} else {
		ESP_LOGE(TAG, "OTA rollback: mark valid failed: %s", esp_err_to_name(err));
	}
#endif
}

static esp_err_t http_tasks_get(httpd_req_t *req)
{
	enum { TASKS_JSON_MAX = 4096 };
	char out[TASKS_JSON_MAX];
	out[0] = '\0';

	uint8_t mac[6];
	selection_snapshot(mac, NULL, 0);

	char q[64] = {0};
	bool fresh = false;
	if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
		char v[32] = {0};
		if (httpd_query_key_value(q, "mac", v, sizeof(v)) == ESP_OK) {
			uint8_t parsed[6];
			if (parse_mac_hex(v, parsed)) {
				mac_copy(mac, parsed);
			}
		}
		fresh = query_bool_value(q, "fresh");
	}

	if (fresh) {
		uint32_t request_id = request_fresh_tasks_for_mac(mac);
		wait_for_task_request(mac, request_id, 2000);
	}

	stack_monitor_snapshot_t snap;
	char tag[16] = {0};
	bool valid = taskmon_get_snapshot(mac, &snap, tag, sizeof(tag));
	if (tag[0] == '\0') {
		if (!lookup_node_tag(mac, tag, sizeof(tag))) {
			copy_tag(tag, sizeof(tag), "node");
		}
	}

	char mac_hex[13];
	mac_to_hex(mac, mac_hex);
	int slot_count = mac_eq(mac, s_local_mac) ? STACK_MONITOR_MAX_TASKS : taskmon_slot_count_for_mac(mac);
	uint32_t uptime_s = 0;
	bool uptime_valid = node_uptime_for_mac(mac, &uptime_s);
	ram_status_t ram = ram_status_for_mac(mac);
	persistent_status_t persistent = persistent_status_for_mac(mac);

	size_t pos = 0;

	if (!valid) {
		pos = append_fmt(out, TASKS_JSON_MAX, pos,
		                 "{\"valid\":false,\"mac\":\"%s\",\"tag\":",
		                 mac_hex);
		pos = append_json_string(out, TASKS_JSON_MAX, pos, tag);
		pos = append_fmt(out, TASKS_JSON_MAX, pos,
		                 ",\"updated_ms\":0,\"age_ms\":0,"
		                 "\"cpu_valid\":false,\"cpu_load_x10\":0,"
		                 "\"slot_count\":%d,\"uptime_valid\":%s,"
		                 "\"uptime_s\":%lu,",
		                 slot_count,
		                 uptime_valid ? "true" : "false",
		                 (unsigned long)uptime_s);
		pos = append_ram_json_fields(out, TASKS_JSON_MAX, pos, &ram);
		pos = append_fmt(out, TASKS_JSON_MAX, pos,
		                 ",\"flash_valid\":%s,"
		                 "\"flash_chip_bytes\":%lu,\"app_used_bytes\":%lu,"
		                 "\"app_partition_bytes\":%lu,"
		                 "\"nvs_valid\":%s,\"nvs_used_entries\":%lu,"
		                 "\"nvs_free_entries\":%lu,\"nvs_available_entries\":%lu,"
		                 "\"nvs_total_entries\":%lu,\"tasks\":[]}",
		                 persistent.flash_valid ? "true" : "false",
		                 (unsigned long)persistent.flash_chip_bytes,
		                 (unsigned long)persistent.app_used_bytes,
		                 (unsigned long)persistent.app_partition_bytes,
		                 persistent.nvs_valid ? "true" : "false",
		                 (unsigned long)persistent.nvs_used_entries,
		                 (unsigned long)persistent.nvs_free_entries,
		                 (unsigned long)persistent.nvs_available_entries,
		                 (unsigned long)persistent.nvs_total_entries);
	} else {
		uint32_t now = ms_now();
		uint32_t age_ms = (now >= snap.updated_ms) ? (now - snap.updated_ms) : 0;

		pos = append_fmt(out, TASKS_JSON_MAX, pos,
		                 "{\"valid\":true,\"mac\":\"%s\",\"tag\":",
		                 mac_hex);
		pos = append_json_string(out, TASKS_JSON_MAX, pos, tag);
		pos = append_fmt(out, TASKS_JSON_MAX, pos,
		                 ",\"updated_ms\":%lu,\"age_ms\":%lu,"
		                 "\"cpu_valid\":%s,\"cpu_load_x10\":%lu,"
		                 "\"slot_count\":%d,\"uptime_valid\":%s,"
		                 "\"uptime_s\":%lu,",
		                 (unsigned long)snap.updated_ms,
		                 (unsigned long)age_ms,
		                 snap.cpu_valid ? "true" : "false",
		                 (unsigned long)snap.cpu_load_x10,
		                 slot_count,
		                 uptime_valid ? "true" : "false",
		                 (unsigned long)uptime_s);
		pos = append_ram_json_fields(out, TASKS_JSON_MAX, pos, &ram);
		pos = append_fmt(out, TASKS_JSON_MAX, pos,
		                 ",\"flash_valid\":%s,"
		                 "\"flash_chip_bytes\":%lu,\"app_used_bytes\":%lu,"
		                 "\"app_partition_bytes\":%lu,"
		                 "\"nvs_valid\":%s,\"nvs_used_entries\":%lu,"
		                 "\"nvs_free_entries\":%lu,\"nvs_available_entries\":%lu,"
		                 "\"nvs_total_entries\":%lu,\"tasks\":[",
		                 persistent.flash_valid ? "true" : "false",
		                 (unsigned long)persistent.flash_chip_bytes,
		                 (unsigned long)persistent.app_used_bytes,
		                 (unsigned long)persistent.app_partition_bytes,
		                 persistent.nvs_valid ? "true" : "false",
		                 (unsigned long)persistent.nvs_used_entries,
		                 (unsigned long)persistent.nvs_free_entries,
		                 (unsigned long)persistent.nvs_available_entries,
		                 (unsigned long)persistent.nvs_total_entries);

		for (uint32_t i = 0; i < snap.count && i < STACK_MONITOR_MAX_TASKS; i++) {
			const stack_monitor_task_info_t *t = &snap.tasks[i];
			if (i > 0) pos = append_fmt(out, TASKS_JSON_MAX, pos, ",");
			pos = append_fmt(out, TASKS_JSON_MAX, pos, "{\"name\":");
			pos = append_json_string(out, TASKS_JSON_MAX, pos, t->name);
			pos = append_fmt(out, TASKS_JSON_MAX, pos,
			                 ",\"prio\":%lu,\"free_words\":%lu,\"cpu_x10\":%ld}",
			                 (unsigned long)t->priority,
			                 (unsigned long)t->free_words,
			                 (long)t->cpu_x10);
		}
		pos = append_fmt(out, TASKS_JSON_MAX, pos, "]}");
	}

	httpd_resp_set_type(req, "application/json");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	return httpd_resp_send(req, out, HTTPD_RESP_USE_STRLEN);
}

static bool query_bool_value(const char *q, const char *key)
{
	char v[12] = {0};
	if (!q || !key) return false;
	if (httpd_query_key_value(q, key, v, sizeof(v)) != ESP_OK) return false;
	return strcmp(v, "1") == 0 ||
	       strcmp(v, "true") == 0 ||
	       strcmp(v, "yes") == 0 ||
	       strcmp(v, "on") == 0;
}

static void stream_sid_from_req(httpd_req_t *req, char *sid, size_t sid_sz)
{
	char q[96] = {0};
	char raw[64] = {0};

	if (!sid || sid_sz == 0) {
		return;
	}

	copy_packet_text(sid, sid_sz, "nosid", 5);
	if (!req || httpd_req_get_url_query_str(req, q, sizeof(q)) != ESP_OK ||
	    httpd_query_key_value(q, "sid", raw, sizeof(raw)) != ESP_OK) {
		return;
	}

	size_t out = 0;
	for (size_t i = 0; raw[i] != '\0' && out + 1 < sid_sz; i++) {
		unsigned char c = (unsigned char)raw[i];
		if (isalnum(c) || c == '_' || c == '-') {
			sid[out++] = (char)c;
		}
	}
	sid[out] = '\0';
	if (out == 0) {
		copy_packet_text(sid, sid_sz, "nosid", 5);
	}
}

static bool stream_sid_matches(const char stored[STREAM_SID_MAX], const char *sid)
{
	if (!sid) {
		return true;
	}
	if (sid[0] == '\0') {
		return true;
	}
	if (strcmp(sid, "nosid") == 0) {
		return stored[0] == '\0' || strcmp(stored, "nosid") == 0;
	}
	return stored[0] != '\0' && strcmp(stored, sid) == 0;
}

static size_t append_health_json(char *out, size_t cap, size_t pos)
{
	bool log_active = false;
	bool ui_active = false;
	bool mesh_active = false;
	bool remote_stream = false;
	bool remote_ready = false;
	uint32_t now = ms_now();
	uint8_t selected_mac[6] = {0};
	uint32_t selected_ms = 0;
	uint32_t last_line_ms = 0;
	uint32_t last_rearm_ms = 0;
	uint32_t last_log_ctrl_ms = 0;
	esp_err_t last_log_ctrl_err = ESP_OK;

	if (s_log_stream_mutex &&
	    xSemaphoreTake(s_log_stream_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
		log_active = s_log_stream.req != NULL;
		xSemaphoreGive(s_log_stream_mutex);
	}
	if (s_ui_stream_mutex &&
	    xSemaphoreTake(s_ui_stream_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
		ui_active = s_ui_stream.req != NULL;
		xSemaphoreGive(s_ui_stream_mutex);
	}
	if (s_mesh_stream_mutex &&
	    xSemaphoreTake(s_mesh_stream_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
		mesh_active = s_mesh_stream.req != NULL;
		xSemaphoreGive(s_mesh_stream_mutex);
	}

	portENTER_CRITICAL(&s_selection_lock);
	{
		mac_copy(selected_mac, s_sel_mac);
		remote_stream = s_stream_active && !mac_eq(s_stream_mac, s_local_mac);
		remote_ready = s_stream_ready;
		selected_ms = s_stream_selected_ms;
		last_line_ms = s_stream_last_line_ms;
		last_rearm_ms = s_last_rearm_ms;
		last_log_ctrl_ms = s_last_log_ctrl_ms;
		last_log_ctrl_err = s_last_log_ctrl_err;
	}
	portEXIT_CRITICAL(&s_selection_lock);

	long selected_age = selected_ms ? (long)(uint32_t)(now - selected_ms) : -1;
	long line_age = last_line_ms ? (long)(uint32_t)(now - last_line_ms) : -1;
	long rearm_age = last_rearm_ms ? (long)(uint32_t)(now - last_rearm_ms) : -1;
	long ctrl_age = last_log_ctrl_ms ? (long)(uint32_t)(now - last_log_ctrl_ms) : -1;
	long app_age = remote_stream ? node_app_age_ms_at(selected_mac, now) : -1;
	size_t internal_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
	size_t internal_min = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
	size_t psram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
	size_t psram_min = heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);

	pos = append_fmt(out, cap, pos,
	                 "{\"log_sse\":%s,\"ui_sse\":%s,\"mesh_sse\":%s,"
	                 "\"remote_stream\":%s,\"remote_stream_ready\":%s,"
	                 "\"remote_selected_age_ms\":%ld,\"remote_line_age_ms\":%ld,"
	                 "\"log_ctrl_age_ms\":%ld,\"last_log_ctrl_age_ms\":%ld,"
	                 "\"last_log_ctrl_err\":%d,\"remote_app_age_ms\":%ld,"
	                 "\"heap_internal_free\":%lu,\"heap_internal_min\":%lu,"
	                 "\"heap_psram_free\":%lu,\"heap_psram_min\":%lu}",
	                 log_active ? "true" : "false",
	                 ui_active ? "true" : "false",
	                 mesh_active ? "true" : "false",
	                 remote_stream ? "true" : "false",
	                 remote_ready ? "true" : "false",
	                 selected_age,
	                 line_age,
	                 rearm_age,
	                 ctrl_age,
	                 (int)last_log_ctrl_err,
	                 app_age,
	                 (unsigned long)internal_free,
	                 (unsigned long)internal_min,
	                 (unsigned long)psram_free,
	                 (unsigned long)psram_min);
	return pos;
}

static size_t append_ui_status_json_for_mac(char *out, size_t cap, size_t pos,
                                            const uint8_t mac[6],
                                            bool include_tasks,
                                            bool include_ota)
{
	pos = append_fmt(out, cap, pos, "{\"nodes\":");
	pos = append_nodes_json(out, cap, pos);
	pos = append_fmt(out, cap, pos, ",\"tasks\":");
	if (include_tasks) {
		pos = append_tasks_json_for_mac(out, cap, pos, mac);
	} else {
		pos = append_fmt(out, cap, pos, "null");
	}

	pos = append_fmt(out, cap, pos, ",\"ota\":");
	if (include_ota) {
		if (mac_eq(mac, s_local_mac)) {
			pos = append_local_ota_json(out, cap, pos);
		} else {
			pos = append_remote_ota_json_for_mac(out, cap, pos, mac);
		}
	} else {
		pos = append_fmt(out, cap, pos, "null");
	}

	pos = append_fmt(out, cap, pos, ",\"health\":");
	pos = append_health_json(out, cap, pos);
	return append_fmt(out, cap, pos, "}");
}

static esp_err_t http_ui_status_get(httpd_req_t *req)
{
	uint8_t mac[6];
	selection_snapshot(mac, NULL, 0);

	char q[96] = {0};
	bool include_tasks = false;
	bool include_ota = false;
	bool fresh_tasks = false;

	if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
		char v[32] = {0};
		if (httpd_query_key_value(q, "mac", v, sizeof(v)) == ESP_OK) {
			uint8_t parsed[6];
			if (parse_mac_hex(v, parsed)) {
				mac_copy(mac, parsed);
			}
		}
		include_tasks = query_bool_value(q, "tasks");
		include_ota = query_bool_value(q, "ota") || include_tasks;
		fresh_tasks = query_bool_value(q, "fresh");
	}

	if (include_tasks && fresh_tasks) {
		uint32_t request_id = request_fresh_tasks_for_mac(mac);
		wait_for_task_request(mac, request_id, 2000);
	}

	char *out = (char *)malloc(UI_STATUS_JSON_MAX);
	if (!out) {
		return http_json_error(req, "500 Internal Server Error",
		                       "no memory for UI status");
	}

	size_t pos = 0;
	out[0] = '\0';
	pos = append_ui_status_json_for_mac(out, UI_STATUS_JSON_MAX, pos, mac,
	                                    include_tasks, include_ota);

	if (pos >= UI_STATUS_JSON_MAX - 2) {
		free(out);
		return http_json_error(req, "500 Internal Server Error",
		                       "UI status JSON truncated");
	}

	httpd_resp_set_type(req, "application/json");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	esp_err_t err = httpd_resp_send(req, out, HTTPD_RESP_USE_STRLEN);
	free(out);
	return err;
}

static size_t append_mesh_status_json(char *out, size_t cap, size_t pos, uint32_t seq)
{
	pos = append_fmt(out, cap, pos,
	                 "{\"type\":\"mesh_status\",\"seq\":%lu,\"now_ms\":%lu,\"mesh\":",
	                 (unsigned long)seq,
	                 (unsigned long)ms_now());
	pos = append_nodes_json(out, cap, pos);
	return append_fmt(out, cap, pos, "}");
}

static esp_err_t http_mesh_status_get(httpd_req_t *req)
{
	char *out = (char *)malloc(MESH_STATUS_JSON_MAX);
	if (!out) {
		return http_json_error(req, "500 Internal Server Error",
		                       "no memory for mesh status");
	}

	size_t pos = append_mesh_status_json(out, MESH_STATUS_JSON_MAX, 0, s_mesh_stream_seq);
	if (pos >= MESH_STATUS_JSON_MAX - 2) {
		free(out);
		return http_json_error(req, "500 Internal Server Error",
		                       "mesh status JSON truncated");
	}

	httpd_resp_set_type(req, "application/json");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	esp_err_t err = httpd_resp_send(req, out, HTTPD_RESP_USE_STRLEN);
	free(out);
	return err;
}

#if LOG_HTTP_ENABLE_MESH_STREAM
static esp_err_t mesh_stream_send_preamble(httpd_req_t *req)
{
	static const char preamble[] = ": node0 mesh stream\n\n";
	httpd_resp_set_type(req, "text/event-stream");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	httpd_resp_set_hdr(req, "Connection", "keep-alive");
	return httpd_resp_send_chunk(req, preamble, strlen(preamble));
}

static esp_err_t mesh_stream_send_snapshot(httpd_req_t *req, uint32_t seq)
{
	char *json = (char *)malloc(MESH_STATUS_JSON_MAX);
	if (!json) {
		return ESP_ERR_NO_MEM;
	}

	size_t pos = append_mesh_status_json(json, MESH_STATUS_JSON_MAX, 0, seq);
	if (pos >= MESH_STATUS_JSON_MAX - 2) {
		free(json);
		return ESP_ERR_NO_MEM;
	}

	char header[48];
	int n = snprintf(header, sizeof(header),
	                 "event: mesh\nid: %lu\ndata: ",
	                 (unsigned long)seq);
	if (n < 0 || (size_t)n >= sizeof(header)) {
		free(json);
		return ESP_FAIL;
	}

	esp_err_t err = httpd_resp_send_chunk(req, header, (size_t)n);
	if (err == ESP_OK) {
		err = httpd_resp_send_chunk(req, json, pos);
	}
	if (err == ESP_OK) {
		err = httpd_resp_send_chunk(req, "\n\n", 2);
	}
	free(json);
	return err;
}

static esp_err_t mesh_stream_send_heartbeat(httpd_req_t *req)
{
	static const char heartbeat[] = ": ping\n\n";
	return httpd_resp_send_chunk(req, heartbeat, sizeof(heartbeat) - 1);
}

static void mesh_stream_complete(httpd_req_t *req)
{
	if (!req) {
		return;
	}
	esp_err_t err = httpd_req_async_handler_complete(req);
	if (err != ESP_OK) {
		ESP_LOGD(TAG, "mesh stream async complete failed: %s", esp_err_to_name(err));
	}
}
#endif

static void mesh_stream_request_close(const char *sid)
{
	if (!s_mesh_stream_mutex || !s_mesh_stream_task) {
		return;
	}

	bool notify = false;
	if (xSemaphoreTake(s_mesh_stream_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
		if (s_mesh_stream.req && stream_sid_matches(s_mesh_stream.sid, sid)) {
			s_mesh_stream.client_close = true;
			notify = true;
		}
		xSemaphoreGive(s_mesh_stream_mutex);
	}

	if (notify) {
		xTaskNotifyGive(s_mesh_stream_task);
	}
}

#if LOG_HTTP_ENABLE_MESH_STREAM
static void mesh_stream_task(void *arg)
{
	(void)arg;

	for (;;) {
		httpd_req_t *req = NULL;
		bool headers_sent = false;
		bool client_close = false;
		uint32_t last_sent_seq = 0;
		uint32_t current_seq = s_mesh_stream_seq;

		if (!s_mesh_stream_mutex ||
		    xSemaphoreTake(s_mesh_stream_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
			ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(MESH_STREAM_HEARTBEAT_MS));
			continue;
		}
		req = s_mesh_stream.req;
		headers_sent = s_mesh_stream.headers_sent;
		client_close = s_mesh_stream.client_close;
		last_sent_seq = s_mesh_stream.seq;
		current_seq = s_mesh_stream_seq;
		xSemaphoreGive(s_mesh_stream_mutex);

		if (!req) {
			ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
			continue;
		}

		if (client_close) {
			if (xSemaphoreTake(s_mesh_stream_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
				if (s_mesh_stream.req == req) {
					memset(&s_mesh_stream, 0, sizeof(s_mesh_stream));
				}
				xSemaphoreGive(s_mesh_stream_mutex);
			}
			mesh_stream_complete(req);
			continue;
		}

		esp_err_t err = ESP_OK;
		if (!headers_sent) {
			err = mesh_stream_send_preamble(req);
			if (err == ESP_OK &&
			    xSemaphoreTake(s_mesh_stream_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
				if (s_mesh_stream.req == req) {
					s_mesh_stream.headers_sent = true;
				}
				xSemaphoreGive(s_mesh_stream_mutex);
			}
		}

		bool sent_snapshot = false;
		if (err == ESP_OK && (!headers_sent || last_sent_seq != current_seq)) {
			err = mesh_stream_send_snapshot(req, current_seq);
			sent_snapshot = (err == ESP_OK);
		} else if (err == ESP_OK) {
			err = mesh_stream_send_heartbeat(req);
		}

		if (err == ESP_OK) {
			if (xSemaphoreTake(s_mesh_stream_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
				if (s_mesh_stream.req == req && sent_snapshot) {
					s_mesh_stream.seq = current_seq;
				}
				xSemaphoreGive(s_mesh_stream_mutex);
			}
			ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(MESH_STREAM_HEARTBEAT_MS));
			continue;
		}

		if (xSemaphoreTake(s_mesh_stream_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
			if (s_mesh_stream.req == req) {
				memset(&s_mesh_stream, 0, sizeof(s_mesh_stream));
			}
			xSemaphoreGive(s_mesh_stream_mutex);
		}
		mesh_stream_complete(req);
	}
}
#endif

#if LOG_HTTP_ENABLE_MESH_STREAM
static esp_err_t http_mesh_stream_busy(httpd_req_t *req)
{
	httpd_resp_set_status(req, "503 Stream Busy");
	httpd_resp_set_type(req, "text/plain");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	return httpd_resp_send(req, "mesh stream busy\n", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t http_mesh_stream_get(httpd_req_t *req)
{
	if (!s_mesh_stream_mutex || !s_mesh_stream_task) {
		httpd_resp_set_status(req, "503 Stream Unavailable");
		httpd_resp_set_type(req, "text/plain");
		httpd_resp_set_hdr(req, "Cache-Control", "no-store");
		return httpd_resp_send(req, "mesh stream unavailable\n", HTTPD_RESP_USE_STRLEN);
	}

	char sid[STREAM_SID_MAX];
	stream_sid_from_req(req, sid, sizeof(sid));

	if (xSemaphoreTake(s_mesh_stream_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
		return http_mesh_stream_busy(req);
	}
	bool busy = (s_mesh_stream.req != NULL);
	xSemaphoreGive(s_mesh_stream_mutex);
	if (busy) {
		return http_mesh_stream_busy(req);
	}

	httpd_req_t *async_req = NULL;
	esp_err_t err = httpd_req_async_handler_begin(req, &async_req);
	if (err != ESP_OK) {
		return err;
	}

	if (xSemaphoreTake(s_mesh_stream_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
		mesh_stream_complete(async_req);
		return ESP_FAIL;
	}
	if (s_mesh_stream.req != NULL) {
		xSemaphoreGive(s_mesh_stream_mutex);
		mesh_stream_complete(async_req);
		return ESP_OK;
	}
	s_mesh_stream.req = async_req;
	s_mesh_stream.seq = 0;
	s_mesh_stream.headers_sent = false;
	s_mesh_stream.client_close = false;
	copy_packet_text(s_mesh_stream.sid, sizeof(s_mesh_stream.sid), sid, sizeof(sid));
	xSemaphoreGive(s_mesh_stream_mutex);

	mesh_stream_notify();
	return ESP_OK;
}
#endif

static esp_err_t ui_stream_send_preamble(httpd_req_t *req)
{
	static const char preamble[] = ": node0 ui stream\n\n";
	httpd_resp_set_type(req, "text/event-stream");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	httpd_resp_set_hdr(req, "Connection", "keep-alive");
	return httpd_resp_send_chunk(req, preamble, sizeof(preamble) - 1);
}

static esp_err_t ui_stream_send_heartbeat(httpd_req_t *req)
{
	static const char heartbeat[] = ": ping\n\n";
	return httpd_resp_send_chunk(req, heartbeat, sizeof(heartbeat) - 1);
}

static esp_err_t ui_stream_send_snapshot(httpd_req_t *req, uint32_t seq)
{
	uint8_t mac[6];
	selection_snapshot(mac, NULL, 0);

	char *json = (char *)malloc(UI_STATUS_JSON_MAX);
	if (!json) {
		return ESP_ERR_NO_MEM;
	}

	size_t pos = append_ui_status_json_for_mac(json, UI_STATUS_JSON_MAX, 0, mac,
	                                           true, true);
	if (pos >= UI_STATUS_JSON_MAX - 2) {
		free(json);
		return ESP_ERR_NO_MEM;
	}

	char header[64];
	int n = snprintf(header, sizeof(header), "event: ui\nid: %lu\ndata: ",
	                 (unsigned long)seq);
	if (n < 0) {
		free(json);
		return ESP_FAIL;
	}

	esp_err_t err = httpd_resp_send_chunk(req, header, (size_t)n);
	if (err == ESP_OK) {
		err = httpd_resp_send_chunk(req, json, pos);
	}
	if (err == ESP_OK) {
		static const char tail[] = "\n\n";
		err = httpd_resp_send_chunk(req, tail, sizeof(tail) - 1);
	}

	free(json);
	return err;
}

static void ui_stream_complete(httpd_req_t *req)
{
	if (!req) {
		return;
	}
	esp_err_t err = httpd_req_async_handler_complete(req);
	if (err != ESP_OK) {
		ESP_LOGD(TAG, "ui stream async complete failed: %s", esp_err_to_name(err));
	}
}

static void ui_stream_request_close(const char *sid)
{
	if (!s_ui_stream_mutex || !s_ui_stream_task) {
		return;
	}

	bool notify = false;
	if (xSemaphoreTake(s_ui_stream_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
		if (s_ui_stream.req && stream_sid_matches(s_ui_stream.sid, sid)) {
			s_ui_stream.client_close = true;
			notify = true;
		}
		xSemaphoreGive(s_ui_stream_mutex);
	}

	if (notify) {
		xTaskNotifyGive(s_ui_stream_task);
	}
}

static bool ui_stream_wait_idle(uint32_t timeout_ms)
{
	uint32_t start = ms_now();

	for (;;) {
		bool idle = true;
		if (xSemaphoreTake(s_ui_stream_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
			return false;
		}
		if (s_ui_stream.req) {
			s_ui_stream.client_close = true;
			idle = false;
		}
		xSemaphoreGive(s_ui_stream_mutex);

		if (idle) {
			return true;
		}
		ui_stream_notify();
		if ((uint32_t)(ms_now() - start) >= timeout_ms) {
			return false;
		}
		vTaskDelay(pdMS_TO_TICKS(40));
	}
}

static void ui_stream_task(void *arg)
{
	(void)arg;

	for (;;) {
		httpd_req_t *req = NULL;
		bool headers_sent = false;
		bool client_close = false;
		uint32_t last_sent_seq = 0;
		uint32_t current_seq = s_ui_stream_seq;

		if (!s_ui_stream_mutex ||
		    xSemaphoreTake(s_ui_stream_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
			ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(UI_STREAM_HEARTBEAT_MS));
			continue;
		}
		req = s_ui_stream.req;
		headers_sent = s_ui_stream.headers_sent;
		client_close = s_ui_stream.client_close;
		last_sent_seq = s_ui_stream.seq;
		current_seq = s_ui_stream_seq;
		xSemaphoreGive(s_ui_stream_mutex);

		if (!req) {
			ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
			continue;
		}

		if (client_close) {
			if (xSemaphoreTake(s_ui_stream_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
				if (s_ui_stream.req == req) {
					memset(&s_ui_stream, 0, sizeof(s_ui_stream));
				}
				xSemaphoreGive(s_ui_stream_mutex);
			}
			ui_stream_complete(req);
			continue;
		}

		esp_err_t err = ESP_OK;
		if (!headers_sent) {
			err = ui_stream_send_preamble(req);
			if (err == ESP_OK &&
			    xSemaphoreTake(s_ui_stream_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
				if (s_ui_stream.req == req) {
					s_ui_stream.headers_sent = true;
				}
				xSemaphoreGive(s_ui_stream_mutex);
			}
		}

		bool sent_snapshot = false;
		if (err == ESP_OK && (!headers_sent || last_sent_seq != current_seq)) {
			err = ui_stream_send_snapshot(req, current_seq);
			sent_snapshot = (err == ESP_OK);
		} else if (err == ESP_OK) {
			err = ui_stream_send_heartbeat(req);
		}

		if (err == ESP_OK) {
			if (xSemaphoreTake(s_ui_stream_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
				if (s_ui_stream.req == req && sent_snapshot) {
					s_ui_stream.seq = current_seq;
				}
				xSemaphoreGive(s_ui_stream_mutex);
			}
			ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(UI_STREAM_HEARTBEAT_MS));
			continue;
		}

		if (xSemaphoreTake(s_ui_stream_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
			if (s_ui_stream.req == req) {
				memset(&s_ui_stream, 0, sizeof(s_ui_stream));
			}
			xSemaphoreGive(s_ui_stream_mutex);
		}
		ui_stream_complete(req);
	}
}

static esp_err_t http_ui_stream_busy(httpd_req_t *req)
{
	httpd_resp_set_status(req, "503 Stream Busy");
	httpd_resp_set_type(req, "text/plain");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	return httpd_resp_send(req, "ui stream busy\n", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t http_ui_stream_get(httpd_req_t *req)
{
	if (!s_ui_stream_mutex || !s_ui_stream_task) {
		httpd_resp_set_status(req, "503 Stream Unavailable");
		httpd_resp_set_type(req, "text/plain");
		httpd_resp_set_hdr(req, "Cache-Control", "no-store");
		return httpd_resp_send(req, "ui stream unavailable\n", HTTPD_RESP_USE_STRLEN);
	}

	char sid[STREAM_SID_MAX];
	stream_sid_from_req(req, sid, sizeof(sid));

	if (!ui_stream_wait_idle(1400)) {
		return http_ui_stream_busy(req);
	}

	httpd_req_t *async_req = NULL;
	esp_err_t err = httpd_req_async_handler_begin(req, &async_req);
	if (err != ESP_OK) {
		return err;
	}

	if (xSemaphoreTake(s_ui_stream_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
		ui_stream_complete(async_req);
		return ESP_FAIL;
	}
	if (s_ui_stream.req != NULL) {
		xSemaphoreGive(s_ui_stream_mutex);
		httpd_resp_set_status(async_req, "503 Stream Busy");
		httpd_resp_set_type(async_req, "text/plain");
		httpd_resp_set_hdr(async_req, "Cache-Control", "no-store");
		(void)httpd_resp_send(async_req, "ui stream busy\n", HTTPD_RESP_USE_STRLEN);
		ui_stream_complete(async_req);
		return ESP_OK;
	}
	s_ui_stream.req = async_req;
	s_ui_stream.seq = 0;
	s_ui_stream.headers_sent = false;
	s_ui_stream.client_close = false;
	copy_packet_text(s_ui_stream.sid, sizeof(s_ui_stream.sid), sid, sizeof(sid));
	xSemaphoreGive(s_ui_stream_mutex);

	ui_stream_notify();
	return ESP_OK;
}

static esp_err_t http_stream_close_post(httpd_req_t *req)
{
	char q[96] = {0};
	char which[8] = "all";
	char sid[STREAM_SID_MAX];

	if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
		(void)httpd_query_key_value(q, "which", which, sizeof(which));
	}
	stream_sid_from_req(req, sid, sizeof(sid));

	bool close_all = strcmp(which, "all") == 0;
	if (close_all || strcmp(which, "log") == 0) {
		log_stream_request_close(sid);
	}
	if (close_all || strcmp(which, "mesh") == 0) {
		mesh_stream_request_close(sid);
	}
	if (close_all || strcmp(which, "ui") == 0) {
		ui_stream_request_close(sid);
	}

	httpd_resp_set_type(req, "text/plain");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	return httpd_resp_send(req, "OK\n", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t http_root_get(httpd_req_t *req)
{
	static const char html[] =
		"<!doctype html>\n"
		"<html><head><meta charset='utf-8'>\n"
		"<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
		"<title>keeMASH logs</title>\n"
		"<style>\n"
		"body{font-family:monospace;background:#111;color:#ddd;margin:0;padding:0;height:100vh;overflow:hidden}\n"
		"#top{height:42px;padding:8px 10px;box-sizing:border-box;background:#1b1b1b;display:flex;gap:10px;align-items:center}\n"
		"#main{display:flex;height:calc(100vh - 42px);min-height:0}\n"
		"#logPane{position:relative;flex:1;min-width:0;min-height:0}\n"
		"#log{height:100%;overflow:auto;padding:10px;white-space:pre;box-sizing:border-box}\n"
		".logMode{display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;border:1px solid #444;border-radius:999px;background:#141414;color:#aaa;box-shadow:inset 0 1px 0 rgba(255,255,255,.05),0 1px 4px rgba(0,0,0,.3)}\n"
		".streamDot{width:9px;height:9px;border-radius:50%;background:#777;box-shadow:0 0 8px #777}\n"
		".streamLive{border-color:#15633a;color:#7dffb2}.streamLive .streamDot{background:#00ff7f;box-shadow:0 0 12px #00ff7f}\n"
		".streamPoll{border-color:#76611a;color:#ffd666}.streamPoll .streamDot{background:#ffcc00;box-shadow:0 0 10px #ffcc00}\n"
		".streamRetry{border-color:#1f5d80;color:#7fd7ff}.streamRetry .streamDot{background:#39bfff;box-shadow:0 0 12px #39bfff}\n"
		".streamErr{border-color:#743030;color:#ff8a8a}.streamErr .streamDot{background:#ff4d4d;box-shadow:0 0 10px #ff4d4d}\n"
		".streamOff{border-color:#333;color:#888}.streamOff .streamDot{background:#666;box-shadow:none}\n"
		"#tasks{display:none;width:370px;overflow:auto;border-left:1px solid #333;background:#151515;padding:10px;box-sizing:border-box}\n"
		"body.showTasks #tasks{display:block}\n"
		"#mesh{display:none;width:370px;overflow:auto;border-left:1px solid #333;background:#12171a;padding:10px;box-sizing:border-box}\n"
		"body.showMesh #mesh{display:block}\n"
		".ln{white-space:pre;margin:0;padding:0}\n"
		"button,select{font-family:monospace;font-size:14px;background:#24282d;color:#e8edf2;border:1px solid #3a424a;border-radius:7px;min-height:28px;box-sizing:border-box}\n"
		"button{padding:4px 10px;cursor:pointer;box-shadow:inset 0 1px 0 rgba(255,255,255,.06),0 1px 3px rgba(0,0,0,.25);transition:background .12s,border-color .12s,color .12s,transform .08s}\n"
		"button:hover:not(:disabled){background:#2f3740;border-color:#52606c;color:#fff}\n"
		"button:active:not(:disabled){transform:translateY(1px)}\n"
		"button:disabled{opacity:.45;cursor:not-allowed;box-shadow:none}\n"
		"select{padding:3px 8px;min-width:130px;background:#191d21;color:#dfe6ee}\n"
		".taskTop{display:flex;justify-content:space-between;align-items:flex-start;gap:8px;margin-bottom:8px;color:#eee}\n"
		".taskLeft{display:grid;grid-template-columns:minmax(0,1fr) auto;grid-template-areas:'title uptime' 'node node';column-gap:8px;row-gap:2px;align-items:baseline;min-width:0;flex:1}\n"
		".taskLeft b{grid-area:title;min-width:0}\n"
		".taskNode{grid-area:node;color:#00ff7f;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;display:block}\n"
		".taskUptime{grid-area:uptime;color:#aaa;white-space:nowrap}\n"
		".taskMeta{text-align:right;color:#aaa;font-size:11px;line-height:1.25;white-space:nowrap;flex:0 0 auto}\n"
		".taskMac{color:#ddd}\n"
		".otaBox{margin-top:7px;text-align:right}\n"
		".otaAction{display:flex;justify-content:flex-end;align-items:center;gap:6px}\n"
		".otaBtn{font-size:12px;min-height:25px;padding:3px 9px;text-transform:uppercase;color:#caffdf;background:#103724;border-color:#1d6e44}\n"
		".otaBtn:hover:not(:disabled){background:#145236;border-color:#25a765;color:#fff}\n"
		".rebootBtn{font-size:12px;min-height:25px;padding:3px 9px;text-transform:uppercase;color:#ffd8c7;background:#3a1d14;border-color:#7b3a25}\n"
		".rebootBtn:hover:not(:disabled){background:#5a2618;border-color:#d4663c;color:#fff}\n"
		".otaSlot{display:inline-flex;align-items:center;min-height:23px;padding:2px 7px;border:1px solid #3d4750;border-radius:999px;background:#191d21;color:#b9c4ce;font-size:11px}\n"
		".otaSlotA{border-color:#18784d;color:#88ffb6;background:#10271d}\n"
		".otaSlotB{border-color:#2b6594;color:#8bd0ff;background:#101f2b}\n"
		".otaSlotUnknown{border-color:#444;color:#888;background:#171717}\n"
		"#otaStatus{margin-top:4px;color:#aaa;max-width:180px;white-space:normal}\n"
		"#otaProg{width:140px;height:8px;margin-top:4px;display:none}\n"
		".cpu{color:#9ad;margin-bottom:8px}\n"
		".ram{color:#adb;margin:-4px 0 8px}\n"
		".flash{color:#dba;margin:-4px 0 8px}\n"
		".meshTop{display:flex;justify-content:space-between;align-items:center;margin-bottom:9px;color:#eef}\n"
		".meshTree{font-size:12px;line-height:1.35}\n"
		".meshItem{border-left:1px solid #33414a;margin-left:8px;padding:4px 0 4px 10px}\n"
		".meshName{color:#8bd0ff;font-weight:bold}.meshLocal .meshName{color:#00ff7f}\n"
		".meshMeta{color:#aab;font-size:11px}.meshBad{color:#ff8a8a}.meshWarn{color:#ffd666}\n"
		"table{width:100%;border-collapse:collapse;font-size:12px}\n"
		"th,td{border-bottom:1px solid #2c2c2c;padding:3px 4px;text-align:right;white-space:nowrap}\n"
		"th:first-child,td:first-child{text-align:left;max-width:150px;overflow:hidden;text-overflow:ellipsis}\n"
		".warn{color:#ffcc00}.bad{color:#ff4d4d}\n"
		".lvI{color:#00ff7f}\n"
		".lvW{color:#ffcc00}\n"
		".lvE{color:#ff4d4d}\n"
		".lvD{color:#66a3ff}\n"
		".lvV{color:#aaaaaa}\n"
		".ts{color:#66a3ff}\n"
		"@media(max-width:760px){#tasks,#mesh{position:fixed;right:0;top:42px;bottom:0;width:90vw;z-index:5;box-shadow:-8px 0 20px #000}}\n"
		"</style></head>\n"
		"<body>\n"
		"<div id='top'>\n"
		"<button onclick='toggleFollow()'>follow: <span id=\"f\">ON</span></button>\n"
		"<button onclick='clearServer()'>clear</button>\n"
		"<button onclick='toggleTasks()'>tasks: <span id=\"tm\">OFF</span></button>\n"
		"<button onclick='toggleMesh()'>mesh: <span id=\"mm\">OFF</span></button>\n"
		"<select id='nodeSel'></select>\n"
		"<span id='logMode' class='logMode streamOff' title='log transport'><span class='streamDot'></span></span>\n"
		"<span id='st'>...</span>\n"
		"</div>\n"
		"<div id='main'>\n"
		"<div id='logPane'><div id='log'></div></div>\n"
		"<div id='mesh'><div class='meshTop'><b>Mesh tree</b><span id='meshState'>...</span></div><div id='meshTree' class='meshTree'>waiting for mesh</div></div>\n"
		"<div id='tasks'><div class='taskTop'><div class='taskLeft'><b>Task manager</b><span id='taskNode' class='taskNode'></span><span id='taskUp' class='taskUptime'>up ?</span></div><div class='taskMeta'><div id='taskMac' class='taskMac'>...</div><div id='taskAge'>...</div><div class='otaBox'><div class='otaAction'><button id='otaBtn' class='otaBtn' onclick='startOta()' disabled>update</button><button id='rebootBtn' class='rebootBtn' onclick='startReboot()' disabled>reboot</button><span id='otaSlot' class='otaSlot otaSlotUnknown'>A/B ?</span></div><div id='otaStatus'></div><progress id='otaProg' max='100' value='0'></progress></div></div></div><div id='taskCpu' class='cpu'>CPU ? / tasks ?/?</div><div id='taskRam' class='ram'>RAM int ? / PSRAM ?</div><div id='taskFlash' class='flash'>FLASH ? / app ? / NVS ?</div><div id='taskTable'></div></div>\n"
		"</div>\n"
		"<script>\n"
		"const pageSid=(Date.now().toString(36)+'-'+Math.random().toString(36).slice(2,10)).replace(/[^a-zA-Z0-9_-]/g,'');\n"
		"let follow=true;\n"
		"let tasksVisible=false;\n"
		"let meshVisible=false;\n"
		"let cursor=0;\n"
		"let lastNodes='';\n"
		"let lastGoodNodes=[];\n"
		"let lastTasks='';\n"
		"let selectedMac='';\n"
		"let localMac='';\n"
		"let otaEnabled=false;\n"
		"let otaSupported=false;\n"
		"let otaBusy=false;\n"
		"let rebootBusy=false;\n"
		"let otaStatusText='OTA ...';\n"
		"let otaSlotText='A/B ?';\n"
		"let otaSlotClass='otaSlotUnknown';\n"
		"let logBusy=false;\n"
		"let nodesBusy=false;\n"
		"let tasksBusyReq=false;\n"
		"let otaStatusBusy=false;\n"
		"let controlPollBusy=false;\n"
		"let activeFetch=false;\n"
		"let logStream=null;\n"
		"let meshStream=null;\n"
		"let uiStream=null;\n"
		"let logStreamReady=false;\n"
		"let logStreamErrors=0;\n"
		"let meshStreamErrors=0;\n"
		"let uiStreamErrors=0;\n"
		"let pollFallbackUntil=0;\n"
		"let reselectBusy=false;\n"
		"let selectionBusy=false;\n"
		"function toggleFollow(){follow=!follow;document.getElementById('f').textContent=follow?'ON':'OFF'}\n"
		"function toggleTasks(){tasksVisible=!tasksVisible;document.body.classList.toggle('showTasks',tasksVisible);document.getElementById('tm').textContent=tasksVisible?'ON':'OFF';if(tasksVisible){clearTasksPanel();loadTasks(true);loadOtaStatus();loadUiStatus(true);startUiStream()}}\n"
		"function toggleMesh(){meshVisible=!meshVisible;document.body.classList.toggle('showMesh',meshVisible);document.getElementById('mm').textContent=meshVisible?'ON':'OFF';if(meshVisible){loadMeshStatus('poll');startUiStream()}else document.getElementById('meshState').textContent='off'}\n"
		"function esc(s){s=String(s||'');return s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')}\n"
		"function pct(x){return x<0?'?':(x/10).toFixed(1)+'%'}\n"
		"function stackCls(w){if(w<128)return 'bad';if(w<256)return 'warn';return ''}\n"
		"function taskSlotsText(count,slots){return count+'/'+(slots>=0?slots:'?')}\n"
		"function pad2(n){return String(n).padStart(2,'0')}\n"
		"function fmtUptime(valid,sec){if(!valid)return 'up ?';sec=Math.max(0,Math.floor(Number(sec)||0));const d=Math.floor(sec/86400);sec%=86400;const h=Math.floor(sec/3600);sec%=3600;const m=Math.floor(sec/60);const s=sec%60;return 'up '+(d>0?d+'d ':'')+pad2(h)+':'+pad2(m)+':'+pad2(s)}\n"
		"function fmtKb(bytes){return Math.round((Number(bytes)||0)/1024)+' KB'}\n"
		"function fmtMb(bytes){return Math.round((Number(bytes)||0)/1048576)+' MB'}\n"
		"function fmtUsedKb(free,total){free=Number(free)||0;total=Number(total)||0;if(total<=0)return '?';return fmtKb(Math.max(0,total-free))+'/'+fmtKb(total)+' used'}\n"
		"function fmtRamPool(label,valid,free,total){return valid&&Number(total)>0?label+' '+fmtUsedKb(free,total):label+' ?'}\n"
		"function fmtRam(j){if(!j.ram_valid)return 'RAM int ? / PSRAM ?';const iv=!!j.ram_internal_valid;const pv=!!j.ram_psram_valid;let s=iv?fmtRamPool('RAM int',true,j.ram_internal_free_bytes,j.ram_internal_total_bytes):fmtRamPool('RAM',true,j.ram_free_bytes,j.ram_total_bytes);return s+' / '+(pv?fmtRamPool('PSRAM',true,j.ram_psram_free_bytes,j.ram_psram_total_bytes):(iv?'PSRAM off':'PSRAM ?'))}\n"
		"function fmtFlash(j){const flash=j.flash_valid?'FLASH '+fmtMb(j.flash_chip_bytes)+' / app '+fmtKb(j.app_used_bytes)+'/'+fmtKb(j.app_partition_bytes):'FLASH ? / app ?';const nvs=j.nvs_valid?'NVS '+j.nvs_used_entries+'/'+j.nvs_total_entries+' used':'NVS ?';return flash+' / '+nvs}\n"
		"async function fetchTimeout(url,ms){\n"
		"  ms=Math.max(ms||0,12000);\n"
		"  const opt={cache:'no-store'};let timer=null;\n"
		"  if(window.AbortController){const c=new AbortController();opt.signal=c.signal;timer=setTimeout(()=>c.abort(),ms);}\n"
		"  try{return await fetch(url,opt);}finally{if(timer)clearTimeout(timer);}\n"
		"}\n"
		"async function controlFetch(url,ms){const start=Date.now();while(activeFetch){if(Date.now()-start>Math.max(ms||0,3000))throw new Error('fetch busy');await new Promise(r=>setTimeout(r,50));}activeFetch=true;try{return await fetchTimeout(url,ms)}finally{activeFetch=false}}\n"
		"function setLogMode(cls,text){const el=document.getElementById('logMode');if(el){el.className='logMode '+cls;el.title='log transport: '+(text||'off')}}\n"
		"function appendLogText(text,reset){const el=document.getElementById('log');if(reset)el.innerHTML='';if(text&&text.length>0)el.insertAdjacentHTML('beforeend',renderChunk(text));if(follow)el.scrollTop=el.scrollHeight}\n"
		"function notifyStreamClose(which){try{const url='/stream/close?which='+(which||'all')+'&sid='+encodeURIComponent(pageSid);if(navigator.sendBeacon){navigator.sendBeacon(url,'');return;}fetch(url,{method:'POST',cache:'no-store',keepalive:true}).catch(()=>{})}catch(e){}}\n"
		"function stopLogStream(notify){if(notify)notifyStreamClose('log');if(logStream){logStream.close();logStream=null;}logStreamReady=false;}\n"
		"function stopMeshStream(notify){if(notify)notifyStreamClose('mesh');if(meshStream){meshStream.close();meshStream=null;}document.getElementById('meshState').textContent='off'}\n"
		"function stopUiStream(notify){if(notify)notifyStreamClose('ui');if(uiStream){uiStream.close();uiStream=null;}}\n"
		"function otaSlotName(label){if(label==='ota_0')return 'A';if(label==='ota_1')return 'B';return '?'}\n"
		"function otaSlotClassFor(label){if(label==='ota_0')return 'otaSlotA';if(label==='ota_1')return 'otaSlotB';return 'otaSlotUnknown'}\n"
		"function setOtaSlot(text,cls){otaSlotText=text||'A/B ?';otaSlotClass=cls||'otaSlotUnknown';const el=document.getElementById('otaSlot');if(el){el.textContent=otaSlotText;el.className='otaSlot '+otaSlotClass}}\n"
		"function updateOtaSlotFromStatus(j){const a=otaSlotName(j.running_label);const n=otaSlotName(j.update_label);if(a==='?'&&n==='?')setOtaSlot('A/B ?','otaSlotUnknown');else setOtaSlot(a+' active / '+n+' next',otaSlotClassFor(j.running_label))}\n"
		"function rememberedNode(){try{return localStorage.getItem('logSelectedMac')||''}catch(e){return ''}}\n"
		"function rememberedNodeTag(){try{return localStorage.getItem('logSelectedTag')||'node'}catch(e){return 'node'}}\n"
		"function rememberNode(mac,tag){try{if(mac)localStorage.setItem('logSelectedMac',mac);if(tag)localStorage.setItem('logSelectedTag',tag)}catch(e){}}\n"
		"function nodeInList(nodes,mac){return !!(mac&&(nodes||[]).some(n=>n.mac===mac))}\n"
		"async function reselectNode(mac){if(!mac||reselectBusy)return;reselectBusy=true;try{await controlFetch('/select?mac='+encodeURIComponent(mac),6000);lastNodes='';await loadUiStatus();}catch(e){}finally{reselectBusy=false}}\n"
		"function applyNodes(j,raw){\n"
		"  if(!j)return;\n"
		"  const s=document.getElementById('nodeSel');\n"
		"  const txt=raw||JSON.stringify(j);if(txt===lastNodes)return;lastNodes=txt;\n"
		"  let nodes=j.nodes||[];if((!nodes||nodes.length===0)&&lastGoodNodes.length>0){nodes=lastGoodNodes}else if(nodes&&nodes.length>0){lastGoodNodes=nodes.slice(0)}const serverCur=j.selected_mac;localMac=j.local_mac||localMac;const prev=s.value;let cur=(selectionBusy?(selectedMac||prev):serverCur)||prev||selectedMac;const remembered=rememberedNode();const rememberedTag=rememberedNodeTag();\n"
		"  const rememberedMissing=remembered&&remembered!==serverCur&&!nodeInList(nodes,remembered);\n"
		"  if(!selectionBusy&&remembered&&remembered!==serverCur&&nodeInList(nodes,remembered)&&!reselectBusy){cur=remembered;setTimeout(()=>reselectNode(remembered),0)}\n"
		"  else if(!selectionBusy&&rememberedMissing){cur=remembered}\n"
		"  selectedMac=cur||selectedMac;s.innerHTML='';\n"
		"  for(const n of nodes){const o=document.createElement('option');o.value=n.mac;o.dataset.tag=n.tag||'node';const p=n.has_gap?'gap':(n.offline?'offline':(n.app_stale?'app stale':(n.stale?'stale':(n.route_table_seen&&!n.telemetry_fresh?'route':(n.proto==='tunnel'?'tunnel':(n.proto==='v2'?'v2':(n.proto==='v1'?'v1':'')))))));o.textContent=(n.tag||'node')+(p?' · '+p:'');s.appendChild(o)}\n"
		"  if(rememberedMissing){const o=document.createElement('option');o.value=remembered;o.dataset.tag=rememberedTag;o.textContent=rememberedTag+' · waiting';s.appendChild(o)}\n"
		"  s.value=cur||prev;selectedMac=s.value||selectedMac;updateOtaUi();\n"
		"}\n"
		"function meshNodeMeta(n){const parts=[];parts.push(n.proto||'v1');if(n.layer)parts.push('L'+n.layer);if(typeof n.parent_rssi==='number'&&n.parent_rssi>-120)parts.push(n.parent_rssi+' dBm');if(n.has_gap)parts.push('gap');parts.push('g/l/r '+(n.gap_count||0)+'/'+(n.lost_count||0)+'/'+(n.replay_count||0));if(n.app_stale)parts.push('app stale');else if(n.route_table_seen&&!n.telemetry_fresh)parts.push('route');if(n.stale&&!n.app_stale)parts.push('stale');if(n.offline)parts.push('offline');return parts.join(' · ')}\n"
		"function renderMeshNode(n,byParent){let cls='meshItem '+(n.mac===localMac?'meshLocal ':'')+(n.offline?'meshBad ':(n.app_stale||n.stale)?'meshWarn ':'');let html='<div class=\"'+cls+'\"><div><span class=\"meshName\">'+esc(n.tag||'node')+'</span> <span class=\"meshMeta\">'+esc(n.mac||'')+'</span></div><div class=\"meshMeta\">'+esc(meshNodeMeta(n))+'</div>';const kids=byParent[n.mac]||[];for(const k of kids){html+=renderMeshNode(k,byParent)}return html+'</div>'}\n"
		"function meshStatusLabel(nodes,mode){const rem=(nodes||[]).filter(n=>n.mac!==localMac);if(rem.some(n=>n.offline))return 'offline';if(rem.some(n=>n.app_stale))return 'app stale';if(rem.some(n=>n.stale))return 'stale';return mode||'live'}\n"
		"function applyMeshStatus(j,mode){const tree=document.getElementById('meshTree');const st=document.getElementById('meshState');const m=j&&j.mesh?j.mesh:j;if(!m||!m.nodes){tree.textContent='waiting for mesh';st.textContent='waiting for telemetry';return;}applyNodes(m,JSON.stringify(m));const nodes=m.nodes||[];const byParent={};let root=nodes.find(n=>n.mac===m.local_mac)||nodes[0];for(const n of nodes){const p=(n.parent_mac&&n.parent_mac!==n.mac)?n.parent_mac:'';if(p){(byParent[p]=byParent[p]||[]).push(n)}}if(root){for(const n of nodes){if(n!==root&&(!n.parent_mac||!nodes.some(x=>x.mac===n.parent_mac))){(byParent[root.mac]=byParent[root.mac]||[]).push(n)}}}tree.innerHTML=root?renderMeshNode(root,byParent):'waiting for route';st.textContent=meshStatusLabel(nodes,mode)}\n"
		"async function loadMeshStatus(mode){const st=document.getElementById('meshState');try{st.textContent=mode||'poll';const r=await controlFetch('/mesh/status',6000);applyMeshStatus(await r.json(),mode||'poll')}catch(e){st.textContent='retry'}}\n"
		"function applyUiStatus(j,mode){if(!j)return;applyNodes(j.nodes,JSON.stringify(j.nodes));if(tasksVisible&&j.tasks)applyTasks(j.tasks,selectedMac||'',JSON.stringify(j.tasks));if(tasksVisible&&j.ota)applyOta(j.ota);if(meshVisible&&j.nodes)applyMeshStatus(j.nodes,mode||'live')}\n"
		"function startUiStream(){if(uiStream||otaBusy)return;if(!window.EventSource){loadUiStatus();return;}try{uiStream=new EventSource('/ui/stream?sid='+encodeURIComponent(pageSid))}catch(e){uiStream=null;loadUiStatus();return;}uiStream.addEventListener('ui',e=>{try{uiStreamErrors=0;applyUiStatus(JSON.parse(e.data||'{}'),'live')}catch(x){}});uiStream.onopen=()=>{uiStreamErrors=0;if(meshVisible)document.getElementById('meshState').textContent='live'};uiStream.onerror=()=>{uiStreamErrors++;stopUiStream(false);if(meshVisible)document.getElementById('meshState').textContent='retry';const d=Math.min(30000,2000*uiStreamErrors);setTimeout(()=>{loadUiStatus();if(!otaBusy)startUiStream()},d)}}\n"
		"function startMeshStream(){startUiStream();if(meshVisible)loadMeshStatus('poll')}\n"
		"function applyOta(j){\n"
		"  if(!j)return;\n"
		"  const local=isLocalSelected();otaEnabled=!!j.enabled;otaSupported=local||!!j.supported;\n"
		"  if(local){updateOtaSlotFromStatus(j);otaStatusText=otaEnabled?'ready':'PIN not set';}\n"
		"  else{const hasSlot=!!(j.running_label||j.update_label||j.running_size||j.update_size);if(otaSupported||hasSlot)updateOtaSlotFromStatus(j);else setOtaSlot('A/B ?','otaSlotUnknown');if(!otaSupported)otaStatusText=j.last_error||'';else if(j.busy&&j.total_bytes>0)otaStatusText='remote '+Math.round((j.written_bytes||0)*100/j.total_bytes)+'%';else if(j.state==='failed')otaStatusText=j.last_error||'remote failed';else if(j.state==='success'||j.state==='rebooting')otaStatusText=j.last_result||j.state;else otaStatusText='ready';}\n"
		"  updateOtaUi();\n"
		"}\n"
		"function applyTasks(j,mac,raw){\n"
		"  if(!j)return;\n"
		"  const txt=raw||JSON.stringify(j);if(txt===lastTasks)return;lastTasks=txt;\n"
		"  const box=document.getElementById('taskTable');const up=fmtUptime(j.uptime_valid,j.uptime_s);\n"
		"  setTaskHeader(j.tag||'node',j.mac||mac,'no data',up);document.getElementById('taskRam').textContent=fmtRam(j);document.getElementById('taskFlash').textContent=fmtFlash(j);\n"
		"  if(!j.valid){box.textContent='waiting for STACKMON';document.getElementById('taskCpu').textContent='CPU ? / tasks ?/?';return;}\n"
		"  const tasks=j.tasks||[];const slots=typeof j.slot_count==='number'?j.slot_count:-1;tasks.sort((a,b)=>(b.cpu_x10-a.cpu_x10)||(a.free_words-b.free_words));\n"
		"  let rows='';for(const t of tasks){const cls=stackCls(t.free_words);rows+='<tr'+(cls?' class='+cls:'')+'><td>'+esc(t.name)+'</td><td>'+t.prio+'</td><td>'+pct(t.cpu_x10)+'</td><td>'+t.free_words+'</td></tr>';}\n"
		"  document.getElementById('taskCpu').textContent='CPU '+(j.cpu_valid?pct(j.cpu_load_x10):'?')+' / tasks '+taskSlotsText(tasks.length,slots);setTaskHeader(j.tag||'node',j.mac||mac,Math.floor((j.age_ms||0)/1000)+'s ago',up);\n"
		"  box.innerHTML='<table><thead><tr><th>task</th><th>prio</th><th>cpu</th><th>free words</th></tr></thead><tbody>'+rows+'</tbody></table>';\n"
		"}\n"
		"function startLogStream(){\n"
		"  if(otaBusy||logStream)return;\n"
		"  if(!window.EventSource){setLogMode('streamPoll','poll');return;}\n"
		"  setLogMode('streamRetry','stream');\n"
		"  try{logStream=new EventSource('/log/stream?from='+cursor+'&sid='+encodeURIComponent(pageSid));}catch(e){setLogMode('streamPoll','poll');pollFallbackUntil=Date.now()+15000;return;}\n"
		"  logStream.onopen=()=>{logStreamReady=true;logStreamErrors=0;setLogMode('streamLive','stream');document.getElementById('st').textContent='LIVE'};\n"
		"  logStream.onmessage=(e)=>{if(e.lastEventId)cursor=parseInt(e.lastEventId)||cursor;appendLogText((e.data||'')+'\\n',false);document.getElementById('st').textContent='LIVE'};\n"
		"  logStream.addEventListener('reset',(e)=>{if(e.lastEventId)cursor=parseInt(e.lastEventId)||0;appendLogText('',true);setLogMode('streamLive','stream')});\n"
		"  logStream.onerror=()=>{logStreamReady=false;logStreamErrors++;setLogMode(logStreamErrors>=2?'streamPoll':'streamRetry',logStreamErrors>=2?'poll':'retry');document.getElementById('st').textContent='RETRY';stopLogStream(false);pollFallbackUntil=Date.now()+8000;tick();const d=Math.min(12000,1200*logStreamErrors);setTimeout(()=>{if(!otaBusy&&Date.now()>pollFallbackUntil-1000){pollFallbackUntil=0;startLogStream()}},d)};\n"
		"}\n"
		"function setTaskHeader(tag,mac,age,up){document.getElementById('taskNode').textContent=tag||'';document.getElementById('taskUp').textContent=up||'up ?';document.getElementById('taskMac').textContent=mac||'...';document.getElementById('taskAge').textContent=age||'...'}\n"
		"function clearTasksPanel(){lastTasks='';setTaskHeader('',selectedMac,'...','up ?');document.getElementById('taskCpu').textContent='CPU ? / tasks ?/?';document.getElementById('taskRam').textContent='RAM int ? / PSRAM ?';document.getElementById('taskFlash').textContent='FLASH ? / app ? / NVS ?';document.getElementById('taskTable').textContent='waiting for STACKMON'}\n"
		"function isLocalSelected(){return !!(localMac&&selectedMac&&localMac===selectedMac)}\n"
		"function selectedNodeTag(){const s=document.getElementById('nodeSel');const o=s&&s.selectedOptions&&s.selectedOptions[0];return o?(o.dataset.tag||o.textContent||'node'):'node'}\n"
		"function selectedOtaTarget(){return isLocalSelected()?'node0':(selectedNodeTag()||'node')}\n"
		"function otaFileKey(){return 'ota-bin-'+(isLocalSelected()?'node0':(selectedMac||selectedNodeTag()||'remote'))}\n"
		"function updateOtaUi(){\n"
		"  const b=document.getElementById('otaBtn');const rb=document.getElementById('rebootBtn');const s=document.getElementById('otaStatus');const local=isLocalSelected();\n"
		"  if(!b||!rb||!s)return;\n"
		"  if(!local&&!otaSupported){b.disabled=true;rb.disabled=true;s.textContent=otaStatusText||'';setOtaSlot(otaSlotText,otaSlotClass);return;}\n"
		"  if(!otaEnabled){b.disabled=true;rb.disabled=true;s.textContent='PIN not set';setOtaSlot(otaSlotText,otaSlotClass);return;}\n"
		"  const rebootSupported=local||otaSupported;\n"
		"  b.disabled=otaBusy||rebootBusy||!otaSupported;rb.disabled=otaBusy||rebootBusy||!rebootSupported;s.textContent=otaSupported?(otaStatusText||'ready'):'';setOtaSlot(otaSlotText,otaSlotClass);\n"
		"}\n"
		"function otaSetStatus(text,showProg,pctVal){\n"
		"  otaStatusText=text||'OTA ready';\n"
		"  const p=document.getElementById('otaProg');\n"
		"  if(p){p.style.display=showProg?'inline-block':'none';if(typeof pctVal==='number')p.value=Math.max(0,Math.min(100,pctVal));}\n"
		"  updateOtaUi();\n"
		"}\n"
		"function idbReq(req){return new Promise((resolve,reject)=>{req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error)})}\n"
		"function otaDb(){return new Promise((resolve,reject)=>{const r=indexedDB.open('node0OtaDb',1);r.onupgradeneeded=()=>r.result.createObjectStore('files');r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error)})}\n"
		"async function otaGetHandle(){try{const db=await otaDb();return await idbReq(db.transaction('files','readonly').objectStore('files').get(otaFileKey()))}catch(e){return null}}\n"
		"async function otaSaveHandle(h){try{const db=await otaDb();await idbReq(db.transaction('files','readwrite').objectStore('files').put(h,otaFileKey()))}catch(e){}}\n"
		"function chooseFileInput(){return new Promise(resolve=>{const i=document.createElement('input');i.type='file';i.accept='.bin,application/octet-stream';i.onchange=()=>{const f=i.files&&i.files[0];if(f)localStorage.setItem('otaLastFile-'+otaFileKey(),JSON.stringify({name:f.name,size:f.size,mtime:f.lastModified}));resolve(f||null)};i.click()})}\n"
		"async function chooseOtaFile(){\n"
		"  if(window.showOpenFilePicker&&window.indexedDB){\n"
		"    const old=await otaGetHandle();\n"
		"    if(old){try{let perm=await old.queryPermission({mode:'read'});if(perm!=='granted')perm=await old.requestPermission({mode:'read'});if(perm==='granted'){const f=await old.getFile();if(confirm('Use saved firmware file for '+selectedOtaTarget()+': '+f.name+'?\\nCancel to choose another file.'))return f;}}catch(e){}}\n"
		"    try{const hs=await showOpenFilePicker({multiple:false,types:[{description:'ESP-IDF firmware',accept:{'application/octet-stream':['.bin']}}]});if(hs&&hs[0]){await otaSaveHandle(hs[0]);return await hs[0].getFile();}}catch(e){return null;}\n"
		"  }\n"
		"  return chooseFileInput();\n"
		"}\n"
		"function safeHeader(s){return String(s||'').replace(/[^\\x20-\\x7e]/g,'?').slice(0,80)}\n"
		"async function loadOtaStatus(){\n"
		"  if(otaBusy||!tasksVisible||otaStatusBusy)return;\n"
		"  const local=isLocalSelected();\n"
		"  otaStatusBusy=true;\n"
		"  try{const url=local?'/ota/status':'/ota/remote/status?mac='+encodeURIComponent(selectedMac||'');const r=await controlFetch(url,6000);applyOta(await r.json());}catch(e){otaEnabled=false;otaSupported=false;otaStatusText='OTA status error';setOtaSlot('A/B ?','otaSlotUnknown');updateOtaUi();}finally{otaStatusBusy=false;}\n"
		"}\n"
		"async function startOta(){\n"
		"  if(otaBusy)return;\n"
		"  const local=isLocalSelected();const target=selectedOtaTarget();\n"
		"  await loadOtaStatus();\n"
		"  if(!local&&!otaSupported){return;}\n"
		"  if(!otaEnabled){alert('OTA is disabled. Set CONFIG_NODE0_OTA_PIN locally and rebuild.');return;}\n"
		"  const file=await chooseOtaFile();\n"
		"  if(!file)return;\n"
		"  if(!file.name.toLowerCase().endsWith('.bin')&&!confirm('Selected file is not .bin. Continue anyway?'))return;\n"
		"  const pin=prompt('OTA PIN');\n"
		"  if(!pin)return;\n"
		"  const confirmPhrase='UPDATE '+String(target||'node').toUpperCase();\n"
		"  const phrase=prompt('Type '+confirmPhrase+' to update '+target+' and reboot.');\n"
		"  if(phrase!==confirmPhrase){alert('OTA cancelled.');return;}\n"
		"  if(!confirm('Upload '+file.name+' ('+fmtKb(file.size)+') to '+target+' and reboot?'))return;\n"
		"  notifyStreamClose('all');stopLogStream();stopMeshStream();stopUiStream();\n"
		"  otaBusy=true;lastNodes='';lastTasks='';otaSetStatus('OTA uploading 0%',true,0);\n"
		"  const xhr=new XMLHttpRequest();\n"
		"  xhr.open('POST',local?'/ota':'/ota/remote?mac='+encodeURIComponent(selectedMac||''));\n"
		"  xhr.setRequestHeader('Content-Type','application/octet-stream');\n"
		"  xhr.setRequestHeader('X-OTA-PIN',pin);\n"
		"  xhr.setRequestHeader('X-OTA-Filename',safeHeader(file.name));\n"
		"  xhr.upload.onprogress=(e)=>{if(e.lengthComputable){const pct=Math.round(e.loaded*100/e.total);otaSetStatus((!local&&pct>=100)?'OTA relaying to mesh...':'OTA uploading '+pct+'%',true,pct)}};\n"
		"  xhr.onload=()=>{let msg=xhr.responseText||'';try{const j=JSON.parse(msg);msg=j.message||j.error||msg}catch(e){};if(xhr.status>=200&&xhr.status<300){otaSetStatus(msg||'OTA OK, rebooting',false,100);if(local){setTimeout(()=>location.reload(),9000)}else{otaBusy=false;updateOtaUi();setTimeout(()=>{loadNodes();startUiStream();startLogStream();},3000)}}else{otaBusy=false;otaSetStatus('OTA failed: '+(msg||xhr.status),false,0);startUiStream();startLogStream()}};\n"
		"  xhr.onerror=()=>{otaBusy=false;otaSetStatus('OTA network error',false,0);startUiStream();startLogStream()};\n"
		"  xhr.send(file);\n"
		"}\n"
		"async function startReboot(){\n"
		"  if(otaBusy||rebootBusy)return;\n"
		"  const local=isLocalSelected();const target=selectedOtaTarget();\n"
		"  await loadOtaStatus();\n"
		"  if(!local&&!otaSupported){return;}\n"
		"  if(!otaEnabled){alert('Reboot is disabled. Set CONFIG_NODE0_OTA_PIN locally and rebuild.');return;}\n"
		"  const pin=prompt('OTA PIN');\n"
		"  if(!pin)return;\n"
		"  const confirmPhrase='REBOOT '+String(target||'node').toUpperCase();\n"
		"  const phrase=prompt('Type '+confirmPhrase+' to reboot '+target+'.');\n"
		"  if(phrase!==confirmPhrase){alert('Reboot cancelled.');return;}\n"
		"  if(!confirm('Reboot '+target+' now?'))return;\n"
		"  notifyStreamClose('all');stopLogStream();stopMeshStream();stopUiStream();\n"
		"  rebootBusy=true;otaBusy=true;otaSetStatus('rebooting '+target+'...',false,0);\n"
		"  const url=local?'/reboot':'/reboot/remote?mac='+encodeURIComponent(selectedMac||'');\n"
		"  try{const r=await fetch(url,{method:'POST',cache:'no-store',headers:{'X-OTA-PIN':pin}});let msg=await r.text();try{const j=JSON.parse(msg);msg=j.message||j.error||msg}catch(e){};if(!r.ok)throw new Error(msg||r.status);otaSetStatus(msg||('rebooting '+target),false,100);if(local){setTimeout(()=>location.reload(),9000)}else{otaBusy=false;rebootBusy=false;updateOtaUi();setTimeout(()=>{loadNodes();startUiStream();startLogStream();},3000)}}catch(e){rebootBusy=false;otaBusy=false;otaSetStatus('reboot failed: '+(e&&e.message?e.message:e),false,0);startUiStream();startLogStream()}\n"
		"}\n"
		"function lvlClassByRest(rest){\n"
		"  if(!rest||rest.length===0) return '';\n"
		"  const c=rest[0];\n"
		"  if(c==='I') return 'lvI';\n"
		"  if(c==='W') return 'lvW';\n"
		"  if(c==='E') return 'lvE';\n"
		"  if(c==='D') return 'lvD';\n"
		"  if(c==='V') return 'lvV';\n"
		"  return '';\n"
		"}\n"
		"function renderChunk(text){\n"
		"  const lines=text.split('\\n');\n"
		"  let out='';\n"
		"  for(let raw of lines){\n"
		"    if(raw===undefined||raw===null) continue;\n"
		"    raw=raw.replace(/\\r/g,'');\n"
		"    if(raw.trim().length===0) continue; // drop fake empty chunk lines\n"
		"\n"
		"    let ts='';\n"
		"    let rest=raw;\n"
		"    if(raw[0]==='['){\n"
		"      const k=raw.indexOf(']');\n"
		"      if(k>0 && k<40){\n"
		"        ts=raw.slice(0,k+1);\n"
		"        rest=raw.slice(k+1).trimStart();\n"
		"      }\n"
		"    }\n"
		"\n"
		"    const cls=lvlClassByRest(rest);\n"
		"    if(ts){\n"
		"      out+=`<div class=\"ln ${cls}\"><span class=\"ts\">${esc(ts)}</span> ${esc(rest)}</div>`;\n"
		"    }else{\n"
		"      out+=`<div class=\"ln ${cls}\">${esc(rest)}</div>`;\n"
		"    }\n"
		"  }\n"
		"  return out;\n"
		"}\n"
		"async function tick(){\n"
		"  if(otaBusy||logBusy)return;\n"
		"  if(window.EventSource&&Date.now()>pollFallbackUntil){if(!logStream)startLogStream();if(logStream)return;}\n"
		"  logBusy=true;\n"
		"  try{\n"
		"    setLogMode('streamPoll','poll');\n"
		"    const r=await controlFetch('/log?from='+cursor,7000);\n"
		"    const next=r.headers.get('X-Log-Next');\n"
		"    const reset=r.headers.get('X-Log-Reset');\n"
		"    const t=await r.text();\n"
		"    appendLogText(t,reset==='1');\n"
		"    if(next) cursor=parseInt(next);\n"
		"    document.getElementById('st').textContent='OK';\n"
		"  }catch(e){setLogMode('streamErr','error');document.getElementById('st').textContent='ERR'}finally{logBusy=false;}\n"
		"}\n"
		"async function loadNodes(){\n"
		"  if(otaBusy||nodesBusy||selectionBusy)return;\n"
		"  const s=document.getElementById('nodeSel');\n"
		"  if(document.activeElement===s) return;\n"
		"  nodesBusy=true;\n"
		"  try{\n"
		"    const r=await controlFetch('/nodes',6000);\n"
		"    const txt=await r.text();\n"
		"    applyNodes(JSON.parse(txt),txt);\n"
		"  }catch(e){}finally{nodesBusy=false;}\n"
		"}\n"
		"async function onNodeSel(){\n"
		"  const s=document.getElementById('nodeSel');\n"
		"  const mac=s.value;\n"
		"  selectionBusy=true;\n"
		"  selectedMac=mac;\n"
		"  rememberNode(mac,selectedNodeTag());\n"
		"  otaEnabled=false;otaSupported=false;otaStatusText='';setOtaSlot('A/B ?','otaSlotUnknown');\n"
		"  clearTasksPanel();\n"
		"  updateOtaUi();\n"
		"  stopLogStream(true);\n"
		"  cursor=0;\n"
		"  document.getElementById('log').innerHTML='';\n"
		"  try{await controlFetch('/select?mac='+mac,6000);}catch(e){}\n"
		"  logStreamErrors=0;pollFallbackUntil=Date.now()+2500;await tick();setTimeout(()=>{pollFallbackUntil=0;startLogStream()},900);\n"
		"  selectionBusy=false;lastNodes='';\n"
		"  if(tasksVisible){loadTasks(true);loadOtaStatus();loadUiStatus(true)}\n"
		"}\n"
		"async function clearServer(){\n"
		"  cursor=0;\n"
		"  try{await controlFetch('/clear',6000);}catch(e){}\n"
		"  document.getElementById('log').innerHTML='';\n"
		"  logStreamErrors=0;\n"
		"}\n"
		"async function loadTasks(fresh){\n"
		"  if(!tasksVisible||otaBusy||tasksBusyReq) return;\n"
		"  if(uiStream&&!fresh) return;\n"
		"  tasksBusyReq=true;\n"
		"  try{\n"
		"    const mac=selectedMac||document.getElementById('nodeSel').value||'';\n"
		"    let url='/tasks'+(mac?'?mac='+encodeURIComponent(mac):'');if(fresh)url+=(url.indexOf('?')>=0?'&':'?')+'fresh=1';\n"
		"    const r=await controlFetch(url,6000);\n"
		"    const txt=await r.text();\n"
		"    applyTasks(JSON.parse(txt),mac,txt);\n"
		"  }catch(e){document.getElementById('taskCpu').textContent='CPU ? / tasks ?/?';document.getElementById('taskRam').textContent='RAM int ? / PSRAM ?';document.getElementById('taskFlash').textContent='FLASH ? / app ? / NVS ?'}finally{tasksBusyReq=false;}\n"
		"}\n"
		"async function loadUiStatus(fresh){\n"
		"  if(controlPollBusy||otaBusy||selectionBusy||uiStream)return;\n"
		"  const s=document.getElementById('nodeSel');\n"
		"  if(document.activeElement===s)return;\n"
		"  controlPollBusy=true;\n"
		"  try{\n"
		"    const mac=selectedMac||s.value||'';const detail=tasksVisible?'1':'0';\n"
		"    const url='/ui/status?tasks='+detail+'&ota='+detail+(fresh?'&fresh=1':'')+(mac?'&mac='+encodeURIComponent(mac):'');\n"
		"    const r=await controlFetch(url,7000);const txt=await r.text();const j=JSON.parse(txt);\n"
		"    applyNodes(j.nodes,JSON.stringify(j.nodes));\n"
		"    if(tasksVisible){applyTasks(j.tasks,mac,JSON.stringify(j.tasks));applyOta(j.ota);}\n"
		"  }catch(e){}finally{controlPollBusy=false;}\n"
		"}\n"
		"async function controlPoll(){await loadUiStatus()}\n"
		"document.getElementById('nodeSel').addEventListener('change',(e)=>{\n"
		"  if(!e.isTrusted) return;\n"
		"  onNodeSel();\n"
		"});\n"
		"window.addEventListener('pagehide',()=>{notifyStreamClose('all');stopLogStream();stopMeshStream();stopUiStream()});\n"
		"selectedMac=rememberedNode()||selectedMac;\n"
		"pollFallbackUntil=Date.now()+16000;\n"
		"setInterval(tick," STR(WEB_POLL_MS) ");\n"
		"setInterval(()=>loadTasks(false)," STR(TASKS_FAST_POLL_MS) ");\n"
		"setInterval(controlPoll," STR(UI_CONTROL_POLL_MS) ");\n"
		"loadUiStatus().finally(()=>{startUiStream();setTimeout(tick,350)});\n"
		"</script>\n"
		"</body></html>\n";

	httpd_resp_set_type(req, "text/html");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	return httpd_resp_send(req, html, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t register_log_http_handlers(httpd_handle_t server)
{
	httpd_uri_t uri_root = {
		.uri		= "/",
		.method		= HTTP_GET,
		.handler	= http_root_get,
		.user_ctx	= NULL
	};

	httpd_uri_t uri_log = {
		.uri		= "/log",
		.method		= HTTP_GET,
		.handler	= http_log_get,
		.user_ctx	= NULL
	};

	httpd_uri_t uri_log_stream = {
		.uri		= "/log/stream",
		.method		= HTTP_GET,
		.handler	= http_log_stream_get,
		.user_ctx	= NULL
	};

	httpd_uri_t uri_tasks = {
		.uri		= "/tasks",
		.method		= HTTP_GET,
		.handler	= http_tasks_get,
		.user_ctx	= NULL
	};

	httpd_uri_t uri_ui_status = {
		.uri		= "/ui/status",
		.method		= HTTP_GET,
		.handler	= http_ui_status_get,
		.user_ctx	= NULL
	};

	httpd_uri_t uri_ui_stream = {
		.uri		= "/ui/stream",
		.method		= HTTP_GET,
		.handler	= http_ui_stream_get,
		.user_ctx	= NULL
	};

	httpd_uri_t uri_mesh_status = {
		.uri		= "/mesh/status",
		.method		= HTTP_GET,
		.handler	= http_mesh_status_get,
		.user_ctx	= NULL
	};

#if LOG_HTTP_ENABLE_MESH_STREAM
	httpd_uri_t uri_mesh_stream = {
		.uri		= "/mesh/stream",
		.method		= HTTP_GET,
		.handler	= http_mesh_stream_get,
		.user_ctx	= NULL
	};
#endif

	httpd_uri_t uri_stream_close = {
		.uri		= "/stream/close",
		.method		= HTTP_POST,
		.handler	= http_stream_close_post,
		.user_ctx	= NULL
	};

	httpd_uri_t uri_reboot = {
		.uri		= "/reboot",
		.method		= HTTP_POST,
		.handler	= http_reboot_post,
		.user_ctx	= NULL
	};

	httpd_uri_t uri_reboot_remote = {
		.uri		= "/reboot/remote",
		.method		= HTTP_POST,
		.handler	= http_reboot_remote_post,
		.user_ctx	= NULL
	};

	httpd_uri_t uri_nodes = {
		.uri		= "/nodes",
		.method		= HTTP_GET,
		.handler	= http_nodes_get,
		.user_ctx	= NULL
	};

	httpd_uri_t uri_select = {
		.uri		= "/select",
		.method		= HTTP_GET,
		.handler	= http_select_get,
		.user_ctx	= NULL
	};

	httpd_uri_t uri_clear = {
		.uri		= "/clear",
		.method		= HTTP_GET,
		.handler	= http_clear_get,
		.user_ctx	= NULL
	};

	httpd_uri_t uri_ota_status = {
		.uri		= "/ota/status",
		.method		= HTTP_GET,
		.handler	= http_ota_status_get,
		.user_ctx	= NULL
	};

	httpd_uri_t uri_ota = {
		.uri		= "/ota",
		.method		= HTTP_POST,
		.handler	= http_ota_post,
		.user_ctx	= NULL
	};

	httpd_uri_t uri_ota_remote_status = {
		.uri		= "/ota/remote/status",
		.method		= HTTP_GET,
		.handler	= http_ota_remote_status_get,
		.user_ctx	= NULL
	};

	httpd_uri_t uri_ota_remote = {
		.uri		= "/ota/remote",
		.method		= HTTP_POST,
		.handler	= http_ota_remote_post,
		.user_ctx	= NULL
	};

	esp_err_t err = httpd_register_uri_handler(server, &uri_root);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_log);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_log_stream);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_tasks);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_ui_status);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_ui_stream);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_mesh_status);
	if (err != ESP_OK) return err;
#if LOG_HTTP_ENABLE_MESH_STREAM
	err = httpd_register_uri_handler(server, &uri_mesh_stream);
	if (err != ESP_OK) return err;
#endif
	err = httpd_register_uri_handler(server, &uri_stream_close);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_reboot);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_reboot_remote);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_nodes);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_select);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_clear);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_ota_status);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_ota);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_ota_remote_status);
	if (err != ESP_OK) return err;
	return httpd_register_uri_handler(server, &uri_ota_remote);
}


/* ----------------- Public API ----------------- */

esp_err_t log_http_server_init(void)
{
	esp_wifi_get_mac(WIFI_IF_STA, s_local_mac);

	strncpy(s_local_tag, "node0", sizeof(s_local_tag) - 1);
	s_local_tag[sizeof(s_local_tag) - 1] = '\0';

	portENTER_CRITICAL(&s_selection_lock);
	mac_copy(s_sel_mac, s_local_mac);
	copy_tag(s_sel_tag, sizeof(s_sel_tag), s_local_tag);
	portEXIT_CRITICAL(&s_selection_lock);

	// vprintf hook
	s_orig_vprintf = (vprintf_like_t)esp_log_set_vprintf(&log_http_vprintf);
	s_ota_mutex = xSemaphoreCreateMutex();
	if (!s_ota_mutex) {
		ESP_LOGW(TAG, "OTA mutex allocation failed; web OTA disabled");
	}
	s_remote_ota_ack_sem = xSemaphoreCreateBinary();
	if (!s_remote_ota_ack_sem) {
		ESP_LOGW(TAG, "remote OTA ACK semaphore allocation failed; remote OTA disabled");
	}
	s_remote_reboot_ack_sem = xSemaphoreCreateBinary();
	if (!s_remote_reboot_ack_sem) {
		ESP_LOGW(TAG, "remote reboot ACK semaphore allocation failed; remote reboot disabled");
	}

	s_log_stream_mutex = xSemaphoreCreateMutex();
	if (!s_log_stream_mutex) {
		ESP_LOGW(TAG, "log stream mutex allocation failed; /log/stream disabled");
	} else if (xTaskCreate(log_stream_task, "log_stream", LOG_STREAM_TASK_STACK,
	                       NULL, 4, &s_log_stream_task) != pdPASS) {
		ESP_LOGW(TAG, "log stream task allocation failed; /log/stream disabled");
		s_log_stream_task = NULL;
		vSemaphoreDelete(s_log_stream_mutex);
		s_log_stream_mutex = NULL;
	}

#if LOG_HTTP_ENABLE_MESH_STREAM
	s_mesh_stream_mutex = xSemaphoreCreateMutex();
	if (!s_mesh_stream_mutex) {
		ESP_LOGW(TAG, "mesh stream mutex allocation failed; /mesh/stream disabled");
	} else if (xTaskCreate(mesh_stream_task, "mesh_stream", MESH_STREAM_TASK_STACK,
	                       NULL, 4, &s_mesh_stream_task) != pdPASS) {
		ESP_LOGW(TAG, "mesh stream task allocation failed; /mesh/stream disabled");
		s_mesh_stream_task = NULL;
		vSemaphoreDelete(s_mesh_stream_mutex);
		s_mesh_stream_mutex = NULL;
	}
#else
	ESP_LOGI(TAG, "/mesh/stream debug task disabled; mesh UI uses /ui/stream");
#endif

	s_ui_stream_mutex = xSemaphoreCreateMutex();
	if (!s_ui_stream_mutex) {
		ESP_LOGW(TAG, "ui stream mutex allocation failed; /ui/stream disabled");
	} else if (xTaskCreate(ui_stream_task, "ui_stream", UI_STREAM_TASK_STACK,
	                       NULL, 4, &s_ui_stream_task) != pdPASS) {
		ESP_LOGW(TAG, "ui stream task allocation failed; /ui/stream disabled");
		s_ui_stream_task = NULL;
		vSemaphoreDelete(s_ui_stream_mutex);
		s_ui_stream_mutex = NULL;
	}

	if (!s_stream_lease_task &&
	    xTaskCreate(stream_lease_task, "log_lease", LOG_LEASE_TASK_STACK, NULL, 4,
	                &s_stream_lease_task) != pdPASS) {
		ESP_LOGW(TAG, "log lease task allocation failed; remote log retry disabled");
		s_stream_lease_task = NULL;
	}

	ESP_LOGI(TAG, "log_http_server_init: vprintf hook installed");
	return ESP_OK;
}

esp_err_t log_http_server_start(void)
{
	if (s_http_server) return ESP_OK;

	httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
	config.httpd.lru_purge_enable = true;
	config.httpd.stack_size = 12288;
	config.httpd.max_open_sockets = HTTPS_MAX_OPEN_SOCKETS;
	config.httpd.max_uri_handlers = 18;
	config.httpd.backlog_conn = 2;
	config.httpd.recv_wait_timeout = 3;
	config.httpd.send_wait_timeout = 3;
	config.httpd.keep_alive_enable = false;
	config.tls_handshake_timeout_ms = 4000;
	config.port_secure = CONFIG_NODE0_HTTPS_PORT;
	config.servercert = node0_https_servercert_pem_start;
	config.servercert_len = node0_https_servercert_pem_end - node0_https_servercert_pem_start;
	config.prvtkey_pem = node0_https_prvtkey_pem_start;
	config.prvtkey_len = node0_https_prvtkey_pem_end - node0_https_prvtkey_pem_start;

	esp_log_level_set("esp_https_server", ESP_LOG_WARN);

	esp_err_t err = httpd_ssl_start(&s_http_server, &config);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "httpd_ssl_start failed: %s", esp_err_to_name(err));
		return err;
	}

	err = register_log_http_handlers(s_http_server);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "register HTTPS handlers failed: %s", esp_err_to_name(err));
		httpd_ssl_stop(s_http_server);
		s_http_server = NULL;
		return err;
	}

	ESP_LOGI(TAG, "HTTPS log server started on port %d", CONFIG_NODE0_HTTPS_PORT);
	ota_mark_running_app_valid_if_pending();
	return ESP_OK;
}
