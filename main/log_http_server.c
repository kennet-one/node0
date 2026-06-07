#include "log_http_server.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_err.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_image_format.h"
#include "esp_mesh.h"
#include "esp_ota_ops.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "nvs.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/portmacro.h"

#include "mesh_proto.h"
#include "stack_monitor.h"

static const char *TAG = "log_http";

extern const unsigned char node0_https_servercert_pem_start[] asm("_binary_node0_https_servercert_pem_start");
extern const unsigned char node0_https_servercert_pem_end[] asm("_binary_node0_https_servercert_pem_end");
extern const unsigned char node0_https_prvtkey_pem_start[] asm("_binary_node0_https_prvtkey_pem_start");
extern const unsigned char node0_https_prvtkey_pem_end[] asm("_binary_node0_https_prvtkey_pem_end");

/* ----------------- Налаштування ----------------- */

#ifndef LOG_HTTP_LINES
	#define LOG_HTTP_LINES			220
#endif

#ifndef LOG_HTTP_LINE_MAX
	#define LOG_HTTP_LINE_MAX		256
#endif

#ifndef LOG_HTTP_HEAP_MAX
	#define LOG_HTTP_HEAP_MAX		512
#endif

#ifndef LOG_HTTP_STACK_TMP
	#define LOG_HTTP_STACK_TMP		128
#endif

#ifndef WEB_POLL_MS
	#define WEB_POLL_MS			500
#endif

#ifndef LOG_HTTP_MAX_NODES
	#define LOG_HTTP_MAX_NODES		24
#endif

#define STR_HELPER(x)	#x
#define STR(x)		STR_HELPER(x)

/* ----------------- Стан ----------------- */

static httpd_handle_t s_http_server = NULL;

static portMUX_TYPE s_log_lock = portMUX_INITIALIZER_UNLOCKED;
static char s_lines[LOG_HTTP_LINES][LOG_HTTP_LINE_MAX];
static uint32_t s_write_idx = 0;	// абсолютний лічильник рядків (cursor)
static uint32_t s_total_lines = 0;

typedef int (*vprintf_like_t)(const char *fmt, va_list ap);
static vprintf_like_t s_orig_vprintf = NULL;

// локальна нода
static uint8_t s_local_mac[6] = {0};
static char s_local_tag[16] = "node0";

// вибраний стрім (по замовчуванню local)
static uint8_t s_sel_mac[6] = {0};
static char s_sel_tag[16] = "node0";

// хто зараз реально стрімить (remote), щоб вимкнути попереднього
static uint8_t s_stream_mac[6] = {0};
static bool s_stream_active = false;

// список нод
typedef struct {
	uint8_t mac[6];
	char tag[16];
	uint32_t last_seen_ms;
	bool uptime_valid;
	uint32_t uptime_s;
	uint32_t uptime_seen_ms;
} node_ent_t;

typedef struct {
	bool valid;
	uint32_t free_bytes;
	uint32_t min_free_bytes;
	uint32_t total_bytes;
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

typedef struct {
	uint8_t mac[6];
	char tag[16];
	bool used;
	bool valid;
	bool staging_active;
	int slot_count;
	ram_status_t ram;
	persistent_status_t persistent;
	stack_monitor_snapshot_t current;
	stack_monitor_snapshot_t staging;
} taskmon_ent_t;

static taskmon_ent_t s_taskmon[LOG_HTTP_MAX_NODES];
static portMUX_TYPE s_taskmon_lock = portMUX_INITIALIZER_UNLOCKED;

static taskmon_ent_t *taskmon_find_locked(const uint8_t mac[6], bool create);

/* ----------------- Helpers ----------------- */

static uint32_t ms_now(void)
{
	return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

static uint32_t local_uptime_s(void)
{
	return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

static bool mac_eq(const uint8_t a[6], const uint8_t b[6])
{
	return memcmp(a, b, 6) == 0;
}

static void mac_copy(uint8_t dst[6], const uint8_t src[6])
{
	memcpy(dst, src, 6);
}

static void mac_to_hex(const uint8_t mac[6], char out[13])
{
	snprintf(out, 13, "%02x%02x%02x%02x%02x%02x",
	         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void copy_tag(char *dst, size_t dst_sz, const char *tag)
{
	if (!dst || dst_sz == 0) return;
	strncpy(dst, (tag && tag[0]) ? tag : "node", dst_sz - 1);
	dst[dst_sz - 1] = '\0';
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

	if (mac_eq(mac, s_sel_mac)) {
		copy_tag(tag, tag_sz, s_sel_tag);
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

	return found;
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

static void log_buffer_clear(void)
{
	portENTER_CRITICAL(&s_log_lock);
	{
		s_write_idx = 0;
		s_total_lines = 0;
		memset(s_lines, 0, sizeof(s_lines));
	}
	portEXIT_CRITICAL(&s_log_lock);
}

static void log_buffer_append_line(const char *line, size_t len)
{
	if (!line || len == 0) return;

	// прибрати кінцеві \r \n
	while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
		len--;
	}

	// якщо після trim нічого не лишилось — не пишемо
	if (len == 0) return;

	portENTER_CRITICAL(&s_log_lock);
	{
		uint32_t idx = s_write_idx % LOG_HTTP_LINES;

		size_t copy_len = (len >= (LOG_HTTP_LINE_MAX - 1)) ? (LOG_HTTP_LINE_MAX - 1) : len;
		memcpy(s_lines[idx], line, copy_len);
		s_lines[idx][copy_len] = '\0';

		s_write_idx++;
		if (s_total_lines < LOG_HTTP_LINES) s_total_lines++;
	}
	portEXIT_CRITICAL(&s_log_lock);
}


static char *log_buffer_snapshot_since(uint32_t from, size_t *out_len, uint32_t *out_next, bool *out_reset)
{
	char *snap = NULL;
	size_t size = 0;

	uint32_t next = 0;
	uint32_t total = 0;
	uint32_t earliest = 0;
	uint32_t start_abs = 0;
	uint32_t count = 0;
	bool reset = false;

	// 1) знімаємо стан (коротко) під lock
	portENTER_CRITICAL(&s_log_lock);
	{
		next = s_write_idx;
		total = s_total_lines;
		earliest = (next >= total) ? (next - total) : 0;
	}
	portEXIT_CRITICAL(&s_log_lock);

	// 2) нормалізація from
	if (from < earliest || from > next) {
		reset = true;
		from = earliest;
	}
	start_abs = from;
	count = (next > start_abs) ? (next - start_abs) : 0;

	// 3) алокація під максимум
	size = (size_t)count * (size_t)LOG_HTTP_LINE_MAX + 1;
	snap = (char *)malloc(size);
	if (!snap) {
		if (out_len) *out_len = 0;
		if (out_next) *out_next = next;
		if (out_reset) *out_reset = true;
		return NULL;
	}

	size_t pos = 0;

	// 4) копіюємо рядки під lock (щоб не рвалися)
	portENTER_CRITICAL(&s_log_lock);
	{
		// якщо за час алокації щось змінилось — перерахуй earliest/next “на льоту”
		next = s_write_idx;
		total = s_total_lines;
		earliest = (next >= total) ? (next - total) : 0;

		// якщо наш start_abs вже випав — ресет
		if (start_abs < earliest || start_abs > next) {
			reset = true;
			start_abs = earliest;
		}

		for (uint32_t abs_i = start_abs; abs_i < next; abs_i++) {
			uint32_t idx = abs_i % LOG_HTTP_LINES;
			const char *line = s_lines[idx];
			size_t l = strnlen(line, LOG_HTTP_LINE_MAX);

			if (pos + l + 2 >= size) break;

			memcpy(snap + pos, line, l);
			pos += l;

			// newline нормалізація
			if (pos == 0 || snap[pos - 1] != '\n') {
				snap[pos++] = '\n';
			}
		}
	}
	portEXIT_CRITICAL(&s_log_lock);

	snap[pos] = '\0';

	if (out_len) *out_len = pos;
	if (out_next) *out_next = next;
	if (out_reset) *out_reset = reset;
	return snap;
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

static void mesh_send_log_ctrl(const uint8_t to_mac[6], bool enable)
{
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

	// НЕ логати тут (щоб не рекурсія у vprintf)
	esp_mesh_send(&dest, &data, MESH_DATA_P2P, NULL, 0);
}

static void select_stream_node(const uint8_t mac[6], const char *tag)
{
	// якщо вже вибрано це саме — нічого не робимо (щоб не смикати CTRL)
	if (mac_eq(mac, s_sel_mac)) {
		if (tag && tag[0]) {
			strncpy(s_sel_tag, tag, sizeof(s_sel_tag) - 1);
			s_sel_tag[sizeof(s_sel_tag) - 1] = '\0';
		}
		return;
	}

	// Вимкнути попередній remote стрім
	if (s_stream_active) {
		mesh_send_log_ctrl(s_stream_mac, false);
		s_stream_active = false;
		memset(s_stream_mac, 0, sizeof(s_stream_mac));
	}

	// Встановити вибір
	mac_copy(s_sel_mac, mac);
	strncpy(s_sel_tag, tag ? tag : "node", sizeof(s_sel_tag) - 1);
	s_sel_tag[sizeof(s_sel_tag) - 1] = '\0';

	// Очистити буфер під нову ноду
	log_buffer_clear();

	// Якщо вибір не local — увімкнути стрім на тій ноді
	if (!mac_eq(s_sel_mac, s_local_mac)) {
		mesh_send_log_ctrl(s_sel_mac, true);
		s_stream_active = true;
		mac_copy(s_stream_mac, s_sel_mac);
	}
}

/* ----------------- vprintf hook (тільки local, якщо local вибраний) ----------------- */

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

	// 2) У буфер пишемо ТІЛЬКИ якщо зараз вибрана local нода
	if (!mac_eq(s_sel_mac, s_local_mac)) {
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

	size_t need = copy_t + (size_t)w + 1;
	if (need > LOG_HTTP_HEAP_MAX) need = LOG_HTTP_HEAP_MAX;

	char *heap_buf = (char *)malloc(need);
	if (!heap_buf) {
		if (!taskmon_ingest_line(s_local_mac, s_local_tag, stack_buf)) {
			log_buffer_append_line(stack_buf, cap - 1);
		}
		return ret;
	}

	memcpy(heap_buf, tprefix, copy_t);
	heap_buf[copy_t] = '\0';

	va_list ap_copy3;
	va_copy(ap_copy3, ap);
	vsnprintf(heap_buf + copy_t, need - copy_t, fmt, ap_copy3);
	va_end(ap_copy3);

	if (!taskmon_ingest_line(s_local_mac, s_local_tag, heap_buf)) {
		log_buffer_append_line(heap_buf, strnlen(heap_buf, need));
	}
	free(heap_buf);

	return ret;
}

/* ----------------- Public API (з mesh RX) ----------------- */

void log_http_server_node_seen_uptime(const uint8_t mac[6], const char *tag,
                                      bool uptime_valid, uint32_t uptime_s)
{
	if (!mac) return;

	uint32_t now = ms_now();

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
				portEXIT_CRITICAL(&s_nodes_lock);
				return;
			}
		}

		if (s_nodes_count < LOG_HTTP_MAX_NODES) {
			mac_copy(s_nodes[s_nodes_count].mac, mac);
			copy_tag(s_nodes[s_nodes_count].tag, sizeof(s_nodes[s_nodes_count].tag), tag);
			s_nodes[s_nodes_count].last_seen_ms = now;
			s_nodes[s_nodes_count].uptime_valid = uptime_valid;
			s_nodes[s_nodes_count].uptime_s = uptime_valid ? uptime_s : 0;
			s_nodes[s_nodes_count].uptime_seen_ms = now;
			s_nodes_count++;
		}
	}
	portEXIT_CRITICAL(&s_nodes_lock);
}

void log_http_server_node_seen(const uint8_t mac[6], const char *tag)
{
	log_http_server_node_seen_uptime(mac, tag, false, 0);
}

void log_http_server_remote_line(const uint8_t mac[6], const char *tag, const char *line)
{
	if (!mac || !line) return;
	if (!mac_eq(mac, s_sel_mac)) return;

	if (!taskmon_ingest_line(mac, tag, line)) {
		log_buffer_append_line(line, strnlen(line, 2048));
	}
}

/* ----------------- HTTP handlers ----------------- */

static esp_err_t http_nodes_get(httpd_req_t *req)
{
	enum { NODES_JSON_MAX = 4096 };
	char *out = (char *)malloc(NODES_JSON_MAX);
	if (!out) {
		httpd_resp_set_type(req, "text/plain");
		return httpd_resp_send(req, "no-mem\n", HTTPD_RESP_USE_STRLEN);
	}

	size_t pos = 0;
	uint32_t local_uptime = local_uptime_s();

	pos += snprintf(out + pos, NODES_JSON_MAX - pos,
		"{\"selected_mac\":\"%02x%02x%02x%02x%02x%02x\",\"selected_tag\":\"%s\",\"nodes\":[",
		s_sel_mac[0], s_sel_mac[1], s_sel_mac[2], s_sel_mac[3], s_sel_mac[4], s_sel_mac[5],
		s_sel_tag
	);

	// local
	pos += snprintf(out + pos, NODES_JSON_MAX - pos,
		"{\"mac\":\"%02x%02x%02x%02x%02x%02x\",\"tag\":\"%s\","
		"\"uptime_valid\":true,\"uptime_s\":%lu}",
		s_local_mac[0], s_local_mac[1], s_local_mac[2], s_local_mac[3], s_local_mac[4], s_local_mac[5],
		s_local_tag,
		(unsigned long)local_uptime
	);

	bool sel_in_list = mac_eq(s_sel_mac, s_local_mac);
	uint32_t now = ms_now();

	portENTER_CRITICAL(&s_nodes_lock);
	{
		for (uint32_t i = 0; i < s_nodes_count; i++) {
			if (pos + 192 >= NODES_JSON_MAX) break;

			// не дублюємо local
			if (mac_eq(s_nodes[i].mac, s_local_mac)) continue;

			if (mac_eq(s_nodes[i].mac, s_sel_mac)) sel_in_list = true;

			bool uptime_valid = s_nodes[i].uptime_valid;
			uint32_t uptime_s = uptime_valid
				? uptime_advanced_s(s_nodes[i].uptime_s, s_nodes[i].uptime_seen_ms, now)
				: 0;

			pos += snprintf(out + pos, NODES_JSON_MAX - pos,
				",{\"mac\":\"%02x%02x%02x%02x%02x%02x\",\"tag\":\"%s\","
				"\"uptime_valid\":%s,\"uptime_s\":%lu}",
				s_nodes[i].mac[0], s_nodes[i].mac[1], s_nodes[i].mac[2],
				s_nodes[i].mac[3], s_nodes[i].mac[4], s_nodes[i].mac[5],
				s_nodes[i].tag,
				uptime_valid ? "true" : "false",
				(unsigned long)uptime_s
			);
		}
	}
	portEXIT_CRITICAL(&s_nodes_lock);

	// якщо вибрана remote нода не в списку — додамо як option (щоб не скидалось)
	if (!sel_in_list && !mac_eq(s_sel_mac, (uint8_t[6]){0,0,0,0,0,0})) {
		if (pos + 192 < NODES_JSON_MAX) {
			pos += snprintf(out + pos, NODES_JSON_MAX - pos,
				",{\"mac\":\"%02x%02x%02x%02x%02x%02x\",\"tag\":\"%s\","
				"\"uptime_valid\":false,\"uptime_s\":0}",
				s_sel_mac[0], s_sel_mac[1], s_sel_mac[2],
				s_sel_mac[3], s_sel_mac[4], s_sel_mac[5],
				s_sel_tag
			);
		}
	}

	pos += snprintf(out + pos, NODES_JSON_MAX - pos, "]}");

	httpd_resp_set_type(req, "application/json");
	esp_err_t err = httpd_resp_send(req, out, HTTPD_RESP_USE_STRLEN);
	free(out);
	return err;
}

static bool parse_mac_hex(const char *s, uint8_t mac[6])
{
	if (!s) return false;
	if (strlen(s) < 12) return false;

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
					strncpy(tag, s_local_tag, sizeof(tag) - 1);
					tag[sizeof(tag) - 1] = '\0';
				} else {
					portENTER_CRITICAL(&s_nodes_lock);
					for (uint32_t i = 0; i < s_nodes_count; i++) {
						if (mac_eq(s_nodes[i].mac, mac)) {
							strncpy(tag, s_nodes[i].tag, sizeof(tag) - 1);
							tag[sizeof(tag) - 1] = '\0';
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
	return httpd_resp_send(req, "OK\n", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t http_clear_get(httpd_req_t *req)
{
	log_buffer_clear();
	httpd_resp_set_type(req, "text/plain");
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

	size_t len = 0;
	uint32_t next = 0;
	bool reset = false;

	char *snap = log_buffer_snapshot_since(from, &len, &next, &reset);
	if (!snap) {
		httpd_resp_set_type(req, "text/plain");
		return httpd_resp_send(req, "no-mem\n", HTTPD_RESP_USE_STRLEN);
	}

	char hdr_next[32];
	snprintf(hdr_next, sizeof(hdr_next), "%lu", (unsigned long)next);
	httpd_resp_set_hdr(req, "X-Log-Next", hdr_next);
	httpd_resp_set_hdr(req, "X-Log-Reset", reset ? "1" : "0");

	httpd_resp_set_type(req, "text/plain");
	esp_err_t err = httpd_resp_send(req, snap, len);
	free(snap);
	return err;
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

static esp_err_t http_tasks_get(httpd_req_t *req)
{
	enum { TASKS_JSON_MAX = 4096 };
	char *out = (char *)malloc(TASKS_JSON_MAX);
	if (!out) {
		httpd_resp_set_type(req, "text/plain");
		return httpd_resp_send(req, "no-mem\n", HTTPD_RESP_USE_STRLEN);
	}

	uint8_t mac[6];
	mac_copy(mac, s_sel_mac);

	char q[64] = {0};
	if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
		char v[32] = {0};
		if (httpd_query_key_value(q, "mac", v, sizeof(v)) == ESP_OK) {
			uint8_t parsed[6];
			if (parse_mac_hex(v, parsed)) {
				mac_copy(mac, parsed);
			}
		}
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
		                 "\"uptime_s\":%lu,\"ram_valid\":%s,"
		                 "\"ram_free_bytes\":%lu,\"ram_min_free_bytes\":%lu,"
		                 "\"ram_total_bytes\":%lu,\"flash_valid\":%s,"
		                 "\"flash_chip_bytes\":%lu,\"app_used_bytes\":%lu,"
		                 "\"app_partition_bytes\":%lu,"
		                 "\"nvs_valid\":%s,\"nvs_used_entries\":%lu,"
		                 "\"nvs_free_entries\":%lu,\"nvs_available_entries\":%lu,"
		                 "\"nvs_total_entries\":%lu,\"tasks\":[]}",
		                 slot_count,
		                 uptime_valid ? "true" : "false",
		                 (unsigned long)uptime_s,
		                 ram.valid ? "true" : "false",
		                 (unsigned long)ram.free_bytes,
		                 (unsigned long)ram.min_free_bytes,
		                 (unsigned long)ram.total_bytes,
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
		                 "\"uptime_s\":%lu,\"ram_valid\":%s,"
		                 "\"ram_free_bytes\":%lu,\"ram_min_free_bytes\":%lu,"
		                 "\"ram_total_bytes\":%lu,\"flash_valid\":%s,"
		                 "\"flash_chip_bytes\":%lu,\"app_used_bytes\":%lu,"
		                 "\"app_partition_bytes\":%lu,"
		                 "\"nvs_valid\":%s,\"nvs_used_entries\":%lu,"
		                 "\"nvs_free_entries\":%lu,\"nvs_available_entries\":%lu,"
		                 "\"nvs_total_entries\":%lu,\"tasks\":[",
		                 (unsigned long)snap.updated_ms,
		                 (unsigned long)age_ms,
		                 snap.cpu_valid ? "true" : "false",
		                 (unsigned long)snap.cpu_load_x10,
		                 slot_count,
		                 uptime_valid ? "true" : "false",
		                 (unsigned long)uptime_s,
		                 ram.valid ? "true" : "false",
		                 (unsigned long)ram.free_bytes,
		                 (unsigned long)ram.min_free_bytes,
		                 (unsigned long)ram.total_bytes,
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
	esp_err_t err = httpd_resp_send(req, out, HTTPD_RESP_USE_STRLEN);
	free(out);
	return err;
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
		"#log{flex:1;overflow:auto;padding:10px;white-space:pre;min-width:0}\n"
		"#tasks{display:none;width:370px;overflow:auto;border-left:1px solid #333;background:#151515;padding:10px;box-sizing:border-box}\n"
		"body.showTasks #tasks{display:block}\n"
		".ln{white-space:pre;margin:0;padding:0}\n"
		"button,select{font-family:monospace;font-size:14px}\n"
		".taskTop{display:flex;justify-content:space-between;gap:8px;margin-bottom:8px;color:#eee}\n"
		".taskLeft{display:flex;gap:6px;align-items:baseline;min-width:0}\n"
		".taskNode{color:#00ff7f;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\n"
		".taskUptime{color:#aaa;white-space:nowrap}\n"
		".taskMeta{text-align:right;color:#aaa;font-size:11px;line-height:1.25;white-space:nowrap}\n"
		".taskMac{color:#ddd}\n"
		".cpu{color:#9ad;margin-bottom:8px}\n"
		".ram{color:#adb;margin:-4px 0 8px}\n"
		".flash{color:#dba;margin:-4px 0 8px}\n"
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
		"@media(max-width:760px){#tasks{position:fixed;right:0;top:42px;bottom:0;width:90vw;z-index:5;box-shadow:-8px 0 20px #000}}\n"
		"</style></head>\n"
		"<body>\n"
		"<div id='top'>\n"
		"<button onclick='toggleFollow()'>follow: <span id=\"f\">ON</span></button>\n"
		"<button onclick='clearServer()'>clear</button>\n"
		"<button onclick='toggleTasks()'>tasks: <span id=\"tm\">OFF</span></button>\n"
		"<select id='nodeSel'></select>\n"
		"<span id='st'>...</span>\n"
		"</div>\n"
		"<div id='main'>\n"
		"<div id='log'></div>\n"
		"<div id='tasks'><div class='taskTop'><div class='taskLeft'><b>Task manager</b><span id='taskNode' class='taskNode'></span><span id='taskUp' class='taskUptime'>up ?</span></div><div class='taskMeta'><div id='taskMac' class='taskMac'>...</div><div id='taskAge'>...</div></div></div><div id='taskCpu' class='cpu'>CPU ? / tasks ?/?</div><div id='taskRam' class='ram'>RAM free ? / min ? / total ?</div><div id='taskFlash' class='flash'>FLASH ? / app ? / NVS ?</div><div id='taskTable'></div></div>\n"
		"</div>\n"
		"<script>\n"
		"let follow=true;\n"
		"let tasksVisible=false;\n"
		"let cursor=0;\n"
		"let lastNodes='';\n"
		"let lastTasks='';\n"
		"let selectedMac='';\n"
		"function toggleFollow(){follow=!follow;document.getElementById('f').textContent=follow?'ON':'OFF'}\n"
		"function toggleTasks(){tasksVisible=!tasksVisible;document.body.classList.toggle('showTasks',tasksVisible);document.getElementById('tm').textContent=tasksVisible?'ON':'OFF';if(tasksVisible)loadTasks()}\n"
		"function esc(s){return s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')}\n"
		"function pct(x){return x<0?'?':(x/10).toFixed(1)+'%'}\n"
		"function stackCls(w){if(w<128)return 'bad';if(w<256)return 'warn';return ''}\n"
		"function taskSlotsText(count,slots){return count+'/'+(slots>=0?slots:'?')}\n"
		"function pad2(n){return String(n).padStart(2,'0')}\n"
		"function fmtUptime(valid,sec){if(!valid)return 'up ?';sec=Math.max(0,Math.floor(Number(sec)||0));const d=Math.floor(sec/86400);sec%=86400;const h=Math.floor(sec/3600);sec%=3600;const m=Math.floor(sec/60);const s=sec%60;return 'up '+(d>0?d+'d ':'')+pad2(h)+':'+pad2(m)+':'+pad2(s)}\n"
		"function fmtKb(bytes){return Math.round((Number(bytes)||0)/1024)+' KB'}\n"
		"function fmtMb(bytes){return Math.round((Number(bytes)||0)/1048576)+' MB'}\n"
		"function fmtRam(j){return j.ram_valid?'RAM free '+fmtKb(j.ram_free_bytes)+' / min '+fmtKb(j.ram_min_free_bytes)+' / total '+fmtKb(j.ram_total_bytes):'RAM free ? / min ? / total ?'}\n"
		"function fmtFlash(j){const flash=j.flash_valid?'FLASH '+fmtMb(j.flash_chip_bytes)+' / app '+fmtKb(j.app_used_bytes)+'/'+fmtKb(j.app_partition_bytes):'FLASH ? / app ?';const nvs=j.nvs_valid?'NVS '+j.nvs_used_entries+'/'+j.nvs_total_entries+' used':'NVS ?';return flash+' / '+nvs}\n"
		"function setTaskHeader(tag,mac,age,up){document.getElementById('taskNode').textContent=tag||'';document.getElementById('taskUp').textContent=up||'up ?';document.getElementById('taskMac').textContent=mac||'...';document.getElementById('taskAge').textContent=age||'...'}\n"
		"function clearTasksPanel(){lastTasks='';setTaskHeader('',selectedMac,'...','up ?');document.getElementById('taskCpu').textContent='CPU ? / tasks ?/?';document.getElementById('taskRam').textContent='RAM free ? / min ? / total ?';document.getElementById('taskFlash').textContent='FLASH ? / app ? / NVS ?';document.getElementById('taskTable').textContent='waiting for STACKMON'}\n"
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
		"    if(raw.trim().length===0) continue; // <-- прибирає фейкові пусті рядки\n"
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
		"  try{\n"
		"    const r=await fetch('/log?from='+cursor);\n"
		"    const next=r.headers.get('X-Log-Next');\n"
		"    const reset=r.headers.get('X-Log-Reset');\n"
		"    const t=await r.text();\n"
		"    const el=document.getElementById('log');\n"
		"    if(reset==='1') el.innerHTML='';\n"
		"    if(t && t.length>0) el.insertAdjacentHTML('beforeend', renderChunk(t));\n"
		"    if(next) cursor=parseInt(next);\n"
		"    if(follow) el.scrollTop=el.scrollHeight;\n"
		"    document.getElementById('st').textContent='OK';\n"
		"  }catch(e){document.getElementById('st').textContent='ERR'}\n"
		"}\n"
		"async function loadNodes(){\n"
		"  const s=document.getElementById('nodeSel');\n"
		"  if(document.activeElement===s) return;\n"
		"  try{\n"
		"    const r=await fetch('/nodes');\n"
		"    const txt=await r.text();\n"
		"    if(txt===lastNodes) return;\n"
		"    lastNodes=txt;\n"
		"    const j=JSON.parse(txt);\n"
		"    const cur=j.selected_mac;\n"
		"    const prev=s.value;\n"
		"    selectedMac=cur||prev||selectedMac;\n"
		"    s.innerHTML='';\n"
		"    for(const n of j.nodes){\n"
		"      const o=document.createElement('option');\n"
		"      o.value=n.mac;\n"
		"      o.textContent=n.tag||'node';\n"
		"      s.appendChild(o);\n"
		"    }\n"
		"    s.value = cur || prev;\n"
		"    selectedMac=s.value||selectedMac;\n"
		"  }catch(e){}\n"
		"}\n"
		"async function onNodeSel(){\n"
		"  const s=document.getElementById('nodeSel');\n"
		"  const mac=s.value;\n"
		"  selectedMac=mac;\n"
		"  clearTasksPanel();\n"
		"  cursor=0;\n"
		"  document.getElementById('log').innerHTML='';\n"
		"  try{await fetch('/select?mac='+mac);}catch(e){}\n"
		"  if(tasksVisible) loadTasks();\n"
		"}\n"
		"async function clearServer(){\n"
		"  cursor=0;\n"
		"  try{await fetch('/clear');}catch(e){}\n"
		"  document.getElementById('log').innerHTML='';\n"
		"}\n"
		"async function loadTasks(){\n"
		"  if(!tasksVisible) return;\n"
		"  try{\n"
		"    const mac=selectedMac||document.getElementById('nodeSel').value||'';\n"
		"    const r=await fetch('/tasks'+(mac?'?mac='+encodeURIComponent(mac):''));\n"
		"    const txt=await r.text();\n"
		"    if(txt===lastTasks) return;\n"
		"    lastTasks=txt;\n"
		"    const j=JSON.parse(txt);\n"
		"    const box=document.getElementById('taskTable');\n"
		"    const up=fmtUptime(j.uptime_valid,j.uptime_s);\n"
		"    setTaskHeader(j.tag||'node',j.mac||mac,'no data',up);\n"
		"    document.getElementById('taskRam').textContent=fmtRam(j);\n"
		"    document.getElementById('taskFlash').textContent=fmtFlash(j);\n"
		"    if(!j.valid){box.textContent='waiting for STACKMON';document.getElementById('taskCpu').textContent='CPU ? / tasks ?/?';return;}\n"
		"    const tasks=j.tasks||[];\n"
		"    const slots=typeof j.slot_count==='number'?j.slot_count:-1;\n"
		"    tasks.sort((a,b)=>(b.cpu_x10-a.cpu_x10)||(a.free_words-b.free_words));\n"
		"    let rows='';\n"
		"    for(const t of tasks){\n"
		"      const cls=stackCls(t.free_words);\n"
		"      rows+='<tr'+(cls?' class='+cls:'')+'><td>'+esc(t.name)+'</td><td>'+t.prio+'</td><td>'+pct(t.cpu_x10)+'</td><td>'+t.free_words+'</td></tr>';\n"
		"    }\n"
		"    document.getElementById('taskCpu').textContent='CPU '+(j.cpu_valid?pct(j.cpu_load_x10):'?')+' / tasks '+taskSlotsText(tasks.length,slots);\n"
		"    setTaskHeader(j.tag||'node',j.mac||mac,Math.floor((j.age_ms||0)/1000)+'s ago',up);\n"
		"    box.innerHTML='<table><thead><tr><th>task</th><th>prio</th><th>cpu</th><th>free words</th></tr></thead><tbody>'+rows+'</tbody></table>';\n"
		"  }catch(e){document.getElementById('taskCpu').textContent='CPU ? / tasks ?/?';document.getElementById('taskRam').textContent='RAM free ? / min ? / total ?';document.getElementById('taskFlash').textContent='FLASH ? / app ? / NVS ?'}\n"
		"}\n"
		"document.getElementById('nodeSel').addEventListener('change',(e)=>{\n"
		"  if(!e.isTrusted) return;\n"
		"  onNodeSel();\n"
		"});\n"
		"setInterval(tick," STR(WEB_POLL_MS) ");\n"
		"setInterval(loadNodes,2000);\n"
		"setInterval(loadTasks,2000);\n"
		"loadNodes();\n"
		"tick();\n"
		"</script>\n"
		"</body></html>\n";

	httpd_resp_set_type(req, "text/html");
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

	httpd_uri_t uri_tasks = {
		.uri		= "/tasks",
		.method		= HTTP_GET,
		.handler	= http_tasks_get,
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

	esp_err_t err = httpd_register_uri_handler(server, &uri_root);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_log);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_tasks);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_nodes);
	if (err != ESP_OK) return err;
	err = httpd_register_uri_handler(server, &uri_select);
	if (err != ESP_OK) return err;
	return httpd_register_uri_handler(server, &uri_clear);
}


/* ----------------- Public API ----------------- */

esp_err_t log_http_server_init(void)
{
	esp_wifi_get_mac(WIFI_IF_STA, s_local_mac);

	// selected = local
	mac_copy(s_sel_mac, s_local_mac);
	strncpy(s_local_tag, "node0", sizeof(s_local_tag) - 1);
	s_local_tag[sizeof(s_local_tag) - 1] = '\0';
	strncpy(s_sel_tag, s_local_tag, sizeof(s_sel_tag) - 1);
	s_sel_tag[sizeof(s_sel_tag) - 1] = '\0';

	// vprintf hook
	s_orig_vprintf = (vprintf_like_t)esp_log_set_vprintf(&log_http_vprintf);

	ESP_LOGI(TAG, "log_http_server_init: vprintf hook installed");
	return ESP_OK;
}

esp_err_t log_http_server_start(void)
{
	if (s_http_server) return ESP_OK;

	httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
	config.httpd.lru_purge_enable = true;
	config.httpd.stack_size = 10240;
	config.port_secure = CONFIG_NODE0_HTTPS_PORT;
	config.servercert = node0_https_servercert_pem_start;
	config.servercert_len = node0_https_servercert_pem_end - node0_https_servercert_pem_start;
	config.prvtkey_pem = node0_https_prvtkey_pem_start;
	config.prvtkey_len = node0_https_prvtkey_pem_end - node0_https_prvtkey_pem_start;

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
	return ESP_OK;
}
