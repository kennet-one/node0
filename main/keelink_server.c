#include "keelink_server.h"

#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "keemash_keelink.h"
#include "keemash_fabric.h"
#include "keemash_mesh_root.h"
#include "mbedtls/base64.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mdns.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "log_http_server.h"
#include "keelink_ble.h"
#include "mesh_root_bcast.h"

#define KEELINK_REPLAY_SLOTS 128U
#define KEELINK_V1_MAX_FRAME (KEEMASH_KEELINK_HEADER_SIZE + KEEMASH_KEELINK_MAX_PAYLOAD)
#define KEELINK_MAX_FRAME \
	((KEELINK_V1_MAX_FRAME > KEEMASH_FABRIC_MAX_WIRE_FRAME) \
		 ? KEELINK_V1_MAX_FRAME : KEEMASH_FABRIC_MAX_WIRE_FRAME)
#define KEELINK_WORKER_STACK 9216U
#define KEELINK_HEARTBEAT_MS 5000U
#define KEELINK_WS_PING_MS 5000U
#define KEELINK_WS_PONG_TIMEOUT_MS 15000U
#define KEELINK_PAIR_FAIL_LIMIT 5U
#define KEELINK_PAIR_BLOCK_MS 60000U
#define KEELINK_COMMAND_MAP_SLOTS 24U
#define KEELINK_INVENTORY_CHUNK 3000U
#define KEELINK_LOG_BACKLOG_HIGH 96U
#define KEELINK_LOG_BACKLOG_LOW 64U
#define KEELINK_PRIORITY_LOG 3U
#define KEELINK_FABRIC_MESSAGE_SLOTS 4U
#define KEELINK_GRAPH_NODE_MAX 25U
#define KEELINK_TRAFFIC_CLASS_COUNT 9U
#define KEELINK_TRAFFIC_CLASS_SLOTS (KEELINK_TRAFFIC_CLASS_COUNT + 1U)
#define KEELINK_REPLAY_COMPAT_QUOTA 12U
#define KEELINK_REPLAY_CONTROL_QUOTA 20U
#define KEELINK_REPLAY_FAULT_QUOTA 8U
#define KEELINK_REPLAY_GRAPH_QUOTA 16U
#define KEELINK_REPLAY_TASK_QUOTA 12U
#define KEELINK_REPLAY_MEMORY_QUOTA 12U
#define KEELINK_REPLAY_STATE_QUOTA 12U
#define KEELINK_REPLAY_SENSOR_QUOTA 16U
#define KEELINK_REPLAY_LOG_QUOTA 8U
#define KEELINK_REPLAY_OTA_QUOTA 12U
#define KEELINK_BLE_FALLBACK_DELAY_MS 3000U
#define KEELINK_BLE_RETRY_MS 5000U

_Static_assert(KEELINK_REPLAY_COMPAT_QUOTA + KEELINK_REPLAY_CONTROL_QUOTA +
	KEELINK_REPLAY_FAULT_QUOTA + KEELINK_REPLAY_GRAPH_QUOTA +
	KEELINK_REPLAY_TASK_QUOTA + KEELINK_REPLAY_MEMORY_QUOTA +
	KEELINK_REPLAY_STATE_QUOTA + KEELINK_REPLAY_SENSOR_QUOTA +
	KEELINK_REPLAY_LOG_QUOTA + KEELINK_REPLAY_OTA_QUOTA ==
	KEELINK_REPLAY_SLOTS, "KeeLink replay quotas must fill the ring");

enum {
	KL_FIELD_PROTOCOL_VERSION = 1,
	KL_FIELD_ROOT_MAC = 2,
	KL_FIELD_CURRENT_EVENT = 3,
	KL_FIELD_LAST_EVENT = 4,
	KL_FIELD_APP_VERSION = 5,
	KL_FIELD_TEXT = 6,
	KL_FIELD_STATUS = 7,
	KL_FIELD_TARGET_MAC = 8,
	KL_FIELD_COMMAND = 9,
	KL_FIELD_COMMAND_ID = 10,
	KL_FIELD_TAG = 11,
	KL_FIELD_INVENTORY_JSON = 12,
	KL_FIELD_SNAPSHOT_ID = 13,
	KL_FIELD_PART_INDEX = 14,
	KL_FIELD_PART_COUNT = 15,
	KL_FIELD_LOG_SUBSCRIBED = 16,
	KL_FIELD_GAP_FIRST = 17,
	KL_FIELD_GAP_LAST = 18,
	KL_FIELD_RTT_MS = 19,
};

typedef struct {
	uint32_t id;
	uint16_t len;
	uint8_t priority;
	uint8_t traffic_class;
	uint64_t class_sequence;
	bool fabric;
	bool streamed;
} replay_meta_t;

typedef struct {
	bool used;
	bool ble;
	bool fabric;
	uint32_t command_id;
	uint32_t correlation_id;
	uint32_t created_ms;
	keemash_fabric_id_t operation_id;
} command_map_t;

typedef enum {
	KEELINK_WS_PROTOCOL_NONE = 0,
	KEELINK_WS_PROTOCOL_V1,
	KEELINK_WS_PROTOCOL_FABRIC_V2,
} keelink_ws_protocol_t;

static const char *TAG = "keelink";
static bool s_mdns_ready;
static httpd_handle_t s_server;
static SemaphoreHandle_t s_lock;
static TaskHandle_t s_worker;
static uint8_t *s_replay;
static keemash_fabric_envelope_t *s_fabric_messages;
static uint32_t s_fabric_message_used;
static replay_meta_t s_replay_meta[KEELINK_REPLAY_SLOTS];
static uint32_t s_event_id;
static uint64_t s_class_sequence[KEELINK_TRAFFIC_CLASS_SLOTS];
static uint64_t s_dispatch_cursor[KEELINK_TRAFFIC_CLASS_SLOTS];
static uint64_t s_resume_end_sequence[KEELINK_TRAFFIC_CLASS_SLOTS];
static uint64_t s_session_id;
static int s_ws_fd = -1;
static uint32_t s_ws_generation;
static bool s_ws_ready;
static keelink_ws_protocol_t s_ws_protocol;
static bool s_fabric_negotiated;
static keemash_fabric_id_t s_controller_id;
static keemash_fabric_id_t s_transport_session;
static uint32_t s_wss_connect_count;
static uint32_t s_resume_accept_count;
static uint32_t s_resume_reset_count;
static uint32_t s_resume_replayed_frames;
static char s_last_resume_reason[65] = "not attempted";
static bool s_ble_fallback_active;
static uint32_t s_ws_down_since_ms;
static uint32_t s_ble_retry_after_ms;
static bool s_log_subscribed;
static bool s_resume_active;
static uint64_t s_resume_cursor[KEELINK_TRAFFIC_CLASS_SLOTS];
static uint8_t s_dispatch_wheel_index;
static uint32_t s_queue_rejected;
static uint32_t s_compat_dropped;
static bool fabric_queue_enabled(void);
static bool s_inventory_dirty;
static uint32_t s_last_heartbeat_ms;
static uint32_t s_last_ws_ping_ms;
static uint32_t s_last_ws_pong_ms;
static uint32_t s_last_ws_ping_value;
static uint32_t s_ws_rtt_ms;
static bool s_ws_rtt_valid;
static command_map_t s_commands[KEELINK_COMMAND_MAP_SLOTS];
static keelink_ble_send_fn s_ble_sender;
static uint32_t s_pair_fail_count;
static uint32_t s_pair_block_until_ms;
static uint32_t s_log_dropped;
static uint64_t s_graph_revision;
static log_http_graph_node_t s_graph_nodes_cache[KEELINK_GRAPH_NODE_MAX];
static size_t s_graph_nodes_cache_count;
static bool s_graph_force_publish = true;

extern const unsigned char node0_https_servercert_pem_start[] asm("_binary_node0_https_servercert_pem_start");
extern const unsigned char node0_https_servercert_pem_end[] asm("_binary_node0_https_servercert_pem_end");

static uint32_t now_ms(void)
{
	return (uint32_t)(esp_timer_get_time() / 1000ULL);
}

static void lock(void)
{
	if (s_lock) xSemaphoreTake(s_lock, portMAX_DELAY);
}

static void unlock(void)
{
	if (s_lock) xSemaphoreGive(s_lock);
}

static keemash_fabric_envelope_t *fabric_message_acquire(void)
{
	keemash_fabric_envelope_t *message = NULL;
	lock();
	for (uint32_t i = 0; s_fabric_messages && i < KEELINK_FABRIC_MESSAGE_SLOTS; i++) {
		uint32_t bit = 1U << i;
		if ((s_fabric_message_used & bit) != 0) continue;
		s_fabric_message_used |= bit;
		message = &s_fabric_messages[i];
		break;
	}
	unlock();
	if (message) {
		*message = (keemash_fabric_envelope_t)
			keemash_fabric_v2_Envelope_init_zero;
	}
	return message;
}

static void fabric_message_release(keemash_fabric_envelope_t *message)
{
	if (!message || !s_fabric_messages) return;
	ptrdiff_t index = message - s_fabric_messages;
	if (index < 0 || (size_t)index >= KEELINK_FABRIC_MESSAGE_SLOTS) return;
	memset(message, 0, sizeof(*message));
	lock();
	s_fabric_message_used &= ~(1U << (uint32_t)index);
	unlock();
}

static void ws_mark_down(int fd)
{
	lock();
	if (s_ws_fd == fd) {
		s_ws_fd = -1;
		s_ws_ready = false;
		s_ws_protocol = KEELINK_WS_PROTOCOL_NONE;
		memset(&s_controller_id, 0, sizeof(s_controller_id));
		memset(&s_transport_session, 0, sizeof(s_transport_session));
		if (s_wss_connect_count) s_ws_down_since_ms = now_ms();
	}
	unlock();
}

void keelink_server_session_closed(int fd)
{
	ws_mark_down(fd);
}

static esp_err_t sha256(const void *data, size_t len, uint8_t out[32])
{
	const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!info || !data || !out) return ESP_ERR_INVALID_ARG;
	return mbedtls_md(info, data, len, out) == 0 ? ESP_OK : ESP_FAIL;
}

static bool constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
	uint8_t diff = 0;
	for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
	return diff == 0;
}

static bool token_hash_load(uint8_t out[32])
{
	nvs_handle_t handle;
	if (nvs_open("keelink", NVS_READONLY, &handle) != ESP_OK) return false;
	size_t len = 32;
	esp_err_t err = nvs_get_blob(handle, "token_hash", out, &len);
	nvs_close(handle);
	return err == ESP_OK && len == 32;
}

static esp_err_t token_hash_store(const uint8_t hash[32])
{
	nvs_handle_t handle;
	esp_err_t err = nvs_open("keelink", NVS_READWRITE, &handle);
	if (err != ESP_OK) return err;
	err = nvs_set_blob(handle, "token_hash", hash, 32);
	if (err == ESP_OK) err = nvs_commit(handle);
	nvs_close(handle);
	return err;
}

static esp_err_t token_revoke(void)
{
	nvs_handle_t handle;
	esp_err_t err = nvs_open("keelink", NVS_READWRITE, &handle);
	if (err != ESP_OK) return err;
	err = nvs_erase_key(handle, "token_hash");
	if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;
	if (err == ESP_OK) err = nvs_commit(handle);
	nvs_close(handle);
	return err;
}

static void authenticated_sessions_close(void)
{
	lock();
	int fd = s_ws_fd;
	s_ws_fd = -1;
	s_ws_ready = false;
	s_fabric_negotiated = false;
	s_ws_down_since_ms = 0;
	s_ble_fallback_active = false;
	s_log_subscribed = false;
	unlock();
	if (fd >= 0 && s_server) httpd_sess_trigger_close(s_server, fd);
	keelink_ble_disable();
}

static esp_err_t public_key_fingerprint(char out[65])
{
	mbedtls_x509_crt crt;
	mbedtls_x509_crt_init(&crt);
	int rc = mbedtls_x509_crt_parse(&crt, node0_https_servercert_pem_start,
		(size_t)(node0_https_servercert_pem_end - node0_https_servercert_pem_start));
	if (rc != 0) {
		mbedtls_x509_crt_free(&crt);
		return ESP_FAIL;
	}
	uint8_t der[1024];
	rc = mbedtls_pk_write_pubkey_der(&crt.pk, der, sizeof(der));
	if (rc <= 0) {
		mbedtls_x509_crt_free(&crt);
		return ESP_FAIL;
	}
	uint8_t digest[32];
	esp_err_t err = sha256(der + sizeof(der) - rc, (size_t)rc, digest);
	mbedtls_x509_crt_free(&crt);
	if (err != ESP_OK) return err;
	for (size_t i = 0; i < sizeof(digest); i++) {
		snprintf(out + i * 2, 3, "%02x", digest[i]);
	}
	out[64] = '\0';
	return ESP_OK;
}

static esp_err_t json_error(httpd_req_t *req, const char *status, const char *message)
{
	char body[192];
	snprintf(body, sizeof(body), "{\"ok\":false,\"error\":\"%s\"}",
		 message ? message : "error");
	httpd_resp_set_status(req, status);
	httpd_resp_set_type(req, "application/json");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

static bool parse_mac(const char *text, uint8_t mac[6])
{
	if (!text || strlen(text) != 12) return false;
	for (size_t i = 0; i < 6; i++) {
		char part[3] = {text[i * 2], text[i * 2 + 1], 0};
		char *end = NULL;
		unsigned long value = strtoul(part, &end, 16);
		if (!end || *end != '\0' || value > 255) return false;
		mac[i] = (uint8_t)value;
	}
	return true;
}

static void format_mac(const uint8_t mac[6], char out[13])
{
	snprintf(out, 13, "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2],
		 mac[3], mac[4], mac[5]);
}

static esp_err_t encode_frame(uint8_t *frame, size_t capacity, uint8_t kind,
			      uint16_t channel, uint32_t message_id,
			      uint32_t correlation_id, const uint8_t *payload,
			      size_t payload_len, size_t *frame_len)
{
	if (!frame || capacity < KEEMASH_KEELINK_HEADER_SIZE + payload_len ||
	    payload_len > KEEMASH_KEELINK_MAX_PAYLOAD) return ESP_ERR_INVALID_SIZE;
	keemash_keelink_header_t header = {
		.kind = kind,
		.channel = channel,
		.payload_len = payload_len,
		.session_id = s_session_id,
		.message_id = message_id,
		.correlation_id = correlation_id,
	};
	esp_err_t err = keemash_keelink_encode_header(frame, &header);
	if (err != ESP_OK) return err;
	if (payload_len) memcpy(frame + KEEMASH_KEELINK_HEADER_SIZE, payload, payload_len);
	if (frame_len) *frame_len = KEEMASH_KEELINK_HEADER_SIZE + payload_len;
	return ESP_OK;
}

static bool fabric_class_valid(int traffic_class)
{
	return traffic_class >= keemash_fabric_v2_TrafficClass_TRAFFIC_CONTROL &&
		traffic_class <= keemash_fabric_v2_TrafficClass_TRAFFIC_OTA;
}

static const uint8_t s_replay_quota[KEELINK_TRAFFIC_CLASS_SLOTS] = {
	[0] = KEELINK_REPLAY_COMPAT_QUOTA,
	[keemash_fabric_v2_TrafficClass_TRAFFIC_CONTROL] =
		KEELINK_REPLAY_CONTROL_QUOTA,
	[keemash_fabric_v2_TrafficClass_TRAFFIC_FAULT] =
		KEELINK_REPLAY_FAULT_QUOTA,
	[keemash_fabric_v2_TrafficClass_TRAFFIC_GRAPH] =
		KEELINK_REPLAY_GRAPH_QUOTA,
	[keemash_fabric_v2_TrafficClass_TRAFFIC_TASK] =
		KEELINK_REPLAY_TASK_QUOTA,
	[keemash_fabric_v2_TrafficClass_TRAFFIC_MEMORY] =
		KEELINK_REPLAY_MEMORY_QUOTA,
	[keemash_fabric_v2_TrafficClass_TRAFFIC_STATE] =
		KEELINK_REPLAY_STATE_QUOTA,
	[keemash_fabric_v2_TrafficClass_TRAFFIC_SENSOR] =
		KEELINK_REPLAY_SENSOR_QUOTA,
	[keemash_fabric_v2_TrafficClass_TRAFFIC_LOG] =
		KEELINK_REPLAY_LOG_QUOTA,
	[keemash_fabric_v2_TrafficClass_TRAFFIC_OTA] =
		KEELINK_REPLAY_OTA_QUOTA,
};

/* CONTROL appears every other turn; the remaining classes retain bounded progress. */
static const uint8_t s_dispatch_wheel[] = {
	keemash_fabric_v2_TrafficClass_TRAFFIC_CONTROL,
	keemash_fabric_v2_TrafficClass_TRAFFIC_FAULT,
	keemash_fabric_v2_TrafficClass_TRAFFIC_CONTROL,
	keemash_fabric_v2_TrafficClass_TRAFFIC_GRAPH,
	keemash_fabric_v2_TrafficClass_TRAFFIC_CONTROL,
	keemash_fabric_v2_TrafficClass_TRAFFIC_OTA,
	keemash_fabric_v2_TrafficClass_TRAFFIC_CONTROL,
	keemash_fabric_v2_TrafficClass_TRAFFIC_TASK,
	keemash_fabric_v2_TrafficClass_TRAFFIC_CONTROL,
	keemash_fabric_v2_TrafficClass_TRAFFIC_MEMORY,
	keemash_fabric_v2_TrafficClass_TRAFFIC_CONTROL,
	keemash_fabric_v2_TrafficClass_TRAFFIC_STATE,
	keemash_fabric_v2_TrafficClass_TRAFFIC_CONTROL,
	keemash_fabric_v2_TrafficClass_TRAFFIC_SENSOR,
	keemash_fabric_v2_TrafficClass_TRAFFIC_CONTROL,
	keemash_fabric_v2_TrafficClass_TRAFFIC_LOG,
	0,
};

static void replay_partition(uint8_t traffic_class, size_t *first, size_t *count)
{
	size_t offset = 0;
	for (uint8_t i = 0; i < traffic_class; i++) offset += s_replay_quota[i];
	if (first) *first = offset;
	if (count) *count = s_replay_quota[traffic_class];
}

static bool replay_meta_pending_locked(const replay_meta_t *meta)
{
	if (!meta || meta->len == 0) return false;
	if (!meta->fabric) return !meta->streamed;
	return fabric_class_valid(meta->traffic_class) &&
		meta->class_sequence > s_dispatch_cursor[meta->traffic_class];
}

static uint32_t replay_pending_count_locked(void)
{
	uint32_t count = 0;
	for (size_t i = 0; i < KEELINK_REPLAY_SLOTS; i++) {
		if (replay_meta_pending_locked(&s_replay_meta[i])) count++;
	}
	return count;
}

static uint32_t replay_class_pending_count_locked(uint8_t traffic_class)
{
	if (traffic_class >= KEELINK_TRAFFIC_CLASS_SLOTS) return 0;
	size_t first;
	size_t count;
	replay_partition(traffic_class, &first, &count);
	uint32_t pending = 0;
	for (size_t i = first; i < first + count; i++) {
		if (replay_meta_pending_locked(&s_replay_meta[i])) pending++;
	}
	return pending;
}

static int replay_append_slot_locked(uint8_t traffic_class)
{
	if (traffic_class >= KEELINK_TRAFFIC_CLASS_SLOTS) return -1;
	size_t first;
	size_t count;
	replay_partition(traffic_class, &first, &count);
	int reusable = -1;
	uint64_t oldest = UINT64_MAX;
	for (size_t i = first; i < first + count; i++) {
		replay_meta_t *meta = &s_replay_meta[i];
		if (meta->len == 0) return (int)i;
		bool delivered = meta->fabric
			? meta->class_sequence <= s_dispatch_cursor[traffic_class]
			: meta->streamed;
		uint64_t order = meta->fabric ? meta->class_sequence : meta->id;
		if (delivered && order < oldest) {
			oldest = order;
			reusable = (int)i;
		}
	}
	return reusable;
}

static int replay_next_for_class_locked(uint8_t traffic_class)
{
	if (traffic_class >= KEELINK_TRAFFIC_CLASS_SLOTS) return -1;
	size_t first;
	size_t count;
	replay_partition(traffic_class, &first, &count);
	int selected = -1;
	uint64_t order = UINT64_MAX;
	for (size_t i = first; i < first + count; i++) {
		const replay_meta_t *meta = &s_replay_meta[i];
		if (!replay_meta_pending_locked(meta)) continue;
		uint64_t candidate = meta->fabric ? meta->class_sequence : meta->id;
		if (candidate < order ||
		    (candidate == order && selected >= 0 &&
		     meta->priority < s_replay_meta[selected].priority)) {
			order = candidate;
			selected = (int)i;
		}
	}
	return selected;
}

static int replay_next_dispatch_locked(void)
{
	const size_t wheel_count = sizeof(s_dispatch_wheel) /
		sizeof(s_dispatch_wheel[0]);
	for (size_t step = 0; step < wheel_count; step++) {
		size_t index = (s_dispatch_wheel_index + step) % wheel_count;
		uint8_t traffic_class = s_dispatch_wheel[index];
		int slot = replay_next_for_class_locked(traffic_class);
		if (slot >= 0) {
			s_dispatch_wheel_index = (uint8_t)((index + 1U) % wheel_count);
			return slot;
		}
	}
	return -1;
}

static bool replay_resume_complete_locked(void)
{
	for (uint8_t traffic_class = 1;
	     traffic_class < KEELINK_TRAFFIC_CLASS_SLOTS; traffic_class++) {
		if (s_dispatch_cursor[traffic_class] <
		    s_resume_end_sequence[traffic_class]) return false;
	}
	return true;
}

static uint32_t replay_append(uint8_t kind, uint16_t channel, uint32_t correlation_id,
			      const uint8_t *payload, size_t payload_len, uint8_t priority)
{
	uint32_t id;
	lock();
	uint32_t backlog = replay_pending_count_locked();
	if (priority == KEELINK_PRIORITY_LOG && s_ws_ready &&
	    backlog >= KEELINK_LOG_BACKLOG_HIGH) {
		s_log_dropped++;
		unlock();
		if (s_worker) xTaskNotifyGive(s_worker);
		return 0;
	}
	int slot = replay_append_slot_locked(0);
	if (slot < 0) {
		s_compat_dropped++;
		if (priority == KEELINK_PRIORITY_LOG) s_log_dropped++;
		unlock();
		if (s_worker) xTaskNotifyGive(s_worker);
		return 0;
	}
	id = ++s_event_id;
	uint8_t *frame = s_replay + slot * KEELINK_MAX_FRAME;
	size_t frame_len = 0;
	s_replay_meta[slot].len = 0;
	if (encode_frame(frame, KEELINK_MAX_FRAME, kind, channel, id, correlation_id,
			 payload, payload_len, &frame_len) != ESP_OK) {
		memset(&s_replay_meta[slot], 0, sizeof(s_replay_meta[slot]));
		id = 0;
	} else {
		s_replay_meta[slot].id = id;
		s_replay_meta[slot].len = (uint16_t)frame_len;
		s_replay_meta[slot].priority = priority;
		s_replay_meta[slot].traffic_class = 0;
		s_replay_meta[slot].class_sequence = id;
		s_replay_meta[slot].fabric = false;
		s_replay_meta[slot].streamed = false;
	}
	unlock();
	if (id && s_worker) xTaskNotifyGive(s_worker);
	return id;
}

static uint64_t fabric_replay_append(keemash_fabric_envelope_t *message,
				     uint8_t priority)
{
	if (!message || !fabric_class_valid(message->traffic_class)) return 0;
	uint32_t id;
	uint64_t class_sequence;
	lock();
	uint32_t backlog = replay_pending_count_locked();
	if (priority == KEELINK_PRIORITY_LOG &&
	    backlog >= KEELINK_LOG_BACKLOG_HIGH) {
		s_log_dropped++;
		unlock();
		if (s_worker) xTaskNotifyGive(s_worker);
		return 0;
	}
	uint8_t traffic_class = (uint8_t)message->traffic_class;
	int slot = replay_append_slot_locked(traffic_class);
	if (slot < 0) {
		s_queue_rejected++;
		if (priority == KEELINK_PRIORITY_LOG) s_log_dropped++;
		unlock();
		if (s_worker) xTaskNotifyGive(s_worker);
		return 0;
	}
	id = ++s_event_id;
	class_sequence = s_class_sequence[traffic_class] + 1U;
	message->sequence = class_sequence;
	message->root_session = s_session_id;
	message->has_transport_session = true;
	message->transport_session = s_transport_session;
	uint8_t *frame = s_replay + slot * KEELINK_MAX_FRAME;
	size_t frame_len = 0;
	s_replay_meta[slot].len = 0;
	if (keemash_fabric_encode_wire(message, frame, KEEMASH_FABRIC_MAX_WIRE_FRAME,
		&frame_len) != ESP_OK) {
		memset(&s_replay_meta[slot], 0, sizeof(s_replay_meta[slot]));
		id = 0;
	} else {
		s_class_sequence[traffic_class] = class_sequence;
		s_replay_meta[slot].id = id;
		s_replay_meta[slot].len = (uint16_t)frame_len;
		s_replay_meta[slot].priority = priority;
		s_replay_meta[slot].traffic_class = traffic_class;
		s_replay_meta[slot].class_sequence = class_sequence;
		s_replay_meta[slot].fabric = true;
		s_replay_meta[slot].streamed = false;
	}
	unlock();
	if (id && s_worker) xTaskNotifyGive(s_worker);
	return id ? class_sequence : 0;
}

static esp_err_t fabric_rebind_transport(uint8_t *frame, size_t capacity,
					 size_t *length,
					 const keemash_fabric_id_t *transport_session)
{
	if (!frame || !length || !transport_session) return ESP_ERR_INVALID_ARG;
	keemash_fabric_envelope_t *message = fabric_message_acquire();
	if (!message) return ESP_ERR_NO_MEM;
	esp_err_t err = keemash_fabric_decode_wire(frame, *length, message);
	if (err == ESP_OK) {
		message->has_transport_session = true;
		message->transport_session = *transport_session;
		err = keemash_fabric_encode_wire(message, frame, capacity, length);
	}
	fabric_message_release(message);
	return err;
}

static esp_err_t ws_send_sync(int fd, const uint8_t *data, size_t len)
{
	if (!s_server || fd < 0 || !data || len == 0) return ESP_ERR_INVALID_STATE;
	httpd_ws_frame_t frame = {
		.type = HTTPD_WS_TYPE_BINARY,
		.payload = (uint8_t *)data,
		.len = len,
	};
	return httpd_ws_send_data(s_server, fd, &frame);
}

static esp_err_t ws_send_ping(int fd, uint32_t value)
{
	if (!s_server || fd < 0) return ESP_ERR_INVALID_STATE;
	httpd_ws_frame_t frame = {
		.type = HTTPD_WS_TYPE_PING,
		.payload = (uint8_t *)&value,
		.len = sizeof(value),
	};
	return httpd_ws_send_data(s_server, fd, &frame);
}

static esp_err_t req_send_frame(httpd_req_t *req, uint8_t kind, uint16_t channel,
				uint32_t message_id, uint32_t correlation_id,
				const uint8_t *payload, size_t payload_len)
{
	uint8_t *frame_data = heap_caps_malloc(KEELINK_MAX_FRAME,
		MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
	if (!frame_data) return ESP_ERR_NO_MEM;
	size_t frame_len = 0;
	esp_err_t err = encode_frame(frame_data, KEELINK_MAX_FRAME, kind, channel,
		message_id, correlation_id, payload, payload_len, &frame_len);
	if (err == ESP_OK) {
		httpd_ws_frame_t frame = {
			.type = HTTPD_WS_TYPE_BINARY,
			.payload = frame_data,
			.len = frame_len,
		};
		err = httpd_ws_send_frame(req, &frame);
	}
	free(frame_data);
	return err;
}

static esp_err_t req_send_fabric(httpd_req_t *req,
				 const keemash_fabric_envelope_t *message)
{
	uint8_t *frame_data = heap_caps_malloc(KEEMASH_FABRIC_MAX_WIRE_FRAME,
		MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
	if (!frame_data) return ESP_ERR_NO_MEM;
	size_t frame_len = 0;
	esp_err_t err = keemash_fabric_encode_wire(message, frame_data,
		KEEMASH_FABRIC_MAX_WIRE_FRAME, &frame_len);
	if (err == ESP_OK) {
		httpd_ws_frame_t frame = {
			.type = HTTPD_WS_TYPE_BINARY,
			.payload = frame_data,
			.len = frame_len,
		};
		err = httpd_ws_send_frame(req, &frame);
	}
	free(frame_data);
	return err;
}

static void publish_gap(uint32_t first, uint32_t last)
{
	uint8_t payload[32];
	keemash_keelink_writer_t writer;
	keemash_keelink_writer_init(&writer, payload, sizeof(payload));
	(void)keemash_keelink_put_u32(&writer, KL_FIELD_GAP_FIRST, first);
	(void)keemash_keelink_put_u32(&writer, KL_FIELD_GAP_LAST, last);
	(void)replay_append(KEEMASH_KEELINK_GAP, KEEMASH_KEELINK_CH_SYSTEM, 0,
		payload, writer.length, 0);
}

static void publish_log_backpressure_gap(uint32_t dropped)
{
	if (fabric_queue_enabled()) {
		keemash_fabric_envelope_t *message = fabric_message_acquire();
		if (!message) return;
		message->protocol_version = KEEMASH_FABRIC_VERSION;
		message->traffic_class = keemash_fabric_v2_TrafficClass_TRAFFIC_LOG;
		message->delivery = keemash_fabric_v2_DeliveryMode_DELIVERY_RELIABLE;
		message->which_body = keemash_fabric_v2_Envelope_gap_tag;
		message->body.gap.traffic_class =
			keemash_fabric_v2_TrafficClass_TRAFFIC_LOG;
		message->body.gap.last_sequence = dropped;
		snprintf(message->body.gap.reason, sizeof(message->body.gap.reason),
			 "backpressure dropped logs");
		(void)fabric_replay_append(message, 0);
		fabric_message_release(message);
		return;
	}
	uint8_t payload[96];
	char text[56];
	keemash_keelink_writer_t writer;
	keemash_keelink_writer_init(&writer, payload, sizeof(payload));
	snprintf(text, sizeof(text), "log backpressure dropped %" PRIu32 " events", dropped);
	(void)keemash_keelink_put_u32(&writer, KL_FIELD_STATUS, dropped);
	(void)keemash_keelink_put_utf8(&writer, KL_FIELD_TEXT, text);
	(void)replay_append(KEEMASH_KEELINK_GAP, KEEMASH_KEELINK_CH_LOG, 0,
		payload, writer.length, 0);
}

static void publish_fabric_graph_snapshot(void)
{
	if (!fabric_queue_enabled()) return;
	log_http_graph_node_t nodes[KEELINK_GRAPH_NODE_MAX] = {0};
	size_t node_count = log_http_server_graph_nodes(nodes,
		sizeof(nodes) / sizeof(nodes[0]));
	if (node_count == 0) return;

	bool force;
	lock();
	force = s_graph_force_publish;
	unlock();
	bool changed = node_count != s_graph_nodes_cache_count;
	for (size_t i = 0; !changed && i < node_count; i++) {
		changed = memcmp(nodes[i].mac, s_graph_nodes_cache[i].mac,
			sizeof(nodes[i].mac)) != 0 ||
			strncmp(nodes[i].tag, s_graph_nodes_cache[i].tag,
				sizeof(nodes[i].tag)) != 0 ||
			nodes[i].boot_session != s_graph_nodes_cache[i].boot_session ||
			nodes[i].online != s_graph_nodes_cache[i].online;
	}
	if (!force && !changed) return;

	const size_t nodes_per_page = 4U;
	uint32_t page_count = (uint32_t)((node_count + nodes_per_page - 1U) /
		nodes_per_page);
	uint64_t revision;
	lock();
	revision = ++s_graph_revision;
	unlock();

	uint8_t root_mac[6];
	esp_wifi_get_mac(WIFI_IF_STA, root_mac);
	keemash_fabric_id_t root_id;
	if (keemash_fabric_legacy_node_id(root_mac, root_mac, &root_id) != ESP_OK) {
		return;
	}

	bool published = true;
	for (uint32_t page = 0; page < page_count; page++) {
		keemash_fabric_envelope_t *message = fabric_message_acquire();
		if (!message) {
			published = false;
			break;
		}
		message->protocol_version = KEEMASH_FABRIC_VERSION;
		message->traffic_class =
			keemash_fabric_v2_TrafficClass_TRAFFIC_GRAPH;
		message->delivery = keemash_fabric_v2_DeliveryMode_DELIVERY_RELIABLE;
		message->has_source_node_id = true;
		message->source_node_id = root_id;
		message->graph_revision = revision;
		message->which_body = keemash_fabric_v2_Envelope_graph_tag;
		message->body.graph.revision = revision;
		message->body.graph.page_index = page;
		message->body.graph.page_count = page_count;

		size_t first = (size_t)page * nodes_per_page;
		size_t limit = first + nodes_per_page;
		if (limit > node_count) limit = node_count;
		for (size_t i = first; i < limit; i++) {
			keemash_fabric_v2_NodeDescriptor *descriptor =
				&message->body.graph.nodes[message->body.graph.nodes_count++];
			descriptor->has_node_id = true;
			if (keemash_fabric_legacy_node_id(root_mac, nodes[i].mac,
				&descriptor->node_id) != ESP_OK) {
				message->body.graph.nodes_count--;
				continue;
			}
			descriptor->route_mac.size = sizeof(nodes[i].mac);
			memcpy(descriptor->route_mac.bytes, nodes[i].mac,
				sizeof(nodes[i].mac));
			snprintf(descriptor->tag, sizeof(descriptor->tag), "%s",
				nodes[i].tag);
			bool local = memcmp(nodes[i].mac, root_mac, sizeof(root_mac)) == 0;
			descriptor->boot_session = local ? s_session_id : nodes[i].boot_session;
			if (local) {
				descriptor->core_version = KEEMASH_MESH_CORE_VERSION;
				snprintf(descriptor->firmware_version,
					sizeof(descriptor->firmware_version), "%s",
					esp_app_get_description()->version);
			}
			descriptor->online = nodes[i].online;
		}
		if (fabric_replay_append(message, 1) == 0) published = false;
		fabric_message_release(message);
		if (!published) break;
	}
	lock();
	if (published) {
		memcpy(s_graph_nodes_cache, nodes, node_count * sizeof(nodes[0]));
		s_graph_nodes_cache_count = node_count;
		s_graph_force_publish = false;
	} else {
		s_graph_force_publish = true;
	}
	unlock();
}

static void publish_inventory_snapshot(void)
{
	publish_fabric_graph_snapshot();
	lock();
	bool defer_compatibility_snapshot = s_fabric_negotiated &&
		(!s_ws_ready || s_ws_fd < 0 ||
		 s_ws_protocol != KEELINK_WS_PROTOCOL_FABRIC_V2);
	unlock();
	if (defer_compatibility_snapshot) return;
	char *json = heap_caps_malloc(12288, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
	if (!json) return;
	size_t json_len = log_http_server_node_list_json(json, 12288);
	if (json_len == 0) {
		free(json);
		return;
	}
	uint32_t snapshot_id = esp_random();
	uint32_t parts = (uint32_t)((json_len + KEELINK_INVENTORY_CHUNK - 1) /
				    KEELINK_INVENTORY_CHUNK);
	for (uint32_t part = 0; part < parts; part++) {
		size_t offset = part * KEELINK_INVENTORY_CHUNK;
		size_t take = json_len - offset;
		if (take > KEELINK_INVENTORY_CHUNK) take = KEELINK_INVENTORY_CHUNK;
		uint8_t payload[KEEMASH_KEELINK_MAX_PAYLOAD];
		keemash_keelink_writer_t writer;
		keemash_keelink_writer_init(&writer, payload, sizeof(payload));
		if (keemash_keelink_put_u32(&writer, KL_FIELD_SNAPSHOT_ID, snapshot_id) != ESP_OK ||
		    keemash_keelink_put_u32(&writer, KL_FIELD_PART_INDEX, part) != ESP_OK ||
		    keemash_keelink_put_u32(&writer, KL_FIELD_PART_COUNT, parts) != ESP_OK ||
		    keemash_keelink_put(&writer, KL_FIELD_INVENTORY_JSON,
			KEEMASH_KEELINK_TLV_UTF8, 0, json + offset, take) != ESP_OK) break;
		(void)replay_append(KEEMASH_KEELINK_SNAPSHOT,
			KEEMASH_KEELINK_CH_INVENTORY, 0, payload, writer.length, 2);
	}
	free(json);
}

static void worker_task(void *arg)
{
	(void)arg;
	for (;;) {
		(void)ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(250));
		bool inventory = false;
		lock();
		if (s_inventory_dirty) {
			s_inventory_dirty = false;
			inventory = true;
		}
		unlock();
		if (inventory) publish_inventory_snapshot();

		uint32_t dropped = 0;
		lock();
		uint32_t backlog = replay_pending_count_locked();
		if (s_log_dropped && backlog <= KEELINK_LOG_BACKLOG_LOW) {
			dropped = s_log_dropped;
			s_log_dropped = 0;
		}
		unlock();
		if (dropped) publish_log_backpressure_gap(dropped);

		uint32_t now = now_ms();
		int stale_fd = -1;
		bool ping_due = false;
		lock();
		if (s_ws_ready && s_ws_fd >= 0 &&
		    (uint32_t)(now - s_last_ws_pong_ms) >= KEELINK_WS_PONG_TIMEOUT_MS) {
			stale_fd = s_ws_fd;
			s_ws_fd = -1;
			s_ws_ready = false;
			s_ws_down_since_ms = now - KEELINK_BLE_FALLBACK_DELAY_MS;
		} else if (s_ws_ready && s_ws_fd >= 0 &&
			   (uint32_t)(now - s_last_ws_ping_ms) >= KEELINK_WS_PING_MS) {
			ping_due = true;
			s_last_ws_ping_ms = now;
			s_last_ws_ping_value = now;
		}
		int ping_fd = s_ws_fd;
		uint32_t ping_generation = s_ws_generation;
		unlock();
		if (stale_fd >= 0) {
			ESP_LOGW(TAG, "WSS pong timeout fd=%d", stale_fd);
			httpd_sess_trigger_close(s_server, stale_fd);
		} else if (ping_due) {
			esp_err_t ping_err = ws_send_ping(ping_fd, now);
			if (ping_err != ESP_OK) {
				lock();
				if (s_ws_fd == ping_fd &&
				    s_ws_generation == ping_generation) {
					s_ws_fd = -1;
					s_ws_ready = false;
					s_ws_protocol = KEELINK_WS_PROTOCOL_NONE;
					s_ws_down_since_ms = now_ms();
				}
				unlock();
			}
		}

		bool enable_ble_fallback = false;
		bool disable_ble_fallback = false;
		lock();
		bool wss_active = s_ws_ready && s_ws_fd >= 0;
		if (wss_active && s_ble_fallback_active) {
			s_ble_fallback_active = false;
			disable_ble_fallback = true;
		} else if (!wss_active && !s_ble_fallback_active &&
			   s_ws_down_since_ms != 0 &&
			   (int32_t)(now - s_ble_retry_after_ms) >= 0 &&
			   (uint32_t)(now - s_ws_down_since_ms) >= KEELINK_BLE_FALLBACK_DELAY_MS) {
			s_ble_fallback_active = true;
			enable_ble_fallback = true;
		}
		unlock();
		if (disable_ble_fallback) keelink_ble_disable();
		if (enable_ble_fallback && keelink_ble_enable() != ESP_OK) {
			lock();
			s_ble_fallback_active = false;
			s_ble_retry_after_ms = now_ms() + KEELINK_BLE_RETRY_MS;
			unlock();
		}

		lock();
		bool heartbeat_due = s_ws_ready &&
			(uint32_t)(now - s_last_heartbeat_ms) >= KEELINK_HEARTBEAT_MS;
		int fd = s_ws_fd;
		uint32_t heartbeat_generation = s_ws_generation;
		unlock();
		if (heartbeat_due) {
			uint8_t payload[32];
			uint8_t frame[KEEMASH_KEELINK_HEADER_SIZE + sizeof(payload)];
			size_t frame_len = 0;
			keemash_keelink_writer_t writer;
			keemash_keelink_writer_init(&writer, payload, sizeof(payload));
			lock();
			uint32_t current_event = s_event_id;
			unlock();
			(void)keemash_keelink_put_u32(&writer, KL_FIELD_CURRENT_EVENT,
				current_event);
			lock();
			bool rtt_valid = s_ws_rtt_valid;
			uint32_t rtt_ms = s_ws_rtt_ms;
			unlock();
			if (rtt_valid) {
				(void)keemash_keelink_put_u32(&writer, KL_FIELD_RTT_MS, rtt_ms);
			}
			esp_err_t heartbeat_err = encode_frame(frame, sizeof(frame),
				KEEMASH_KEELINK_HEARTBEAT, KEEMASH_KEELINK_CH_SYSTEM,
				0, 0, payload, writer.length, &frame_len);
			if (heartbeat_err == ESP_OK) heartbeat_err = ws_send_sync(fd, frame, frame_len);
			lock();
			s_last_heartbeat_ms = now;
			if (heartbeat_err != ESP_OK && s_ws_fd == fd &&
			    s_ws_generation == heartbeat_generation) {
				s_ws_fd = -1;
				s_ws_ready = false;
				s_ws_down_since_ms = now;
			}
			unlock();
		}

		for (;;) {
			uint8_t *copy = NULL;
			size_t len = 0;
			uint32_t id = 0;
			uint64_t class_sequence = 0;
			uint8_t traffic_class = 0;
			int selected_slot = -1;
			uint32_t connection_generation = 0;
			bool fabric = false;
			bool replayed = false;
			keemash_fabric_id_t transport_session = {0};
			lock();
			if (s_resume_active && replay_resume_complete_locked()) {
				s_resume_active = false;
			}
			if (!s_ws_ready || s_ws_fd < 0) {
				unlock();
				break;
			}
			selected_slot = replay_next_dispatch_locked();
			if (selected_slot < 0) {
				unlock();
				break;
			}
			replay_meta_t meta = s_replay_meta[selected_slot];
			id = meta.id;
			len = meta.len;
			fabric = meta.fabric;
			traffic_class = meta.traffic_class;
			class_sequence = meta.class_sequence;
			replayed = fabric && s_resume_active &&
				class_sequence > s_resume_cursor[traffic_class] &&
				class_sequence <= s_resume_end_sequence[traffic_class];
			transport_session = s_transport_session;
			copy = heap_caps_malloc(KEELINK_MAX_FRAME,
				MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
			if (copy) memcpy(copy,
				s_replay + (size_t)selected_slot * KEELINK_MAX_FRAME, len);
			fd = s_ws_fd;
			connection_generation = s_ws_generation;
			unlock();
			if (!copy) break;
			esp_err_t err = ESP_OK;
			if (fabric) {
				err = fabric_rebind_transport(copy,
					KEEMASH_FABRIC_MAX_WIRE_FRAME, &len,
					&transport_session);
			}
			if (err == ESP_OK) err = ws_send_sync(fd, copy, len);
			free(copy);
			lock();
			bool same_frame = selected_slot >= 0 &&
				s_replay_meta[selected_slot].id == id &&
				s_replay_meta[selected_slot].class_sequence == class_sequence &&
				s_replay_meta[selected_slot].fabric == fabric;
			if (err == ESP_OK && s_ws_fd == fd &&
			    s_ws_generation == connection_generation && same_frame) {
				if (fabric) {
					s_dispatch_cursor[traffic_class] = class_sequence;
				} else {
					s_replay_meta[selected_slot].streamed = true;
				}
				if (replayed) s_resume_replayed_frames++;
			} else if (err != ESP_ERR_NO_MEM && err != ESP_OK &&
				   s_ws_fd == fd &&
				   s_ws_generation == connection_generation) {
				ESP_LOGW(TAG, "WSS send failed: %s", esp_err_to_name(err));
				s_ws_fd = -1;
				s_ws_ready = false;
				s_ws_down_since_ms = now_ms();
			}
			unlock();
			if (err != ESP_OK) break;
		}
	}
}

static bool bearer_token_valid(httpd_req_t *req)
{
	char auth[96] = {0};
	if (httpd_req_get_hdr_value_str(req, "Authorization", auth, sizeof(auth)) != ESP_OK ||
	    strncmp(auth, "Bearer ", 7) != 0) return false;
	uint8_t token[32] = {0};
	size_t token_len = 0;
	if (mbedtls_base64_decode(token, sizeof(token), &token_len,
		(const unsigned char *)auth + 7, strlen(auth + 7)) != 0 || token_len != 32) {
		mbedtls_platform_zeroize(token, sizeof(token));
		return false;
	}
	uint8_t expected[32] = {0};
	uint8_t actual[32] = {0};
	bool valid = token_hash_load(expected) &&
		sha256(token, sizeof(token), actual) == ESP_OK &&
		constant_time_equal(expected, actual, sizeof(expected));
	mbedtls_platform_zeroize(token, sizeof(token));
	mbedtls_platform_zeroize(actual, sizeof(actual));
	mbedtls_platform_zeroize(expected, sizeof(expected));
	return valid;
}

static esp_err_t ws_pre_handshake(httpd_req_t *req)
{
	if (!bearer_token_valid(req)) return ESP_FAIL;

	int fd = httpd_req_to_sockfd(req);
	lock();
	int old_fd = s_ws_fd;
	s_ws_generation++;
	if (s_ws_generation == 0) s_ws_generation = 1;
	s_ws_fd = fd;
	s_ws_ready = false;
	s_ws_protocol = KEELINK_WS_PROTOCOL_NONE;
	memset(&s_controller_id, 0, sizeof(s_controller_id));
	memset(&s_transport_session, 0, sizeof(s_transport_session));
	s_wss_connect_count++;
	s_ws_down_since_ms = 0;
	s_ble_fallback_active = false;
	s_ble_retry_after_ms = 0;
	s_last_ws_ping_ms = now_ms();
	s_last_ws_pong_ms = s_last_ws_ping_ms;
	s_last_ws_ping_value = s_last_ws_ping_ms;
	s_ws_rtt_ms = 0;
	s_ws_rtt_valid = false;
	s_resume_active = false;
	memset(s_resume_cursor, 0, sizeof(s_resume_cursor));
	memset(s_resume_end_sequence, 0, sizeof(s_resume_end_sequence));
	unlock();
	keelink_ble_disable();
	if (old_fd >= 0 && old_fd != fd) httpd_sess_trigger_close(req->handle, old_fd);
	ESP_LOGI(TAG, "authenticated WSS client connected fd=%d", fd);
	return ESP_OK;
}

static bool command_map_add(uint32_t command_id, uint32_t correlation_id, bool ble,
			    bool fabric, const keemash_fabric_id_t *operation_id)
{
	lock();
	size_t chosen = KEELINK_COMMAND_MAP_SLOTS;
	for (size_t i = 0; i < KEELINK_COMMAND_MAP_SLOTS; i++) {
		if (!s_commands[i].used) {
			chosen = i;
			break;
		}
	}
	bool added = false;
	if (chosen < KEELINK_COMMAND_MAP_SLOTS) {
		s_commands[chosen] = (command_map_t){
			.used = true,
			.ble = ble,
			.fabric = fabric,
			.command_id = command_id,
			.correlation_id = correlation_id,
			.created_ms = now_ms(),
		};
		if (operation_id) s_commands[chosen].operation_id = *operation_id;
		added = true;
	}
	unlock();
	return added;
}

static bool command_map_take(uint32_t command_id, command_map_t *result)
{
	bool found = false;
	lock();
	for (size_t i = 0; i < KEELINK_COMMAND_MAP_SLOTS; i++) {
		if (s_commands[i].used && s_commands[i].command_id == command_id) {
			if (result) *result = s_commands[i];
			memset(&s_commands[i], 0, sizeof(s_commands[i]));
			found = true;
			break;
		}
	}
	unlock();
	return found;
}

static esp_err_t handle_control_request(httpd_req_t *req,
					const keemash_keelink_header_t *header,
					const uint8_t *payload)
{
	char mac_text[16] = {0};
	char command[96] = {0};
	keemash_keelink_reader_t reader;
	keemash_keelink_reader_init(&reader, payload, header->payload_len);
	keemash_keelink_tlv_t tlv;
	while (keemash_keelink_reader_next(&reader, &tlv) == ESP_OK) {
		if (tlv.field_id == KL_FIELD_TARGET_MAC) {
			(void)keemash_keelink_tlv_copy_text(&tlv, mac_text, sizeof(mac_text));
		} else if (tlv.field_id == KL_FIELD_COMMAND) {
			(void)keemash_keelink_tlv_copy_text(&tlv, command, sizeof(command));
		}
	}
	uint8_t mac[6];
	if (!parse_mac(mac_text, mac) || !command[0] || header->correlation_id == 0) {
		uint8_t out[96];
		keemash_keelink_writer_t writer;
		keemash_keelink_writer_init(&writer, out, sizeof(out));
		(void)keemash_keelink_put_utf8(&writer, KL_FIELD_TEXT, "invalid control request");
		return req_send_frame(req, KEEMASH_KEELINK_ERROR,
			KEEMASH_KEELINK_CH_CONTROL, 0, header->correlation_id,
			out, writer.length);
	}
	uint32_t command_id = mesh_v2_root_next_command_id();
	if (!command_map_add(command_id, header->correlation_id, false, false, NULL)) {
		uint8_t out[96];
		keemash_keelink_writer_t writer;
		keemash_keelink_writer_init(&writer, out, sizeof(out));
		(void)keemash_keelink_put_u32(&writer, KL_FIELD_STATUS,
			(uint32_t)ESP_ERR_NO_MEM);
		(void)keemash_keelink_put_utf8(&writer, KL_FIELD_TEXT,
			"command window busy");
		return req_send_frame(req, KEEMASH_KEELINK_RESPONSE,
			KEEMASH_KEELINK_CH_CONTROL, 0, header->correlation_id,
			out, writer.length);
	}
	esp_err_t err = mesh_root_submit_direct_command(mac, command, command_id);
	if (err != ESP_OK) {
		(void)command_map_take(command_id, NULL);
		uint8_t out[128];
		keemash_keelink_writer_t writer;
		keemash_keelink_writer_init(&writer, out, sizeof(out));
		(void)keemash_keelink_put_u32(&writer, KL_FIELD_STATUS, (uint32_t)err);
		(void)keemash_keelink_put_utf8(&writer, KL_FIELD_TEXT, esp_err_to_name(err));
		return req_send_frame(req, KEEMASH_KEELINK_RESPONSE,
			KEEMASH_KEELINK_CH_CONTROL, 0, header->correlation_id,
			out, writer.length);
	}
	return ESP_OK;
}

static esp_err_t send_fabric_control_result(httpd_req_t *req,
					    uint64_t correlation,
					    const keemash_fabric_id_t *operation_id,
					    uint32_t status, const char *text)
{
	keemash_fabric_envelope_t *reply = fabric_message_acquire();
	if (!reply) return ESP_ERR_NO_MEM;
	reply->protocol_version = KEEMASH_FABRIC_VERSION;
	reply->traffic_class = keemash_fabric_v2_TrafficClass_TRAFFIC_CONTROL;
	reply->delivery = keemash_fabric_v2_DeliveryMode_DELIVERY_RELIABLE;
	reply->root_session = s_session_id;
	reply->has_transport_session = true;
	reply->transport_session = s_transport_session;
	reply->correlation = correlation;
	reply->has_operation_id = operation_id != NULL;
	if (operation_id) reply->operation_id = *operation_id;
	reply->which_body = keemash_fabric_v2_Envelope_control_result_tag;
	reply->body.control_result.has_operation_id = operation_id != NULL;
	if (operation_id) reply->body.control_result.operation_id = *operation_id;
	reply->body.control_result.outcome = status == ESP_OK
		? keemash_fabric_v2_Outcome_OUTCOME_OK
		: keemash_fabric_v2_Outcome_OUTCOME_FAILED;
	reply->body.control_result.status = status;
	snprintf(reply->body.control_result.text,
		sizeof(reply->body.control_result.text), "%s", text ? text : "");
	esp_err_t err = req_send_fabric(req, reply);
	fabric_message_release(reply);
	return err;
}

static bool fabric_resume_prepare_locked(const keemash_fabric_v2_Hello *hello,
					 char *reason, size_t reason_size)
{
	uint64_t cursors[KEELINK_TRAFFIC_CLASS_SLOTS] = {0};
	bool seen[KEELINK_TRAFFIC_CLASS_SLOTS] = {false};
	uint32_t found[KEELINK_TRAFFIC_CLASS_SLOTS] = {0};

	if (hello->known_root_session == 0 ||
	    hello->known_root_session != s_session_id) {
		snprintf(reason, reason_size, "root session reset");
		return false;
	}
	if (hello->cursors_count != KEELINK_TRAFFIC_CLASS_COUNT) {
		snprintf(reason, reason_size, "incomplete cursor set");
		return false;
	}
	for (pb_size_t i = 0; i < hello->cursors_count; i++) {
		int traffic_class = hello->cursors[i].traffic_class;
		if (!fabric_class_valid(traffic_class) || seen[traffic_class]) {
			snprintf(reason, reason_size, "invalid cursor set");
			return false;
		}
		seen[traffic_class] = true;
		cursors[traffic_class] = hello->cursors[i].sequence;
		if (cursors[traffic_class] > s_class_sequence[traffic_class]) {
			snprintf(reason, reason_size, "cursor ahead of root");
			return false;
		}
		if (s_class_sequence[traffic_class] - cursors[traffic_class] >
		    s_replay_quota[traffic_class]) {
			snprintf(reason, reason_size, "replay window exceeded");
			return false;
		}
	}

	for (size_t i = 0; i < KEELINK_REPLAY_SLOTS; i++) {
		const replay_meta_t *meta = &s_replay_meta[i];
		if (!meta->fabric && meta->len != 0 && !meta->streamed) {
			snprintf(reason, reason_size,
				 "compatibility frame requires snapshot reset");
			return false;
		}
		if (!meta->fabric || meta->len == 0 || meta->id > s_event_id ||
		    !fabric_class_valid(meta->traffic_class)) continue;
		if (meta->class_sequence > cursors[meta->traffic_class] &&
		    meta->class_sequence <= s_class_sequence[meta->traffic_class]) {
			found[meta->traffic_class]++;
		}
	}
	for (uint32_t traffic_class = 1; traffic_class <= KEELINK_TRAFFIC_CLASS_COUNT;
	     traffic_class++) {
		uint64_t needed = s_class_sequence[traffic_class] - cursors[traffic_class];
		if (needed != found[traffic_class]) {
			snprintf(reason, reason_size, "replay gap in class %lu",
				 (unsigned long)traffic_class);
			return false;
		}
	}

	memcpy(s_resume_cursor, cursors, sizeof(s_resume_cursor));
	memcpy(s_dispatch_cursor, cursors, sizeof(s_dispatch_cursor));
	memcpy(s_resume_end_sequence, s_class_sequence,
		sizeof(s_resume_end_sequence));
	s_resume_active = !replay_resume_complete_locked();
	reason[0] = '\0';
	return true;
}

static esp_err_t handle_fabric_hello(httpd_req_t *req,
				     const keemash_fabric_envelope_t *message)
{
	const keemash_fabric_v2_Hello *hello = &message->body.hello;
	if (!hello->has_controller_id || !hello->has_transport_session ||
	    keemash_fabric_id_is_zero(&hello->controller_id) ||
	    keemash_fabric_id_is_zero(&hello->transport_session) || hello->zero_rtt) {
		return ESP_ERR_INVALID_ARG;
	}

	keemash_fabric_envelope_t *reply = fabric_message_acquire();
	if (!reply) return ESP_ERR_NO_MEM;
	reply->protocol_version = KEEMASH_FABRIC_VERSION;
	reply->traffic_class = keemash_fabric_v2_TrafficClass_TRAFFIC_GRAPH;
	reply->delivery = keemash_fabric_v2_DeliveryMode_DELIVERY_RELIABLE;
	reply->root_session = s_session_id;
	reply->has_transport_session = true;
	reply->transport_session = hello->transport_session;
	reply->correlation = message->sequence;
	reply->which_body = keemash_fabric_v2_Envelope_welcome_tag;
	reply->body.welcome.protocol_version = KEEMASH_FABRIC_VERSION;
	reply->body.welcome.max_frame = KEEMASH_FABRIC_MAX_WIRE_FRAME;
	reply->body.welcome.capabilities = KEEMASH_FABRIC_CAP_TYPED_GRAPH |
		KEEMASH_FABRIC_CAP_RESUME | KEEMASH_FABRIC_CAP_OPERATION_ID |
		KEEMASH_FABRIC_CAP_LATEST_SENSOR;
	reply->body.welcome.has_transport_session = true;
	reply->body.welcome.transport_session = hello->transport_session;
	reply->body.welcome.root_session = s_session_id;
	lock();
	bool resume_accepted = fabric_resume_prepare_locked(hello,
		reply->body.welcome.fallback_reason,
		sizeof(reply->body.welcome.fallback_reason));
	unlock();
	reply->body.welcome.resume_accepted = resume_accepted;
	char resume_reason[sizeof(reply->body.welcome.fallback_reason)];
	snprintf(resume_reason, sizeof(resume_reason), "%s",
		reply->body.welcome.fallback_reason);

	esp_err_t err = req_send_fabric(req, reply);
	fabric_message_release(reply);
	lock();
	if (err == ESP_OK && s_ws_fd == httpd_req_to_sockfd(req)) {
		s_controller_id = hello->controller_id;
		s_transport_session = hello->transport_session;
		s_ws_protocol = KEELINK_WS_PROTOCOL_FABRIC_V2;
		s_fabric_negotiated = true;
		s_ws_ready = true;
		if (!resume_accepted) {
			s_resume_active = false;
			memcpy(s_dispatch_cursor, s_class_sequence,
				sizeof(s_dispatch_cursor));
			memset(s_resume_cursor, 0, sizeof(s_resume_cursor));
			memset(s_resume_end_sequence, 0,
				sizeof(s_resume_end_sequence));
			for (size_t i = 0; i < KEELINK_REPLAY_SLOTS; i++) {
				if (!s_replay_meta[i].fabric) {
					s_replay_meta[i].streamed = true;
				}
			}
			s_graph_force_publish = true;
			s_resume_reset_count++;
		} else {
			s_resume_accept_count++;
		}
		snprintf(s_last_resume_reason, sizeof(s_last_resume_reason), "%s",
			 resume_accepted ? "accepted" : resume_reason);
	}
	unlock();
	if (err == ESP_OK) {
		ESP_LOGI(TAG, "Fabric resume %s%s%s",
			 resume_accepted ? "accepted" : "reset",
			 resume_reason[0] ? ": " : "", resume_reason);
		keelink_server_publish_inventory();
		if (s_worker) xTaskNotifyGive(s_worker);
	}
	return err;
}

static esp_err_t handle_fabric_control_request(httpd_req_t *req,
					       const keemash_fabric_envelope_t *message)
{
	const keemash_fabric_v2_ControlRequest *request =
		&message->body.control_request;
	if (!request->has_operation_id || !request->has_target_node_id ||
	    request->payload.size != 6U || !request->command[0] ||
	    message->correlation == 0 || message->correlation > UINT32_MAX ||
	    (message->has_operation_id &&
	     (message->operation_id.high != request->operation_id.high ||
	      message->operation_id.low != request->operation_id.low))) {
		return send_fabric_control_result(req, message->correlation,
			request->has_operation_id ? &request->operation_id : NULL,
			ESP_ERR_INVALID_ARG, "invalid Fabric control request");
	}

	uint8_t root_mac[6];
	keemash_fabric_id_t expected_node_id;
	esp_wifi_get_mac(WIFI_IF_STA, root_mac);
	if (keemash_fabric_legacy_node_id(root_mac, request->payload.bytes,
		&expected_node_id) != ESP_OK ||
	    expected_node_id.high != request->target_node_id.high ||
	    expected_node_id.low != request->target_node_id.low) {
		return send_fabric_control_result(req, message->correlation,
			&request->operation_id, ESP_ERR_INVALID_ARG,
			"target identity does not match route alias");
	}

	uint32_t command_id = mesh_v2_root_next_command_id();
	if (!command_map_add(command_id, (uint32_t)message->correlation, false,
		true, &request->operation_id)) {
		return send_fabric_control_result(req, message->correlation,
			&request->operation_id, ESP_ERR_NO_MEM, "command window busy");
	}
	esp_err_t err = mesh_root_submit_direct_command(request->payload.bytes,
		request->command, command_id);
	if (err != ESP_OK) {
		(void)command_map_take(command_id, NULL);
		return send_fabric_control_result(req, message->correlation,
			&request->operation_id, err, esp_err_to_name(err));
	}
	return ESP_OK;
}

static esp_err_t handle_fabric_frame(httpd_req_t *req, const uint8_t *frame,
				     size_t frame_len)
{
	keemash_fabric_envelope_t *message = fabric_message_acquire();
	if (!message) return ESP_ERR_NO_MEM;
	esp_err_t err = keemash_fabric_decode_wire(frame, frame_len, message);
	if (err != ESP_OK) {
		fabric_message_release(message);
		return err;
	}
	if (message->which_body == keemash_fabric_v2_Envelope_hello_tag &&
	    message->traffic_class == keemash_fabric_v2_TrafficClass_TRAFFIC_GRAPH) {
		err = handle_fabric_hello(req, message);
		fabric_message_release(message);
		return err;
	}
	lock();
	bool valid_lease = s_ws_protocol == KEELINK_WS_PROTOCOL_FABRIC_V2 &&
		message->has_transport_session &&
		message->transport_session.high == s_transport_session.high &&
		message->transport_session.low == s_transport_session.low;
	unlock();
	if (!valid_lease) {
		fabric_message_release(message);
		return ESP_ERR_INVALID_STATE;
	}
	if (message->which_body == keemash_fabric_v2_Envelope_control_request_tag &&
	    message->traffic_class == keemash_fabric_v2_TrafficClass_TRAFFIC_CONTROL) {
		err = handle_fabric_control_request(req, message);
		fabric_message_release(message);
		return err;
	}
	if (message->which_body == keemash_fabric_v2_Envelope_probe_tag) {
		message->root_session = s_session_id;
		message->body.probe.receiver_mono_us = (uint64_t)esp_timer_get_time();
		message->body.probe.reply_mono_us = (uint64_t)esp_timer_get_time();
		err = req_send_fabric(req, message);
		fabric_message_release(message);
		return err;
	}
	fabric_message_release(message);
	return ESP_ERR_NOT_SUPPORTED;
}

static esp_err_t ws_handler(httpd_req_t *req)
{
	httpd_ws_frame_t ws = {0};
	ws.type = HTTPD_WS_TYPE_BINARY;
	esp_err_t err = httpd_ws_recv_frame(req, &ws, 0);
	if (err != ESP_OK) {
		ws_mark_down(httpd_req_to_sockfd(req));
		return err;
	}
	if (ws.type == HTTPD_WS_TYPE_CLOSE || ws.type == HTTPD_WS_TYPE_PING ||
	    ws.type == HTTPD_WS_TYPE_PONG) {
		uint8_t control_payload[125];
		if (ws.len > sizeof(control_payload)) return ESP_ERR_INVALID_SIZE;
		ws.payload = control_payload;
		err = httpd_ws_recv_frame(req, &ws, sizeof(control_payload));
		if (err != ESP_OK) {
			ws_mark_down(httpd_req_to_sockfd(req));
			return err;
		}
		if (ws.type == HTTPD_WS_TYPE_PING) {
			ws.type = HTTPD_WS_TYPE_PONG;
			return httpd_ws_send_frame(req, &ws);
		}
		if (ws.type == HTTPD_WS_TYPE_CLOSE) {
			int fd = httpd_req_to_sockfd(req);
			ws_mark_down(fd);
			ws.len = 0;
			ws.payload = NULL;
			err = httpd_ws_send_frame(req, &ws);
			httpd_sess_trigger_close(req->handle, fd);
			return err;
		}
		if (ws.len == sizeof(uint32_t)) {
			uint32_t echoed = 0;
			memcpy(&echoed, ws.payload, sizeof(echoed));
			uint32_t received_ms = now_ms();
			lock();
			if (s_ws_fd == httpd_req_to_sockfd(req) &&
			    echoed == s_last_ws_ping_value) {
				s_last_ws_pong_ms = received_ms;
				s_ws_rtt_ms = received_ms - echoed;
				s_ws_rtt_valid = true;
			}
			unlock();
		}
		return ESP_OK;
	}
	if (ws.type != HTTPD_WS_TYPE_BINARY || ws.len > KEELINK_MAX_FRAME) return ESP_ERR_INVALID_SIZE;
	uint8_t *frame = heap_caps_malloc(ws.len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
	if (!frame) return ESP_ERR_NO_MEM;
	ws.payload = frame;
	err = httpd_ws_recv_frame(req, &ws, ws.len);
	if (err != ESP_OK) {
		free(frame);
		return err;
	}
	if (keemash_fabric_is_wire_frame(frame, ws.len)) {
		err = handle_fabric_frame(req, frame, ws.len);
		free(frame);
		return err;
	}
	keemash_keelink_header_t header = {0};
	err = keemash_keelink_decode_header(frame, ws.len, &header);
	if (err != ESP_OK) {
		free(frame);
		return err;
	}
	const uint8_t *payload = frame + KEEMASH_KEELINK_HEADER_SIZE;
	if (header.kind == KEEMASH_KEELINK_HELLO &&
	    header.channel == KEEMASH_KEELINK_CH_SYSTEM) {
		uint32_t last_event = 0;
		keemash_keelink_reader_t reader;
		keemash_keelink_reader_init(&reader, payload, header.payload_len);
		keemash_keelink_tlv_t tlv;
		while (keemash_keelink_reader_next(&reader, &tlv) == ESP_OK) {
			if (tlv.field_id == KL_FIELD_LAST_EVENT) {
				(void)keemash_keelink_tlv_u32(&tlv, &last_event);
			}
		}
		uint8_t root_mac[6];
		char root_mac_text[13];
		esp_wifi_get_mac(WIFI_IF_STA, root_mac);
		format_mac(root_mac, root_mac_text);
		uint8_t out[160];
		keemash_keelink_writer_t writer;
		keemash_keelink_writer_init(&writer, out, sizeof(out));
		(void)keemash_keelink_put_u32(&writer, KL_FIELD_PROTOCOL_VERSION,
			KEEMASH_KEELINK_VERSION);
		(void)keemash_keelink_put_utf8(&writer, KL_FIELD_ROOT_MAC, root_mac_text);
		(void)keemash_keelink_put_u32(&writer, KL_FIELD_CURRENT_EVENT, s_event_id);
		(void)keemash_keelink_put_utf8(&writer, KL_FIELD_APP_VERSION,
			esp_app_get_description()->version);
		err = req_send_frame(req, KEEMASH_KEELINK_WELCOME,
			KEEMASH_KEELINK_CH_SYSTEM, 0, header.message_id,
			out, writer.length);
		lock();
		s_ws_ready = err == ESP_OK;
		s_ws_protocol = err == ESP_OK ? KEELINK_WS_PROTOCOL_V1
			: KEELINK_WS_PROTOCOL_NONE;
		if (err == ESP_OK) {
			s_fabric_negotiated = false;
			s_log_subscribed = false;
			for (size_t i = 0; i < KEELINK_REPLAY_SLOTS; i++) {
				if (!s_replay_meta[i].fabric) {
					s_replay_meta[i].streamed = true;
				}
			}
		}
		uint32_t current_event = s_event_id;
		bool needs_snapshot = err == ESP_OK;
		unlock();
		if (needs_snapshot) {
			if (last_event && last_event < current_event) {
				publish_gap(last_event + 1U, current_event);
			}
			keelink_server_publish_inventory();
		}
		if (s_worker) xTaskNotifyGive(s_worker);
	} else if (header.kind == KEEMASH_KEELINK_REQUEST &&
		   header.channel == KEEMASH_KEELINK_CH_CONTROL) {
		lock();
		bool fabric_session = s_ws_protocol == KEELINK_WS_PROTOCOL_FABRIC_V2;
		unlock();
		err = fabric_session ? ESP_ERR_NOT_SUPPORTED
			: handle_control_request(req, &header, payload);
	} else if (header.kind == KEEMASH_KEELINK_REQUEST &&
		   header.channel == KEEMASH_KEELINK_CH_INVENTORY) {
		keelink_server_publish_inventory();
		err = ESP_OK;
	} else if (header.kind == KEEMASH_KEELINK_REQUEST &&
		   header.channel == KEEMASH_KEELINK_CH_LOG) {
		bool enabled = false;
		keemash_keelink_reader_t reader;
		keemash_keelink_reader_init(&reader, payload, header.payload_len);
		keemash_keelink_tlv_t tlv;
		while (keemash_keelink_reader_next(&reader, &tlv) == ESP_OK) {
			if (tlv.field_id == KL_FIELD_LOG_SUBSCRIBED) {
				(void)keemash_keelink_tlv_bool(&tlv, &enabled);
			}
		}
		lock();
		s_log_subscribed = enabled;
		unlock();
		err = ESP_OK;
	} else if (header.kind == KEEMASH_KEELINK_HEARTBEAT) {
		err = ESP_OK;
	} else {
		err = ESP_ERR_NOT_SUPPORTED;
	}
	free(frame);
	return err;
}

static esp_err_t info_get(httpd_req_t *req)
{
	uint8_t hash[32] = {0};
	bool paired = token_hash_load(hash);
	char fingerprint[65] = "unavailable";
	(void)public_key_fingerprint(fingerprint);
	uint8_t mac[6];
	char mac_text[13];
	esp_wifi_get_mac(WIFI_IF_STA, mac);
	format_mac(mac, mac_text);
	char body[1024];
	bool wss_active;
	keelink_ws_protocol_t wss_protocol;
	uint32_t wss_connect_count;
	uint32_t resume_accept_count;
	uint32_t resume_reset_count;
	uint32_t resume_replayed_frames;
	char last_resume_reason[sizeof(s_last_resume_reason)];
	uint64_t graph_revision;
	bool ble_fallback_active;
	uint32_t ws_down_age_ms;
	uint32_t queue_pending;
	uint32_t control_pending;
	uint32_t ota_pending;
	uint32_t log_pending;
	uint32_t queue_rejected;
	uint32_t compat_dropped;
	uint32_t log_dropped;
	lock();
	wss_active = s_ws_ready && s_ws_fd >= 0;
	wss_protocol = s_ws_protocol;
	wss_connect_count = s_wss_connect_count;
	resume_accept_count = s_resume_accept_count;
	resume_reset_count = s_resume_reset_count;
	resume_replayed_frames = s_resume_replayed_frames;
	snprintf(last_resume_reason, sizeof(last_resume_reason), "%s",
		s_last_resume_reason);
	graph_revision = s_graph_revision;
	ble_fallback_active = s_ble_fallback_active;
	ws_down_age_ms = s_ws_down_since_ms ? now_ms() - s_ws_down_since_ms : 0;
	queue_pending = replay_pending_count_locked();
	control_pending = replay_class_pending_count_locked(
		keemash_fabric_v2_TrafficClass_TRAFFIC_CONTROL);
	ota_pending = replay_class_pending_count_locked(
		keemash_fabric_v2_TrafficClass_TRAFFIC_OTA);
	log_pending = replay_class_pending_count_locked(
		keemash_fabric_v2_TrafficClass_TRAFFIC_LOG);
	queue_rejected = s_queue_rejected;
	compat_dropped = s_compat_dropped;
	log_dropped = s_log_dropped;
	unlock();
	snprintf(body, sizeof(body),
		"{\"protocol\":\"KeeLink\",\"version\":1,\"fabric_version\":2,"
		"\"fabric_transports\":[\"wss\"],\"quic\":false,\"root_mac\":\"%s\","
		"\"paired\":%s,\"wss\":true,\"wss_active\":%s,"
		"\"wss_protocol\":\"%s\","
		"\"wss_seen\":%s,\"wss_connect_count\":%" PRIu32 ","
		"\"resume_accept_count\":%" PRIu32 ","
		"\"resume_reset_count\":%" PRIu32 ","
		"\"resume_replayed_frames\":%" PRIu32 ","
		"\"last_resume_reason\":\"%s\","
		"\"graph_revision\":%" PRIu64 ","
		"\"queue_pending\":%" PRIu32 ","
		"\"control_pending\":%" PRIu32 ","
		"\"ota_pending\":%" PRIu32 ","
		"\"log_pending\":%" PRIu32 ","
		"\"queue_rejected\":%" PRIu32 ","
		"\"compat_dropped\":%" PRIu32 ","
		"\"log_dropped\":%" PRIu32 ","
		"\"ws_down_age_ms\":%" PRIu32 ","
		"\"ble_fallback_active\":%s,\"ble\":%s,"
		"\"ble_state\":\"%s\",\"ble_error\":%d,"
		"\"ble_boot_checkpoint\":%" PRIu32 ",\"reset_reason\":%d,"
		"\"tls_public_key_sha256\":\"%s\",\"max_frame\":%u}",
		mac_text, paired ? "true" : "false", wss_active ? "true" : "false",
		wss_protocol == KEELINK_WS_PROTOCOL_FABRIC_V2 ? "fabric-v2" :
			(wss_protocol == KEELINK_WS_PROTOCOL_V1 ? "keelink-v1" : "none"),
		wss_connect_count ? "true" : "false", wss_connect_count,
		resume_accept_count, resume_reset_count, resume_replayed_frames,
		last_resume_reason,
		graph_revision, queue_pending, control_pending, ota_pending,
		log_pending, queue_rejected, compat_dropped, log_dropped,
		ws_down_age_ms,
		ble_fallback_active ? "true" : "false",
		keelink_ble_ready() ? "true" : "false", keelink_ble_state(),
		(int)keelink_ble_last_error(), keelink_ble_boot_checkpoint(),
		(int)esp_reset_reason(), fingerprint,
		(unsigned)KEELINK_MAX_FRAME);
	httpd_resp_set_type(req, "application/json");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	esp_err_t err = httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
	mbedtls_platform_zeroize(hash, sizeof(hash));
	return err;
}

static esp_err_t pair_post(httpd_req_t *req)
{
	uint32_t now = now_ms();
	lock();
	bool blocked = (int32_t)(s_pair_block_until_ms - now) > 0;
	unlock();
	if (blocked) return json_error(req, "429 Too Many Requests", "pairing temporarily rate limited");
	if (!log_http_server_admin_pin_valid(req)) {
		lock();
		if (++s_pair_fail_count >= KEELINK_PAIR_FAIL_LIMIT) {
			s_pair_block_until_ms = now + KEELINK_PAIR_BLOCK_MS;
			s_pair_fail_count = 0;
		}
		unlock();
		return json_error(req, "403 Forbidden", "bad admin PIN");
	}
	uint8_t token[32] = {0};
	uint8_t hash[32] = {0};
	esp_fill_random(token, sizeof(token));
	if (sha256(token, sizeof(token), hash) != ESP_OK || token_hash_store(hash) != ESP_OK) {
		mbedtls_platform_zeroize(token, sizeof(token));
		mbedtls_platform_zeroize(hash, sizeof(hash));
		return json_error(req, "500 Internal Server Error", "token storage failed");
	}
	unsigned char encoded[48];
	size_t encoded_len = 0;
	if (mbedtls_base64_encode(encoded, sizeof(encoded), &encoded_len,
		token, sizeof(token)) != 0) {
		(void)token_revoke();
		mbedtls_platform_zeroize(token, sizeof(token));
		mbedtls_platform_zeroize(hash, sizeof(hash));
		return json_error(req, "500 Internal Server Error", "token encoding failed");
	}
	mbedtls_platform_zeroize(token, sizeof(token));
	mbedtls_platform_zeroize(hash, sizeof(hash));
	lock();
	s_pair_fail_count = 0;
	s_pair_block_until_ms = 0;
	unlock();
	char body[192];
	snprintf(body, sizeof(body), "{\"ok\":true,\"token\":\"%.*s\",\"token_version\":1}",
		(int)encoded_len, encoded);
	httpd_resp_set_type(req, "application/json");
	httpd_resp_set_hdr(req, "Cache-Control", "no-store");
	esp_err_t err = httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
	if (err != ESP_OK) (void)token_revoke();
	mbedtls_platform_zeroize(encoded, sizeof(encoded));
	mbedtls_platform_zeroize(body, sizeof(body));
	return err;
}

static esp_err_t revoke_post(httpd_req_t *req)
{
	if (!bearer_token_valid(req) && !log_http_server_admin_pin_valid(req)) {
		return json_error(req, "403 Forbidden", "authentication required");
	}
	esp_err_t err = token_revoke();
	if (err != ESP_OK) return json_error(req, "500 Internal Server Error", "revoke failed");
	authenticated_sessions_close();
	httpd_resp_set_type(req, "application/json");
	return httpd_resp_sendstr(req, "{\"ok\":true,\"message\":\"token revoked\"}");
}

esp_err_t keelink_server_init(void)
{
	if (s_worker) return ESP_OK;
	if (!keemash_keelink_selftest()) return ESP_ERR_INVALID_CRC;
	s_lock = xSemaphoreCreateMutex();
	if (!s_lock) return ESP_ERR_NO_MEM;
	s_replay = heap_caps_calloc(KEELINK_REPLAY_SLOTS, KEELINK_MAX_FRAME,
		MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
	s_fabric_messages = heap_caps_calloc(KEELINK_FABRIC_MESSAGE_SLOTS,
		sizeof(*s_fabric_messages), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
	if (!s_replay || !s_fabric_messages) {
		free(s_fabric_messages);
		s_fabric_messages = NULL;
		free(s_replay);
		s_replay = NULL;
		vSemaphoreDelete(s_lock);
		s_lock = NULL;
		return ESP_ERR_NO_MEM;
	}
	s_session_id = ((uint64_t)esp_random() << 32) | esp_random();
	if (xTaskCreateWithCaps(worker_task, "keelink_tx", KEELINK_WORKER_STACK, NULL, 5,
		&s_worker, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) != pdPASS) {
		free(s_fabric_messages);
		s_fabric_messages = NULL;
		free(s_replay);
		s_replay = NULL;
		vSemaphoreDelete(s_lock);
		s_lock = NULL;
		return ESP_ERR_NO_MEM;
	}
	ESP_LOGI(TAG, "KeeLink Fabric v2 + v1 fallback ready, replay=%u bytes, messages=%u bytes in PSRAM",
		(unsigned)(KEELINK_REPLAY_SLOTS * KEELINK_MAX_FRAME),
		(unsigned)(KEELINK_FABRIC_MESSAGE_SLOTS * sizeof(*s_fabric_messages)));
	return ESP_OK;
}

esp_err_t keelink_server_network_ready(void)
{
	if (s_mdns_ready) return ESP_OK;
	esp_err_t err = mdns_init();
	if (err != ESP_OK) {
		ESP_LOGW(TAG, "mDNS init failed: %s", esp_err_to_name(err));
		return err;
	}
	uint8_t mac[6];
	char mac_text[13];
	esp_wifi_get_mac(WIFI_IF_STA, mac);
	format_mac(mac, mac_text);
	(void)mdns_hostname_set("keemash-root");
	(void)mdns_instance_name_set("KeeMASH node0");
	mdns_txt_item_t txt[] = {
		{"version", "1"},
		{"fabric", "2"},
		{"transports", "wss"},
		{"root", mac_text},
		{"path", "/keelink/ws"},
	};
	(void)mdns_service_add("KeeLink", "_keelink", "_tcp",
		CONFIG_NODE0_HTTPS_PORT, txt, sizeof(txt) / sizeof(txt[0]));
	(void)mdns_service_add("KeeMASH HTTPS", "_https", "_tcp",
		CONFIG_NODE0_HTTPS_PORT, NULL, 0);
	s_mdns_ready = true;
	return ESP_OK;
}

esp_err_t keelink_server_register(httpd_handle_t server)
{
	if (!server) return ESP_ERR_INVALID_ARG;
	esp_err_t err = keelink_server_init();
	if (err != ESP_OK) return err;
	s_server = server;
	httpd_uri_t info = {.uri = "/keelink/info", .method = HTTP_GET, .handler = info_get};
	httpd_uri_t pair = {.uri = "/keelink/pair", .method = HTTP_POST, .handler = pair_post};
	httpd_uri_t revoke = {.uri = "/keelink/revoke", .method = HTTP_POST, .handler = revoke_post};
	httpd_uri_t ws = {
		.uri = "/keelink/ws",
		.method = HTTP_GET,
		.handler = ws_handler,
		.is_websocket = true,
		.handle_ws_control_frames = true,
		.ws_pre_handshake_cb = ws_pre_handshake,
	};
	err = httpd_register_uri_handler(server, &info);
	if (err == ESP_OK) err = httpd_register_uri_handler(server, &pair);
	if (err == ESP_OK) err = httpd_register_uri_handler(server, &revoke);
	if (err == ESP_OK) err = httpd_register_uri_handler(server, &ws);
	return err;
}

void keelink_server_publish_inventory(void)
{
	lock();
	s_inventory_dirty = true;
	unlock();
	if (s_worker) xTaskNotifyGive(s_worker);
}

static void publish_text_event_priority(uint16_t channel, const uint8_t mac[6],
					const char *tag, const char *text,
					uint8_t priority)
{
	lock();
	bool defer_topology = channel == KEEMASH_KEELINK_CH_TOPOLOGY &&
		s_fabric_negotiated &&
		(!s_ws_ready || s_ws_fd < 0 ||
		 s_ws_protocol != KEELINK_WS_PROTOCOL_FABRIC_V2);
	unlock();
	if (defer_topology) return;

	uint8_t payload[512];
	keemash_keelink_writer_t writer;
	keemash_keelink_writer_init(&writer, payload, sizeof(payload));
	char mac_text[13];
	if (mac) {
		format_mac(mac, mac_text);
		(void)keemash_keelink_put_utf8(&writer, KL_FIELD_TARGET_MAC, mac_text);
	}
	if (tag && tag[0]) (void)keemash_keelink_put_utf8(&writer, KL_FIELD_TAG, tag);
	if (text) (void)keemash_keelink_put_utf8(&writer, KL_FIELD_TEXT, text);
	(void)replay_append(KEEMASH_KEELINK_EVENT, channel, 0, payload,
		writer.length, priority);
}

void keelink_server_publish_text_event(uint16_t channel, const uint8_t mac[6],
					const char *tag, const char *text)
{
	publish_text_event_priority(channel, mac, tag, text, 2);
}

static bool fabric_queue_enabled(void)
{
	lock();
	bool active = s_fabric_negotiated;
	unlock();
	return active;
}

static bool fabric_node_identity(const uint8_t mac[6],
				 keemash_fabric_id_t *node_id,
				 uint32_t *boot_session)
{
	if (!mac || !node_id) return false;
	uint8_t root_mac[6];
	esp_wifi_get_mac(WIFI_IF_STA, root_mac);
	if (keemash_fabric_legacy_node_id(root_mac, mac, node_id) != ESP_OK) {
		return false;
	}
	if (boot_session) {
		mesh_v2_root_stats_t stats = {0};
		*boot_session = mesh_v2_root_stats_for_mac(mac, &stats)
			? stats.node_session_id : 0;
	}
	return true;
}

static const char *fabric_sensor_path(uint16_t metric_id)
{
	switch (metric_id) {
	case MESH_V2_SENSOR_METRIC_CO2_PPM:
		return "sensors.co2.ppm";
	case MESH_V2_SENSOR_METRIC_TEMPERATURE_C:
		return "sensors.temperature.c";
	case MESH_V2_SENSOR_METRIC_HUMIDITY_RH:
		return "sensors.humidity.rh";
	case MESH_V2_SENSOR_METRIC_ILLUMINANCE_LUX:
		return "sensors.illuminance.lux";
	case MESH_V2_SENSOR_METRIC_HEART_RATE_BPM:
		return "sensors.heart_rate.bpm";
	default:
		return NULL;
	}
}

static double fabric_sensor_value(const mesh_v2_sensor_entry_t *entry)
{
	double value = entry->value;
	if (entry->scale10 < 0) {
		for (int i = 0; i < -entry->scale10; i++) value /= 10.0;
	} else {
		for (int i = 0; i < entry->scale10; i++) value *= 10.0;
	}
	return value;
}

bool keelink_server_publish_sensor_fabric(
	const uint8_t mac[6], const mesh_v2_sensor_snapshot_payload_t *snapshot)
{
	if (!mac || !snapshot || !fabric_queue_enabled()) return false;
	keemash_fabric_id_t node_id;
	uint32_t boot_session = 0;
	if (!fabric_node_identity(mac, &node_id, &boot_session)) return false;
	for (uint8_t i = 0; i < snapshot->count; i++) {
		const mesh_v2_sensor_entry_t *entry = &snapshot->entries[i];
		const char *path = fabric_sensor_path(entry->metric_id);
		if (!path) continue;
		keemash_fabric_envelope_t *message = fabric_message_acquire();
		if (!message) return false;
		message->protocol_version = KEEMASH_FABRIC_VERSION;
		message->traffic_class = keemash_fabric_v2_TrafficClass_TRAFFIC_SENSOR;
		message->delivery = keemash_fabric_v2_DeliveryMode_DELIVERY_LATEST;
		message->has_source_node_id = true;
		message->source_node_id = node_id;
		message->which_body = keemash_fabric_v2_Envelope_telemetry_tag;
		message->body.telemetry.has_endpoint_id = true;
		if (keemash_fabric_endpoint_id(&node_id, path,
			&message->body.telemetry.endpoint_id) != ESP_OK) {
			fabric_message_release(message);
			continue;
		}
		message->body.telemetry.boot_session = boot_session;
		message->body.telemetry.sample_sequence =
			((uint64_t)snapshot->generation << 8) | i;
		message->body.telemetry.acquisition_mono_us =
			(uint64_t)snapshot->sample_uptime_ms * 1000ULL;
		message->body.telemetry.quality_flags = entry->status;
		message->body.telemetry.generation = snapshot->generation;
		message->body.telemetry.request_id = snapshot->request_id;
		message->body.telemetry.metric_id = entry->metric_id;
		message->body.telemetry.scale10 = entry->scale10;
		message->body.telemetry.validity =
			(entry->status & MESH_V2_SENSOR_STATUS_ERROR)
				? keemash_fabric_v2_Validity_VALIDITY_INVALID
			: !(entry->status & MESH_V2_SENSOR_STATUS_VALID)
				? keemash_fabric_v2_Validity_VALIDITY_UNAVAILABLE
			: (entry->status & MESH_V2_SENSOR_STATUS_STALE)
				? keemash_fabric_v2_Validity_VALIDITY_STALE
				: keemash_fabric_v2_Validity_VALIDITY_VALID;
		message->body.telemetry.which_value =
			keemash_fabric_v2_TelemetrySample_double_value_tag;
		message->body.telemetry.value.double_value = fabric_sensor_value(entry);
		(void)fabric_replay_append(message, 2);
		fabric_message_release(message);
	}
	return true;
}

bool keelink_server_publish_task_fabric(
	const uint8_t mac[6], const mesh_v2_task_snapshot_payload_t *snapshot)
{
	if (!mac || !snapshot || !fabric_queue_enabled()) return false;
	keemash_fabric_id_t node_id;
	uint32_t boot_session = 0;
	if (!fabric_node_identity(mac, &node_id, &boot_session)) return true;
	keemash_fabric_envelope_t *message = fabric_message_acquire();
	if (!message) return true;
	message->protocol_version = KEEMASH_FABRIC_VERSION;
	message->traffic_class = keemash_fabric_v2_TrafficClass_TRAFFIC_TASK;
	message->delivery = keemash_fabric_v2_DeliveryMode_DELIVERY_RELIABLE;
	message->has_source_node_id = true;
	message->source_node_id = node_id;
	message->which_body = keemash_fabric_v2_Envelope_tasks_tag;
	message->body.tasks.has_node_id = true;
	message->body.tasks.node_id = node_id;
	message->body.tasks.boot_session = boot_session;
	message->body.tasks.acquisition_mono_us = (uint64_t)snapshot->updated_ms * 1000ULL;
	message->body.tasks.actual_count = snapshot->task_total;
	message->body.tasks.truncated =
		(snapshot->flags & MESH_V2_TASK_SNAPSHOT_FLAG_LAST) == 0;
	message->body.tasks.request_id = snapshot->request_id;
	message->body.tasks.updated_ms = snapshot->updated_ms;
	message->body.tasks.uptime_s = snapshot->uptime_s;
	message->body.tasks.cpu_load_x10 = snapshot->cpu_load_x10;
	message->body.tasks.cpu_valid = snapshot->cpu_valid != 0;
	message->body.tasks.task_index = snapshot->task_index;
	size_t count = snapshot->task_count;
	if (count > MESH_V2_TASK_SNAPSHOT_MAX_ENTRIES) {
		count = MESH_V2_TASK_SNAPSHOT_MAX_ENTRIES;
	}
	message->body.tasks.tasks_count = count;
	for (size_t i = 0; i < count; i++) {
		const mesh_v2_task_entry_t *source = &snapshot->tasks[i];
		keemash_fabric_v2_TaskEntry *target = &message->body.tasks.tasks[i];
		snprintf(target->name, sizeof(target->name), "%.*s",
			MESH_V2_TASK_NAME_MAX, source->name);
		target->stack_free_words = source->free_words;
		target->priority = source->priority;
		target->cpu_load_x10 = source->cpu_x10 > 0
			? (uint32_t)source->cpu_x10 : 0;
	}
	(void)fabric_replay_append(message, 1);
	fabric_message_release(message);
	return true;
}

bool keelink_server_publish_memory_fabric(
	const uint8_t mac[6], const mesh_v2_memory_payload_t *snapshot)
{
	if (!mac || !snapshot || !fabric_queue_enabled()) return false;
	keemash_fabric_id_t node_id;
	uint32_t boot_session = 0;
	if (!fabric_node_identity(mac, &node_id, &boot_session)) return true;
	keemash_fabric_envelope_t *message = fabric_message_acquire();
	if (!message) return true;
	message->protocol_version = KEEMASH_FABRIC_VERSION;
	message->traffic_class = keemash_fabric_v2_TrafficClass_TRAFFIC_MEMORY;
	message->delivery = keemash_fabric_v2_DeliveryMode_DELIVERY_RELIABLE;
	message->has_source_node_id = true;
	message->source_node_id = node_id;
	message->which_body = keemash_fabric_v2_Envelope_memory_tag;
	message->body.memory.has_node_id = true;
	message->body.memory.node_id = node_id;
	message->body.memory.boot_session = boot_session;
	message->body.memory.acquisition_mono_us =
		(uint64_t)snapshot->uptime_s * 1000000ULL;
	message->body.memory.internal_total = snapshot->internal_total;
	message->body.memory.internal_free = snapshot->internal_free;
	message->body.memory.internal_min_free = snapshot->internal_min_free;
	message->body.memory.psram_total = snapshot->psram_total;
	message->body.memory.psram_free = snapshot->psram_free;
	message->body.memory.psram_min_free = snapshot->psram_min_free;
	message->body.memory.flash_size = snapshot->flash_chip;
	message->body.memory.image_size = snapshot->app_used;
	message->body.memory.app_slot_size = snapshot->app_slot;
	message->body.memory.nvs_used_entries = snapshot->nvs_used;
	message->body.memory.nvs_total_entries = snapshot->nvs_total;
	message->body.memory.uptime_s = snapshot->uptime_s;
	message->body.memory.psram_expected = snapshot->psram_expected;
	message->body.memory.nvs_free_entries = snapshot->nvs_free;
	message->body.memory.nvs_available_entries = snapshot->nvs_available;
	message->body.memory.heap_total = snapshot->heap_total;
	message->body.memory.heap_free = snapshot->heap_free;
	message->body.memory.heap_min_free = snapshot->heap_min_free;
	message->body.memory.psram_enabled = snapshot->psram_enabled != 0;
	(void)fabric_replay_append(message, 1);
	fabric_message_release(message);
	return true;
}

void keelink_server_publish_log(const uint8_t mac[6], const char *tag, const char *line)
{
	lock();
	bool enabled = s_log_subscribed;
	unlock();
	if (!enabled || !line) return;
	if (fabric_queue_enabled()) {
		keemash_fabric_id_t node_id;
		uint32_t boot_session = 0;
		if (!fabric_node_identity(mac, &node_id, &boot_session)) return;
		keemash_fabric_envelope_t *message = fabric_message_acquire();
		if (!message) return;
		message->protocol_version = KEEMASH_FABRIC_VERSION;
		message->traffic_class = keemash_fabric_v2_TrafficClass_TRAFFIC_LOG;
		message->delivery = keemash_fabric_v2_DeliveryMode_DELIVERY_RELIABLE;
		message->has_source_node_id = true;
		message->source_node_id = node_id;
		message->which_body = keemash_fabric_v2_Envelope_log_tag;
		message->body.log.has_node_id = true;
		message->body.log.node_id = node_id;
		message->body.log.boot_session = boot_session;
		message->body.log.acquisition_mono_us = (uint64_t)now_ms() * 1000ULL;
		snprintf(message->body.log.text, sizeof(message->body.log.text), "%s", line);
		(void)fabric_replay_append(message, KEELINK_PRIORITY_LOG);
		fabric_message_release(message);
		return;
	}
	publish_text_event_priority(KEEMASH_KEELINK_CH_LOG, mac, tag, line,
		KEELINK_PRIORITY_LOG);
}

void keelink_server_command_result(uint32_t command_id, uint8_t status, const char *text)
{
	command_map_t command = {0};
	if (!command_map_take(command_id, &command)) return;
	if (command.fabric) {
		keemash_fabric_envelope_t *reply = fabric_message_acquire();
		if (!reply) return;
		reply->protocol_version = KEEMASH_FABRIC_VERSION;
		reply->traffic_class = keemash_fabric_v2_TrafficClass_TRAFFIC_CONTROL;
		reply->delivery = keemash_fabric_v2_DeliveryMode_DELIVERY_RELIABLE;
		reply->correlation = command.correlation_id;
		reply->has_operation_id = true;
		reply->operation_id = command.operation_id;
		reply->which_body = keemash_fabric_v2_Envelope_control_result_tag;
		reply->body.control_result.has_operation_id = true;
		reply->body.control_result.operation_id = command.operation_id;
		reply->body.control_result.outcome = status == 0
			? keemash_fabric_v2_Outcome_OUTCOME_OK
			: keemash_fabric_v2_Outcome_OUTCOME_FAILED;
		reply->body.control_result.status = status;
		snprintf(reply->body.control_result.text,
			sizeof(reply->body.control_result.text), "%s", text ? text : "");
		(void)fabric_replay_append(reply, 0);
		fabric_message_release(reply);
		return;
	}
	uint8_t payload[256];
	keemash_keelink_writer_t writer;
	keemash_keelink_writer_init(&writer, payload, sizeof(payload));
	(void)keemash_keelink_put_u32(&writer, KL_FIELD_STATUS, status);
	(void)keemash_keelink_put_u32(&writer, KL_FIELD_COMMAND_ID, command_id);
	(void)keemash_keelink_put_utf8(&writer, KL_FIELD_TEXT, text ? text : "");
	if (command.ble && s_ble_sender) {
		uint8_t frame[KEEMASH_KEELINK_HEADER_SIZE + sizeof(payload)];
		size_t frame_len = 0;
		if (encode_frame(frame, sizeof(frame), KEEMASH_KEELINK_RESPONSE,
			KEEMASH_KEELINK_CH_CONTROL, 0, command.correlation_id, payload,
			writer.length, &frame_len) == ESP_OK) {
			(void)s_ble_sender(frame, frame_len);
		}
	} else {
		(void)replay_append(KEEMASH_KEELINK_RESPONSE,
			KEEMASH_KEELINK_CH_CONTROL, command.correlation_id,
			payload, writer.length, 0);
	}
}

void keelink_server_set_ble_sender(keelink_ble_send_fn sender)
{
	lock();
	s_ble_sender = sender;
	unlock();
}

bool keelink_server_token_verifier(uint8_t out[32])
{
	return out && token_hash_load(out);
}

bool keelink_server_wss_active(void)
{
	lock();
	bool active = s_ws_ready && s_ws_fd >= 0;
	unlock();
	return active;
}

esp_err_t keelink_server_handle_ble_frame(const uint8_t *frame, size_t frame_len,
					  uint8_t *response, size_t response_capacity,
					  size_t *response_len)
{
	if (!frame || !response || !response_len) return ESP_ERR_INVALID_ARG;
	if (!s_worker || !s_lock) return ESP_ERR_INVALID_STATE;
	*response_len = 0;
	keemash_keelink_header_t header = {0};
	esp_err_t err = keemash_keelink_decode_header(frame, frame_len, &header);
	if (err != ESP_OK) return err;
	const uint8_t *payload = frame + KEEMASH_KEELINK_HEADER_SIZE;
	keemash_keelink_writer_t writer;
	if (response_capacity < KEEMASH_KEELINK_HEADER_SIZE) return ESP_ERR_INVALID_SIZE;
	uint8_t *out = response + KEEMASH_KEELINK_HEADER_SIZE;
	size_t out_capacity = response_capacity - KEEMASH_KEELINK_HEADER_SIZE;
	keemash_keelink_writer_init(&writer, out, out_capacity);

	if (header.kind == KEEMASH_KEELINK_HELLO &&
	    header.channel == KEEMASH_KEELINK_CH_SYSTEM) {
		uint8_t mac[6];
		char mac_text[13];
		esp_wifi_get_mac(WIFI_IF_STA, mac);
		format_mac(mac, mac_text);
		(void)keemash_keelink_put_u32(&writer, KL_FIELD_PROTOCOL_VERSION,
			KEEMASH_KEELINK_VERSION);
		(void)keemash_keelink_put_utf8(&writer, KL_FIELD_ROOT_MAC, mac_text);
		(void)keemash_keelink_put_utf8(&writer, KL_FIELD_APP_VERSION,
			esp_app_get_description()->version);
		return encode_frame(response, response_capacity, KEEMASH_KEELINK_WELCOME,
			KEEMASH_KEELINK_CH_SYSTEM, 0, header.message_id,
			out, writer.length, response_len);
	}

	if (header.kind == KEEMASH_KEELINK_REQUEST &&
	    header.channel == KEEMASH_KEELINK_CH_INVENTORY) {
		char *json = heap_caps_malloc(KEEMASH_KEELINK_MAX_PAYLOAD,
			MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
		if (!json) return ESP_ERR_NO_MEM;
		size_t json_len = log_http_server_node_list_json(
			json, KEEMASH_KEELINK_MAX_PAYLOAD);
		if (!json_len || keemash_keelink_put(&writer,
			KL_FIELD_INVENTORY_JSON, KEEMASH_KEELINK_TLV_UTF8, 0,
			json, json_len) != ESP_OK) {
			free(json);
			return ESP_ERR_INVALID_SIZE;
		}
		free(json);
		return encode_frame(response, response_capacity,
			KEEMASH_KEELINK_SNAPSHOT, KEEMASH_KEELINK_CH_INVENTORY,
			0, header.correlation_id, out, writer.length, response_len);
	}

	if (header.kind == KEEMASH_KEELINK_REQUEST &&
	    header.channel == KEEMASH_KEELINK_CH_CONTROL) {
		if (keelink_server_wss_active()) return ESP_ERR_INVALID_STATE;
		char mac_text[16] = {0};
		char command[96] = {0};
		keemash_keelink_reader_t reader;
		keemash_keelink_reader_init(&reader, payload, header.payload_len);
		keemash_keelink_tlv_t tlv;
		while (keemash_keelink_reader_next(&reader, &tlv) == ESP_OK) {
			if (tlv.field_id == KL_FIELD_TARGET_MAC) {
				(void)keemash_keelink_tlv_copy_text(&tlv, mac_text,
					sizeof(mac_text));
			} else if (tlv.field_id == KL_FIELD_COMMAND) {
				(void)keemash_keelink_tlv_copy_text(&tlv, command,
					sizeof(command));
			}
		}
		uint8_t mac[6];
		if (!parse_mac(mac_text, mac) || !command[0] ||
		    header.correlation_id == 0) return ESP_ERR_INVALID_ARG;
		uint32_t command_id = mesh_v2_root_next_command_id();
		if (!command_map_add(command_id, header.correlation_id, true, false, NULL)) {
			return ESP_ERR_NO_MEM;
		}
		err = mesh_root_submit_direct_command(mac, command, command_id);
		if (err != ESP_OK) {
			(void)command_map_take(command_id, NULL);
			return err;
		}
		return ESP_OK;
	}
	return ESP_ERR_NOT_SUPPORTED;
}
