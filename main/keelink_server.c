#include "keelink_server.h"

#include <stdbool.h>
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
#define KEELINK_MAX_FRAME (KEEMASH_KEELINK_HEADER_SIZE + KEEMASH_KEELINK_MAX_PAYLOAD)
#define KEELINK_WORKER_STACK 9216U
#define KEELINK_HEARTBEAT_MS 5000U
#define KEELINK_WS_PING_MS 1000U
#define KEELINK_WS_PONG_TIMEOUT_MS 3000U
#define KEELINK_PAIR_FAIL_LIMIT 5U
#define KEELINK_PAIR_BLOCK_MS 60000U
#define KEELINK_COMMAND_MAP_SLOTS 24U
#define KEELINK_INVENTORY_CHUNK 3000U
#define KEELINK_LOG_BACKLOG_HIGH 96U
#define KEELINK_LOG_BACKLOG_LOW 64U
#define KEELINK_PRIORITY_LOG 3U
#define KEELINK_BLE_FALLBACK_DELAY_MS 3000U
#define KEELINK_BLE_RETRY_MS 5000U
#define KEELINK_UART_CLAIM_PREFIX "keelink.claim.v1:"
#define KEELINK_UART_CLAIM_OK_PREFIX "keelink.claim.ok.v1:"
#define KEELINK_UART_CLAIM_ERROR "keelink.claim.err.v1:rejected"
#define KEELINK_UART_COMPACT_PREFIX "KC1:"
#define KEELINK_UART_COMPACT_TIMEOUT_MS 20000U

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
};

typedef struct {
	uint32_t id;
	uint16_t len;
	uint8_t priority;
	uint8_t reserved;
} replay_meta_t;

typedef struct {
	bool used;
	bool ble;
	uint32_t command_id;
	uint32_t correlation_id;
	uint32_t created_ms;
} command_map_t;

typedef struct {
	char session[5];
	char nonce_b64[25];
	char token_b64[45];
	uint8_t received_mask;
	uint32_t updated_ms;
} uart_claim_state_t;

static const char *TAG = "keelink";
static bool s_mdns_ready;
static httpd_handle_t s_server;
static SemaphoreHandle_t s_lock;
static TaskHandle_t s_worker;
static uint8_t *s_replay;
static replay_meta_t s_replay_meta[KEELINK_REPLAY_SLOTS];
static uint32_t s_event_id;
static uint64_t s_session_id;
static int s_ws_fd = -1;
static bool s_ws_ready;
static uint32_t s_wss_connect_count;
static bool s_ble_fallback_active;
static uint32_t s_ws_down_since_ms;
static uint32_t s_ble_retry_after_ms;
static bool s_log_subscribed;
static uint32_t s_next_send_id;
static bool s_inventory_dirty;
static uint32_t s_last_heartbeat_ms;
static uint32_t s_last_ws_ping_ms;
static uint32_t s_last_ws_pong_ms;
static command_map_t s_commands[KEELINK_COMMAND_MAP_SLOTS];
static keelink_ble_send_fn s_ble_sender;
static uint32_t s_pair_fail_count;
static uint32_t s_pair_block_until_ms;
static uint32_t s_log_dropped;
static uart_claim_state_t s_uart_claim;

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

static void ws_mark_down(int fd)
{
	lock();
	if (s_ws_fd == fd) {
		s_ws_fd = -1;
		s_ws_ready = false;
		s_log_subscribed = false;
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
	s_ws_down_since_ms = 0;
	s_ble_fallback_active = false;
	s_log_subscribed = false;
	unlock();
	if (fd >= 0 && s_server) httpd_sess_trigger_close(s_server, fd);
	keelink_ble_disable();
}

static int hex_nibble(char value)
{
	if (value >= '0' && value <= '9') return value - '0';
	if (value >= 'a' && value <= 'f') return value - 'a' + 10;
	if (value >= 'A' && value <= 'F') return value - 'A' + 10;
	return -1;
}

static bool decode_hex(const char *text, uint8_t *out, size_t out_len)
{
	if (!text || !out) return false;
	for (size_t i = 0; i < out_len; i++) {
		int high = hex_nibble(text[i * 2]);
		int low = hex_nibble(text[i * 2 + 1]);
		if (high < 0 || low < 0) return false;
		out[i] = (uint8_t)((high << 4) | low);
	}
	return true;
}

static void encode_hex(const uint8_t *bytes, size_t len, char *out)
{
	static const char digits[] = "0123456789abcdef";
	for (size_t i = 0; i < len; i++) {
		out[i * 2] = digits[bytes[i] >> 4];
		out[i * 2 + 1] = digits[bytes[i] & 0x0f];
	}
	out[len * 2] = '\0';
}

static void uart_claim_state_reset(void)
{
	mbedtls_platform_zeroize(&s_uart_claim, sizeof(s_uart_claim));
}

static esp_err_t uart_claim_commit(const uint8_t nonce[16], const char token_b64[45],
				   uint8_t proof[32])
{
	static const uint8_t context[] = "KeeLink UART claim v1";
	uint8_t token[32] = {0};
	uint8_t token_hash[32] = {0};
	uint8_t root_mac[6] = {0};
	uint8_t proof_input[(sizeof(context) - 1U) + 16U + sizeof(root_mac)];
	size_t token_len = 0;
	esp_err_t err = ESP_FAIL;

	if (mbedtls_base64_decode(token, sizeof(token), &token_len,
		(const unsigned char *)token_b64, 44U) != 0 ||
	    token_len != sizeof(token) ||
	    sha256(token, sizeof(token), token_hash) != ESP_OK ||
	    esp_wifi_get_mac(WIFI_IF_STA, root_mac) != ESP_OK) {
		goto done;
	}
	memcpy(proof_input, context, sizeof(context) - 1U);
	memcpy(proof_input + sizeof(context) - 1U, nonce, 16U);
	memcpy(proof_input + sizeof(context) - 1U + 16U, root_mac, sizeof(root_mac));
	const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!info || mbedtls_md_hmac(info, token, sizeof(token), proof_input,
				     sizeof(proof_input), proof) != 0 ||
	    token_hash_store(token_hash) != ESP_OK) {
		goto done;
	}

	authenticated_sessions_close();
	lock();
	s_pair_fail_count = 0;
	s_pair_block_until_ms = 0;
	unlock();
	err = ESP_OK;

done:
	mbedtls_platform_zeroize(token, sizeof(token));
	mbedtls_platform_zeroize(token_hash, sizeof(token_hash));
	mbedtls_platform_zeroize(root_mac, sizeof(root_mac));
	mbedtls_platform_zeroize(proof_input, sizeof(proof_input));
	return err;
}

static bool uart_claim_handle_compact(const char *line, char *response,
				      size_t response_capacity)
{
	const size_t line_len = strlen(line);
	if (line_len < 13U || strncmp(line, KEELINK_UART_COMPACT_PREFIX,
					 sizeof(KEELINK_UART_COMPACT_PREFIX) - 1U) != 0) {
		return false;
	}
	if (!response || response_capacity == 0) return true;
	response[0] = '\0';
	if (line[8] != ':' || line[11] != ':' || hex_nibble(line[4]) < 0 ||
	    hex_nibble(line[5]) < 0 || hex_nibble(line[6]) < 0 ||
	    hex_nibble(line[7]) < 0) {
		return true;
	}

	char session[5];
	memcpy(session, line + 4, 4);
	session[4] = '\0';
	const uint32_t now = now_ms();
	if (s_uart_claim.updated_ms == 0 ||
	    (uint32_t)(now - s_uart_claim.updated_ms) > KEELINK_UART_COMPACT_TIMEOUT_MS ||
	    strcmp(s_uart_claim.session, session) != 0) {
		uart_claim_state_reset();
		memcpy(s_uart_claim.session, session, sizeof(session));
	}
	s_uart_claim.updated_ms = now;

	const char group = line[9];
	const char part = line[10];
	const char *chunk = line + 12;
	const size_t chunk_len = line_len - 12U;
	uint8_t bit = 0;
	if (group == 'N' && (part == '0' || part == '1') && chunk_len == 12U) {
		const unsigned index = (unsigned)(part - '0');
		memcpy(s_uart_claim.nonce_b64 + index * 12U, chunk, 12U);
		bit = (uint8_t)(1U << index);
	} else if (group == 'T' && part >= '0' && part <= '3' && chunk_len == 11U) {
		const unsigned index = (unsigned)(part - '0');
		memcpy(s_uart_claim.token_b64 + index * 11U, chunk, 11U);
		bit = (uint8_t)(1U << (index + 2U));
	} else {
		snprintf(response, response_capacity, "KC1:%s:E:rejected", session);
		uart_claim_state_reset();
		return true;
	}
	s_uart_claim.received_mask |= bit;
	if (s_uart_claim.received_mask != 0x3fU) {
		snprintf(response, response_capacity, "KC1:%s:A:%c%c", session, group, part);
		return true;
	}

	uint8_t nonce[16] = {0};
	uint8_t proof[32] = {0};
	unsigned char proof_b64[45] = {0};
	size_t nonce_len = 0;
	size_t proof_len = 0;
	if (mbedtls_base64_decode(nonce, sizeof(nonce), &nonce_len,
		(const unsigned char *)s_uart_claim.nonce_b64, 24U) != 0 ||
	    nonce_len != sizeof(nonce) ||
	    uart_claim_commit(nonce, s_uart_claim.token_b64, proof) != ESP_OK ||
	    mbedtls_base64_encode(proof_b64, sizeof(proof_b64), &proof_len,
		proof, sizeof(proof)) != 0 || proof_len != 44U) {
		snprintf(response, response_capacity, "KC1:%s:E:rejected", session);
	} else {
		const int written = snprintf(response, response_capacity,
			"KC1:%s:A:%c%c\nKC1:%s:P0:%.*s\nKC1:%s:P1:%.*s\n"
			"KC1:%s:P2:%.*s\nKC1:%s:P3:%.*s",
			session, group, part, session, 11, proof_b64,
			session, 11, proof_b64 + 11,
			session, 11, proof_b64 + 22, session, 11, proof_b64 + 33);
		if (written < 0 || written >= (int)response_capacity) {
			(void)token_revoke();
			response[0] = '\0';
		}
	}
	mbedtls_platform_zeroize(nonce, sizeof(nonce));
	mbedtls_platform_zeroize(proof, sizeof(proof));
	mbedtls_platform_zeroize(proof_b64, sizeof(proof_b64));
	uart_claim_state_reset();
	return true;
}

bool keelink_server_handle_uart_claim(const char *line, char *response,
				      size_t response_capacity)
{
	if (line && strncmp(line, KEELINK_UART_COMPACT_PREFIX,
			   sizeof(KEELINK_UART_COMPACT_PREFIX) - 1U) == 0) {
		return uart_claim_handle_compact(line, response, response_capacity);
	}
	const size_t prefix_len = sizeof(KEELINK_UART_CLAIM_PREFIX) - 1U;
	if (!line || strncmp(line, KEELINK_UART_CLAIM_PREFIX, prefix_len) != 0) {
		return false;
	}
	if (!response || response_capacity == 0) return true;
	response[0] = '\0';
	const char *payload = line + prefix_len;
	if (strlen(payload) != 32U + 1U + 44U || payload[32] != ':') {
		snprintf(response, response_capacity, "%s", KEELINK_UART_CLAIM_ERROR);
		return true;
	}

	uint8_t nonce[16] = {0};
	uint8_t proof[32] = {0};
	esp_err_t err = ESP_FAIL;

	if (!decode_hex(payload, nonce, sizeof(nonce)) ||
	    uart_claim_commit(nonce, payload + 33, proof) != ESP_OK) {
		goto done;
	}
	char nonce_hex[33];
	char proof_hex[65];
	encode_hex(nonce, sizeof(nonce), nonce_hex);
	encode_hex(proof, sizeof(proof), proof_hex);
	if (snprintf(response, response_capacity, "%s%s:%s",
		     KEELINK_UART_CLAIM_OK_PREFIX, nonce_hex, proof_hex) >=
	    (int)response_capacity) {
		(void)token_revoke();
		response[0] = '\0';
		goto done;
	}
	err = ESP_OK;

done:
	if (err != ESP_OK && response[0] == '\0') {
		snprintf(response, response_capacity, "%s", KEELINK_UART_CLAIM_ERROR);
	}
	mbedtls_platform_zeroize(nonce, sizeof(nonce));
	mbedtls_platform_zeroize(proof, sizeof(proof));
	return true;
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

static uint32_t replay_append(uint8_t kind, uint16_t channel, uint32_t correlation_id,
			      const uint8_t *payload, size_t payload_len, uint8_t priority)
{
	uint32_t id;
	lock();
	uint32_t backlog = s_next_send_id <= s_event_id
		? s_event_id - s_next_send_id + 1U : 0U;
	if (priority == KEELINK_PRIORITY_LOG && s_ws_ready &&
	    backlog >= KEELINK_LOG_BACKLOG_HIGH) {
		s_log_dropped++;
		unlock();
		if (s_worker) xTaskNotifyGive(s_worker);
		return 0;
	}
	id = ++s_event_id;
	size_t slot = id % KEELINK_REPLAY_SLOTS;
	uint8_t *frame = s_replay + slot * KEELINK_MAX_FRAME;
	size_t frame_len = 0;
	if (encode_frame(frame, KEELINK_MAX_FRAME, kind, channel, id, correlation_id,
			 payload, payload_len, &frame_len) != ESP_OK) {
		id = 0;
	} else {
		s_replay_meta[slot].id = id;
		s_replay_meta[slot].len = (uint16_t)frame_len;
		s_replay_meta[slot].priority = priority;
	}
	unlock();
	if (id && s_worker) xTaskNotifyGive(s_worker);
	return id;
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

static esp_err_t send_gap_sync(int fd, uint32_t first, uint32_t last)
{
	uint8_t payload[32];
	uint8_t frame[KEEMASH_KEELINK_HEADER_SIZE + sizeof(payload)];
	size_t frame_len = 0;
	keemash_keelink_writer_t writer;
	keemash_keelink_writer_init(&writer, payload, sizeof(payload));
	(void)keemash_keelink_put_u32(&writer, KL_FIELD_GAP_FIRST, first);
	(void)keemash_keelink_put_u32(&writer, KL_FIELD_GAP_LAST, last);
	esp_err_t err = encode_frame(frame, sizeof(frame), KEEMASH_KEELINK_GAP,
		KEEMASH_KEELINK_CH_SYSTEM, 0, 0, payload, writer.length, &frame_len);
	return err == ESP_OK ? ws_send_sync(fd, frame, frame_len) : err;
}

static void publish_log_backpressure_gap(uint32_t dropped)
{
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

static void publish_inventory_snapshot(void)
{
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
		uint32_t backlog = s_next_send_id <= s_event_id
			? s_event_id - s_next_send_id + 1U : 0U;
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
			s_log_subscribed = false;
			s_ws_down_since_ms = now - KEELINK_BLE_FALLBACK_DELAY_MS;
		} else if (s_ws_ready && s_ws_fd >= 0 &&
			   (uint32_t)(now - s_last_ws_ping_ms) >= KEELINK_WS_PING_MS) {
			ping_due = true;
			s_last_ws_ping_ms = now;
		}
		int ping_fd = s_ws_fd;
		unlock();
		if (stale_fd >= 0) {
			ESP_LOGW(TAG, "WSS pong timeout fd=%d", stale_fd);
			httpd_sess_trigger_close(s_server, stale_fd);
		} else if (ping_due) {
			esp_err_t ping_err = ws_send_ping(ping_fd, now);
			if (ping_err != ESP_OK) ws_mark_down(ping_fd);
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
			esp_err_t heartbeat_err = encode_frame(frame, sizeof(frame),
				KEEMASH_KEELINK_HEARTBEAT, KEEMASH_KEELINK_CH_SYSTEM,
				0, 0, payload, writer.length, &frame_len);
			if (heartbeat_err == ESP_OK) heartbeat_err = ws_send_sync(fd, frame, frame_len);
			lock();
			s_last_heartbeat_ms = now;
			if (heartbeat_err != ESP_OK && s_ws_fd == fd) {
				s_ws_fd = -1;
				s_ws_ready = false;
				s_log_subscribed = false;
				s_ws_down_since_ms = now;
			}
			unlock();
		}

		for (;;) {
			uint8_t *copy = NULL;
			size_t len = 0;
			uint32_t id = 0;
			lock();
			if (!s_ws_ready || s_ws_fd < 0 || s_next_send_id > s_event_id) {
				unlock();
				break;
			}
			uint32_t oldest = s_event_id >= KEELINK_REPLAY_SLOTS
				? s_event_id - KEELINK_REPLAY_SLOTS + 1 : 1;
			if (s_next_send_id < oldest) {
				uint32_t lost_first = s_next_send_id;
				s_next_send_id = oldest;
				fd = s_ws_fd;
				unlock();
				esp_err_t gap_err = send_gap_sync(fd, lost_first, oldest - 1);
				if (gap_err != ESP_OK) {
					lock();
					if (s_ws_fd == fd) {
						s_ws_fd = -1;
						s_ws_ready = false;
						s_log_subscribed = false;
						s_ws_down_since_ms = now_ms();
					}
					unlock();
					break;
				}
				continue;
			}
			id = s_next_send_id;
			size_t slot = id % KEELINK_REPLAY_SLOTS;
			if (s_replay_meta[slot].id != id || s_replay_meta[slot].len == 0) {
				s_next_send_id++;
				unlock();
				continue;
			}
			len = s_replay_meta[slot].len;
			copy = heap_caps_malloc(len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
			if (copy) memcpy(copy, s_replay + slot * KEELINK_MAX_FRAME, len);
			fd = s_ws_fd;
			unlock();
			if (!copy) break;
			esp_err_t err = ws_send_sync(fd, copy, len);
			free(copy);
			lock();
			if (err == ESP_OK && s_ws_fd == fd && s_next_send_id == id) {
				s_next_send_id++;
			} else if (err != ESP_OK && s_ws_fd == fd) {
				ESP_LOGW(TAG, "WSS send failed: %s", esp_err_to_name(err));
				s_ws_fd = -1;
				s_ws_ready = false;
				s_log_subscribed = false;
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
	s_ws_fd = fd;
	s_ws_ready = false;
	s_wss_connect_count++;
	s_ws_down_since_ms = 0;
	s_ble_fallback_active = false;
	s_ble_retry_after_ms = 0;
	s_last_ws_ping_ms = now_ms();
	s_last_ws_pong_ms = s_last_ws_ping_ms;
	s_log_subscribed = false;
	s_next_send_id = s_event_id + 1;
	unlock();
	keelink_ble_disable();
	if (old_fd >= 0 && old_fd != fd) httpd_sess_trigger_close(req->handle, old_fd);
	ESP_LOGI(TAG, "authenticated WSS client connected fd=%d", fd);
	return ESP_OK;
}

static void command_map_add(uint32_t command_id, uint32_t correlation_id, bool ble)
{
	lock();
	size_t chosen = KEELINK_COMMAND_MAP_SLOTS;
	uint32_t oldest = UINT32_MAX;
	for (size_t i = 0; i < KEELINK_COMMAND_MAP_SLOTS; i++) {
		if (!s_commands[i].used) {
			chosen = i;
			break;
		}
		if (s_commands[i].created_ms < oldest) {
			oldest = s_commands[i].created_ms;
			chosen = i;
		}
	}
	if (chosen < KEELINK_COMMAND_MAP_SLOTS) {
		s_commands[chosen] = (command_map_t){
			.used = true,
			.ble = ble,
			.command_id = command_id,
			.correlation_id = correlation_id,
			.created_ms = now_ms(),
		};
	}
	unlock();
}

static bool command_map_take(uint32_t command_id, uint32_t *correlation_id,
			     bool *ble)
{
	bool found = false;
	lock();
	for (size_t i = 0; i < KEELINK_COMMAND_MAP_SLOTS; i++) {
		if (s_commands[i].used && s_commands[i].command_id == command_id) {
			if (correlation_id) *correlation_id = s_commands[i].correlation_id;
			if (ble) *ble = s_commands[i].ble;
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
	command_map_add(command_id, header->correlation_id, false);
	esp_err_t err = mesh_root_submit_direct_command(mac, command, command_id);
	if (err != ESP_OK) {
		uint32_t ignored;
		(void)command_map_take(command_id, &ignored, NULL);
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
		lock();
		if (s_ws_fd == httpd_req_to_sockfd(req)) s_last_ws_pong_ms = now_ms();
		unlock();
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
		uint32_t oldest = s_event_id >= KEELINK_REPLAY_SLOTS
			? s_event_id - KEELINK_REPLAY_SLOTS + 1 : 1;
		s_ws_ready = err == ESP_OK;
		s_next_send_id = last_event + 1;
		if (s_next_send_id < oldest) s_next_send_id = s_event_id + 1;
		bool needs_snapshot = last_event == 0 || last_event + 1 < oldest;
		unlock();
		if (needs_snapshot) {
			if (last_event && last_event + 1 < oldest) publish_gap(last_event + 1, oldest - 1);
			keelink_server_publish_inventory();
		}
		if (s_worker) xTaskNotifyGive(s_worker);
	} else if (header.kind == KEEMASH_KEELINK_REQUEST &&
		   header.channel == KEEMASH_KEELINK_CH_CONTROL) {
		err = handle_control_request(req, &header, payload);
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
	char body[640];
	bool wss_active;
	uint32_t wss_connect_count;
	bool ble_fallback_active;
	uint32_t ws_down_age_ms;
	lock();
	wss_active = s_ws_ready && s_ws_fd >= 0;
	wss_connect_count = s_wss_connect_count;
	ble_fallback_active = s_ble_fallback_active;
	ws_down_age_ms = s_ws_down_since_ms ? now_ms() - s_ws_down_since_ms : 0;
	unlock();
	snprintf(body, sizeof(body),
		"{\"protocol\":\"KeeLink\",\"version\":1,\"root_mac\":\"%s\","
		"\"paired\":%s,\"wss\":true,\"wss_active\":%s,"
		"\"wss_seen\":%s,\"wss_connect_count\":%" PRIu32 ","
		"\"ws_down_age_ms\":%" PRIu32 ","
		"\"ble_fallback_active\":%s,\"ble\":%s,"
		"\"ble_state\":\"%s\",\"ble_error\":%d,"
		"\"ble_boot_checkpoint\":%" PRIu32 ",\"reset_reason\":%d,"
		"\"tls_public_key_sha256\":\"%s\",\"max_frame\":%u}",
		mac_text, paired ? "true" : "false", wss_active ? "true" : "false",
		wss_connect_count ? "true" : "false", wss_connect_count, ws_down_age_ms,
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
	if (!s_replay) {
		vSemaphoreDelete(s_lock);
		s_lock = NULL;
		return ESP_ERR_NO_MEM;
	}
	s_session_id = ((uint64_t)esp_random() << 32) | esp_random();
	if (xTaskCreateWithCaps(worker_task, "keelink_tx", KEELINK_WORKER_STACK, NULL, 5,
		&s_worker, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) != pdPASS) {
		free(s_replay);
		s_replay = NULL;
		vSemaphoreDelete(s_lock);
		s_lock = NULL;
		return ESP_ERR_NO_MEM;
	}
	ESP_LOGI(TAG, "KeeLink v1 ready, replay=%u bytes in PSRAM",
		(unsigned)(KEELINK_REPLAY_SLOTS * KEELINK_MAX_FRAME));
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

void keelink_server_publish_log(const uint8_t mac[6], const char *tag, const char *line)
{
	lock();
	bool enabled = s_log_subscribed;
	unlock();
	if (enabled) publish_text_event_priority(KEEMASH_KEELINK_CH_LOG, mac, tag,
		line, KEELINK_PRIORITY_LOG);
}

void keelink_server_command_result(uint32_t command_id, uint8_t status, const char *text)
{
	uint32_t correlation_id;
	bool ble = false;
	if (!command_map_take(command_id, &correlation_id, &ble)) return;
	uint8_t payload[256];
	keemash_keelink_writer_t writer;
	keemash_keelink_writer_init(&writer, payload, sizeof(payload));
	(void)keemash_keelink_put_u32(&writer, KL_FIELD_STATUS, status);
	(void)keemash_keelink_put_u32(&writer, KL_FIELD_COMMAND_ID, command_id);
	(void)keemash_keelink_put_utf8(&writer, KL_FIELD_TEXT, text ? text : "");
	if (ble && s_ble_sender) {
		uint8_t frame[KEEMASH_KEELINK_HEADER_SIZE + sizeof(payload)];
		size_t frame_len = 0;
		if (encode_frame(frame, sizeof(frame), KEEMASH_KEELINK_RESPONSE,
			KEEMASH_KEELINK_CH_CONTROL, 0, correlation_id, payload,
			writer.length, &frame_len) == ESP_OK) {
			(void)s_ble_sender(frame, frame_len);
		}
	} else {
		(void)replay_append(KEEMASH_KEELINK_RESPONSE,
			KEEMASH_KEELINK_CH_CONTROL, correlation_id,
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
		command_map_add(command_id, header.correlation_id, true);
		err = mesh_root_submit_direct_command(mac, command, command_id);
		if (err != ESP_OK) {
			uint32_t ignored;
			(void)command_map_take(command_id, &ignored, NULL);
			return err;
		}
		return ESP_OK;
	}
	return ESP_ERR_NOT_SUPPORTED;
}
