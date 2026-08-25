#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_mesh.h"
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "mesh_root_bcast.h"
#include "mesh_v2_link.h"
#include "keemash_mesh_root.h"
#include "keelink_server.h"
#include "log_http_server.h"
#include "uart_bridge.h"

static const char *TAG = "root_bcast";
#define COMMAND_PENDING_SLOTS 16
#define COMMAND_RESULT_TIMEOUT_MS \
	((uint32_t)CONFIG_KEEMASH_REL_ROUTE_GRACE_MS + 15000U)

typedef struct {
	bool used;
	uint8_t peer[6];
	uint32_t root_session;
	uint32_t command_id;
	uint32_t queued_ms;
	char owner[16];
} pending_command_t;

static portMUX_TYPE s_pending_lock = portMUX_INITIALIZER_UNLOCKED;
static pending_command_t s_pending[COMMAND_PENDING_SLOTS];
static TaskHandle_t s_pending_task;

static bool starts_with(const char *text, const char *prefix)
{
	return text && prefix && strncmp(text, prefix, strlen(prefix)) == 0;
}

static bool strict_number_in_range(const char *text, float minimum, float maximum)
{
	if (!text || !text[0]) return false;
	errno = 0;
	char *end = NULL;
	float value = strtof(text, &end);
	return errno == 0 && end != text && end && *end == '\0' &&
	       isfinite(value) && value >= minimum && value <= maximum;
}

static bool parse_hex_field(const char *text, size_t offset, size_t digits,
			    uint32_t *value)
{
	if (!text || !value || digits == 0 || digits > 8) return false;
	uint32_t parsed = 0;
	for (size_t i = 0; i < digits; i++) {
		char c = text[offset + i];
		uint8_t nibble;
		if (c >= '0' && c <= '9') nibble = (uint8_t)(c - '0');
		else if (c >= 'a' && c <= 'f') nibble = (uint8_t)(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F') nibble = (uint8_t)(c - 'A' + 10);
		else return false;
		parsed = (parsed << 4) | nibble;
	}
	*value = parsed;
	return true;
}

static bool is_heater_schedule_command(const char *payload)
{
	if (!payload || strncmp(payload, "S5", 2) != 0) return false;
	size_t length = strlen(payload);
	uint32_t generation = 0;
	if (strcmp(payload, "S5Q") == 0) return true;
	if (length == 4 && strncmp(payload, "S5Q", 3) == 0) {
		uint32_t index = 0;
		return parse_hex_field(payload, 3, 1, &index) && index < 8;
	}
	if (length == 11 && strncmp(payload, "S5C", 3) == 0) {
		return parse_hex_field(payload, 3, 8, &generation) && generation != 0;
	}
	if (length == 14 && strncmp(payload, "S5B", 3) == 0) {
		uint32_t count = 0, enabled = 0, persist = 0;
		return parse_hex_field(payload, 3, 8, &generation) && generation != 0 &&
		       parse_hex_field(payload, 11, 1, &count) && count <= 8 &&
		       parse_hex_field(payload, 12, 1, &enabled) && enabled <= 1 &&
		       parse_hex_field(payload, 13, 1, &persist) && persist <= 1;
	}
	if (length == 22 && strncmp(payload, "S5P", 3) == 0) {
		uint32_t index = 0, enabled = 0, minute = 0;
		uint32_t target = 0, action = 0, days = 0;
		return parse_hex_field(payload, 3, 8, &generation) && generation != 0 &&
		       parse_hex_field(payload, 11, 1, &index) && index < 8 &&
		       parse_hex_field(payload, 12, 1, &enabled) && enabled <= 1 &&
		       parse_hex_field(payload, 13, 3, &minute) && minute < 24U * 60U &&
		       parse_hex_field(payload, 16, 3, &target) &&
		       target >= 50 && target <= 350 &&
		       parse_hex_field(payload, 19, 1, &action) && action <= 6 &&
		       parse_hex_field(payload, 20, 2, &days) && days != 0 && days <= 0x7f;
	}
	return false;
}

static bool is_power_schedule_command(const char *payload)
{
	if (!payload || strncmp(payload, "PS", 2) != 0) return false;
	size_t length = strlen(payload);
	uint32_t generation = 0;
	if (strcmp(payload, "PSQ") == 0) return true;
	if (length == 4 && strncmp(payload, "PSQ", 3) == 0) {
		uint32_t index = 0;
		return parse_hex_field(payload, 3, 1, &index) && index < 8;
	}
	if (length == 11 && strncmp(payload, "PSC", 3) == 0) {
		return parse_hex_field(payload, 3, 8, &generation) && generation != 0;
	}
	if (length == 14 && strncmp(payload, "PSB", 3) == 0) {
		uint32_t count = 0, enabled = 0, persist = 0;
		return parse_hex_field(payload, 3, 8, &generation) && generation != 0 &&
		       parse_hex_field(payload, 11, 1, &count) && count <= 8 &&
		       parse_hex_field(payload, 12, 1, &enabled) && enabled <= 1 &&
		       parse_hex_field(payload, 13, 1, &persist) && persist <= 1;
	}
	if (length == 19 && strncmp(payload, "PSP", 3) == 0) {
		uint32_t index = 0, enabled = 0, minute = 0, action = 0, days = 0;
		return parse_hex_field(payload, 3, 8, &generation) && generation != 0 &&
		       parse_hex_field(payload, 11, 1, &index) && index < 8 &&
		       parse_hex_field(payload, 12, 1, &enabled) && enabled <= 1 &&
		       parse_hex_field(payload, 13, 3, &minute) && minute < 24U * 60U &&
		       parse_hex_field(payload, 16, 1, &action) && action <= 1 &&
		       parse_hex_field(payload, 17, 2, &days) &&
		       days != 0 && days <= 0x7f;
	}
	return false;
}

static bool is_heater_command(const char *payload)
{
	if (!payload) return false;
	if (is_heater_schedule_command(payload)) return true;
	if (strcmp(payload, "hero") == 0 || strcmp(payload, "heho") == 0 ||
	    strcmp(payload, "heater.status") == 0) {
		return true;
	}
	if (strlen(payload) == 3 && payload[0] == 'h' && payload[1] == 'e' &&
	    payload[2] >= '0' && payload[2] <= '5') {
		return true;
	}
	if (starts_with(payload, "W5")) {
		return strict_number_in_range(payload + 2, 5.0f, 35.0f);
	}
	if (strlen(payload) == 3 && payload[0] == 'P' && payload[1] == '5' &&
	    (payload[2] == '0' || payload[2] == '1')) {
		return true;
	}
	if (starts_with(payload, "05")) {
		return strict_number_in_range(payload + 2, -40.0f, 80.0f);
	}
	return false;
}

static const char *command_owner(const char *payload)
{
	if (!payload) return NULL;
	if (is_heater_command(payload)) return "Kheater";
	if (is_power_schedule_command(payload)) return "kPowerLed";
	if (starts_with(payload, "garland") || starts_with(payload, "garl")) return "garland";
	if (starts_with(payload, "powled") || strcmp(payload, "pwech") == 0) return "kPowerLed";
	if (strcmp(payload, "lam") == 0 || strcmp(payload, "lamech") == 0 ||
	    strcmp(payload, "lampk.status") == 0) return "lampk";
	if (strcmp(payload, "pomp") == 0 || strcmp(payload, "flow") == 0 ||
	    strcmp(payload, "ion") == 0 || strcmp(payload, "huOn") == 0 ||
	    strcmp(payload, "echo_turb") == 0 || strcmp(payload, "pm1") == 0 ||
	    starts_with(payload, "14") || starts_with(payload, "18") ||
	    starts_with(payload, "19")) return "humidifier";
	if (strcmp(payload, "readtds") == 0) return "Keetds";
	if (strcmp(payload, "choinka.status") == 0) return "choinka";
	if (strcmp(payload, "ppm_echo") == 0 ||
	    strcmp(payload, "temp_echo") == 0 ||
	    strcmp(payload, "humi_echo") == 0 ||
	    strcmp(payload, "lux_echo") == 0 ||
	    strcmp(payload, "sens_echo") == 0 ||
	    starts_with(payload, "mixer.weather:")) return "esp_mixer";
	return NULL;
}
static uint32_t s_root_cnt = 1000000;

static uint32_t now_ms(void)
{
	return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

static void command_feedback(const char *code, const char *owner,
			     uint32_t command_id, const char *detail)
{
	char token[48];
	snprintf(token, sizeof(token), "ERR:%s:%s", code, owner);
	uart_bridge_send_line(token);
	log_http_server_command_status(
		strcmp(code, "OFFLINE") == 0 ? "offline" :
		strcmp(code, "TIMEOUT") == 0 ? "timeout" : "rejected",
		owner, command_id, detail);
	ESP_LOGW(TAG, "%s id=%lu detail=%s", token,
		 (unsigned long)command_id, detail ? detail : "");
}

static void pending_task(void *arg)
{
	(void)arg;
	for (;;) {
		vTaskDelay(pdMS_TO_TICKS(250));
		pending_command_t expired[COMMAND_PENDING_SLOTS];
		size_t count = 0;
		uint32_t now = now_ms();
		portENTER_CRITICAL(&s_pending_lock);
		for (size_t i = 0; i < COMMAND_PENDING_SLOTS; i++) {
			if (s_pending[i].used &&
			    (uint32_t)(now - s_pending[i].queued_ms) >=
				    COMMAND_RESULT_TIMEOUT_MS) {
				expired[count++] = s_pending[i];
				memset(&s_pending[i], 0, sizeof(s_pending[i]));
			}
		}
		portEXIT_CRITICAL(&s_pending_lock);
		for (size_t i = 0; i < count; i++) {
			keelink_server_command_result(expired[i].command_id,
				MESH_V2_CONTROL_STATUS_FAILED, "result timeout");
			command_feedback("TIMEOUT", expired[i].owner,
					 expired[i].command_id, "result timeout");
		}
	}
}

static bool ensure_pending_task(void)
{
	if (s_pending_task) return true;
	if (xTaskCreate(pending_task, "cmd_pending", 3072, NULL, 4,
			&s_pending_task) != pdPASS) {
		s_pending_task = NULL;
		ESP_LOGE(TAG, "failed to start command result tracker");
		return false;
	}
	return true;
}

static bool pending_add(const uint8_t peer[6], uint32_t root_session,
			uint32_t command_id, const char *owner)
{
	bool added = false;
	portENTER_CRITICAL(&s_pending_lock);
	for (size_t i = 0; i < COMMAND_PENDING_SLOTS; i++) {
		if (!s_pending[i].used) {
			s_pending[i].used = true;
			memcpy(s_pending[i].peer, peer, 6);
			s_pending[i].root_session = root_session;
			s_pending[i].command_id = command_id;
			s_pending[i].queued_ms = now_ms();
			snprintf(s_pending[i].owner, sizeof(s_pending[i].owner),
				 "%s", owner);
			added = true;
			break;
		}
	}
	portEXIT_CRITICAL(&s_pending_lock);
	return added;
}

static bool pending_take(const uint8_t peer[6], uint32_t root_session,
			 uint32_t command_id, pending_command_t *out)
{
	pending_command_t found = {0};
	portENTER_CRITICAL(&s_pending_lock);
	for (size_t i = 0; i < COMMAND_PENDING_SLOTS; i++) {
		if (s_pending[i].used &&
		    memcmp(s_pending[i].peer, peer, 6) == 0 &&
		    s_pending[i].command_id == command_id &&
		    (s_pending[i].root_session == 0 ||
		     root_session == s_pending[i].root_session)) {
			found = s_pending[i];
			memset(&s_pending[i], 0, sizeof(s_pending[i]));
			break;
		}
	}
	portEXIT_CRITICAL(&s_pending_lock);
	if (out) *out = found;
	return found.used;
}

static esp_err_t send_v1_text(const uint8_t dst[6], const char *payload)
{
	mesh_packet_t pkt = {0};
	pkt.magic = MESH_PKT_MAGIC;
	pkt.version = MESH_PKT_VERSION;
	pkt.type = MESH_PKT_TYPE_TEXT;
	pkt.counter = s_root_cnt++;
	esp_wifi_get_mac(WIFI_IF_STA, pkt.src_mac);
	strncpy(pkt.payload, payload, sizeof(pkt.payload) - 1);
	return mesh_v2_link_send(dst, &pkt, sizeof(pkt),
				 KEEMASH_REL_PRIORITY_CONTROL);
}

esp_err_t mesh_root_send_state_to_mixer(const char *legacy_token)
{
	if (!legacy_token || !legacy_token[0]) return ESP_ERR_INVALID_ARG;
	uint8_t mixer_mac[6] = {0};
	if (!mesh_v2_root_find_lossless_by_tag(
		    "esp_mixer", mixer_mac, MESH_V2_CAP_TYPED_CONTROL)) {
		return ESP_ERR_NOT_FOUND;
	}

	char command[MESH_V2_CONTROL_TEXT_MAX];
	int n = snprintf(command, sizeof(command), "state:%s", legacy_token);
	if (n <= 0 || (size_t)n >= sizeof(command)) return ESP_ERR_INVALID_SIZE;
	return mesh_v2_root_send_command(
		mixer_mac, mesh_v2_root_next_command_id(), command);
}

void mesh_root_broadcast_text(const char *payload)
{
	if (!esp_mesh_is_root()) {
		ESP_LOGW(TAG, "called but this node is not ROOT, skip");
		return;
	}

	if (!payload || !payload[0]) {
		return;
	}
	if (starts_with(payload, "PS") && !is_power_schedule_command(payload)) {
		command_feedback("REJECTED", "kPowerLed", 0,
				 "invalid power schedule payload");
		return;
	}
	if ((starts_with(payload, "W5") &&
	     !strict_number_in_range(payload + 2, 5.0f, 35.0f)) ||
	    (starts_with(payload, "05") &&
	     !strict_number_in_range(payload + 2, -40.0f, 80.0f))) {
		command_feedback("REJECTED", "Kheater", 0,
				 "invalid heater numeric payload");
		return;
	}

	const char *owner = command_owner(payload);
	if (owner) {
		if (!ensure_pending_task()) {
			command_feedback("REJECTED", owner, 0,
					 "command result tracker unavailable");
			return;
		}
		uint8_t owner_mac[6] = {0};
		if (mesh_v2_root_find_lossless_by_tag(owner, owner_mac,
						      MESH_V2_CAP_TYPED_CONTROL)) {
			uint32_t command_id = mesh_v2_root_next_command_id();
			mesh_v2_root_stats_t stats = {0};
			(void)mesh_v2_root_stats_for_mac(owner_mac, &stats);
			if (!pending_add(owner_mac, stats.root_session_id,
					 command_id, owner)) {
				command_feedback("REJECTED", owner, command_id,
						 "pending table full");
				return;
			}
			esp_err_t rel_err = mesh_v2_root_send_command(owner_mac, command_id,
							 payload);
			if (rel_err == ESP_OK) {
				log_http_server_command_status("queued", owner, command_id,
							 payload);
				ESP_LOGI(TAG, "reliable command id=%lu owner=%s payload=\"%s\"",
				         (unsigned long)command_id, owner, payload);
			} else {
				(void)pending_take(owner_mac, stats.root_session_id,
						   command_id, NULL);
				command_feedback("REJECTED", owner, command_id,
						 esp_err_to_name(rel_err));
			}
			return;
		}
		if (!log_http_server_find_routable_by_tag(owner, owner_mac)) {
			command_feedback("OFFLINE", owner, 0, "owner route unavailable");
			return;
		}
		if (mesh_v2_root_peer_advertises_lossless(
			    owner_mac, MESH_V2_CAP_TYPED_CONTROL)) {
			command_feedback("OFFLINE", owner, 0,
					 "lossless session not ready");
			return;
		}
		esp_err_t v1_err = send_v1_text(owner_mac, payload);
		if (v1_err != ESP_OK) {
			command_feedback("REJECTED", owner, 0,
					 esp_err_to_name(v1_err));
		} else {
			log_http_server_command_status("queued", owner, 0,
							 "legacy unicast");
		}
		return;
	}

	mesh_packet_t pkt;
	memset(&pkt, 0, sizeof(pkt));

	pkt.magic   = MESH_PKT_MAGIC;
	pkt.version = MESH_PKT_VERSION;
	pkt.type    = MESH_PKT_TYPE_TEXT;
	pkt.counter = s_root_cnt++;

	// Fill root STA MAC for legacy packet routing.
	esp_wifi_get_mac(WIFI_IF_STA, pkt.src_mac);

	// Copy the legacy text command into the fixed packet payload.
	strncpy(pkt.payload, payload, sizeof(pkt.payload) - 1);
	pkt.payload[sizeof(pkt.payload) - 1] = '\0';

	mesh_data_t data = {
		.data  = (uint8_t *)&pkt,
		.size  = sizeof(pkt),
		.proto = MESH_PROTO_BIN,
		.tos   = MESH_TOS_P2P,
	};

	// Collect current ESP-MESH routes.
	mesh_addr_t route_table[CONFIG_MESH_ROUTE_TABLE_SIZE];
	int route_table_size = 0;

	esp_err_t err = esp_mesh_get_routing_table(
		route_table,
		CONFIG_MESH_ROUTE_TABLE_SIZE * sizeof(mesh_addr_t),
		&route_table_size
	);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "esp_mesh_get_routing_table failed: 0x%x (%s)",
		         err, esp_err_to_name(err));
		return;
	}

	if (route_table_size == 0) {
		ESP_LOGW(TAG, "no children in routing table, nothing to broadcast");
		return;
	}

	int target_count = 0;
	for (int i = 0; i < route_table_size; ++i) {
		if (memcmp(route_table[i].addr, pkt.src_mac, 6) != 0) {
			target_count++;
		}
	}

	if (target_count == 0) {
		ESP_LOGW(TAG, "no remote children in routing table, nothing to broadcast");
		return;
	}

	ESP_LOGI(TAG,
	         "ROOT UART BCAST: to %d nodes, payload=\"%s\"",
	         target_count, pkt.payload);

	for (int i = 0; i < route_table_size; ++i) {
		if (memcmp(route_table[i].addr, pkt.src_mac, 6) == 0) {
			continue;
		}
		err = mesh_v2_link_send(route_table[i].addr, data.data, data.size,
					KEEMASH_REL_PRIORITY_CONTROL);
		if (err != ESP_OK) {
			ESP_LOGE(TAG,
			         "send[%d] failed: 0x%x (%s)",
			         i, err, esp_err_to_name(err));
		}
	}
}

esp_err_t mesh_root_submit_direct_command(const uint8_t peer[6],
					  const char *payload,
					  uint32_t command_id)
{
	if (!peer || !payload || !payload[0] || command_id == 0) {
		return ESP_ERR_INVALID_ARG;
	}
	const char *owner = command_owner(payload);
	if (!owner) return ESP_ERR_NOT_SUPPORTED;
	uint8_t owner_mac[6] = {0};
	if (!mesh_v2_root_find_lossless_by_tag(owner, owner_mac,
					      MESH_V2_CAP_TYPED_CONTROL)) {
		return ESP_ERR_NOT_FOUND;
	}
	if (memcmp(owner_mac, peer, sizeof(owner_mac)) != 0) {
		return ESP_ERR_INVALID_ARG;
	}
	if (!ensure_pending_task()) return ESP_ERR_INVALID_STATE;
	mesh_v2_root_stats_t stats = {0};
	(void)mesh_v2_root_stats_for_mac(owner_mac, &stats);
	if (!pending_add(owner_mac, stats.root_session_id, command_id, owner)) {
		return ESP_ERR_NO_MEM;
	}
	esp_err_t err = mesh_v2_root_send_command(owner_mac, command_id, payload);
	if (err != ESP_OK) {
		(void)pending_take(owner_mac, stats.root_session_id, command_id, NULL);
		return err;
	}
	log_http_server_command_status("queued", owner, command_id, payload);
	return ESP_OK;
}

void mesh_root_command_result(const uint8_t peer[6], uint32_t root_session,
			      uint32_t command_id, uint8_t status,
			      const char *text)
{
	pending_command_t found = {0};
	if (!pending_take(peer, root_session, command_id, &found)) return;
	keelink_server_command_result(command_id, status, text);

	if (status == MESH_V2_CONTROL_STATUS_OK) {
		log_http_server_command_status("ok", found.owner, command_id,
					     text ? text : "");
		return;
	}
	if (text && strcmp(text, "power_off") == 0) {
		command_feedback("POWER_OFF", found.owner, command_id, text);
	} else {
		command_feedback("REJECTED", found.owner, command_id,
				 text ? text : "command rejected");
	}
}
