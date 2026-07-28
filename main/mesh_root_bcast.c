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

static bool is_heater_command(const char *payload)
{
	if (!payload) return false;
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
	if (starts_with(payload, "05")) {
		return strict_number_in_range(payload + 2, -40.0f, 80.0f);
	}
	return false;
}

static const char *command_owner(const char *payload)
{
	if (!payload) return NULL;
	if (is_heater_command(payload)) return "Kheater";
	if (starts_with(payload, "garland") || starts_with(payload, "garl")) return "garland";
	if (starts_with(payload, "powled") || strcmp(payload, "pwech") == 0) return "kPowerLed";
	if (strcmp(payload, "pomp") == 0 || strcmp(payload, "flow") == 0 ||
	    strcmp(payload, "ion") == 0 || strcmp(payload, "huOn") == 0 ||
	    strcmp(payload, "echo_turb") == 0 || strcmp(payload, "pm1") == 0 ||
	    starts_with(payload, "14") || starts_with(payload, "18") ||
	    starts_with(payload, "19")) return "humidifier";
	if (strcmp(payload, "readtds") == 0) return "Keetds";
	if (strcmp(payload, "choinka.status") == 0) return "choinka";
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

void mesh_root_broadcast_text(const char *payload)
{
	if (!esp_mesh_is_root()) {
		ESP_LOGW(TAG, "called but this node is not ROOT, skip");
		return;
	}

	if (!payload || !payload[0]) {
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

void mesh_root_command_result(const uint8_t peer[6], uint32_t root_session,
			      uint32_t command_id, uint8_t status,
			      const char *text)
{
	pending_command_t found = {0};
	if (!pending_take(peer, root_session, command_id, &found)) return;

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
