#include <stdbool.h>
#include <string.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_mesh.h"
#include "sdkconfig.h"

#include "mesh_root_bcast.h"
#include "mesh_v2_link.h"


static const char *TAG = "root_bcast";
static uint32_t s_command_id = 1;

static bool starts_with(const char *text, const char *prefix)
{
	return text && prefix && strncmp(text, prefix, strlen(prefix)) == 0;
}

static const char *command_owner(const char *payload)
{
	if (!payload) return NULL;
	if (starts_with(payload, "garland") || starts_with(payload, "garl")) return "garland";
	if (starts_with(payload, "powled") || strcmp(payload, "pwech") == 0) return "kPowerLed";
	if (strcmp(payload, "pomp") == 0 || strcmp(payload, "flow") == 0 ||
	    strcmp(payload, "ion") == 0 || strcmp(payload, "huOn") == 0 ||
	    strcmp(payload, "echo_turb") == 0 || strcmp(payload, "pm1") == 0 ||
	    starts_with(payload, "14") || starts_with(payload, "18") ||
	    starts_with(payload, "19")) return "humidifier";
	if (strcmp(payload, "readtds") == 0) return "Keetds";
	return NULL;
}
static uint32_t s_root_cnt = 1000000;

void mesh_root_broadcast_text(const char *payload)
{
	if (!esp_mesh_is_root()) {
		ESP_LOGW(TAG, "called but this node is not ROOT, skip");
		return;
	}

	if (!payload || !payload[0]) {
		return;
	}

	const char *owner = command_owner(payload);
	if (owner) {
		uint8_t owner_mac[6] = {0};
		if (mesh_v2_root_find_ready_by_tag(owner, owner_mac)) {
			uint32_t command_id = s_command_id++;
			if (s_command_id == 0) s_command_id = 1;
			esp_err_t rel_err = mesh_v2_root_send_command(owner_mac, command_id, payload);
			if (rel_err == ESP_OK) {
				ESP_LOGI(TAG, "reliable command id=%lu owner=%s payload=\"%s\"",
				         (unsigned long)command_id, owner, payload);
				return;
			}
			ESP_LOGW(TAG, "reliable command fallback owner=%s err=%s",
			         owner, esp_err_to_name(rel_err));
		}
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
		err = esp_mesh_send(&route_table[i], &data, MESH_DATA_P2P, NULL, 0);
		if (err != ESP_OK) {
			ESP_LOGE(TAG,
			         "send[%d] failed: 0x%x (%s)",
			         i, err, esp_err_to_name(err));
		}
	}
}
