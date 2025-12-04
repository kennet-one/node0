#include <string.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_mesh.h"
#include "sdkconfig.h"     // щоб мати CONFIG_MESH_ROUTE_TABLE_SIZE

#include "mesh_root_bcast.h"

// ВАЖЛИВО: структура й константи повинні збігатись з тим,
// що вже є в mesh_main.c
typedef struct __attribute__((packed)) {
	uint8_t  magic;
	uint8_t  version;
	uint8_t  type;
	uint8_t  reserved;
	uint32_t counter;
	uint8_t  src_mac[6];
	char     payload[32];
} mesh_packet_t;

#define MESH_PKT_MAGIC       0xA5
#define MESH_PKT_VERSION     1
#define MESH_PKT_TYPE_TEXT   1

static const char *TAG = "root_bcast";
static uint32_t s_root_cnt = 1000000;     // окремий лічильник для root

void mesh_root_broadcast_text(const char *payload)
{
	if (!esp_mesh_is_root()) {
		ESP_LOGW(TAG, "called but this node is not ROOT, skip");
		return;
	}

	if (!payload || !payload[0]) {
		return;
	}

	mesh_packet_t pkt;
	memset(&pkt, 0, sizeof(pkt));

	pkt.magic   = MESH_PKT_MAGIC;
	pkt.version = MESH_PKT_VERSION;
	pkt.type    = MESH_PKT_TYPE_TEXT;
	pkt.counter = s_root_cnt++;

	// MAC root-ноди
	esp_wifi_get_mac(WIFI_IF_STA, pkt.src_mac);

	// Копіюємо рядок у payload
	strncpy(pkt.payload, payload, sizeof(pkt.payload) - 1);
	pkt.payload[sizeof(pkt.payload) - 1] = '\0';

	mesh_data_t data = {
		.data  = (uint8_t *)&pkt,
		.size  = sizeof(pkt),
		.proto = MESH_PROTO_BIN,
		.tos   = MESH_TOS_P2P,
	};

	// Забираємо routing table
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

	ESP_LOGI(TAG,
	         "ROOT UART BCAST: to %d nodes, payload=\"%s\"",
	         route_table_size, pkt.payload);

	for (int i = 0; i < route_table_size; ++i) {
		err = esp_mesh_send(&route_table[i], &data, MESH_DATA_P2P, NULL, 0);
		if (err != ESP_OK) {
			ESP_LOGE(TAG,
			         "send[%d] failed: 0x%x (%s)",
			         i, err, esp_err_to_name(err));
		}
	}
}
