#include "mesh_time_sync.h"

#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_mesh.h"

static const char *TAG = "mesh_time";

static bool s_has_time = false;
static bool s_started = false;
static uint32_t s_period_ms = MESH_TIME_SYNC_PERIOD_MS;

static bool time_is_valid(time_t t)
{
	// та ж логіка як у тебе: “не 1970”
	return (t >= 1577836800); // 2020-01-01
}

static void apply_tz_poland(void)
{
	// Польща / CET-CEST (як у твоєму time_sync.c)
	setenv("TZ", "CET-1CEST,M3.5.0/2,M10.5.0/3", 1);
	tzset();
}

bool mesh_time_sync_has_time(void)
{
	return s_has_time;
}

void mesh_time_sync_init(void)
{
	apply_tz_poland();
}

static esp_err_t bcast_time_once(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	if (!time_is_valid(tv.tv_sec)) {
		return ESP_ERR_INVALID_STATE;
	}

	mesh_packet_t pkt;
	memset(&pkt, 0, sizeof(pkt));

	pkt.magic = MESH_PKT_MAGIC;
	pkt.version = MESH_PKT_VERSION;
	pkt.type = MESH_PKT_TYPE_TIME;

	esp_wifi_get_mac(WIFI_IF_STA, pkt.src_mac);

	// payload: [0..3]=sec, [4..7]=usec
	uint32_t sec = (uint32_t)tv.tv_sec;
	uint32_t usec = (uint32_t)tv.tv_usec;
	memcpy(&pkt.payload[0], &sec, sizeof(sec));
	memcpy(&pkt.payload[4], &usec, sizeof(usec));

	// routing table
	int rt_size = esp_mesh_get_routing_table_size();
	if (rt_size <= 0) {
		return ESP_ERR_INVALID_STATE;
	}

	mesh_addr_t self_id = {0};
	esp_mesh_get_id(&self_id);

	mesh_addr_t *table = (mesh_addr_t *)malloc((size_t)rt_size * sizeof(mesh_addr_t));
	if (!table) {
		return ESP_ERR_NO_MEM;
	}

	int table_size = rt_size;
	esp_mesh_get_routing_table(table, rt_size * 6, &table_size);

	mesh_data_t data;
	data.data = (uint8_t *)&pkt;
	data.size = sizeof(pkt);
	data.proto = MESH_PROTO_BIN;
	data.tos = MESH_TOS_P2P;

	esp_err_t last_err = ESP_OK;

	for (int i = 0; i < table_size; i++) {
		// не шлемо самому собі
		if (memcmp(table[i].addr, self_id.addr, 6) == 0) {
			continue;
		}
		esp_err_t err = esp_mesh_send(&table[i], &data, MESH_DATA_P2P, NULL, 0);
		if (err != ESP_OK) {
			last_err = err;
		}
	}

	free(table);
	return last_err;
}

static void mesh_time_sync_root_task(void *arg)
{
	TickType_t last = xTaskGetTickCount();

	for (;;) {
		vTaskDelayUntil(&last, pdMS_TO_TICKS(s_period_ms));

		// якщо раптом прошивку зальєш не на root — просто мовчки нічого не робимо
		if (!esp_mesh_is_root()) {
			continue;
		}
		if (esp_mesh_get_layer() <= 0) {
			continue;
		}

		esp_err_t err = bcast_time_once();
		if (err == ESP_OK) {
			ESP_LOGD(TAG, "time broadcast OK");
		}
	}
}

esp_err_t mesh_time_sync_root_start(uint32_t period_ms)
{
	if (s_started) return ESP_OK;
	s_started = true;

	if (period_ms >= 1000) {
		s_period_ms = period_ms;
	}

	// 3072..4096 більш ніж достатньо
	xTaskCreate(mesh_time_sync_root_task, "mesh_time_tx", 4096, NULL, 5, NULL);
	ESP_LOGI(TAG, "root time sync started, period=%lu ms", (unsigned long)s_period_ms);
	return ESP_OK;
}

void mesh_time_sync_handle_packet(const mesh_packet_t *pkt)
{
	if (!pkt) return;

	if (pkt->magic != MESH_PKT_MAGIC || pkt->version != MESH_PKT_VERSION) return;
	if (pkt->type != MESH_PKT_TYPE_TIME) return;

	uint32_t sec = 0;
	uint32_t usec = 0;
	memcpy(&sec, &pkt->payload[0], sizeof(sec));
	memcpy(&usec, &pkt->payload[4], sizeof(usec));

	if (usec >= 1000000) return;
	if (!time_is_valid((time_t)sec)) return;

	struct timeval tv;
	tv.tv_sec = (time_t)sec;
	tv.tv_usec = (suseconds_t)usec;

	apply_tz_poland();
	settimeofday(&tv, NULL);
	s_has_time = true;

	ESP_LOGI(TAG, "time synced from root: %lu.%06lu",
		(unsigned long)sec,
		(unsigned long)usec
	);
}
