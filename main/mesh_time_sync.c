#include "mesh_time_sync.h"

#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <inttypes.h>

#include "sdkconfig.h"
#include "esp_log.h"
#include "esp_mesh.h"
#include "esp_wifi.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "mesh_time";

// Має співпасти з твоїм mesh_packet_t
typedef struct __attribute__((packed)) {
	uint8_t		magic;
	uint8_t		version;
	uint8_t		type;
	uint8_t		reserved;
	uint32_t	counter;
	uint8_t		src_mac[6];
	uint8_t		payload[32];
} mesh_packet_wire_t;

typedef struct __attribute__((packed)) {
	int64_t		epoch_sec;
	uint32_t	seq;
} mesh_time_payload_t;

#define OUR_MAGIC	0xA5
#define OUR_VER		1
#define TIME_VALID_EPOCH	1577836800LL	// 2020-01-01

static bool			s_inited = false;
static bool			s_root_task_started = false;
static uint32_t		s_period_ms = 60000;
static uint32_t		s_seq = 0;

static uint32_t		s_last_rx_seq = 0;
static bool			s_have_time = false;

static void set_tz_pl(void)
{
	// Те саме правило, що ти вже юзаєш на node0
	setenv("TZ", "CET-1CEST,M3.5.0/2,M10.5.0/3", 1);
	tzset();
}

static bool is_time_valid_now(void)
{
	time_t now = 0;
	time(&now);
	return ((int64_t)now > TIME_VALID_EPOCH);
}

void mesh_time_sync_init(void)
{
	if (s_inited) return;
	s_inited = true;
	set_tz_pl();
}

static void mesh_time_sync_root_set_period_ms(uint32_t period_ms)
{
	if (period_ms < 1000) period_ms = 1000;
	s_period_ms = period_ms;
}

static esp_err_t root_send_time_to_all(int64_t epoch_sec, uint32_t seq)
{
	mesh_packet_wire_t pkt;
	memset(&pkt, 0, sizeof(pkt));

	pkt.magic = OUR_MAGIC;
	pkt.version = OUR_VER;
	pkt.type = MESH_TIME_SYNC_TYPE_TIME;
	pkt.counter = seq;
	esp_wifi_get_mac(WIFI_IF_STA, pkt.src_mac);

	mesh_time_payload_t tp;
	memset(&tp, 0, sizeof(tp));
	tp.epoch_sec = epoch_sec;
	tp.seq = seq;
	memcpy(pkt.payload, &tp, sizeof(tp));

	mesh_data_t data;
	memset(&data, 0, sizeof(data));
	data.data = (uint8_t *)&pkt;
	data.size = sizeof(pkt);
	data.proto = MESH_PROTO_BIN;
	data.tos = MESH_TOS_P2P;

	mesh_addr_t route_table[CONFIG_MESH_ROUTE_TABLE_SIZE];
	int route_table_size = 0;

	esp_err_t err = esp_mesh_get_routing_table(route_table,
		CONFIG_MESH_ROUTE_TABLE_SIZE * 6,
		&route_table_size
	);
	if (err != ESP_OK) {
		return err;
	}
	if (route_table_size <= 0) {
		return ESP_OK;
	}

	esp_err_t last_err = ESP_OK;
	for (int i = 0; i < route_table_size; i++) {
		esp_err_t e = esp_mesh_send(&route_table[i], &data, MESH_DATA_P2P, NULL, 0);
		if (e != ESP_OK) last_err = e;
	}
	return last_err;
}

static void mesh_time_root_task(void *arg)
{
	// Перший "тик" робимо швидко, щоб після появи часу ноди не чекали 60с
	TickType_t last = xTaskGetTickCount();
	bool first_sent = false;

	while (true) {

		// якщо ще не слали перший раз — перевіряєм частіше
		if (!first_sent) {
			vTaskDelay(pdMS_TO_TICKS(1000));
		} else {
			vTaskDelayUntil(&last, pdMS_TO_TICKS(s_period_ms));
		}

		if (!esp_mesh_is_root()) continue;
		if (!is_time_valid_now()) continue;

		time_t now = 0;
		time(&now);

		s_seq++;

		esp_err_t err = root_send_time_to_all((int64_t)now, s_seq);
		if (err == ESP_OK) {
			ESP_LOGI(TAG, "TIME TX seq=%" PRIu32 " epoch=%" PRId64, s_seq, (int64_t)now);
		} else {
			ESP_LOGW(TAG, "TIME TX err=%s seq=%" PRIu32, esp_err_to_name(err), s_seq);
		}

		first_sent = true;
		last = xTaskGetTickCount();
	}
}

esp_err_t mesh_time_sync_root_start(uint32_t period_ms)
{
	mesh_time_sync_init();
	mesh_time_sync_root_set_period_ms(period_ms);

	if (s_root_task_started) return ESP_OK;
	s_root_task_started = true;

	if (xTaskCreate(mesh_time_root_task, "mesh_time_tx", 4096, NULL, 4, NULL) != pdPASS) {
		s_root_task_started = false;
		return ESP_ERR_NO_MEM;
	}

	return ESP_OK;
}

esp_err_t mesh_time_sync_handle_rx(const void *pkt_buf, size_t pkt_len)
{
	mesh_time_sync_init();

	if (!pkt_buf || pkt_len < sizeof(mesh_packet_wire_t)) {
		return ESP_ERR_INVALID_SIZE;
	}

	const mesh_packet_wire_t *pkt = (const mesh_packet_wire_t *)pkt_buf;

	// фільтр “це точно наш пакет”
	if (pkt->magic != OUR_MAGIC || pkt->version != OUR_VER) {
		return ESP_ERR_INVALID_ARG;
	}
	if (pkt->type != MESH_TIME_SYNC_TYPE_TIME) {
		return ESP_ERR_INVALID_ARG;
	}

	mesh_time_payload_t tp;
	memset(&tp, 0, sizeof(tp));
	memcpy(&tp, pkt->payload, sizeof(tp));

	if (tp.epoch_sec <= TIME_VALID_EPOCH) {
		return ESP_ERR_INVALID_RESPONSE;
	}

	// простий анти-rollback / анти-дублікат
	if (s_have_time && tp.seq != 0 && tp.seq <= s_last_rx_seq) {
		return ESP_OK;
	}

	struct timeval tv;
	tv.tv_sec = (time_t)tp.epoch_sec;
	tv.tv_usec = 0;
	settimeofday(&tv, NULL);

	s_have_time = true;
	s_last_rx_seq = tp.seq;

	ESP_LOGI(TAG, "TIME RX seq=%" PRIu32 " set epoch=%" PRId64, tp.seq, tp.epoch_sec);
	return ESP_OK;
}
