#include "keelink_ble.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "freertos/idf_additions.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "host/ble_uuid.h"
#include "keemash_keelink.h"
#include "mbedtls/platform_util.h"
#include "nimble/ble.h"
#include "nimble/nimble_port.h"
#include "os/os_mbuf.h"
#include "psa/crypto.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "store/config/ble_store_config.h"

#include "keelink_server.h"

#define BLE_FRAME_MAX (KEEMASH_KEELINK_HEADER_SIZE + KEEMASH_KEELINK_MAX_PAYLOAD)
#define BLE_REASSEMBLY_TIMEOUT_MS 10000U
#define BLE_TX_QUEUE_DEPTH 4U
#define BLE_TX_TASK_STACK 5120U
#define BLE_FRAGMENT_HEADER 6U
#define BLE_FRAGMENT_MAX_DATA 180U
#define BLE_TX_CONFIRM_TIMEOUT_MS 3000U
#define BLE_TX_READY_TIMEOUT_MS 3000U
#define BLE_TX_SEND_RETRIES 5U

typedef struct {
	uint16_t len;
	uint8_t data[];
} ble_tx_item_t;

static const char *TAG = "keelink_ble";
static uint8_t s_own_addr_type;
static uint16_t s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static uint16_t s_response_handle;
static bool s_authenticated;
static bool s_indications_enabled;
static uint8_t s_challenge[30];
static uint8_t *s_rx_frame;
static uint16_t s_rx_total;
static uint16_t s_rx_received;
static uint32_t s_rx_started_ms;
static QueueHandle_t s_tx_queue;
static SemaphoreHandle_t s_tx_ack;
static TaskHandle_t s_tx_task;
static TaskHandle_t s_host_task;
static bool s_ready;
static bool s_host_synced;
static bool s_host_started;
static bool s_advertising_enabled;
static char s_device_name[16] = "KeeMASH root";
static esp_err_t s_last_error = ESP_ERR_INVALID_STATE;

typedef enum {
	BLE_START_IDLE = 0,
	BLE_START_ALLOCATING,
	BLE_START_NIMBLE,
	BLE_START_SERVICES,
	BLE_START_TX_TASK,
	BLE_START_HOST,
	BLE_START_STANDBY,
	BLE_START_ADVERTISING,
	BLE_START_FAILED,
} ble_start_state_t;

static volatile ble_start_state_t s_start_state = BLE_START_IDLE;

#define BLE_CHECKPOINT_MAGIC 0x4b4c424cU
typedef struct {
	uint32_t magic;
	uint32_t code;
	uint32_t code_inverse;
} ble_boot_checkpoint_t;

RTC_NOINIT_ATTR static volatile ble_boot_checkpoint_t s_boot_checkpoint;

static void boot_checkpoint_set(uint32_t code)
{
	if (code != 10 && s_boot_checkpoint.magic == BLE_CHECKPOINT_MAGIC &&
	    s_boot_checkpoint.code_inverse == ~s_boot_checkpoint.code &&
	    s_boot_checkpoint.code > code) return;
	s_boot_checkpoint.magic = BLE_CHECKPOINT_MAGIC;
	s_boot_checkpoint.code = code;
	s_boot_checkpoint.code_inverse = ~code;
}

void ble_store_config_init(void);

/* 8e8b7d00-2d2c-4f6e-9b15-4b65654c696e */
static const ble_uuid128_t s_service_uuid = BLE_UUID128_INIT(
	0x6e,0x69,0x4c,0x65,0x65,0x4b,0x15,0x9b,0x6e,0x4f,0x2c,0x2d,0x00,0x7d,0x8b,0x8e);
static const ble_uuid128_t s_challenge_uuid = BLE_UUID128_INIT(
	0x01,0x00,0x4c,0x65,0x65,0x4b,0x15,0x9b,0x6e,0x4f,0x2c,0x2d,0x00,0x7d,0x8b,0x8e);
static const ble_uuid128_t s_auth_uuid = BLE_UUID128_INIT(
	0x02,0x00,0x4c,0x65,0x65,0x4b,0x15,0x9b,0x6e,0x4f,0x2c,0x2d,0x00,0x7d,0x8b,0x8e);
static const ble_uuid128_t s_request_uuid = BLE_UUID128_INIT(
	0x03,0x00,0x4c,0x65,0x65,0x4b,0x15,0x9b,0x6e,0x4f,0x2c,0x2d,0x00,0x7d,0x8b,0x8e);
static const ble_uuid128_t s_response_uuid = BLE_UUID128_INIT(
	0x04,0x00,0x4c,0x65,0x65,0x4b,0x15,0x9b,0x6e,0x4f,0x2c,0x2d,0x00,0x7d,0x8b,0x8e);

static uint32_t now_ms(void)
{
	return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

static uint16_t read_u16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static void write_u16(uint8_t *p, uint16_t value)
{
	p[0] = (uint8_t)value;
	p[1] = (uint8_t)(value >> 8);
}

static void challenge_refresh(void)
{
	esp_fill_random(s_challenge, 24);
	(void)esp_wifi_get_mac(WIFI_IF_STA, s_challenge + 24);
}

static bool verify_auth(const uint8_t supplied[32])
{
	uint8_t key[32];
	if (!keelink_server_token_verifier(key) || psa_crypto_init() != PSA_SUCCESS) {
		return false;
	}
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = 0;
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&attributes, sizeof(key) * 8U);
	psa_status_t status = psa_import_key(&attributes, key, sizeof(key), &key_id);
	mbedtls_platform_zeroize(key, sizeof(key));
	psa_reset_key_attributes(&attributes);
	if (status != PSA_SUCCESS) return false;
	status = psa_mac_verify(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
		s_challenge, sizeof(s_challenge), supplied, 32);
	(void)psa_destroy_key(key_id);
	return status == PSA_SUCCESS;
}

static esp_err_t queue_frame(const uint8_t *frame, size_t frame_len)
{
	if (!frame || frame_len == 0 || frame_len > BLE_FRAME_MAX || !s_tx_queue) {
		return ESP_ERR_INVALID_ARG;
	}
	ble_tx_item_t *item = heap_caps_malloc(sizeof(*item) + frame_len,
		MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
	if (!item) return ESP_ERR_NO_MEM;
	item->len = (uint16_t)frame_len;
	memcpy(item->data, frame, frame_len);
	if (xQueueSend(s_tx_queue, &item, 0) != pdTRUE) {
		free(item);
		return ESP_ERR_NO_MEM;
	}
	if (s_tx_task) xTaskNotifyGive(s_tx_task);
	return ESP_OK;
}

static int send_fragment(const ble_tx_item_t *item, uint16_t offset)
{
	if (!item || s_conn_handle == BLE_HS_CONN_HANDLE_NONE ||
	    !s_authenticated || !s_indications_enabled) return BLE_HS_ENOTCONN;
	uint16_t mtu = ble_att_mtu(s_conn_handle);
	uint16_t available = mtu > BLE_FRAGMENT_HEADER + 3
		? mtu - BLE_FRAGMENT_HEADER - 3 : 1;
	if (available > BLE_FRAGMENT_MAX_DATA) available = BLE_FRAGMENT_MAX_DATA;
	uint16_t take = item->len - offset;
	if (take > available) take = available;
	uint8_t packet[BLE_FRAGMENT_HEADER + BLE_FRAGMENT_MAX_DATA];
	write_u16(packet, item->len);
	write_u16(packet + 2, offset);
	write_u16(packet + 4, take);
	memcpy(packet + BLE_FRAGMENT_HEADER, item->data + offset, take);
	struct os_mbuf *om = ble_hs_mbuf_from_flat(packet, BLE_FRAGMENT_HEADER + take);
	if (!om) return BLE_HS_ENOMEM;
	return ble_gatts_indicate_custom(s_conn_handle, s_response_handle, om);
}

static void tx_task(void *arg)
{
	(void)arg;
	for (;;) {
		ble_tx_item_t *item = NULL;
		if (xQueueReceive(s_tx_queue, &item, portMAX_DELAY) != pdTRUE || !item) continue;
		uint16_t offset = 0;
		uint32_t ready_started = now_ms();
		while (offset < item->len) {
			while (s_conn_handle == BLE_HS_CONN_HANDLE_NONE ||
			       !s_authenticated || !s_indications_enabled) {
				vTaskDelay(pdMS_TO_TICKS(50));
				if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE ||
				    (uint32_t)(now_ms() - ready_started) >= BLE_TX_READY_TIMEOUT_MS) break;
			}
			if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE || !s_authenticated ||
			    !s_indications_enabled) break;
			uint16_t mtu = ble_att_mtu(s_conn_handle);
			uint16_t take = mtu > BLE_FRAGMENT_HEADER + 3
				? mtu - BLE_FRAGMENT_HEADER - 3 : 1;
			if (take > BLE_FRAGMENT_MAX_DATA) take = BLE_FRAGMENT_MAX_DATA;
			if (take > item->len - offset) take = item->len - offset;
			int rc = BLE_HS_EUNKNOWN;
			for (unsigned retry = 0; retry < BLE_TX_SEND_RETRIES; retry++) {
				(void)xSemaphoreTake(s_tx_ack, 0);
				rc = send_fragment(item, offset);
				if (rc == 0) break;
				vTaskDelay(pdMS_TO_TICKS(100));
			}
			if (rc != 0) {
				ESP_LOGW(TAG, "indication abandoned rc=%d", rc);
				break;
			}
			if (xSemaphoreTake(s_tx_ack,
				pdMS_TO_TICKS(BLE_TX_CONFIRM_TIMEOUT_MS)) != pdTRUE) {
				ESP_LOGW(TAG, "indication confirmation timeout");
				break;
			}
			offset += take;
		}
		free(item);
	}
}

static int flatten_write(struct os_mbuf *om, uint8_t *out, uint16_t capacity,
			 uint16_t *length)
{
	uint16_t len = OS_MBUF_PKTLEN(om);
	if (len > capacity) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
	return ble_hs_mbuf_to_flat(om, out, capacity, length) == 0
		? 0 : BLE_ATT_ERR_UNLIKELY;
}

static int process_request_fragment(const uint8_t *data, uint16_t len)
{
	if (!s_authenticated) return BLE_ATT_ERR_INSUFFICIENT_AUTHEN;
	if (len < BLE_FRAGMENT_HEADER) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
	uint16_t total = read_u16(data);
	uint16_t offset = read_u16(data + 2);
	uint16_t chunk = read_u16(data + 4);
	if (total < KEEMASH_KEELINK_HEADER_SIZE || total > BLE_FRAME_MAX ||
	    chunk != len - BLE_FRAGMENT_HEADER || offset + chunk > total) {
		return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
	}
	uint32_t now = now_ms();
	if ((uint32_t)(now - s_rx_started_ms) > BLE_REASSEMBLY_TIMEOUT_MS) {
		s_rx_total = 0;
		s_rx_received = 0;
	}
	if (offset == 0) {
		s_rx_total = total;
		s_rx_received = 0;
		s_rx_started_ms = now;
	}
	if (total != s_rx_total) return BLE_ATT_ERR_INVALID_OFFSET;
	if (offset < s_rx_received && offset + chunk <= s_rx_received) {
		return memcmp(s_rx_frame + offset, data + BLE_FRAGMENT_HEADER, chunk) == 0
			? 0 : BLE_ATT_ERR_INVALID_OFFSET;
	}
	if (offset != s_rx_received) return BLE_ATT_ERR_INVALID_OFFSET;
	memcpy(s_rx_frame + offset, data + BLE_FRAGMENT_HEADER, chunk);
	s_rx_received += chunk;
	if (s_rx_received != s_rx_total) return 0;

	uint8_t *response = heap_caps_malloc(BLE_FRAME_MAX,
		MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
	if (!response) return BLE_ATT_ERR_INSUFFICIENT_RES;
	size_t response_len = 0;
	esp_err_t err = keelink_server_handle_ble_frame(s_rx_frame, s_rx_total,
		response, BLE_FRAME_MAX, &response_len);
	s_rx_total = 0;
	s_rx_received = 0;
	if (err == ESP_OK && response_len) err = queue_frame(response, response_len);
	free(response);
	return err == ESP_OK ? 0 : BLE_ATT_ERR_UNLIKELY;
}

static int gatt_access(uint16_t conn_handle, uint16_t attr_handle,
		       struct ble_gatt_access_ctxt *ctxt, void *arg)
{
	const ble_uuid_t *uuid = ctxt->chr->uuid;
	if (ble_uuid_cmp(uuid, &s_challenge_uuid.u) == 0) {
		if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR) return BLE_ATT_ERR_UNLIKELY;
		return os_mbuf_append(ctxt->om, s_challenge, sizeof(s_challenge)) == 0
			? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
	}
	if (ble_uuid_cmp(uuid, &s_auth_uuid.u) == 0) {
		uint8_t supplied[32];
		uint16_t len = 0;
		if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR ||
		    flatten_write(ctxt->om, supplied, sizeof(supplied), &len) != 0 ||
		    len != sizeof(supplied)) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
		s_authenticated = conn_handle == s_conn_handle && verify_auth(supplied);
		challenge_refresh();
		ESP_LOGI(TAG, "BLE client authentication %s",
			s_authenticated ? "accepted" : "rejected");
		return s_authenticated ? 0 : BLE_ATT_ERR_INSUFFICIENT_AUTHEN;
	}
	if (ble_uuid_cmp(uuid, &s_request_uuid.u) == 0) {
		uint8_t data[BLE_FRAGMENT_HEADER + BLE_FRAGMENT_MAX_DATA];
		uint16_t len = 0;
		if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) return BLE_ATT_ERR_UNLIKELY;
		int rc = flatten_write(ctxt->om, data, sizeof(data), &len);
		return rc == 0 ? process_request_fragment(data, len) : rc;
	}
	return BLE_ATT_ERR_UNLIKELY;
}

static const struct ble_gatt_svc_def s_services[] = {{
	.type = BLE_GATT_SVC_TYPE_PRIMARY,
	.uuid = &s_service_uuid.u,
	.characteristics = (struct ble_gatt_chr_def[]){{
		.uuid = &s_challenge_uuid.u,
		.access_cb = gatt_access,
		.flags = BLE_GATT_CHR_F_READ,
	},{
		.uuid = &s_auth_uuid.u,
		.access_cb = gatt_access,
		.flags = BLE_GATT_CHR_F_WRITE,
	},{
		.uuid = &s_request_uuid.u,
		.access_cb = gatt_access,
		.flags = BLE_GATT_CHR_F_WRITE,
	},{
		.uuid = &s_response_uuid.u,
		.access_cb = gatt_access,
		.val_handle = &s_response_handle,
		.flags = BLE_GATT_CHR_F_INDICATE,
	},{0}},
},{0}};

static bool advertise(void);

static int gap_event(struct ble_gap_event *event, void *arg)
{
	(void)arg;
	switch (event->type) {
	case BLE_GAP_EVENT_CONNECT:
		if (event->connect.status == 0) {
			s_conn_handle = event->connect.conn_handle;
			s_authenticated = false;
			s_indications_enabled = false;
			challenge_refresh();
			ESP_LOGI(TAG, "BLE fallback connected");
		} else {
			(void)advertise();
		}
		break;
	case BLE_GAP_EVENT_DISCONNECT:
		s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
		s_authenticated = false;
		s_indications_enabled = false;
		s_rx_total = 0;
		s_rx_received = 0;
		xSemaphoreGive(s_tx_ack);
		(void)advertise();
		break;
	case BLE_GAP_EVENT_ADV_COMPLETE:
		(void)advertise();
		break;
	case BLE_GAP_EVENT_SUBSCRIBE:
		if (event->subscribe.attr_handle == s_response_handle) {
			s_indications_enabled = event->subscribe.cur_indicate != 0;
			if (s_tx_task) xTaskNotifyGive(s_tx_task);
		}
		break;
	case BLE_GAP_EVENT_NOTIFY_TX:
		if (event->notify_tx.attr_handle == s_response_handle &&
		    event->notify_tx.indication) xSemaphoreGive(s_tx_ack);
		break;
	default:
		break;
	}
	return 0;
}

static bool advertise(void)
{
	if (!s_advertising_enabled) return true;

	struct ble_hs_adv_fields fields = {0};
	fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
	fields.uuids128 = (ble_uuid128_t *)&s_service_uuid;
	fields.num_uuids128 = 1;
	fields.uuids128_is_complete = 1;
	int rc = ble_gap_adv_set_fields(&fields);
	if (rc != 0) {
		ESP_LOGW(TAG, "advertising fields failed rc=%d", rc);
		return false;
	}
	struct ble_hs_adv_fields response = {0};
	response.name = (const uint8_t *)s_device_name;
	response.name_len = strlen((const char *)response.name);
	response.name_is_complete = 1;
	rc = ble_gap_adv_rsp_set_fields(&response);
	if (rc != 0) {
		ESP_LOGW(TAG, "scan response fields failed rc=%d", rc);
		return false;
	}
	struct ble_gap_adv_params params = {0};
	params.conn_mode = BLE_GAP_CONN_MODE_UND;
	params.disc_mode = BLE_GAP_DISC_MODE_GEN;
	params.channel_map = BLE_GAP_ADV_DFLT_CHANNEL_MAP;
	/* BLE interval units are 0.625 ms; low duty protects ESP-MESH airtime. */
	params.itvl_min = 800;
	params.itvl_max = 960;
	rc = ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER, &params,
		gap_event, NULL);
	if (rc != 0 && rc != BLE_HS_EALREADY) {
		ESP_LOGW(TAG, "advertising start failed rc=%d", rc);
		return false;
	}
	return true;
}

static void on_sync(void)
{
	boot_checkpoint_set(80);
	if (ble_hs_util_ensure_addr(0) != 0) {
		ESP_LOGE(TAG, "BLE address initialization failed");
		s_last_error = ESP_FAIL;
		s_start_state = BLE_START_FAILED;
		return;
	}
	boot_checkpoint_set(81);
	if (ble_hs_id_infer_auto(0, &s_own_addr_type) != 0) {
		ESP_LOGE(TAG, "BLE address type inference failed");
		s_last_error = ESP_FAIL;
		s_start_state = BLE_START_FAILED;
		return;
	}
	boot_checkpoint_set(82);
	s_host_synced = true;
	s_ready = true;
	s_last_error = ESP_OK;
	s_start_state = BLE_START_STANDBY;
	boot_checkpoint_set(83);
	if (s_advertising_enabled && advertise()) {
		s_start_state = BLE_START_ADVERTISING;
	}
	boot_checkpoint_set(100);
	ESP_LOGI(TAG, "NimBLE KeeLink fallback ready in %s",
		s_start_state == BLE_START_ADVERTISING ? "advertising" : "standby");
}

static void on_reset(int reason)
{
	s_ready = false;
	s_host_synced = false;
	s_start_state = BLE_START_HOST;
	ESP_LOGW(TAG, "NimBLE reset reason=%d", reason);
}

static void host_task(void *arg)
{
	(void)arg;
	nimble_port_run();
	s_host_started = false;
	s_host_task = NULL;
	vTaskDelete(NULL);
}

esp_err_t keelink_ble_init(void)
{
	if (s_tx_task) return ESP_OK;
	boot_checkpoint_set(10);
	s_ready = false;
	s_host_synced = false;
	s_host_started = false;
	s_advertising_enabled = false;
	s_last_error = ESP_ERR_INVALID_STATE;
	s_start_state = BLE_START_ALLOCATING;
	uint8_t root_mac[6] = {0};
	if (esp_read_mac(root_mac, ESP_MAC_WIFI_STA) == ESP_OK) {
		snprintf(s_device_name, sizeof(s_device_name), "KeeMASH-%02X%02X",
			root_mac[4], root_mac[5]);
	}
	s_rx_frame = heap_caps_malloc(BLE_FRAME_MAX,
		MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
	if (!s_rx_frame) {
		s_last_error = ESP_ERR_NO_MEM;
		s_start_state = BLE_START_FAILED;
		return ESP_ERR_NO_MEM;
	}
	boot_checkpoint_set(20);
	s_tx_queue = xQueueCreate(BLE_TX_QUEUE_DEPTH, sizeof(ble_tx_item_t *));
	s_tx_ack = xSemaphoreCreateBinary();
	if (!s_tx_queue || !s_tx_ack) goto no_mem;
	boot_checkpoint_set(30);

	s_start_state = BLE_START_NIMBLE;
	boot_checkpoint_set(40);
	esp_err_t err = nimble_port_init();
	if (err != ESP_OK) goto fail;
	boot_checkpoint_set(41);
	s_start_state = BLE_START_SERVICES;
	ble_hs_cfg.reset_cb = on_reset;
	ble_hs_cfg.sync_cb = on_sync;
	ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
	ble_svc_gap_init();
	ble_svc_gatt_init();
	int rc = ble_gatts_count_cfg(s_services);
	if (rc == 0) rc = ble_gatts_add_svcs(s_services);
	if (rc != 0) {
		err = ESP_FAIL;
		goto fail_nimble;
	}
	boot_checkpoint_set(50);
	(void)ble_svc_gap_device_name_set(s_device_name);
	ble_store_config_init();
	s_start_state = BLE_START_TX_TASK;
	boot_checkpoint_set(60);
	if (xTaskCreateWithCaps(tx_task, "keelink_ble_tx", BLE_TX_TASK_STACK, NULL, 5,
		&s_tx_task, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) != pdPASS) {
		err = ESP_ERR_NO_MEM;
		goto fail_nimble;
	}
	boot_checkpoint_set(61);
	keelink_server_set_ble_sender(queue_frame);
	s_last_error = ESP_OK;
	return ESP_OK;

fail_nimble:
	(void)nimble_port_deinit();
fail:
	s_last_error = err;
	s_start_state = BLE_START_FAILED;
	if (s_tx_ack) vSemaphoreDelete(s_tx_ack);
	if (s_tx_queue) vQueueDelete(s_tx_queue);
	free(s_rx_frame);
	s_tx_ack = NULL;
	s_tx_queue = NULL;
	s_rx_frame = NULL;
	return err;
no_mem:
	err = ESP_ERR_NO_MEM;
	goto fail;
}

esp_err_t keelink_ble_start_host(void)
{
	if (!s_tx_task || s_start_state == BLE_START_FAILED) {
		return s_last_error == ESP_OK ? ESP_ERR_INVALID_STATE : s_last_error;
	}
	if (s_host_started) return ESP_OK;
	s_start_state = BLE_START_HOST;
	boot_checkpoint_set(70);
	s_host_started = true;
	BaseType_t created = xTaskCreatePinnedToCoreWithCaps(
		host_task, "nimble_host", CONFIG_BT_NIMBLE_HOST_TASK_STACK_SIZE,
		NULL, configMAX_PRIORITIES - 4, &s_host_task,
		CONFIG_BT_NIMBLE_PINNED_TO_CORE,
		MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
	if (created != pdPASS) {
		s_host_started = false;
		s_host_task = NULL;
		s_last_error = ESP_ERR_NO_MEM;
		s_start_state = BLE_START_FAILED;
		return ESP_ERR_NO_MEM;
	}
	boot_checkpoint_set(71);
	return ESP_OK;
}

esp_err_t keelink_ble_enable(void)
{
	if (!s_tx_task || s_start_state == BLE_START_FAILED) {
		return s_last_error == ESP_OK ? ESP_ERR_INVALID_STATE : s_last_error;
	}
	s_advertising_enabled = true;
	if (!s_host_started) return ESP_ERR_INVALID_STATE;
	if (!s_host_synced) return ESP_OK;
	if (!advertise()) {
		s_last_error = ESP_FAIL;
		s_start_state = BLE_START_STANDBY;
		return ESP_FAIL;
	}
	s_ready = true;
	s_last_error = ESP_OK;
	s_start_state = BLE_START_ADVERTISING;
	boot_checkpoint_set(100);
	ESP_LOGI(TAG, "NimBLE KeeLink fallback advertising active");
	return ESP_OK;
}

void keelink_ble_disable(void)
{
	s_advertising_enabled = false;
	if (!s_host_synced) return;

	if (s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
		(void)ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
	} else {
		(void)ble_gap_adv_stop();
	}
	s_start_state = BLE_START_STANDBY;
	ESP_LOGI(TAG, "NimBLE KeeLink fallback standby");
}

bool keelink_ble_ready(void)
{
	return s_ready;
}

esp_err_t keelink_ble_last_error(void)
{
	return s_last_error;
}

const char *keelink_ble_state(void)
{
	switch (s_start_state) {
	case BLE_START_IDLE: return "idle";
	case BLE_START_ALLOCATING: return "allocating";
	case BLE_START_NIMBLE: return "nimble";
	case BLE_START_SERVICES: return "services";
	case BLE_START_TX_TASK: return "tx_task";
	case BLE_START_HOST: return "host";
	case BLE_START_STANDBY: return "standby";
	case BLE_START_ADVERTISING: return "advertising";
	case BLE_START_FAILED: return "failed";
	default: return "unknown";
	}
}

uint32_t keelink_ble_boot_checkpoint(void)
{
	if (s_boot_checkpoint.magic != BLE_CHECKPOINT_MAGIC ||
	    s_boot_checkpoint.code_inverse != ~s_boot_checkpoint.code) return 0;
	return s_boot_checkpoint.code;
}

void keelink_ble_note_boot_checkpoint(uint32_t checkpoint)
{
	boot_checkpoint_set(checkpoint);
}
