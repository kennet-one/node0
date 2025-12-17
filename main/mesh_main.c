#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mesh.h"
#include "esp_mesh_internal.h"
#include "esp_netif.h"
#include "nvs_flash.h"

#include "legacy_proto.h"
#include "stack_monitor.h"
#include "uart_bridge.h"
#include "log_http_server.h"
#include "time_sync.h"
#include "log_time_vprintf.h"
#include "mesh_proto.h"
#include "mesh_time_sync.h"

/* -------------------------------------------------------------------------- */
/*  Константи / глобальні змінні                                              */
/* -------------------------------------------------------------------------- */

#define RX_SIZE          (256)
#define TX_INTERVAL_MS   (5000)
//#define FIXED_ROOT  1   // на node0

static const char *MESH_TAG = "node0";

/* Один і той самий MESH_ID на всі ноди в цій мережі */
static const uint8_t MESH_ID[6] = { 0x77, 0x77, 0x77, 0x77, 0x77, 0x77 };

static bool       is_running        = true;
static bool       is_mesh_connected = false;
static mesh_addr_t mesh_parent_addr;
static int        mesh_layer        = -1;
static esp_netif_t *netif_sta       = NULL;

/* -------------------------------------------------------------------------- */
/*  Мінімальний власний протокол                                              */
/* -------------------------------------------------------------------------- */
/*
 * Формат нашого пакету:
 *  magic    - 0xA5 (для перевірки, що це "наш" пакет)
 *  version  - версія протоколу (1)
 *  type     - тип (1 = просто текстове "Hello N")
 *  reserved - вирівнювання, запас
 *  counter  - лічильник пакета від цієї ноди
 *  src_mac  - MAC відправника
 *  payload  - невеликий текст (рядок з '\0' в кінці)
 */

/* -------------------------------------------------------------------------- */
/*  Прототипи                                                                 */
/* -------------------------------------------------------------------------- */

static void mesh_event_handler(void *arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data);

static void ip_event_handler(void *arg,
                             esp_event_base_t event_base,
                             int32_t event_id,
                             void *event_data);

static void mesh_tx_task(void *arg);
static void mesh_rx_task(void *arg);
static esp_err_t mesh_comm_start(void);

// -----------------------------SINGLE_SENDER---------------------------------------
static const uint8_t NODE1_MAC[6] = { 0xA0, 0xDD, 0x6C, 0x0F, 0x31, 0xE4 };

static esp_err_t mesh_send_single(const uint8_t to_mac[6],
                                  const mesh_packet_t *pkt)
{
    mesh_addr_t dest = {0};
    mesh_data_t data;

    // заповнюємо адресу призначення
    memcpy(dest.addr, to_mac, 6);

    data.data  = (uint8_t *)pkt;
    data.size  = sizeof(*pkt);
    data.proto = MESH_PROTO_BIN;
    data.tos   = MESH_TOS_P2P;

    // звичайний p2p-send – mesh сам прокладе маршрут
    return esp_mesh_send(&dest, &data, MESH_DATA_P2P, NULL, 0);
}

#define SINGLE_TX_INTERVAL_MS  5000   // 5 секунд

// щоб можна було вмикати/вимикати відправника на різних білдах
#define I_AM_SINGLE_SENDER     1      // на вузлі, який ШЛЕ, став 1; на інших 0

static void mesh_single_tx_task(void *arg)
{
    mesh_packet_t pkt;
    esp_err_t     err;
    uint32_t      counter = 0;

    TickType_t last_wake = xTaskGetTickCount();

    while (is_running) {
        // чекаємо рівно 5 сек від попереднього “тика”
        vTaskDelayUntil(&last_wake, pdMS_TO_TICKS(SINGLE_TX_INTERVAL_MS));

        // якщо нода ще не в mesh – нічого не робимо
        if (!is_mesh_connected) {
            continue;
        }

        counter++;

        memset(&pkt, 0, sizeof(pkt));
        pkt.magic   = MESH_PKT_MAGIC;
        pkt.version = MESH_PKT_VERSION;
        pkt.type    = MESH_PKT_TYPE_TEXT;
        pkt.counter = counter;

        // MAC цієї ноди – для логів
        esp_wifi_get_mac(WIFI_IF_STA, pkt.src_mac);

        snprintf(pkt.payload, sizeof(pkt.payload),
                 "single %lu", (unsigned long)counter);

        err = mesh_send_single(NODE1_MAC, &pkt);
        if (err == ESP_OK) {
            ESP_LOGI(MESH_TAG,
                     "SINGLE TX -> " MACSTR " cnt=%lu payload=\"%s\"",
                     MAC2STR(NODE1_MAC),
                     (unsigned long)counter,
                     pkt.payload);
        } else {
            ESP_LOGE(MESH_TAG,
                     "mesh_send_single failed: 0x%x (%s)",
                     err, esp_err_to_name(err));
        }
    }

    vTaskDelete(NULL);
}


/* -------------------------------------------------------------------------- */
/*  TX task – періодично шлемо пакет на root                                  */
/* -------------------------------------------------------------------------- */

static void mesh_tx_task(void *arg)
{
	mesh_packet_t pkt;
	mesh_data_t   data;
	mesh_addr_t   dest;
	esp_err_t     err;
	uint32_t      counter = 0;

	data.data  = (uint8_t *)&pkt;
	data.proto = MESH_PROTO_BIN;
	data.tos   = MESH_TOS_P2P;

	while (is_running) {
		vTaskDelay(pdMS_TO_TICKS(TX_INTERVAL_MS));

		// Шлемо тільки, якщо ми підключені до mesh і ми НЕ root
		if (!is_mesh_connected || esp_mesh_is_root()) {
			continue;
		}

		counter++;

		memset(&pkt, 0, sizeof(pkt));
		pkt.magic   = MESH_PKT_MAGIC;
		pkt.version = MESH_PKT_VERSION;
		pkt.type    = MESH_PKT_TYPE_TEXT;
		pkt.counter = counter;

		// MAC цієї ноди (STA інтерфейс)
		esp_wifi_get_mac(WIFI_IF_STA, pkt.src_mac);

		snprintf(pkt.payload, sizeof(pkt.payload),
		         "Hello %lu", (unsigned long)counter);

		data.size = sizeof(pkt);

		// 00:00:00:00:00:00 => "відправити на root"
		memset(&dest, 0, sizeof(dest));

		err = esp_mesh_send(&dest, &data, MESH_DATA_P2P, NULL, 0);
		if (err == ESP_OK) {
			ESP_LOGI(MESH_TAG,
			         "TX -> ROOT: cnt=%lu, payload=\"%s\"",
			         (unsigned long)counter, pkt.payload);
		} else {
			ESP_LOGE(MESH_TAG,
			         "esp_mesh_send failed: 0x%x (%s)",
			         err, esp_err_to_name(err));
		}
	}
	vTaskDelete(NULL);
}

/* -------------------------------------------------------------------------- */
/*  RX task – слухаємо пакети від інших нод                                   */
/* -------------------------------------------------------------------------- */

static void mesh_rx_task(void *arg)
{
	mesh_packet_t pkt;
	mesh_data_t   data;
	mesh_addr_t   from;
	int           flag;
	esp_err_t     err;

	data.data = (uint8_t *)&pkt;
	data.size = sizeof(pkt);

	while (is_running) {

		data.size = sizeof(pkt);
		err = esp_mesh_recv(&from, &data, portMAX_DELAY, &flag, NULL, 0);
		if (err != ESP_OK) {
			ESP_LOGE(MESH_TAG,
			         "esp_mesh_recv failed: 0x%x (%s)",
			         err, esp_err_to_name(err));
			continue;
		}
		if (data.size < sizeof(mesh_packet_t)) {
			ESP_LOGW(MESH_TAG,
			         "RX short packet: %d bytes", data.size);
			continue;
		}

		// Перевіряємо, що це "наш" формат
		if (pkt.magic != MESH_PKT_MAGIC || pkt.version != MESH_PKT_VERSION) {
			ESP_LOGW(MESH_TAG,
			         "RX unknown packet from " MACSTR,
			         MAC2STR(from.addr));
			continue;
		}

		if (pkt.type == MESH_PKT_TYPE_TEXT) {
			// Гарантуємо, що payload закінчується '\0'
			pkt.payload[sizeof(pkt.payload) - 1] = '\0';
			ESP_LOGI(MESH_TAG,
			         "RX TEXT: cnt=%lu from " MACSTR
			         " (src_mac=" MACSTR "), payload=\"%s\"",
			         (unsigned long)pkt.counter,
			         MAC2STR(from.addr),
			         MAC2STR(pkt.src_mac),
			         pkt.payload);
            legacy_handle_text(pkt.payload);
		} else {
			ESP_LOGI(MESH_TAG,
			         "RX type=%u cnt=%lu from " MACSTR,
			         pkt.type,
			         (unsigned long)pkt.counter,
			         MAC2STR(from.addr));
		}
	}
	vTaskDelete(NULL);
}

/* -------------------------------------------------------------------------- */
/*  Запуск задач TX/RX один раз                                               */
/* -------------------------------------------------------------------------- */

static esp_err_t mesh_comm_start(void)
{
	static bool started = false;

	if (!started) {
		started = true;
		xTaskCreate(mesh_tx_task, "mesh_tx", 4096, NULL, 5, NULL);
		xTaskCreate(mesh_rx_task, "mesh_rx", 4096, NULL, 5, NULL);
        xTaskCreate(mesh_single_tx_task,"mesh_single_tx",4096, NULL, 5, NULL);
        stack_monitor_start(3);
	}
	return ESP_OK;
}

/* -------------------------------------------------------------------------- */
/*  MESH events                                                               */
/* -------------------------------------------------------------------------- */

static void mesh_event_handler(void *arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data)
{
	mesh_addr_t id = {0};
	static uint16_t last_layer = 0;

	switch (event_id) {
	case MESH_EVENT_STARTED: {
		esp_mesh_get_id(&id);
		ESP_LOGI(MESH_TAG,
		         "<MESH_EVENT_STARTED> ID:" MACSTR,
		         MAC2STR(id.addr));
		is_mesh_connected = false;
		mesh_layer = esp_mesh_get_layer();
	}
	break;

	case MESH_EVENT_STOPPED: {
		ESP_LOGI(MESH_TAG, "<MESH_EVENT_STOPPED>");
		is_mesh_connected = false;
		mesh_layer = esp_mesh_get_layer();
	}
	break;

	case MESH_EVENT_CHILD_CONNECTED: {
		mesh_event_child_connected_t *child =
		    (mesh_event_child_connected_t *)event_data;
		ESP_LOGI(MESH_TAG,
		         "<MESH_EVENT_CHILD_CONNECTED> aid:%d, " MACSTR,
		         child->aid, MAC2STR(child->mac));
	}
	break;

	case MESH_EVENT_CHILD_DISCONNECTED: {
		mesh_event_child_disconnected_t *child =
		    (mesh_event_child_disconnected_t *)event_data;
		ESP_LOGI(MESH_TAG,
		         "<MESH_EVENT_CHILD_DISCONNECTED> aid:%d, " MACSTR,
		         child->aid, MAC2STR(child->mac));
	}
	break;

	case MESH_EVENT_ROUTING_TABLE_ADD: {
		mesh_event_routing_table_change_t *rt =
		    (mesh_event_routing_table_change_t *)event_data;
		ESP_LOGW(MESH_TAG,
		         "<MESH_EVENT_ROUTING_TABLE_ADD> add %d, new:%d, layer:%d",
		         rt->rt_size_change, rt->rt_size_new, mesh_layer);
	}
	break;

	case MESH_EVENT_ROUTING_TABLE_REMOVE: {
		mesh_event_routing_table_change_t *rt =
		    (mesh_event_routing_table_change_t *)event_data;
		ESP_LOGW(MESH_TAG,
		         "<MESH_EVENT_ROUTING_TABLE_REMOVE> remove %d, new:%d, layer:%d",
		         rt->rt_size_change, rt->rt_size_new, mesh_layer);
	}
	break;

	case MESH_EVENT_NO_PARENT_FOUND: {
		mesh_event_no_parent_found_t *np =
		    (mesh_event_no_parent_found_t *)event_data;
		ESP_LOGI(MESH_TAG,
		         "<MESH_EVENT_NO_PARENT_FOUND> scan times:%d",
		         np->scan_times);
	}
	break;

	case MESH_EVENT_PARENT_CONNECTED: {
		mesh_event_connected_t *conn =
		    (mesh_event_connected_t *)event_data;
		esp_mesh_get_id(&id);
		mesh_layer = conn->self_layer;
		memcpy(mesh_parent_addr.addr, conn->connected.bssid, 6);

		ESP_LOGI(MESH_TAG,
		         "<MESH_EVENT_PARENT_CONNECTED> layer:%d -> %d, parent:" MACSTR
		         " %s, ID:" MACSTR ", duty:%d",
		         last_layer, mesh_layer,
		         MAC2STR(mesh_parent_addr.addr),
		         esp_mesh_is_root() ? "<ROOT>" :
		         (mesh_layer == 2) ? "<layer2>" : "",
		         MAC2STR(id.addr),
		         conn->duty);
		last_layer = mesh_layer;
		is_mesh_connected = true;

		if (esp_mesh_is_root()) {
			esp_netif_dhcpc_stop(netif_sta);
			esp_netif_dhcpc_start(netif_sta);

		}
		mesh_comm_start();
	}
	break;

	case MESH_EVENT_PARENT_DISCONNECTED: {
		mesh_event_disconnected_t *disc =
		    (mesh_event_disconnected_t *)event_data;
		ESP_LOGI(MESH_TAG,
		         "<MESH_EVENT_PARENT_DISCONNECTED> reason:%d",
		         disc->reason);
		is_mesh_connected = false;
		mesh_layer = esp_mesh_get_layer();
	}
	break;

	case MESH_EVENT_LAYER_CHANGE: {
		mesh_event_layer_change_t *lc =
		    (mesh_event_layer_change_t *)event_data;
		mesh_layer = lc->new_layer;
		ESP_LOGI(MESH_TAG,
		         "<MESH_EVENT_LAYER_CHANGE> layer:%d -> %d %s",
		         last_layer, mesh_layer,
		         esp_mesh_is_root() ? "<ROOT>" :
		         (mesh_layer == 2) ? "<layer2>" : "");
		last_layer = mesh_layer;
	}
	break;

	case MESH_EVENT_ROOT_ADDRESS: {
		mesh_event_root_address_t *ra =
		    (mesh_event_root_address_t *)event_data;
		ESP_LOGI(MESH_TAG,
		         "<MESH_EVENT_ROOT_ADDRESS> root:" MACSTR,
		         MAC2STR(ra->addr));
	}
	break;

	case MESH_EVENT_TODS_STATE: {
		mesh_event_toDS_state_t *st =
		    (mesh_event_toDS_state_t *)event_data;
		ESP_LOGI(MESH_TAG,
		         "<MESH_EVENT_TODS_STATE> state:%d",
		         *st);
	}
	break;

	case MESH_EVENT_NETWORK_STATE: {
		mesh_event_network_state_t *ns =
		    (mesh_event_network_state_t *)event_data;
		ESP_LOGI(MESH_TAG,
		         "<MESH_EVENT_NETWORK_STATE> is_rootless:%d",
		         ns->is_rootless);
	}
	break;

	default:
		ESP_LOGI(MESH_TAG,
		         "unknown mesh event id:%" PRId32,
		         event_id);
		break;
	}
}

/* -------------------------------------------------------------------------- */
/*  IP events (коли root отримує IP від роутера)                              */
/* -------------------------------------------------------------------------- */

static void ip_event_handler(void *arg,
                             esp_event_base_t event_base,
                             int32_t event_id,
                             void *event_data)
{
	ip_event_got_ip_t *ev = (ip_event_got_ip_t *)event_data;
	ESP_LOGI(MESH_TAG,
	         "<IP_EVENT_STA_GOT_IP> IP:" IPSTR,
	         IP2STR(&ev->ip_info.ip));
	
	time_sync_start();	

	mesh_time_sync_root_start(5000);

	// Якщо ми root – запускаємо HTTP-сервер
	if (esp_mesh_is_root()) {
		log_http_server_start();
	}
}


/* -------------------------------------------------------------------------- */
/*  app_main – ініціалізація mesh + Wi-Fi                                     */
/* -------------------------------------------------------------------------- */

void app_main(void)
{
	//ESP_ERROR_CHECK(mesh_light_init());   // якщо не треба LED – можна забрати
	log_time_vprintf_start();
	
	ESP_ERROR_CHECK(nvs_flash_init());
	ESP_ERROR_CHECK(esp_netif_init());
	ESP_ERROR_CHECK(esp_event_loop_create_default());

	// Створюємо netif для mesh (sta + softAP, але зберігаємо тільки sta)
	ESP_ERROR_CHECK(
	    esp_netif_create_default_wifi_mesh_netifs(&netif_sta, NULL));

	// Wi-Fi
	wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&wifi_cfg));
	ESP_ERROR_CHECK(
	    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
	                               &ip_event_handler, NULL));
	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_FLASH));
	ESP_ERROR_CHECK(esp_wifi_start());

	// MESH
	ESP_ERROR_CHECK(esp_mesh_init());
	ESP_ERROR_CHECK(
	    esp_event_handler_register(MESH_EVENT, ESP_EVENT_ANY_ID,
	                               &mesh_event_handler, NULL));
    // --- налаштування типу вузла / фіксований root ---

        // Ця прошивка буде завжди root (якщо може підключитися до роутера)
    ESP_ERROR_CHECK(esp_mesh_fix_root(true));       // не віддаємо роль root
    ESP_ERROR_CHECK(esp_mesh_set_type(MESH_ROOT));  // я – root


	ESP_ERROR_CHECK(esp_mesh_set_topology(CONFIG_MESH_TOPOLOGY));
	ESP_ERROR_CHECK(esp_mesh_set_max_layer(CONFIG_MESH_MAX_LAYER));
	ESP_ERROR_CHECK(esp_mesh_set_vote_percentage(1));
	ESP_ERROR_CHECK(esp_mesh_set_xon_qsize(128));

	ESP_ERROR_CHECK(esp_mesh_disable_ps());
	ESP_ERROR_CHECK(esp_mesh_set_ap_assoc_expire(10));

	mesh_cfg_t cfg = MESH_INIT_CONFIG_DEFAULT();

	// mesh_id
	memcpy(cfg.mesh_id.addr, MESH_ID, 6);

	// роутер (твій домашній Wi-Fi з menuconfig)
	cfg.channel        = CONFIG_MESH_CHANNEL;
	cfg.router.ssid_len = strlen(CONFIG_MESH_ROUTER_SSID);
	memcpy(cfg.router.ssid,
	       CONFIG_MESH_ROUTER_SSID,
	       cfg.router.ssid_len);
	memcpy(cfg.router.password,
	       CONFIG_MESH_ROUTER_PASSWD,
	       strlen(CONFIG_MESH_ROUTER_PASSWD));

	// mesh AP (для дітей)
	ESP_ERROR_CHECK(esp_mesh_set_ap_authmode(CONFIG_MESH_AP_AUTHMODE));
	cfg.mesh_ap.max_connection        = CONFIG_MESH_AP_CONNECTIONS;
	cfg.mesh_ap.nonmesh_max_connection = CONFIG_MESH_NON_MESH_AP_CONNECTIONS;
	memcpy(cfg.mesh_ap.password,
	       CONFIG_MESH_AP_PASSWD,
	       strlen(CONFIG_MESH_AP_PASSWD));

	ESP_ERROR_CHECK(esp_mesh_set_config(&cfg));

	ESP_ERROR_CHECK(esp_mesh_start());

	ESP_LOGI(MESH_TAG,
	         "mesh started, heap:%" PRId32 ", root_fixed:%d, topo:%d %s, ps:%d",
	         esp_get_minimum_free_heap_size(),
	         esp_mesh_is_root_fixed(),
	         esp_mesh_get_topology(),
	         esp_mesh_get_topology() ? "(chain)" : "(tree)",
	         esp_mesh_is_ps_enabled());

	uart_bridge_init();
	uart_bridge_start();
	log_http_server_init();
	mesh_time_sync_init();
	
}
