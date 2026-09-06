#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_mesh.h"
#include "esp_mesh_internal.h"
#include "esp_netif.h"
#include "esp_private/wifi_os_adapter.h"
#include "nvs_flash.h"
#include "lwip/ip4_addr.h"

#include "legacy_proto.h"
#include "stack_monitor.h"
#include "uart_bridge.h"
#include "log_http_server.h"
#include "keelink_ble.h"
#include "time_sync.h"
#include "log_time_vprintf.h"
#include "mesh_proto.h"
#include "mesh_time_sync.h"
#include "mesh_v2_link.h"
#include "heater_zone.h"
#include "keemash_mesh_network.h"

/* -------------------------------------------------------------------------- */
/*  Constants / globals                                                       */
/* -------------------------------------------------------------------------- */

#define RX_SIZE          (256)
#define TX_INTERVAL_MS   (5000)
#define MESH_TX_TASK_STACK (2048U)
#define MESH_RX_TASK_STACK (6144U)
#define NODE0_WIFI_MTXON_STACK_EXTRA_WORDS (1000U)
#define NODE0_WIFI_MRX_STACK_EXTRA_WORDS   (500U)
//#define FIXED_ROOT  1   // node0 only

static const char *MESH_TAG = "node0";

static void log_internal_heap(const char *stage)
{
	ESP_LOGI(MESH_TAG,
	         "internal heap %s: free=%u largest=%u minimum=%u",
	         stage ? stage : "unknown",
	         (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
	         (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
	         (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
}

/* Same MESH_ID on every node in this mesh network. */
static const uint8_t MESH_ID[6] = { 0x77, 0x77, 0x77, 0x77, 0x77, 0x77 };

static bool       is_running        = true;
static bool       is_mesh_connected = false;
static mesh_addr_t mesh_parent_addr;
static int        mesh_layer        = -1;
static esp_netif_t *netif_sta       = NULL;

typedef int32_t (*node0_wifi_task_create_fn_t)(void *task_func,
                                               const char *name,
                                               uint32_t stack_depth,
                                               void *param,
                                               uint32_t prio,
                                               void *task_handle);

typedef int32_t (*node0_wifi_task_create_pinned_fn_t)(void *task_func,
                                                      const char *name,
                                                      uint32_t stack_depth,
                                                      void *param,
                                                      uint32_t prio,
                                                      void *task_handle,
                                                      uint32_t core_id);

static node0_wifi_task_create_fn_t s_wifi_task_create_orig = NULL;
static node0_wifi_task_create_pinned_fn_t s_wifi_task_create_pinned_orig = NULL;
static bool s_wifi_task_stack_patch_installed = false;

static uint32_t node0_wifi_stack_depth_for_task(const char *name,
                                                uint32_t stack_depth)
{
	if (name && strcmp(name, "MTXON") == 0) {
		return stack_depth + NODE0_WIFI_MTXON_STACK_EXTRA_WORDS;
	}
	if (name && strcmp(name, "MRX") == 0) {
		return stack_depth + NODE0_WIFI_MRX_STACK_EXTRA_WORDS;
	}

	return stack_depth;
}

static int32_t node0_wifi_task_create_wrapper(void *task_func,
                                              const char *name,
                                              uint32_t stack_depth,
                                              void *param,
                                              uint32_t prio,
                                              void *task_handle)
{
	return s_wifi_task_create_orig(
	    task_func,
	    name,
	    node0_wifi_stack_depth_for_task(name, stack_depth),
	    param,
	    prio,
	    task_handle);
}

static int32_t node0_wifi_task_create_pinned_wrapper(void *task_func,
                                                     const char *name,
                                                     uint32_t stack_depth,
                                                     void *param,
                                                     uint32_t prio,
                                                     void *task_handle,
                                                     uint32_t core_id)
{
	return s_wifi_task_create_pinned_orig(
	    task_func,
	    name,
	    node0_wifi_stack_depth_for_task(name, stack_depth),
	    param,
	    prio,
	    task_handle,
	    core_id);
}

static void node0_install_wifi_task_stack_patch(void)
{
	if (s_wifi_task_stack_patch_installed) {
		return;
	}

	if (!g_wifi_osi_funcs._task_create ||
	    !g_wifi_osi_funcs._task_create_pinned_to_core) {
		ESP_LOGW(MESH_TAG, "Wi-Fi stack patch skipped: Wi-Fi OS adapter missing task hooks");
		return;
	}

	s_wifi_task_create_orig = g_wifi_osi_funcs._task_create;
	s_wifi_task_create_pinned_orig = g_wifi_osi_funcs._task_create_pinned_to_core;
	g_wifi_osi_funcs._task_create = node0_wifi_task_create_wrapper;
	g_wifi_osi_funcs._task_create_pinned_to_core = node0_wifi_task_create_pinned_wrapper;
	s_wifi_task_stack_patch_installed = true;

	ESP_LOGI(MESH_TAG,
	         "Wi-Fi stack patch installed: MTXON +%u words, MRX +%u words",
	         (unsigned)NODE0_WIFI_MTXON_STACK_EXTRA_WORDS,
	         (unsigned)NODE0_WIFI_MRX_STACK_EXTRA_WORDS);
}

/* -------------------------------------------------------------------------- */
/*  Minimal local protocol                                                    */
/* -------------------------------------------------------------------------- */
/*
 * Packet format:
 *  magic    - 0xA5, identifies our packet
 *  version  - protocol version
 *  type     - packet type
 *  reserved - alignment / future use
 *  counter  - per-node packet counter
 *  src_mac  - sender MAC
 *  payload  - small zero-terminated text payload
 */

/* -------------------------------------------------------------------------- */
/*  Prototypes                                                                */
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
static esp_err_t node0_restart_dhcp_client(void);

#if CONFIG_NODE0_STATIC_IP_ENABLE
static esp_err_t node0_apply_static_ip(void);
#endif

static void copy_packet_text(char *dst, size_t dst_sz, const char *src, size_t src_sz)
{
	size_t n = 0;

	if (!dst || dst_sz == 0) {
		return;
	}

	if (src && src_sz > 0) {
		n = strnlen(src, src_sz);
		if (n >= dst_sz) {
			n = dst_sz - 1;
		}
		memcpy(dst, src, n);
	}
	dst[n] = '\0';
}

static esp_err_t copy_mesh_config_string(uint8_t *dst, size_t dst_sz,
                                         const char *src, size_t *out_len,
                                         const char *label)
{
	if (!dst || dst_sz == 0 || !src) {
		ESP_LOGE(MESH_TAG, "%s config string is invalid", label ? label : "mesh");
		return ESP_ERR_INVALID_ARG;
	}

	size_t len = strnlen(src, dst_sz + 1);
	if (len > dst_sz) {
		ESP_LOGE(MESH_TAG, "%s too long: %u > %u bytes",
		         label ? label : "mesh",
		         (unsigned)len,
		         (unsigned)dst_sz);
		return ESP_ERR_INVALID_SIZE;
	}

	memset(dst, 0, dst_sz);
	memcpy(dst, src, len);
	if (out_len) {
		*out_len = len;
	}
	return ESP_OK;
}

#define I_AM_SINGLE_SENDER     0      // debug single-target sender; production node0 must keep this disabled

// -----------------------------SINGLE_SENDER---------------------------------------
#if I_AM_SINGLE_SENDER
static const uint8_t NODE1_MAC[6] = { 0xA0, 0xDD, 0x6C, 0x0F, 0x31, 0xE4 };

static esp_err_t mesh_send_single(const uint8_t to_mac[6],
                                  const mesh_packet_t *pkt)
{
    mesh_addr_t dest = {0};
    mesh_data_t data;

    // Fill destination address.
    memcpy(dest.addr, to_mac, 6);

    data.data  = (uint8_t *)pkt;
    data.size  = sizeof(*pkt);
    data.proto = MESH_PROTO_BIN;
    data.tos   = MESH_TOS_P2P;

    // Normal P2P send; ESP-MESH resolves the route.
    return mesh_v2_link_send(dest.addr, data.data, data.size,
                             KEEMASH_REL_PRIORITY_NORMAL);
}
#endif


static esp_err_t node0_restart_dhcp_client(void)
{
	if (!netif_sta) {
		return ESP_ERR_INVALID_STATE;
	}

	esp_err_t err = esp_netif_dhcpc_stop(netif_sta);
	if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
		ESP_LOGW(MESH_TAG,
		         "DHCP client stop failed before restart: %s",
		         esp_err_to_name(err));
		return err;
	}

	err = esp_netif_dhcpc_start(netif_sta);
	if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED) {
		ESP_LOGW(MESH_TAG,
		         "DHCP client start failed: %s",
		         esp_err_to_name(err));
		return err;
	}

	return ESP_OK;
}


#if CONFIG_NODE0_STATIC_IP_ENABLE
static esp_err_t node0_set_dns_server(const char *addr, esp_netif_dns_type_t type)
{
	esp_netif_dns_info_t dns = {0};

	dns.ip.u_addr.ip4.addr = ipaddr_addr(addr);
	dns.ip.type = IPADDR_TYPE_V4;
	if (dns.ip.u_addr.ip4.addr == IPADDR_NONE) {
		ESP_LOGE(MESH_TAG, "invalid static DNS address: %s", addr);
		return ESP_ERR_INVALID_ARG;
	}

	return esp_netif_set_dns_info(netif_sta, type, &dns);
}


static esp_err_t node0_apply_static_ip(void)
{
	if (!netif_sta) {
		return ESP_ERR_INVALID_STATE;
	}

	uint32_t ip_addr = ipaddr_addr(CONFIG_NODE0_STATIC_IP_ADDR);
	uint32_t netmask_addr = ipaddr_addr(CONFIG_NODE0_STATIC_NETMASK_ADDR);
	uint32_t gw_addr = ipaddr_addr(CONFIG_NODE0_STATIC_GW_ADDR);

	if (ip_addr == IPADDR_NONE ||
	    netmask_addr == IPADDR_NONE ||
	    gw_addr == IPADDR_NONE) {
		ESP_LOGE(MESH_TAG,
		         "invalid static IP config ip:%s netmask:%s gw:%s",
		         CONFIG_NODE0_STATIC_IP_ADDR,
		         CONFIG_NODE0_STATIC_NETMASK_ADDR,
		         CONFIG_NODE0_STATIC_GW_ADDR);
		return ESP_ERR_INVALID_ARG;
	}

	esp_err_t err = esp_netif_dhcpc_stop(netif_sta);
	if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
		ESP_LOGE(MESH_TAG,
		         "failed to stop DHCP client before static IP: %s",
		         esp_err_to_name(err));
		return err;
	}

	esp_netif_ip_info_t ip = {0};
	ip.ip.addr = ip_addr;
	ip.netmask.addr = netmask_addr;
	ip.gw.addr = gw_addr;

	err = esp_netif_set_ip_info(netif_sta, &ip);
	if (err != ESP_OK) {
		ESP_LOGE(MESH_TAG,
		         "failed to set static IP info: %s",
		         esp_err_to_name(err));
		return err;
	}

	err = node0_set_dns_server(CONFIG_NODE0_STATIC_DNS_ADDR, ESP_NETIF_DNS_MAIN);
	if (err != ESP_OK) {
		ESP_LOGE(MESH_TAG,
		         "failed to set static DNS: %s",
		         esp_err_to_name(err));
		return err;
	}

	ESP_LOGI(MESH_TAG,
	         "static IP configured ip:%s netmask:%s gw:%s dns:%s",
	         CONFIG_NODE0_STATIC_IP_ADDR,
	         CONFIG_NODE0_STATIC_NETMASK_ADDR,
	         CONFIG_NODE0_STATIC_GW_ADDR,
	         CONFIG_NODE0_STATIC_DNS_ADDR);
	return ESP_OK;
}
#endif


#define SINGLE_TX_INTERVAL_MS  5000   // 5 seconds

// Keep this toggle so the debug sender can be enabled per build.
#if I_AM_SINGLE_SENDER
static void mesh_single_tx_task(void *arg)
{
    mesh_packet_t pkt;
    esp_err_t     err;
    uint32_t      counter = 0;

    TickType_t last_wake = xTaskGetTickCount();

    while (is_running) {
        // Wait exactly one interval after the previous tick.
        vTaskDelayUntil(&last_wake, pdMS_TO_TICKS(SINGLE_TX_INTERVAL_MS));

        // Do nothing before the node is in the mesh.
        if (!is_mesh_connected) {
            continue;
        }

        counter++;

        memset(&pkt, 0, sizeof(pkt));
        pkt.magic   = MESH_PKT_MAGIC;
        pkt.version = MESH_PKT_VERSION;
        pkt.type    = MESH_PKT_TYPE_TEXT;
        pkt.counter = counter;

        // This node MAC for diagnostics.
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
#endif


/* -------------------------------------------------------------------------- */
/*  TX task: periodically send a packet to root                                */
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

		// Send only when connected to mesh and not acting as root.
		if (!is_mesh_connected || esp_mesh_is_root()) {
			continue;
		}

		counter++;

		memset(&pkt, 0, sizeof(pkt));
		pkt.magic   = MESH_PKT_MAGIC;
		pkt.version = MESH_PKT_VERSION;
		pkt.type    = MESH_PKT_TYPE_TEXT;
		pkt.counter = counter;

		// This node MAC on the STA interface.
		esp_wifi_get_mac(WIFI_IF_STA, pkt.src_mac);

		snprintf(pkt.payload, sizeof(pkt.payload),
		         "Hello %lu", (unsigned long)counter);

		data.size = sizeof(pkt);

		// 00:00:00:00:00:00 means "send to root".
		memset(&dest, 0, sizeof(dest));

		err = mesh_v2_link_send(dest.addr, data.data, data.size,
					KEEMASH_REL_PRIORITY_NORMAL);
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
/*  RX task: receive packets from other nodes                                  */
/* -------------------------------------------------------------------------- */
static void mesh_rx_task(void *arg)
{
	uint8_t      rx_buf[256];
	mesh_data_t  data;
	mesh_addr_t  from;
	int          flag = 0;
	esp_err_t    err;

	memset(&data, 0, sizeof(data));
	data.data = rx_buf;
	data.size = sizeof(rx_buf);

	while (is_running) {

		data.size = sizeof(rx_buf);
		err = esp_mesh_recv(&from, &data, portMAX_DELAY, &flag, NULL, 0);
		if (err != ESP_OK) {
			ESP_LOGE(MESH_TAG, "esp_mesh_recv failed: 0x%x (%s)", err, esp_err_to_name(err));
			continue;
		}

		if (data.size < sizeof(mesh_pkt_hdr_t)) {
			ESP_LOGW(MESH_TAG, "RX too short: %d bytes", data.size);
			continue;
		}

		const mesh_pkt_hdr_t *h = (const mesh_pkt_hdr_t *)rx_buf;

		if (h->magic == MESH_PKT_MAGIC && h->version == MESH_PKT_VERSION_V2) {
			mesh_v2_root_handle_rx(from.addr, rx_buf, data.size);
			continue;
		}

		// Our protocol?
		if (h->magic == MESH_PKT_MAGIC && h->version == MESH_PKT_VERSION) {

			// 1) NodeInfo for menu/listing.
			if (h->type == MESH_LOG_TYPE_NODEINFO) {
				if (data.size >= sizeof(mesh_nodeinfo_v2_packet_t)) {
					const mesh_nodeinfo_v2_packet_t *p = (const mesh_nodeinfo_v2_packet_t *)rx_buf;
					char tag[sizeof(p->tag) + 1];
					copy_packet_text(tag, sizeof(tag), p->tag, sizeof(p->tag));
					log_http_server_node_seen_uptime(p->h.src_mac, tag, true, p->uptime_s);
				} else if (data.size >= sizeof(mesh_nodeinfo_packet_t)) {
					const mesh_nodeinfo_packet_t *p = (const mesh_nodeinfo_packet_t *)rx_buf;
					char tag[sizeof(p->tag) + 1];
					copy_packet_text(tag, sizeof(tag), p->tag, sizeof(p->tag));
					log_http_server_node_seen(p->h.src_mac, tag);
				}
				continue;
			}

			// 2) Log line. The web log layer filters by selected node.
			if (h->type == MESH_LOG_TYPE_LINE) {
				if (data.size >= sizeof(mesh_log_line_packet_t)) {
					const mesh_log_line_packet_t *p = (const mesh_log_line_packet_t *)rx_buf;
					char tag[sizeof(p->tag) + 1];
					char line[sizeof(p->line) + 1];
					copy_packet_text(tag, sizeof(tag), p->tag, sizeof(p->tag));
					copy_packet_text(line, sizeof(line), p->line, sizeof(p->line));
					log_http_server_node_seen(p->h.src_mac, tag);          // keep node visible in the list
					log_http_server_remote_line(p->h.src_mac, tag, line); // buffered only when selected
				}
				continue;
			}

			// 4) Legacy TEXT packet.
			if (h->type == MESH_OTA_TYPE_STATUS) {
				if (data.size >= sizeof(mesh_ota_status_packet_t)) {
					const mesh_ota_status_packet_t *p = (const mesh_ota_status_packet_t *)rx_buf;
					log_http_server_remote_ota_status(p->h.src_mac, p, data.size);
				}
				continue;
			}

			if (h->type == MESH_REBOOT_TYPE_STATUS) {
				if (data.size >= sizeof(mesh_reboot_status_packet_t)) {
					const mesh_reboot_status_packet_t *p = (const mesh_reboot_status_packet_t *)rx_buf;
					log_http_server_remote_reboot_status(p->h.src_mac, p);
				}
				continue;
			}

			if (h->type == MESH_PKT_TYPE_TEXT) {
				if (data.size >= sizeof(mesh_packet_t)) {
					const mesh_packet_t *p = (const mesh_packet_t *)rx_buf;
					char payload[33];
					memcpy(payload, p->payload, 32);
					payload[32] = '\0';

					ESP_LOGI(MESH_TAG, "RX TEXT: cnt=%lu from " MACSTR " payload=\"%s\"",
						(unsigned long)p->counter, MAC2STR(from.addr), payload);

					// Hook legacy_handle_text() here if needed again.
					legacy_handle_text(payload);
				}
				continue;
			}

			// Other packet types in our protocol.
			ESP_LOGI(MESH_TAG, "RX type=%u from " MACSTR " len=%u", h->type, MAC2STR(from.addr), (unsigned)data.size);
			continue;
		}

		// Unknown protocol; keep ignoring it for now.
		ESP_LOGW(MESH_TAG, "RX unknown packet from " MACSTR " len=%u", MAC2STR(from.addr), (unsigned)data.size);
	}
	vTaskDelete(NULL);
}


/* -------------------------------------------------------------------------- */
/*  Start TX/RX tasks once                                                     */
/* -------------------------------------------------------------------------- */

static esp_err_t mesh_comm_start(void)
{
	static bool started = false;

	if (!started) {
		started = true;
		xTaskCreate(mesh_tx_task, "mesh_tx", MESH_TX_TASK_STACK, NULL, 5, NULL);
		xTaskCreate(mesh_rx_task, "mesh_rx", MESH_RX_TASK_STACK, NULL, 5, NULL);
#if I_AM_SINGLE_SENDER
        xTaskCreate(mesh_single_tx_task,"mesh_single_tx",4096, NULL, 5, NULL);
#endif
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
		log_http_server_refresh_routes();
		mesh_v2_link_refresh_routes();
	}
	break;

	case MESH_EVENT_ROUTING_TABLE_REMOVE: {
		mesh_event_routing_table_change_t *rt =
		    (mesh_event_routing_table_change_t *)event_data;
		ESP_LOGW(MESH_TAG,
		         "<MESH_EVENT_ROUTING_TABLE_REMOVE> remove %d, new:%d, layer:%d",
		         rt->rt_size_change, rt->rt_size_new, mesh_layer);
		log_http_server_refresh_routes();
		mesh_v2_link_refresh_routes();
		log_http_server_mesh_state_changed();
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
#if CONFIG_NODE0_STATIC_IP_ENABLE
			esp_err_t err = node0_apply_static_ip();
			if (err != ESP_OK) {
				ESP_LOGW(MESH_TAG,
				         "static IP setup failed (%s), falling back to DHCP",
				         esp_err_to_name(err));
				ESP_ERROR_CHECK_WITHOUT_ABORT(node0_restart_dhcp_client());
			}
#else
			ESP_ERROR_CHECK_WITHOUT_ABORT(node0_restart_dhcp_client());
#endif

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
/*  IP events: root received router-facing IP                                  */
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

	// Start the web server only on root.
	if (esp_mesh_is_root()) {
		keelink_ble_note_boot_checkpoint(95);
		if (log_http_server_start() == ESP_OK) {
			log_http_server_network_ready();
		}
	}
}


/* -------------------------------------------------------------------------- */
/*  app_main: mesh + Wi-Fi init                                                */
/* -------------------------------------------------------------------------- */

void app_main(void)
{
	//ESP_ERROR_CHECK(mesh_light_init());   // optional LED init
	log_time_vprintf_start();
	
	ESP_ERROR_CHECK(nvs_flash_init());
	esp_err_t zone_err = heater_zone_init();
	if (zone_err != ESP_OK) ESP_LOGE("heater_zone", "zone routing unavailable: %s", esp_err_to_name(zone_err));
	ESP_ERROR_CHECK(esp_netif_init());
	ESP_ERROR_CHECK(esp_event_loop_create_default());

	// Create mesh netifs; keep the STA netif handle.
	ESP_ERROR_CHECK(
	    esp_netif_create_default_wifi_mesh_netifs(&netif_sta, NULL));

	// Wi-Fi
	node0_install_wifi_task_stack_patch();
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
    // --- node type / fixed root setup ---

        // This firmware always acts as root when it can reach the router.
    ESP_ERROR_CHECK(keemash_mesh_apply_single_root_policy(
        KEEMASH_MESH_ROLE_ROOT));


	ESP_ERROR_CHECK(esp_mesh_set_topology(CONFIG_MESH_TOPOLOGY));
	ESP_ERROR_CHECK(esp_mesh_set_max_layer(CONFIG_MESH_MAX_LAYER));
	ESP_ERROR_CHECK(esp_mesh_set_vote_percentage(1));
	ESP_ERROR_CHECK(esp_mesh_set_xon_qsize(128));

	ESP_ERROR_CHECK(esp_mesh_disable_ps());
	/* Encrypted mesh children may be quiet for more than the 10 s default. */
	ESP_ERROR_CHECK(esp_mesh_set_ap_assoc_expire(30));

	mesh_cfg_t cfg = MESH_INIT_CONFIG_DEFAULT();

	// mesh_id
	memcpy(cfg.mesh_id.addr, MESH_ID, 6);

	// Router-facing Wi-Fi credentials from menuconfig.
	cfg.channel        = CONFIG_MESH_CHANNEL;
	size_t router_ssid_len = 0;
	ESP_ERROR_CHECK(copy_mesh_config_string(cfg.router.ssid,
	                                        sizeof(cfg.router.ssid),
	                                        CONFIG_MESH_ROUTER_SSID,
	                                        &router_ssid_len,
	                                        "router ssid"));
	cfg.router.ssid_len = (uint8_t)router_ssid_len;
	ESP_ERROR_CHECK(copy_mesh_config_string(cfg.router.password,
	                                        sizeof(cfg.router.password),
	                                        CONFIG_MESH_ROUTER_PASSWD,
	                                        NULL,
	                                        "router password"));

	// Mesh AP for child nodes.
	ESP_ERROR_CHECK(esp_mesh_set_ap_authmode(CONFIG_MESH_AP_AUTHMODE));
	cfg.mesh_ap.max_connection        = CONFIG_MESH_AP_CONNECTIONS;
	cfg.mesh_ap.nonmesh_max_connection = CONFIG_MESH_NON_MESH_AP_CONNECTIONS;
	ESP_ERROR_CHECK(copy_mesh_config_string(cfg.mesh_ap.password,
	                                        sizeof(cfg.mesh_ap.password),
	                                        CONFIG_MESH_AP_PASSWD,
	                                        NULL,
	                                        "mesh ap password"));

	ESP_ERROR_CHECK(esp_mesh_set_config(&cfg));

	ESP_ERROR_CHECK(log_http_server_init());
	ESP_ERROR_CHECK(log_http_server_start());
	log_internal_heap("before BLE");
#if CONFIG_NODE0_KEELINK_ENABLE && CONFIG_NODE0_KEELINK_BLE_ENABLE
	esp_err_t ble_err = keelink_ble_init();
	if (ble_err == ESP_OK) {
		keelink_ble_note_boot_checkpoint(75);
		ble_err = keelink_ble_start_host();
	}
	if (ble_err != ESP_OK) {
		ESP_LOGW(MESH_TAG, "KeeLink BLE pre-mesh startup failed: %s",
			esp_err_to_name(ble_err));
	}
	log_internal_heap("after BLE host start");
#endif
	ESP_ERROR_CHECK(esp_mesh_start());
	keelink_ble_note_boot_checkpoint(90);
	mesh_v2_link_require();
	esp_err_t v2_init_err = mesh_v2_root_init();
	ESP_ERROR_CHECK(v2_init_err);
	mesh_v2_link_refresh_routes();

	ESP_LOGI(MESH_TAG,
	         "mesh started, heap:%" PRId32 ", root_fixed:%d, topo:%d %s, ps:%d",
	         esp_get_minimum_free_heap_size(),
	         esp_mesh_is_root_fixed(),
	         esp_mesh_get_topology(),
	         esp_mesh_get_topology() ? "(chain)" : "(tree)",
	         esp_mesh_is_ps_enabled());
	log_internal_heap("after mesh start");

	uart_bridge_init();
	uart_bridge_start();
	mesh_time_sync_init();
	
}
