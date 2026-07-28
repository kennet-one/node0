#include "mesh_v2_link.h"

#include <stddef.h>
#include <string.h>

#include "esp_err.h"
#include "esp_mesh.h"
#include "esp_wifi.h"
#include "sdkconfig.h"

#include "keemash_mesh_hooks.h"
#include "keemash_mesh_tx_broker.h"
#include "legacy_proto.h"
#include "log_http_server.h"
#include "mesh_root_bcast.h"

static keemash_mesh_tx_broker_t *s_tx_broker;

static esp_err_t raw_mesh_send(void *user, const uint8_t dst[6],
			       const void *packet, size_t packet_len)
{
	(void)user;
	mesh_addr_t dest = {0};
	if (dst) memcpy(dest.addr, dst, 6);
	mesh_data_t data = {
		.data = (uint8_t *)packet,
		.size = packet_len,
		.proto = MESH_PROTO_BIN,
		.tos = MESH_TOS_P2P,
	};
	return esp_mesh_send(&dest, &data, MESH_DATA_P2P, NULL, 0);
}

void mesh_v2_link_require(void)
{
	if (s_tx_broker) return;
	keemash_mesh_tx_broker_config_t cfg = {
		.slots = 32,
		.control_reserved_slots = 4,
		.max_packet_size = 512,
		.task_stack_words = 4096,
		.task_priority = 7,
		.task_name = "mesh_tx",
		.raw_send = raw_mesh_send,
	};
	ESP_ERROR_CHECK(keemash_mesh_tx_broker_init(&s_tx_broker, &cfg));
}

void mesh_v2_link_refresh_routes(void)
{
	mesh_addr_t routes[CONFIG_MESH_ROUTE_TABLE_SIZE];
	int count = 0;
	if (esp_mesh_get_routing_table(routes, sizeof(routes), &count) != ESP_OK) return;
	uint8_t local[6] = {0};
	esp_wifi_get_mac(WIFI_IF_STA, local);
	uint8_t macs[CONFIG_MESH_ROUTE_TABLE_SIZE][6];
	size_t remote_count = 0;
	for (int i = 0; i < count && remote_count < CONFIG_MESH_ROUTE_TABLE_SIZE; i++) {
		if (memcmp(routes[i].addr, local, 6) == 0) continue;
		memcpy(macs[remote_count++], routes[i].addr, 6);
	}
	mesh_v2_root_sync_routes(remote_count ? &macs[0][0] : NULL, remote_count);
}

esp_err_t keemash_mesh_transport_send(const uint8_t dst[6], const void *packet, size_t packet_len)
{
	if (!packet || packet_len == 0) return ESP_ERR_INVALID_ARG;
	if (!s_tx_broker) return ESP_ERR_INVALID_STATE;
	return keemash_mesh_tx_broker_submit_auto(s_tx_broker, dst, packet, packet_len);
}

esp_err_t mesh_v2_link_send(const uint8_t dst[6], const void *packet,
			    size_t packet_len, uint8_t priority)
{
	if (!packet || packet_len == 0) return ESP_ERR_INVALID_ARG;
	if (!s_tx_broker) return ESP_ERR_INVALID_STATE;
	return keemash_mesh_tx_broker_submit(s_tx_broker, dst, packet, packet_len,
					     priority);
}

void mesh_v2_link_tx_stats(keemash_mesh_tx_broker_stats_t *out)
{
	keemash_mesh_tx_broker_stats(s_tx_broker, out);
}

void keemash_mesh_get_local_mac(uint8_t mac[6])
{
	esp_wifi_get_mac(WIFI_IF_STA, mac);
}

void keemash_mesh_root_on_node_seen_uptime(const uint8_t mac[6], const char *tag,
                                           bool uptime_valid, uint32_t uptime_s)
{
	log_http_server_node_seen_uptime(mac, tag, uptime_valid, uptime_s);
}

void keemash_mesh_root_on_node_seen(const uint8_t mac[6], const char *tag)
{
	log_http_server_node_seen(mac, tag);
}

void keemash_mesh_root_on_log_line(const uint8_t mac[6], const char *tag, const char *line)
{
	log_http_server_node_seen(mac, tag);
	log_http_server_remote_line(mac, tag, line);
}

void keemash_mesh_root_on_task_snapshot(const uint8_t mac[6],
                                        const mesh_v2_task_snapshot_payload_t *snapshot)
{
	log_http_server_task_snapshot_v2(mac, snapshot);
}

void keemash_mesh_root_on_memory_snapshot(const uint8_t mac[6],
                                          const mesh_v2_memory_payload_t *snapshot)
{
	log_http_server_memory_snapshot_v2(mac, snapshot);
}

void keemash_mesh_root_on_ota_status(const uint8_t mac[6],
                                     const mesh_v2_ota_status_payload_t *status,
                                     size_t status_len)
{
	log_http_server_remote_ota_status_v2(mac, status, status_len);
}

void keemash_mesh_root_on_topology(const uint8_t mac[6], const void *payload, size_t payload_len)
{
	log_http_server_node_topology(mac, payload, payload_len);
}

void keemash_mesh_root_on_control_event(const char *text)
{
	legacy_handle_text(text);
}

void keemash_mesh_root_on_control(const uint8_t peer[6], uint32_t root_session,
				  uint32_t node_session, uint8_t kind,
				  uint32_t command_id, uint8_t status,
				  const char *text)
{
	(void)node_session;
	if (kind == MESH_V2_CONTROL_RESULT) {
		mesh_root_command_result(peer, root_session, command_id, status, text);
	}
}

void keemash_mesh_root_on_state_changed(void)
{
	log_http_server_mesh_state_changed();
}
