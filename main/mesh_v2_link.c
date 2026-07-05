#include "mesh_v2_link.h"

#include <stddef.h>
#include <string.h>

#include "esp_err.h"
#include "esp_mesh.h"
#include "esp_wifi.h"

#include "keemash_mesh_hooks.h"
#include "legacy_proto.h"
#include "log_http_server.h"

void mesh_v2_link_require(void)
{
}

esp_err_t keemash_mesh_transport_send(const uint8_t dst[6], const void *packet, size_t packet_len)
{
	if (!packet || packet_len == 0) return ESP_ERR_INVALID_ARG;
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

void keemash_mesh_root_on_state_changed(void)
{
	log_http_server_mesh_state_changed();
}
