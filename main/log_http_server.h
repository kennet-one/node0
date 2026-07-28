#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mesh_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t log_http_server_init(void);
esp_err_t log_http_server_start(void);

// Called by root RX path for NODEINFO.
void log_http_server_node_seen(const uint8_t mac[6], const char *tag);
void log_http_server_node_seen_uptime(const uint8_t mac[6], const char *tag,
                                      bool uptime_valid, uint32_t uptime_s);
void log_http_server_node_topology(const uint8_t mac[6],
                                   const mesh_v2_topology_payload_t *topology,
                                   size_t topology_len);
void log_http_server_task_snapshot_v2(const uint8_t mac[6],
                                      const mesh_v2_task_snapshot_payload_t *snapshot);
void log_http_server_memory_snapshot_v2(const uint8_t mac[6],
                                        const mesh_v2_memory_payload_t *snapshot);

// Called by root RX path for LOG_LINE.
void log_http_server_remote_line(const uint8_t mac[6], const char *tag, const char *line);

void log_http_server_remote_ota_status(const uint8_t mac[6],
                                       const mesh_ota_status_packet_t *status,
                                       size_t status_len);
void log_http_server_remote_ota_status_v2(const uint8_t mac[6],
                                          const mesh_v2_ota_status_payload_t *status,
                                          size_t status_len);
void log_http_server_remote_reboot_status(const uint8_t mac[6],
                                          const mesh_reboot_status_packet_t *status);

// Called by mesh events when the routing table changes.
void log_http_server_refresh_routes(void);
void log_http_server_mesh_state_changed(void);
bool log_http_server_find_routable_by_tag(const char *tag, uint8_t mac[6]);
void log_http_server_command_status(const char *state, const char *owner,
                                    uint32_t command_id, const char *detail);

#ifdef __cplusplus
}
#endif
