#pragma once

#include "esp_err.h"
#include <stdbool.h>
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
                                   const mesh_v2_topology_payload_t *topology);

// Called by root RX path for LOG_LINE.
void log_http_server_remote_line(const uint8_t mac[6], const char *tag, const char *line);

void log_http_server_remote_ota_status(const uint8_t mac[6],
                                       const mesh_ota_status_packet_t *status);

// Called by mesh events when the routing table changes.
void log_http_server_refresh_routes(void);

#ifdef __cplusplus
}
#endif
