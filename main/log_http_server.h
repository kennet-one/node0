#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t log_http_server_init(void);
esp_err_t log_http_server_start(void);

// Викликає root при RX: NODEINFO
void log_http_server_node_seen(const uint8_t mac[6], const char *tag);
void log_http_server_node_seen_uptime(const uint8_t mac[6], const char *tag,
                                      bool uptime_valid, uint32_t uptime_s);

// Викликає root при RX: LOG_LINE
void log_http_server_remote_line(const uint8_t mac[6], const char *tag, const char *line);

#ifdef __cplusplus
}
#endif
