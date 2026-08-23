#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_http_server.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t keelink_server_init(void);
esp_err_t keelink_server_register(httpd_handle_t server);
esp_err_t keelink_server_network_ready(void);

typedef esp_err_t (*keelink_ble_send_fn)(const uint8_t *frame, size_t frame_len);
void keelink_server_set_ble_sender(keelink_ble_send_fn sender);
bool keelink_server_token_verifier(uint8_t out[32]);
bool keelink_server_wss_active(void);
void keelink_server_session_closed(int fd);
bool keelink_server_handle_uart_claim(const char *line, char *response,
				      size_t response_capacity);
esp_err_t keelink_server_handle_ble_frame(const uint8_t *frame, size_t frame_len,
					  uint8_t *response, size_t response_capacity,
					  size_t *response_len);

void keelink_server_publish_inventory(void);
void keelink_server_publish_log(const uint8_t mac[6], const char *tag,
				 const char *line);
void keelink_server_publish_text_event(uint16_t channel, const uint8_t mac[6],
					const char *tag, const char *text);
void keelink_server_command_result(uint32_t command_id, uint8_t status,
				   const char *text);

#ifdef __cplusplus
}
#endif
