#include "uart_bridge.h"

#include <string.h>

#include "esp_log.h"
#include "driver/uart.h"
#include "driver/gpio.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "mesh_root_bcast.h"
#include "keelink_server.h"

static const char *TAG = "uart_bridge";

/* -------------------------------------------------------------------------- */
/*  UART configuration                                                        */
/* -------------------------------------------------------------------------- */

/*
 * KeeMASH bridge: UART1, TX=17, RX=16, 115200.
 */
#define UART_BRIDGE_PORT   UART_NUM_1
#define UART_BRIDGE_TX_PIN GPIO_NUM_17
#define UART_BRIDGE_RX_PIN GPIO_NUM_16
#define UART_BRIDGE_BAUD   115200

#define UART_BRIDGE_RX_BUF 128

static TaskHandle_t s_uart_task = NULL;

/* -------------------------------------------------------------------------- */
/*  Read complete UART lines and route them through the mesh root.             */
/* -------------------------------------------------------------------------- */

static void uart_bridge_task(void *arg)
{
	uint8_t buf[UART_BRIDGE_RX_BUF];
	size_t  len = 0;

	while (1) {
		int n = uart_read_bytes(
		    UART_BRIDGE_PORT,
		    buf + len,
		    UART_BRIDGE_RX_BUF - 1 - len,
		    pdMS_TO_TICKS(20));

		if (n > 0) {
			len += n;

			// Parse CR/LF-delimited lines.
			for (size_t i = 0; i < len; ++i) {
				uint8_t ch = buf[i];

				if (ch == '\r') {
					// Ignore CR; LF terminates the line.
					continue;
				}

				if (ch == '\n') {
					// Complete line in [0..i-1].
					buf[i] = 0;
					char *line = (char *)buf;

					// Trim leading whitespace.
					while (*line == ' ' || *line == '\t') {
						++line;
					}
					// Trim trailing whitespace.
					size_t L = strlen(line);
					while (L > 0 &&
					       (line[L - 1] == ' ' ||
					        line[L - 1] == '\t')) {
						line[--L] = 0;
					}

					if (L > 0) {
						char response[128] = {0};
						if (keelink_server_handle_uart_claim(line, response,
									    sizeof(response))) {
							ESP_LOGI(TAG, "RX UART: KeeLink commissioning request");
							char *reply = response;
							while (reply && *reply) {
								char *next = strchr(reply, '\n');
								if (next) *next = '\0';
								if (*reply) {
									uart_bridge_send_line(reply);
									if (next) vTaskDelay(pdMS_TO_TICKS(125));
								}
								reply = next ? next + 1 : NULL;
							}
							memset(response, 0, sizeof(response));
						} else {
							ESP_LOGI(TAG, "RX UART: '%s'", line);
							// Route HMI lines through the owner map.
							mesh_root_broadcast_text(line);
						}
					}

					// Move the remaining bytes to the start of the buffer.
					size_t remain = len - (i + 1);
					memmove(buf, buf + i + 1, remain);
					len = remain;
					i   = (size_t)-1;   // Restart parsing from the buffer head.
				}
			}

			// Drop an unterminated line that fills the fixed buffer.
			if (len >= UART_BRIDGE_RX_BUF - 1) {
				len = 0;
			}
		}
	}
}

/* -------------------------------------------------------------------------- */
/*  Public API                                                                */
/* -------------------------------------------------------------------------- */

void uart_bridge_init(void)
{
	uart_config_t cfg = {
		.baud_rate  = UART_BRIDGE_BAUD,
		.data_bits  = UART_DATA_8_BITS,
		.parity     = UART_PARITY_DISABLE,
		.stop_bits  = UART_STOP_BITS_1,
		.flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
		.source_clk = UART_SCLK_DEFAULT
	};

	// The driver owns the RX buffer; TX remains unbuffered.
	ESP_ERROR_CHECK(uart_driver_install(
	    UART_BRIDGE_PORT,
	    UART_BRIDGE_RX_BUF * 2,
	    0,
	    0,
	    NULL,
	    0));

	ESP_ERROR_CHECK(uart_param_config(UART_BRIDGE_PORT, &cfg));

	ESP_ERROR_CHECK(uart_set_pin(
	    UART_BRIDGE_PORT,
	    UART_BRIDGE_TX_PIN,
	    UART_BRIDGE_RX_PIN,
	    UART_PIN_NO_CHANGE,
	    UART_PIN_NO_CHANGE));

	ESP_LOGI(TAG, "UART bridge init: port=%d TX=%d RX=%d baud=%d",
	         (int)UART_BRIDGE_PORT,
	         (int)UART_BRIDGE_TX_PIN,
	         (int)UART_BRIDGE_RX_PIN,
	         UART_BRIDGE_BAUD);
}

void uart_bridge_start(void)
{
	if (s_uart_task) {
		return;
	}

	BaseType_t ok = xTaskCreate(
	    uart_bridge_task,
	    "uart_bridge",
	    4096,
	    NULL,
	    5,
	    &s_uart_task);

	if (ok != pdPASS) {
		ESP_LOGE(TAG, "failed to create uart_bridge task");
		s_uart_task = NULL;
	}
}

/*
 * Send one line to the Windows/Bluetooth bridge. The UART driver owns
 * serialization; this module does not add another FreeRTOS queue.
 */
void uart_bridge_send_line(const char *text)
{
	if (!text) {
		return;
	}

	size_t len = strlen(text);
	if (!len) {
		return;
	}

	uart_write_bytes(UART_BRIDGE_PORT, text, len);

	// Add LF so the peer receives one complete line.
	const char nl = '\n';
	uart_write_bytes(UART_BRIDGE_PORT, &nl, 1);

	if (strncmp(text, "keelink.claim.", 15) == 0 ||
	    strncmp(text, "KC1:", 4) == 0) {
		ESP_LOGI(TAG, "TX UART: KeeLink commissioning response");
	} else {
		ESP_LOGI(TAG, "TX UART: '%s'", text);
	}
}
