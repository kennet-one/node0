#include "uart_bridge.h"

#include <string.h>

#include "esp_log.h"
#include "driver/uart.h"
#include "driver/gpio.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "mesh_root_bcast.h"   // тут оголошено mesh_root_broadcast_text()

static const char *TAG = "uart_bridge";

/* -------------------------------------------------------------------------- */
/*  Налаштування UART                                                         */
/* -------------------------------------------------------------------------- */

/*
 * Підлаштуй під свої пін-а, якщо потрібно.
 * Зараз: UART1, TX=17, RX=16, 115200.
 */
#define UART_BRIDGE_PORT   UART_NUM_1
#define UART_BRIDGE_TX_PIN GPIO_NUM_17
#define UART_BRIDGE_RX_PIN GPIO_NUM_16
#define UART_BRIDGE_BAUD   115200

#define UART_BRIDGE_RX_BUF 128

static TaskHandle_t s_uart_task = NULL;

/* -------------------------------------------------------------------------- */
/*  Таска: читаємо UART построчно, шлемо в mesh root-broadcast                */
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

			// Парсимо по '\n' / '\r'
			for (size_t i = 0; i < len; ++i) {
				uint8_t ch = buf[i];

				if (ch == '\r') {
					// ігноруємо CR
					continue;
				}

				if (ch == '\n') {
					// є ціла строка [0..i-1]
					buf[i] = 0;
					char *line = (char *)buf;

					// обрізаємо пробіли з початку
					while (*line == ' ' || *line == '\t') {
						++line;
					}
					// і з кінця
					size_t L = strlen(line);
					while (L > 0 &&
					       (line[L - 1] == ' ' ||
					        line[L - 1] == '\t')) {
						line[--L] = 0;
					}

					if (L > 0) {
						ESP_LOGI(TAG, "RX UART: '%s'", line);
						// розкидуємо по всій mesh-мережі
						mesh_root_broadcast_text(line);
					}

					// зсуваємо хвіст буфера в початок
					size_t remain = len - (i + 1);
					memmove(buf, buf + i + 1, remain);
					len = remain;
					i   = (size_t)-1;   // стартуємо цикл заново
				}
			}

			// якщо буфер забитий без '\n' – просто обнуляємо
			if (len >= UART_BRIDGE_RX_BUF - 1) {
				len = 0;
			}
		}
	}
}

/* -------------------------------------------------------------------------- */
/*  Публічні функції                                                          */
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

	// RX-буфер для драйвера, TX не використовуємо буферизацію
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
 * Відправити строку в UART (одна команда для Windows-моста / Bluetooth-ESP).
 * Ніяких FreeRTOS-черг тут немає – просто uart_write_bytes().
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

	// додаємо '\n', щоб з того боку приймалося як окрема строка
	const char nl = '\n';
	uart_write_bytes(UART_BRIDGE_PORT, &nl, 1);

	ESP_LOGI(TAG, "TX UART: '%s'", text);
}
