// main/uart_bridge.c

#include <string.h>
#include "esp_log.h"
#include "esp_err.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "driver/uart.h"
#include "driver/gpio.h"

#include "mesh_root_bcast.h"


#define ROOT_UART_PORT UART_NUM_1    // можна 1 або 2
#define ROOT_UART_TX   GPIO_NUM_17   // TX root -> RX master (17 -> 16)
#define ROOT_UART_RX   GPIO_NUM_16   // RX root <- TX master (16 <- 17)

static const char *TAGU = "uart_bridge";

static void uart_bridge_task(void *arg)
{
    uint8_t buf[128];

    while (1) {
        // читаємо, максимум 127 байт, 20мс таймаут
        int n = uart_read_bytes(ROOT_UART_PORT,
                                (uint8_t*)buf,
                                sizeof(buf) - 1,
                                pdMS_TO_TICKS(20));
        if (n > 0) {
            buf[n] = 0;  // робимо "рядок" для логів

            // можна тут почистити \r\n/пробіли, якщо хочеш
            ESP_LOGI(TAGU, "RX UART: '%s'", (char *)buf);

                    // якщо з Arduino прилетів тільки \r\n, можна ще підчистити:
            while (n > 0 && (buf[n-1] == '\r' || buf[n-1] == '\n')) {
                buf[--n] = '\0';
            }
            
            if (n == 0) {
                continue;
            }

            mesh_root_broadcast_text((const char*)buf);

            // TODO: тут можеш парсити команду і
            // або шити її в esp_mesh_send(),
            // або просто логати, або відповідати назад через uart_write_bytes().
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

esp_err_t uart_bridge_init(void)
{
    const uart_config_t cfg = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    ESP_ERROR_CHECK(uart_driver_install(
        ROOT_UART_PORT,
        2048,   // RX буфер
        0,      // TX буфер (0 = не юзаємо)
        0,
        NULL,
        0));

    ESP_ERROR_CHECK(uart_param_config(ROOT_UART_PORT, &cfg));

    ESP_ERROR_CHECK(uart_set_pin(
        ROOT_UART_PORT,
        ROOT_UART_TX,
        ROOT_UART_RX,
        UART_PIN_NO_CHANGE,
        UART_PIN_NO_CHANGE));

    ESP_LOGI(TAGU, "UART bridge init on U%d TX=%d RX=%d",
             ROOT_UART_PORT, (int)ROOT_UART_TX, (int)ROOT_UART_RX);

    // Стартуємо таску
    xTaskCreate(uart_bridge_task,
                "uart_bridge",
                4096,
                NULL,
                4,
                NULL);

    return ESP_OK;
}
