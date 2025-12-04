#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Ініціалізація UART-бріджа (конфіг порта, пінів, драйвера) */
void uart_bridge_init(void);

/** Старт задачі, яка читає UART і шле текст у mesh root-broadcast */
void uart_bridge_start(void);

/** Відправити одну строку в UART (додасть '\n' в кінці). */
void uart_bridge_send_line(const char *text);

#ifdef __cplusplus
}
#endif
