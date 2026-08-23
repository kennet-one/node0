#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Configure the UART bridge port, pins and driver. */
void uart_bridge_init(void);

/** Start the task that reads UART lines and routes legacy text into the mesh. */
void uart_bridge_start(void);

/** Send one UART line and append a newline. */
void uart_bridge_send_line(const char *text);

#ifdef __cplusplus
}
#endif
