#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// Ми займаємо type=2 під TIME
#define MESH_TIME_SYNC_TYPE_TIME	2

void		mesh_time_sync_init(void);

// Root: стартує таску, яка розсилає час всім нодам раз в period_ms
esp_err_t	mesh_time_sync_root_start(uint32_t period_ms);

// RX: викликаєш у mesh_rx_task, коли pkt.type == 2
esp_err_t	mesh_time_sync_handle_rx(const void *pkt_buf, size_t pkt_len);

#ifdef __cplusplus
}
#endif
