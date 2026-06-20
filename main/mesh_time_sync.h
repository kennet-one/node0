#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// TIME packets use legacy type=2.
#define MESH_TIME_SYNC_TYPE_TIME	2

void		mesh_time_sync_init(void);

// Root: start the task that sends time to mesh nodes every period_ms.
esp_err_t	mesh_time_sync_root_start(uint32_t period_ms);

// RX: call from mesh_rx_task when pkt.type == 2.
esp_err_t	mesh_time_sync_handle_rx(const void *pkt_buf, size_t pkt_len);

#ifdef __cplusplus
}
#endif
