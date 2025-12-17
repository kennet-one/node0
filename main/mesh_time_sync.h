#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "mesh_proto.h"

#ifndef MESH_TIME_SYNC_PERIOD_MS
	#define MESH_TIME_SYNC_PERIOD_MS	60000	// 1 хв; потім легко поміняєш на 10 хв
#endif

// Викликати на ВСІХ нодах (root і не-root). Просто готує TZ.
void mesh_time_sync_init(void);

// ТІЛЬКИ на root: стартує задачу, яка раз на period_ms розсилає час всім.
esp_err_t mesh_time_sync_root_start(uint32_t period_ms);

// Викликати в RX, коли прийшов пакет type=TIME
void mesh_time_sync_handle_packet(const mesh_packet_t *pkt);

// Просто щоб бачити стан (опціонально)
bool mesh_time_sync_has_time(void);
