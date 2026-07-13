#pragma once

#include <stddef.h>

#include "esp_err.h"
#include "keemash_mesh_root.h"
#include "keemash_mesh_tx_broker.h"

void mesh_v2_link_require(void);
void mesh_v2_link_refresh_routes(void);
esp_err_t mesh_v2_link_send(const uint8_t dst[6], const void *packet,
			    size_t packet_len, uint8_t priority);
void mesh_v2_link_tx_stats(keemash_mesh_tx_broker_stats_t *out);
