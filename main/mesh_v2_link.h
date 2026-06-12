#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_mesh.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	bool seen;
	bool tunnel_seen;
	bool has_gap;
	uint32_t session_id;
	uint32_t expected_seq;
	uint32_t gap_count;
	uint32_t replay_count;
	uint32_t lost_count;
	uint32_t last_v2_ms;
	uint32_t last_tunnel_ms;
} mesh_v2_root_stats_t;

esp_err_t mesh_v2_root_handle_rx(const mesh_addr_t *from, const void *pkt_buf, size_t pkt_len);
bool mesh_v2_root_stats_for_mac(const uint8_t mac[6], mesh_v2_root_stats_t *out);
bool mesh_v2_root_tunnel_ready_for_mac(const uint8_t mac[6]);
esp_err_t mesh_v2_root_send_log_ctrl(const uint8_t mac[6], bool enable);

#ifdef __cplusplus
}
#endif
