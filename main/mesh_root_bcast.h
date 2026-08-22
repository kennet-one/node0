#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// Route a known command to its owner, or broadcast unknown legacy text.
void mesh_root_broadcast_text(const char *payload);
esp_err_t mesh_root_send_state_to_mixer(const char *legacy_token);
void mesh_root_command_result(const uint8_t peer[6], uint32_t root_session,
			      uint32_t command_id, uint8_t status,
			      const char *text);
esp_err_t mesh_root_submit_direct_command(const uint8_t peer[6],
					  const char *payload,
					  uint32_t command_id);

#ifdef __cplusplus
}
#endif
