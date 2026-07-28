#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Route a known command to its owner, or broadcast unknown legacy text.
void mesh_root_broadcast_text(const char *payload);
void mesh_root_command_result(const uint8_t peer[6], uint32_t root_session,
			      uint32_t command_id, uint8_t status,
			      const char *text);

#ifdef __cplusplus
}
#endif
