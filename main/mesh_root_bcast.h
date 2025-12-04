#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Розсилає текстовий payload від root до всіх нод mesh
void mesh_root_broadcast_text(const char *payload);

#ifdef __cplusplus
}
#endif
