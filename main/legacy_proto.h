#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/** Обробка текстового payload’у типу "TDSB123", "readtds", "pm1", ... */
void legacy_handle_text(const char *msg);

/** Просто каже, чи це, скоріше за все, сенсорне значення */
bool legacy_is_sensor_value(const char *msg);

#ifdef __cplusplus
}
#endif
