#pragma once

#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t log_time_vprintf_start(void);
void log_time_vprintf_enable(bool en);

#ifdef __cplusplus
}
#endif
