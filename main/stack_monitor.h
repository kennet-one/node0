#pragma once

#include "freertos/FreeRTOS.h"

#ifdef __cplusplus
extern "C" {
#endif

// Стартує окрему таску моніторингу стеків + CPU usage
void stack_monitor_start(UBaseType_t priority);

#ifdef __cplusplus
}
#endif
