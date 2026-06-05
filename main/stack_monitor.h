#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "freertos/FreeRTOS.h"

#define STACK_MONITOR_MAX_TASKS		25
#define STACK_MONITOR_TASK_NAME_MAX	16

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	char		name[STACK_MONITOR_TASK_NAME_MAX];
	uint32_t	priority;
	uint32_t	free_words;
	uint32_t	free_bytes;
	int32_t		cpu_x10;
} stack_monitor_task_info_t;

typedef struct {
	uint32_t	updated_ms;
	uint32_t	count;
	uint32_t	cpu_load_x10;
	bool		cpu_valid;
	stack_monitor_task_info_t tasks[STACK_MONITOR_MAX_TASKS];
} stack_monitor_snapshot_t;

// Starts a separate task that samples stack high-water marks and CPU usage.
void stack_monitor_start(UBaseType_t priority);

// Copies the latest task snapshot. Returns false before the first sample exists.
bool stack_monitor_get_snapshot(stack_monitor_snapshot_t *out);

#ifdef __cplusplus
}
#endif
