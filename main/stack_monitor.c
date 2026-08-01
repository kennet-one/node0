#include "stack_monitor.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_log.h"

#define STACK_MONITOR_PERIOD_MS		60000
#define STACK_MONITOR_TASK_STACK	8192U
#define STACK_MONITOR_CAPTURE_HEADROOM	4U

static const char *TAG = "[STACKMON]";

static SemaphoreHandle_t s_snapshot_lock = NULL;
static SemaphoreHandle_t s_sample_lock = NULL;
static stack_monitor_snapshot_t s_snapshot;
static bool s_snapshot_valid = false;

static TaskStatus_t s_prev[STACK_MONITOR_CAPTURE_MAX_TASKS];
static UBaseType_t s_prev_count = 0;
static bool s_have_prev = false;

static void stack_monitor_publish(const stack_monitor_snapshot_t *snapshot)
{
	if (!snapshot || !s_snapshot_lock) return;

	if (xSemaphoreTake(s_snapshot_lock, pdMS_TO_TICKS(50)) == pdTRUE) {
		s_snapshot = *snapshot;
		s_snapshot_valid = true;
		xSemaphoreGive(s_snapshot_lock);
	}
}

bool stack_monitor_get_snapshot(stack_monitor_snapshot_t *out)
{
	if (!out || !s_snapshot_lock) return false;

	bool ok = false;
	if (xSemaphoreTake(s_snapshot_lock, pdMS_TO_TICKS(50)) == pdTRUE) {
		if (s_snapshot_valid) {
			*out = s_snapshot;
			ok = true;
		}
		xSemaphoreGive(s_snapshot_lock);
	}
	return ok;
}

static void copy_task_name(char *dst, size_t dst_sz, const char *name)
{
	if (!dst || dst_sz == 0) return;
	if (!name || !name[0]) {
		name = "noname";
	}

	size_t n = strnlen(name, dst_sz - 1);
	memcpy(dst, name, n);
	dst[n] = '\0';
}

static void fill_stack_fields(stack_monitor_task_info_t *dst, const TaskStatus_t *src,
                              int32_t cpu_x10)
{
	if (!dst || !src) return;

	copy_task_name(dst->name, sizeof(dst->name), src->pcTaskName);
	dst->priority = (uint32_t)src->uxCurrentPriority;
	dst->free_words = (uint32_t)src->usStackHighWaterMark;
	dst->free_bytes = (uint32_t)src->usStackHighWaterMark * sizeof(StackType_t);
	dst->cpu_x10 = cpu_x10;
}

static bool collect_sample_locked(stack_monitor_snapshot_t *snapshot, bool emit_log)
{
	if (!snapshot) return false;

	TaskStatus_t *cur = NULL;
	UBaseType_t count = 0;
	UBaseType_t observed_total = 0;
	UBaseType_t capacity = 0;
	uint32_t total_time = 0;

	memset(snapshot, 0, sizeof(*snapshot));

	for (uint32_t attempt = 0; attempt < 2; ++attempt) {
		observed_total = uxTaskGetNumberOfTasks();
		capacity = observed_total + STACK_MONITOR_CAPTURE_HEADROOM;
		if (capacity < STACK_MONITOR_CAPTURE_HEADROOM) {
			capacity = STACK_MONITOR_CAPTURE_HEADROOM;
		}
		if (capacity > STACK_MONITOR_CAPTURE_MAX_TASKS) {
			capacity = STACK_MONITOR_CAPTURE_MAX_TASKS;
		}

		free(cur);
		cur = calloc(capacity, sizeof(*cur));
		if (!cur) {
			ESP_LOGE(TAG, "failed to allocate task snapshot for %u entries",
			         (unsigned)capacity);
			return false;
		}

		total_time = 0;
		count = uxTaskGetSystemState(cur, capacity, &total_time);
		if (count != 0 || attempt != 0 ||
		    uxTaskGetNumberOfTasks() <= capacity) {
			break;
		}
	}

	snapshot->updated_ms = (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
	uint32_t live_total = (uint32_t)uxTaskGetNumberOfTasks();
	snapshot->task_total = count ? (uint32_t)count : live_total;
	if (snapshot->task_total < live_total) snapshot->task_total = live_total;
	snapshot->count = count;
	if (snapshot->count > STACK_MONITOR_MAX_TASKS) {
		snapshot->count = STACK_MONITOR_MAX_TASKS;
	}
	snapshot->truncated = count == 0 || snapshot->task_total > snapshot->count;
	snapshot->cpu_valid = s_have_prev;

	if (emit_log) {
		ESP_LOGI(TAG,
		         "===== STACK MONITOR: displayed=%u total=%u slots=%u truncated=%u =====",
		         (unsigned)snapshot->count,
		         (unsigned)snapshot->task_total,
		         (unsigned)STACK_MONITOR_MAX_TASKS,
		         snapshot->truncated ? 1U : 0U);
	}

	if (count == 0) {
		if (emit_log) ESP_LOGW(TAG, "task list changed during capture; snapshot unavailable");
		free(cur);
		if (emit_log) ESP_LOGI(TAG, "===== END STACK MONITOR =====");
		return false;
	}

	if (!s_have_prev) {
		for (UBaseType_t i = 0; i < snapshot->count; ++i) {
			fill_stack_fields(&snapshot->tasks[i], &cur[i], -1);

			if (emit_log) {
				ESP_LOGI(TAG,
				         "\"%s\" prio=%u free=%u words (%u bytes), cpu=?",
				         snapshot->tasks[i].name,
				         (unsigned)snapshot->tasks[i].priority,
				         (unsigned)snapshot->tasks[i].free_words,
				         (unsigned)snapshot->tasks[i].free_bytes);
			}
		}

		for (UBaseType_t i = 0; i < count; ++i) {
			if (i >= STACK_MONITOR_CAPTURE_MAX_TASKS) break;
			s_prev[i] = cur[i];
		}
		s_prev_count = count;
		if (s_prev_count > STACK_MONITOR_CAPTURE_MAX_TASKS) {
			s_prev_count = STACK_MONITOR_CAPTURE_MAX_TASKS;
		}
		s_have_prev = true;
	} else {
		uint64_t dt_total = 0;
		uint64_t dt_idle = 0;
		uint32_t *dt_arr = calloc(count, sizeof(*dt_arr));
		if (!dt_arr) {
			ESP_LOGE(TAG, "failed to allocate task runtime deltas");
			free(cur);
			return false;
		}

		for (UBaseType_t i = 0; i < count; ++i) {
			TaskStatus_t *c = &cur[i];
			uint32_t prev_run = 0;
			bool found_prev = false;

			for (UBaseType_t j = 0; j < s_prev_count; ++j) {
				if (s_prev[j].xTaskNumber == c->xTaskNumber) {
					prev_run = s_prev[j].ulRunTimeCounter;
					found_prev = true;
					break;
				}
			}

			uint32_t dt = found_prev ? (c->ulRunTimeCounter - prev_run) : 0;
			dt_arr[i] = dt;
			dt_total += dt;

			const char *name = c->pcTaskName ? c->pcTaskName : "";
			if (strcmp(name, "IDLE0") == 0 || strcmp(name, "IDLE1") == 0) {
				dt_idle += dt;
			}
		}

		for (UBaseType_t i = 0; i < snapshot->count; ++i) {
			float cpu_pct = 0.0f;
			if (dt_total > 0) {
				cpu_pct = (float)dt_arr[i] * 100.0f / (float)dt_total;
			}

			fill_stack_fields(&snapshot->tasks[i], &cur[i],
			                  (int32_t)(cpu_pct * 10.0f + 0.5f));

			if (emit_log) {
				ESP_LOGI(TAG,
				         "\"%s\" prio=%u free=%u words, cpu=%.1f%%",
				         snapshot->tasks[i].name,
				         (unsigned)snapshot->tasks[i].priority,
				         (unsigned)snapshot->tasks[i].free_words,
				         cpu_pct);
			}

		}

		for (UBaseType_t i = 0; i < count; ++i) {
			if (i >= STACK_MONITOR_CAPTURE_MAX_TASKS) break;
			s_prev[i] = cur[i];
		}
		s_prev_count = count;
		if (s_prev_count > STACK_MONITOR_CAPTURE_MAX_TASKS) {
			s_prev_count = STACK_MONITOR_CAPTURE_MAX_TASKS;
		}

		float cpu_load = 0.0f;
		if (dt_total > 0) {
			cpu_load = (float)(dt_total - dt_idle) * 100.0f / (float)dt_total;
		}
		snapshot->cpu_load_x10 = (uint32_t)(cpu_load * 10.0f + 0.5f);

		if (emit_log) {
			ESP_LOGI(TAG,
			         "CPU: CPU load ~ %.1f%%  (dt_total=%" PRIu64 ", dt_idle=%" PRIu64 ")",
			         cpu_load,
			         dt_total,
			         dt_idle);
		}
		free(dt_arr);
	}

	if (emit_log) {
		ESP_LOGI(TAG, "===== END STACK MONITOR =====");
	}

	free(cur);
	return true;
}

bool stack_monitor_sample_now(stack_monitor_snapshot_t *out)
{
	if (!s_sample_lock) return false;

	bool ok = false;
	if (xSemaphoreTake(s_sample_lock, pdMS_TO_TICKS(250)) == pdTRUE) {
		stack_monitor_snapshot_t snapshot = {0};
		ok = collect_sample_locked(&snapshot, false);
		if (ok) {
			stack_monitor_publish(&snapshot);
			if (out) *out = snapshot;
		}
		xSemaphoreGive(s_sample_lock);
	}
	return ok;
}

static void stack_monitor_task(void *arg)
{
	(void)arg;

	for (;;) {
		if (s_sample_lock &&
		    xSemaphoreTake(s_sample_lock, pdMS_TO_TICKS(250)) == pdTRUE) {
			stack_monitor_snapshot_t snapshot = {0};
			if (collect_sample_locked(&snapshot, true)) {
				stack_monitor_publish(&snapshot);
			}
			xSemaphoreGive(s_sample_lock);
		}

		vTaskDelay(pdMS_TO_TICKS(STACK_MONITOR_PERIOD_MS));
	}
}

void stack_monitor_start(UBaseType_t priority)
{
	static bool started = false;

	if (started) {
		return;
	}
	started = true;

	if (!s_snapshot_lock) {
		s_snapshot_lock = xSemaphoreCreateMutex();
		if (!s_snapshot_lock) {
			ESP_LOGE(TAG, "failed to create snapshot mutex");
			started = false;
			return;
		}
	}

	if (!s_sample_lock) {
		s_sample_lock = xSemaphoreCreateMutex();
		if (!s_sample_lock) {
			ESP_LOGE(TAG, "failed to create sample mutex");
			started = false;
			return;
		}
	}

	BaseType_t ok = xTaskCreate(
			stack_monitor_task,
			"stack_mon",
			STACK_MONITOR_TASK_STACK,
			NULL,
			priority,
			NULL);

	if (ok != pdPASS) {
		ESP_LOGE(TAG, "failed to create stack_monitor task");
		started = false;
	}
}
