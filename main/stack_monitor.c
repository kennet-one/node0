#include "stack_monitor.h"

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_log.h"

#define STACK_MONITOR_PERIOD_MS	60000	// every 60 seconds

static const char *TAG = "[STACKMON]";

static SemaphoreHandle_t s_snapshot_lock = NULL;
static stack_monitor_snapshot_t s_snapshot;
static bool s_snapshot_valid = false;

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

// Collect task stack and CPU counters for the web task manager.
static void stack_monitor_task(void *arg)
{
	(void)arg;

	// Попередній знімок
	static TaskStatus_t	prev[STACK_MONITOR_MAX_TASKS];
	static UBaseType_t	prev_count   = 0;
	static bool			have_prev    = false;

	for (;;) {
		TaskStatus_t	cur[STACK_MONITOR_MAX_TASKS];
		UBaseType_t		count       = 0;
		uint32_t		total_time  = 0;
		stack_monitor_snapshot_t snapshot = {0};

		count = uxTaskGetSystemState(cur,
				STACK_MONITOR_MAX_TASKS,
				&total_time);
		if (count > STACK_MONITOR_MAX_TASKS) {
			count = STACK_MONITOR_MAX_TASKS;
		}

		ESP_LOGI(TAG,
		         "===== STACK MONITOR: %u task(s), slots=%u =====",
		         (unsigned)count,
		         (unsigned)STACK_MONITOR_MAX_TASKS);

		snapshot.updated_ms = (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
		snapshot.count = count;
		snapshot.cpu_valid = have_prev;

		if (!have_prev) {
			// First pass: publish stack data. CPU percentages become available
			// after the next sample.
			for (UBaseType_t i = 0; i < count; ++i) {
				const char *name = cur[i].pcTaskName;
				if (!name || !name[0]) {
					name = "noname";
				}

				size_t free_words = cur[i].usStackHighWaterMark;
				size_t free_bytes = free_words * sizeof(StackType_t);

				strncpy(snapshot.tasks[i].name, name, sizeof(snapshot.tasks[i].name) - 1);
				snapshot.tasks[i].priority = (uint32_t)cur[i].uxCurrentPriority;
				snapshot.tasks[i].free_words = (uint32_t)free_words;
				snapshot.tasks[i].free_bytes = (uint32_t)free_bytes;
				snapshot.tasks[i].cpu_x10 = -1;

				ESP_LOGI(TAG,
						"\"%s\" prio=%u free=%u words (%u bytes), cpu=?",
						name,
						(unsigned)cur[i].uxCurrentPriority,
						(unsigned)free_words,
						(unsigned)free_bytes);

				prev[i] = cur[i];
			}
			prev_count = count;
			have_prev  = true;
		} else {
			uint64_t dt_total = 0;
			uint64_t dt_idle  = 0;
			uint32_t dt_arr[STACK_MONITOR_MAX_TASKS] = {0};

			for (UBaseType_t i = 0; i < count; ++i) {
				TaskStatus_t *c = &cur[i];
				uint32_t prev_run = 0;
				bool found_prev = false;

				for (UBaseType_t j = 0; j < prev_count; ++j) {
					if (prev[j].xTaskNumber == c->xTaskNumber) {
						prev_run = prev[j].ulRunTimeCounter;
						found_prev = true;
						break;
					}
				}

				uint32_t dt = found_prev ? (c->ulRunTimeCounter - prev_run) : 0;
				dt_arr[i]   = dt;
				dt_total   += dt;

				const char *name = c->pcTaskName ? c->pcTaskName : "";
				if (strcmp(name, "IDLE0") == 0 || strcmp(name, "IDLE1") == 0) {
					dt_idle += dt;
				}
			}

			for (UBaseType_t i = 0; i < count; ++i) {
				TaskStatus_t *c = &cur[i];
				const char *name = c->pcTaskName;
				if (!name || !name[0]) {
					name = "noname";
				}

				size_t free_words = c->usStackHighWaterMark;
				float cpu_pct = 0.0f;
				if (dt_total > 0) {
					cpu_pct = (float)dt_arr[i] * 100.0f / (float)dt_total;
				}

				strncpy(snapshot.tasks[i].name, name, sizeof(snapshot.tasks[i].name) - 1);
				snapshot.tasks[i].priority = (uint32_t)c->uxCurrentPriority;
				snapshot.tasks[i].free_words = (uint32_t)free_words;
				snapshot.tasks[i].free_bytes = (uint32_t)(free_words * sizeof(StackType_t));
				snapshot.tasks[i].cpu_x10 = (int32_t)(cpu_pct * 10.0f + 0.5f);

				ESP_LOGI(TAG,
						"\"%s\" prio=%u free=%u words, cpu=%.1f%%",
						name,
						(unsigned)c->uxCurrentPriority,
						(unsigned)free_words,
						cpu_pct);

				prev[i] = cur[i];
			}
			prev_count = count;

			float cpu_load = 0.0f;
			if (dt_total > 0) {
				cpu_load = (float)(dt_total - dt_idle) * 100.0f / (float)dt_total;
			}
			snapshot.cpu_load_x10 = (uint32_t)(cpu_load * 10.0f + 0.5f);

			ESP_LOGI(TAG,
					"CPU: CPU load ~ %.1f%%  (dt_total=%" PRIu64 ", dt_idle=%" PRIu64 ")",
					cpu_load,
					dt_total,
					dt_idle);
		}

		ESP_LOGI(TAG, "===== END STACK MONITOR =====");

		stack_monitor_publish(&snapshot);

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

	BaseType_t ok = xTaskCreate(
			stack_monitor_task,
			"stack_mon",
			6000,			// стек монітора
			NULL,
			priority,
			NULL);

	if (ok != pdPASS) {
		ESP_LOGE(TAG, "failed to create stack_monitor task");
		started = false;
	}
}
