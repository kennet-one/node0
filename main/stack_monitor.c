#include "stack_monitor.h"

#include <string.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#define STACK_MONITOR_MAX_TASKS	25
#define STACK_MONITOR_PERIOD_MS	60000	// раз на 60 секунд

static const char *TAG = "[STACKMON]";

// Основна таска моніторингу
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

		// Знімаємо стан усіх тасок
		count = uxTaskGetSystemState(cur,
				STACK_MONITOR_MAX_TASKS,
				&total_time);

		ESP_LOGI(TAG, "===== STACK MONITOR: %u task(s) =====",
				(unsigned)count);

		if (!have_prev) {
			// Перший прохід – ще нема попереднього снапшота,
			// показуємо тільки стек, CPU ставимо "?"
			for (UBaseType_t i = 0; i < count; ++i) {
				const char *name = cur[i].pcTaskName;
				if (!name || !name[0]) {
					name = "noname";
				}

				size_t free_words = cur[i].usStackHighWaterMark;
				size_t free_bytes = free_words * sizeof(StackType_t);

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
			// Другий і далі проходи – рахуємо дельти ulRunTimeCounter

			uint64_t dt_total = 0;
			uint64_t dt_idle  = 0;
			uint32_t dt_arr[STACK_MONITOR_MAX_TASKS] = {0};

			// Перший прохід: рахуємо dt для кожної таски і сумарний dt_total
			for (UBaseType_t i = 0; i < count; ++i) {
				TaskStatus_t *c = &cur[i];
				uint32_t prev_run = 0;

				// шукаємо відповідну таску в попередньому знімку по xTaskNumber
				for (UBaseType_t j = 0; j < prev_count; ++j) {
					if (prev[j].xTaskNumber == c->xTaskNumber) {
						prev_run = prev[j].ulRunTimeCounter;
						break;
					}
				}

				uint32_t dt = c->ulRunTimeCounter - prev_run;
				dt_arr[i]   = dt;
				dt_total   += dt;

				const char *name = c->pcTaskName ? c->pcTaskName : "";
				if (strcmp(name, "IDLE0") == 0 || strcmp(name, "IDLE1") == 0) {
					dt_idle += dt;
				}
			}

			// Другий прохід: друкуємо стек + відсоток CPU для кожної таски
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

				ESP_LOGI(TAG,
						"\"%s\" prio=%u free=%u words, cpu=%.1f%%",
						name,
						(unsigned)c->uxCurrentPriority,
						(unsigned)free_words,
						cpu_pct);

				// оновлюємо prev
				prev[i] = cur[i];
			}
			prev_count = count;

			// Підсумкове CPU навантаження (без idle)
			float cpu_load = 0.0f;
			if (dt_total > 0) {
				cpu_load = (float)(dt_total - dt_idle) * 100.0f / (float)dt_total;
			}

			ESP_LOGI(TAG,
					"CPU: CPU load ~ %.1f%%  (dt_total=%" PRIu64 ", dt_idle=%" PRIu64 ")",
					cpu_load, dt_total, dt_idle);
		}

		ESP_LOGI(TAG, "===== END STACK MONITOR =====");

		vTaskDelay(pdMS_TO_TICKS(STACK_MONITOR_PERIOD_MS));
	}
}

// Публічний старт монітора
void stack_monitor_start(UBaseType_t priority)
{
	static bool started = false;

	if (started) {
		return;
	}
	started = true;

	BaseType_t ok = xTaskCreate(
			stack_monitor_task,
			"stack_mon",
			4096,			// стек монітора
			NULL,
			priority,
			NULL);

	if (ok != pdPASS) {
		ESP_LOGE(TAG, "failed to create stack_monitor task");
	}
}
