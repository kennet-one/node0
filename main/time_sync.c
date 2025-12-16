#include "time_sync.h"

#include <time.h>
#include <sys/time.h>
#include <string.h>

#include "esp_log.h"
#include "lwip/apps/sntp.h"

static const char *TAG = "time";

static bool s_started = false;

static void set_tz_pl(void)
{
	// Europe/Warsaw (CET/CEST). Працює без інтернету, лише як правило переходу на літній час.
	setenv("TZ", "CET-1CEST,M3.5.0/2,M10.5.0/3", 1);
	tzset();
}

bool time_sync_is_valid(void)
{
	time_t now = 0;
	time(&now);
	// будь-який “нормальний” Unix time (після 2020 року)
	return (now > 1577836800);
}

void time_sync_start(void)
{
	if (s_started) return;
	s_started = true;

	set_tz_pl();

	sntp_setoperatingmode(SNTP_OPMODE_POLL);
	sntp_setservername(0, "pool.ntp.org");
	sntp_init();

	ESP_LOGI(TAG, "SNTP started");
}

void time_sync_format(char *out, size_t out_len)
{
	if (!out || out_len == 0) return;

	if (!time_sync_is_valid()) {
		snprintf(out, out_len, "no-time");
		return;
	}

	time_t now = 0;
	struct tm t;
	time(&now);
	localtime_r(&now, &t);

	strftime(out, out_len, "%Y-%m-%d %H:%M:%S", &t);
}
