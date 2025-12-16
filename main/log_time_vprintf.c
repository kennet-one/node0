#include "log_time_vprintf.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "esp_log.h"
#include "esp_err.h"

/*
	ВАЖЛИВО:
	В деяких збірках компілятор “не бачить” прототип esp_log_set_vprintf (через хедери/конфіг).
	Тому даємо forward-declare. Якщо він уже оголошений — це не заважає (та сама сигнатура).
*/
#ifdef __cplusplus
extern "C" {
#endif
extern vprintf_like_t esp_log_set_vprintf(vprintf_like_t func);
#ifdef __cplusplus
}
#endif

static bool s_started = false;
static bool s_enabled = true;

static bool get_local_time_str(char *out, size_t out_sz)
{
	if (out_sz < 20) {
		return false;
	}

	time_t now = 0;
	struct tm tm_now;

	time(&now);
	localtime_r(&now, &tm_now);

	// якщо час ще не синхронізований (приблизно 1970) — не вставляємо
	if (tm_now.tm_year < (2020 - 1900)) {
		return false;
	}

	// "YYYY-MM-DD HH:MM:SS" => 19 символів + '\0'
	size_t n = strftime(out, out_sz, "%Y-%m-%d %H:%M:%S", &tm_now);
	return (n > 0);
}


static bool is_log_line_start(char c0, char c1)
{
	// Формат ESP-IDF: "I (1234) TAG: ..."
	// Перший символ — рівень, другий — пробіл
	if (c1 != ' ') return false;

	return (c0 == 'E' || c0 == 'W' || c0 == 'I' || c0 == 'D' || c0 == 'V');
}

static int log_time_vprintf(const char *fmt, va_list ap)
{
	char orig[256];
	char out[320];
	char ts[32];

	va_list ap2;
	va_copy(ap2, ap);
	vsnprintf(orig, sizeof(orig), fmt, ap2);
	va_end(ap2);

	orig[sizeof(orig) - 1] = '\0';

	bool have_ts = false;
	if (s_enabled) {
		have_ts = get_local_time_str(ts, sizeof(ts));
	}

	if (s_enabled && have_ts && is_log_line_start(orig[0], orig[1])) {
		// Спроба вставити час після ") " щоб зберегти колір (рядок все ще починається з 'I')
		char *p = strchr(orig, ')');
		if (p && p[1] == ' ') {
			int head_len = (int)((p - orig) + 2); // включно ") "
			snprintf(out, sizeof(out),
				"%.*s[%s] %s",
				head_len, orig,
				ts,
				orig + head_len
			);
		} else {
			// fallback (дуже рідко)
			snprintf(out, sizeof(out), "%s [%s]", orig, ts);
		}
	} else if (s_enabled && have_ts) {
		// Якщо це не “класичний” log-рядок — просто дописуємо час на початок
		snprintf(out, sizeof(out), "[%s] %s", ts, orig);
	} else {
		// Без часу
		strncpy(out, orig, sizeof(out));
		out[sizeof(out) - 1] = '\0';
	}

	// Пишемо напряму в stdout (UART). Не використовуємо ESP_LOG всередині хука!
	fputs(out, stdout);

	// Повертаємо “щось” (не критично)
	return (int)strlen(out);
}

esp_err_t log_time_vprintf_start(void)
{
	if (s_started) {
		return ESP_OK;
	}
	s_started = true;

	// Ставимо наш хук
	esp_log_set_vprintf(log_time_vprintf);

	return ESP_OK;
}

void log_time_vprintf_enable(bool en)
{
	s_enabled = en;
}
