#include "log_http_server.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_netif.h"
#include "esp_err.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/portmacro.h"

static const char *TAG = "log_http";

/* ---------- Налаштування буфера логів ---------- */
#ifndef LOG_HTTP_LINES
	#define LOG_HTTP_LINES			200
#endif

#ifndef LOG_HTTP_LINE_MAX
	#define LOG_HTTP_LINE_MAX		256
#endif

// Максимальний рядок, який можемо виділити з heap, якщо log довший за стек-буфер
#ifndef LOG_HTTP_HEAP_MAX
	#define LOG_HTTP_HEAP_MAX		512
#endif

// Невеликий стек-буфер (щоб не вбивати MTXON)
#ifndef LOG_HTTP_STACK_TMP
	#define LOG_HTTP_STACK_TMP		128
#endif

static httpd_handle_t s_http_server = NULL;

static portMUX_TYPE s_log_lock = portMUX_INITIALIZER_UNLOCKED;
static char s_lines[LOG_HTTP_LINES][LOG_HTTP_LINE_MAX];
static uint32_t s_write_idx = 0;
static uint32_t s_total_lines = 0;

/* ---------- vprintf chaining ---------- */
typedef int (*vprintf_like_t)(const char *fmt, va_list ap);
static vprintf_like_t s_orig_vprintf = NULL;

/* ---------- Helpers ---------- */

static bool build_time_prefix(char *out, size_t out_sz)
{
	if (!out || out_sz == 0) return false;

	time_t now = time(NULL);
	if (now <= 0) {
		snprintf(out, out_sz, "[no-time] ");
		return true;
	}

	struct tm tm_now;
	if (!localtime_r(&now, &tm_now)) {
		snprintf(out, out_sz, "[no-time] ");
		return true;
	}

	// strftime не дає тупих -Wformat-truncation як snprintf з %04d
	size_t n = strftime(out, out_sz, "[%Y-%m-%d %H:%M:%S] ", &tm_now);
	if (n == 0) {
		snprintf(out, out_sz, "[no-time] ");
	}
	return true;
}

static void log_buffer_append_line(const char *line, size_t len)
{
	if (!line || len == 0) return;

	// Записуємо один рядок у кільцевий буфер
	portENTER_CRITICAL(&s_log_lock);
	{
		uint32_t idx = s_write_idx % LOG_HTTP_LINES;

		// Безпечна копія + термінатор
		size_t copy_len = (len >= (LOG_HTTP_LINE_MAX - 1)) ? (LOG_HTTP_LINE_MAX - 1) : len;
		memcpy(s_lines[idx], line, copy_len);
		s_lines[idx][copy_len] = '\0';

		s_write_idx++;
		if (s_total_lines < LOG_HTTP_LINES) s_total_lines++;
	}
	portEXIT_CRITICAL(&s_log_lock);
}

static char *log_buffer_snapshot(size_t *out_len)
{
	char *snap = NULL;
	size_t size = 0;

	portENTER_CRITICAL(&s_log_lock);
	{
		// Оцінимо максимум: всі рядки по LINE_MAX
		size = (size_t)s_total_lines * (size_t)LOG_HTTP_LINE_MAX + 1;
	}
	portEXIT_CRITICAL(&s_log_lock);

	snap = (char *)malloc(size);
	if (!snap) {
		if (out_len) *out_len = 0;
		return NULL;
	}

	size_t pos = 0;
	portENTER_CRITICAL(&s_log_lock);
	{
		// Старт — найстаріший рядок
		uint32_t start = (s_write_idx >= s_total_lines) ? (s_write_idx - s_total_lines) : 0;

		for (uint32_t i = 0; i < s_total_lines; i++) {
			uint32_t idx = (start + i) % LOG_HTTP_LINES;
			const char *line = s_lines[idx];
			size_t l = strnlen(line, LOG_HTTP_LINE_MAX);

			if (pos + l + 1 >= size) break;
			memcpy(snap + pos, line, l);
			pos += l;

			// Гарантуємо newline для кожного рядка
			if (pos == 0 || snap[pos - 1] != '\n') {
				snap[pos++] = '\n';
			}
		}
	}
	portEXIT_CRITICAL(&s_log_lock);

	snap[pos] = '\0';
	if (out_len) *out_len = pos;
	return snap;
}

/* ---------- vprintf hook: UART + HTTP buffer ---------- */

static int log_http_vprintf(const char *fmt, va_list ap)
{
	// 1) Друк на UART/оригінальний sink
	int ret = 0;
	if (s_orig_vprintf) {
		va_list ap_copy;
		va_copy(ap_copy, ap);
		ret = s_orig_vprintf(fmt, ap_copy);
		va_end(ap_copy);
	}

	// 2) Запис у HTTP буфер (з ДОДАНИМ локальним часом)
	char tprefix[40];
	build_time_prefix(tprefix, sizeof(tprefix));
	size_t tlen = strnlen(tprefix, sizeof(tprefix));

	// Малий стек-буфер
	char stack_buf[LOG_HTTP_STACK_TMP];
	size_t cap = sizeof(stack_buf);

	// Кладемо prefix
	size_t copy_t = (tlen < (cap - 1)) ? tlen : (cap - 1);
	memcpy(stack_buf, tprefix, copy_t);
	stack_buf[copy_t] = '\0';

	// Форматуємо msg у стек-буфер
	va_list ap_copy2;
	va_copy(ap_copy2, ap);
	int w = vsnprintf(stack_buf + copy_t, cap - copy_t, fmt, ap_copy2);
	va_end(ap_copy2);

	if (w < 0) {
		// Якщо формат зламався — хоча б prefix запишемо
		log_buffer_append_line(stack_buf, strnlen(stack_buf, cap));
		return ret;
	}

	// Якщо влізло в стек — пишемо як є
	if ((size_t)w < (cap - copy_t)) {
		size_t total = copy_t + (size_t)w;
		log_buffer_append_line(stack_buf, total);
		return ret;
	}

	// Якщо не влізло — пробуємо heap (але з лімітом)
	size_t need = copy_t + (size_t)w + 1;
	if (need > LOG_HTTP_HEAP_MAX) need = LOG_HTTP_HEAP_MAX;

	char *heap_buf = (char *)malloc(need);
	if (!heap_buf) {
		// fallback: запишемо обрізаний стек
		log_buffer_append_line(stack_buf, cap - 1);
		return ret;
	}

	memcpy(heap_buf, tprefix, copy_t);
	heap_buf[copy_t] = '\0';

	va_list ap_copy3;
	va_copy(ap_copy3, ap);
	vsnprintf(heap_buf + copy_t, need - copy_t, fmt, ap_copy3);
	va_end(ap_copy3);

	log_buffer_append_line(heap_buf, strnlen(heap_buf, need));
	free(heap_buf);

	return ret;
}

/* ---------- HTTP handlers ---------- */

static esp_err_t http_root_get(httpd_req_t *req)
{
	static const char html[] =
		"<!doctype html>\n"
		"<html><head><meta charset='utf-8'>\n"
		"<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
		"<title>keeMASH logs</title>\n"
		"<style>\n"
		"body{font-family:monospace;background:#111;color:#ddd;margin:0;padding:0}\n"
		"#top{padding:10px;background:#1b1b1b;position:sticky;top:0}\n"
		"#log{white-space:pre;overflow:auto;height:calc(100vh - 60px);padding:10px}\n"
		"button{margin-right:10px}\n"
		"</style></head>\n"
		"<body>\n"
		"<div id='top'>\n"
		"<button onclick='toggleFollow()'>follow: <span id=\"f\">ON</span></button>\n"
		"<button onclick='clearLog()'>clear</button>\n"
		"<span id='st'></span>\n"
		"</div>\n"
		"<div id='log'></div>\n"
		"<script>\n"
		"let follow=true;\n"
		"function toggleFollow(){follow=!follow;document.getElementById('f').textContent=follow?'ON':'OFF'}\n"
		"function clearLog(){document.getElementById('log').textContent=''}\n"
		"async function tick(){\n"
		"  try{\n"
		"    const r=await fetch('/log');\n"
		"    const t=await r.text();\n"
		"    const el=document.getElementById('log');\n"
		"    el.textContent=t;\n"
		"    if(follow) el.scrollTop=el.scrollHeight;\n"
		"    document.getElementById('st').textContent='OK';\n"
		"  }catch(e){document.getElementById('st').textContent='ERR'}\n"
		"}\n"
		"setInterval(tick,500);\n"
		"tick();\n"
		"</script>\n"
		"</body></html>\n";

	httpd_resp_set_type(req, "text/html");
	return httpd_resp_send(req, html, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t http_log_get(httpd_req_t *req)
{
	size_t len = 0;
	char *snap = log_buffer_snapshot(&len);
	if (!snap) {
		httpd_resp_set_type(req, "text/plain");
		return httpd_resp_send(req, "no-mem\n", HTTPD_RESP_USE_STRLEN);
	}

	httpd_resp_set_type(req, "text/plain");
	esp_err_t err = httpd_resp_send(req, snap, len);
	free(snap);
	return err;
}

/* ---------- Public API ---------- */

esp_err_t log_http_server_init(void)
{
	// Ставимо хук, але зберігаємо попередній vprintf (щоб UART/логер не зламати)
	s_orig_vprintf = (vprintf_like_t)esp_log_set_vprintf(&log_http_vprintf);
	ESP_LOGI(TAG, "log_http_server_init: vprintf hook installed");
	return ESP_OK;
}

esp_err_t log_http_server_start(void)
{
	if (s_http_server) return ESP_OK;

	httpd_config_t config = HTTPD_DEFAULT_CONFIG();
	config.stack_size = 4096;		// щоб httpd не був крихкий
	config.lru_purge_enable = true;

	esp_err_t err = httpd_start(&s_http_server, &config);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "httpd_start failed: %s", esp_err_to_name(err));
		return err;
	}

	httpd_uri_t uri_root = {
		.uri		= "/",
		.method		= HTTP_GET,
		.handler	= http_root_get,
		.user_ctx	= NULL
	};

	httpd_uri_t uri_log = {
		.uri		= "/log",
		.method		= HTTP_GET,
		.handler	= http_log_get,
		.user_ctx	= NULL
	};

	httpd_register_uri_handler(s_http_server, &uri_root);
	httpd_register_uri_handler(s_http_server, &uri_log);

	ESP_LOGI(TAG, "HTTP log server started");
	return ESP_OK;
}
