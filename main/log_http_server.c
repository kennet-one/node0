#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_err.h"
#include "esp_http_server.h"

#include "log_http_server.h"

#define LOG_HTTP_TAG        "log_http"
#define LOG_BUFFER_SIZE     8192   // ~8 KB логів (можеш збільшити/зменшити)

static char s_log_buffer[LOG_BUFFER_SIZE];
static size_t s_log_head = 0;      // наступна позиція для запису
static size_t s_log_size = 0;      // скільки байт реально зайнято

static portMUX_TYPE s_log_spinlock = portMUX_INITIALIZER_UNLOCKED;

static vprintf_like_t s_orig_vprintf = NULL;
static bool s_log_inited = false;

static httpd_handle_t s_http_server = NULL;

/* ------------------------- Кільцевий буфер ------------------------- */

static void log_buffer_append(const char *data, size_t len)
{
	if (!data || len == 0) {
		return;
	}

	// Якщо рядок більший за буфер – беремо тільки хвіст
	if (len > LOG_BUFFER_SIZE) {
		data += (len - LOG_BUFFER_SIZE);
		len = LOG_BUFFER_SIZE;
	}

	portENTER_CRITICAL(&s_log_spinlock);

	for (size_t i = 0; i < len; ++i) {
		s_log_buffer[s_log_head] = data[i];
		s_log_head = (s_log_head + 1) % LOG_BUFFER_SIZE;
		if (s_log_size < LOG_BUFFER_SIZE) {
			s_log_size++;
		}
	}

	portEXIT_CRITICAL(&s_log_spinlock);
}

// Робимо копію всіх логів в один лінійний буфер
static char *log_buffer_snapshot(size_t *out_len)
{
	char *out;
	size_t size, head;

	portENTER_CRITICAL(&s_log_spinlock);
	size = s_log_size;
	head = s_log_head;
	portEXIT_CRITICAL(&s_log_spinlock);

	out = malloc(size + 1);
	if (!out) {
		if (out_len) *out_len = 0;
		return NULL;
	}

	// tail – початок корисних даних
	size_t tail = (head + LOG_BUFFER_SIZE - size) % LOG_BUFFER_SIZE;

	for (size_t i = 0; i < size; ++i) {
		size_t idx = (tail + i) % LOG_BUFFER_SIZE;
		out[i] = s_log_buffer[idx];
	}
	out[size] = '\0';

	if (out_len) {
		*out_len = size;
	}
	return out;
}

/* ------------------------- vprintf-hook ------------------------- */

// Наш vprintf: клонить аргументи, шле в старий vprintf, плюс пише в буфер
static int log_http_vprintf(const char *fmt, va_list args)
{
	// 1) копія для нашого vsnprintf
	va_list args_copy;
	va_copy(args_copy, args);

	// 2) викликаємо оригінальний vprintf (UART/термінал)
	int ret = 0;
	if (s_orig_vprintf) {
		ret = s_orig_vprintf(fmt, args);
	}

	// 3) формуємо строку в локальний буфер
	char buf[256];
	int len = vsnprintf(buf, sizeof(buf), fmt, args_copy);
	va_end(args_copy);

	if (len > 0) {
		if ((size_t)len >= sizeof(buf)) {
			// рядок обрізано, але ок
			log_buffer_append(buf, sizeof(buf) - 1);
		} else {
			log_buffer_append(buf, (size_t)len);
		}
	}
	return ret;
}

esp_err_t log_http_server_init(void)
{
	if (s_log_inited) {
		return ESP_OK;
	}
	s_log_inited = true;

	// ставимо свій vprintf-хук і зберігаємо попередній
	s_orig_vprintf = esp_log_set_vprintf(&log_http_vprintf);

	ESP_LOGI(LOG_HTTP_TAG, "log_http_server_init: logging hook installed");
	return ESP_OK;
}

/* ------------------------- HTTP handlers ------------------------- */

static esp_err_t root_get_handler(httpd_req_t *req)
{
	const char *html =
		"<!DOCTYPE html>"
		"<html>"
		"<head>"
		"<meta charset=\"utf-8\">"
		"<title>ESP-MESH root log</title>"
		"<style>"
		"body{font-family:monospace;background:#111;color:#eee;margin:0;padding:0;}"
		"#log{white-space:pre-wrap;padding:8px;}"
		"</style>"
		"</head>"
		"<body>"
		"<h2 style=\"margin:8px;\">ESP-MESH root log (live)</h2>"
		"<pre id=\"log\">Loading...</pre>"
		"<script>"
		"function updateLog(){"
			"fetch('/log').then(function(r){return r.text();}).then(function(t){"
				"var pre=document.getElementById('log');"
				"pre.textContent=t;"
				"window.scrollTo(0, document.body.scrollHeight);"
			"}).catch(function(e){"
				"console.error(e);"
			"});"
		"}"
		"updateLog();"
		"setInterval(updateLog, 500);"  // 500 мс – можна змінити
		"</script>"
		"</body>"
		"</html>";

	httpd_resp_set_type(req, "text/html; charset=utf-8");
	httpd_resp_send(req, html, HTTPD_RESP_USE_STRLEN);
	return ESP_OK;
}


// /log – чистий текст без HTML
static esp_err_t log_get_handler(httpd_req_t *req)
{
	httpd_resp_set_type(req, "text/plain; charset=utf-8");

	size_t len = 0;
	char *snapshot = log_buffer_snapshot(&len);
	if (snapshot && len > 0) {
		httpd_resp_send_chunk(req, snapshot, len);
	}
	free(snapshot);

	httpd_resp_sendstr_chunk(req, NULL);
	return ESP_OK;
}

/* ------------------------- Старт HTTP-сервера ------------------------- */

esp_err_t log_http_server_start(void)
{
	if (s_http_server) {
		return ESP_OK;
	}

	log_http_server_init(); // на всякий випадок

	httpd_config_t config = HTTPD_DEFAULT_CONFIG();
	config.server_port = 80;
	config.lru_purge_enable = true;

	esp_err_t err = httpd_start(&s_http_server, &config);
	if (err != ESP_OK) {
		ESP_LOGE(LOG_HTTP_TAG, "httpd_start failed: 0x%x (%s)", err, esp_err_to_name(err));
		return err;
	}

	httpd_uri_t root_uri = {
		.uri       = "/",
		.method    = HTTP_GET,
		.handler   = root_get_handler,
		.user_ctx  = NULL
	};
	httpd_register_uri_handler(s_http_server, &root_uri);

	httpd_uri_t log_uri = {
		.uri       = "/log",
		.method    = HTTP_GET,
		.handler   = log_get_handler,
		.user_ctx  = NULL
	};
	httpd_register_uri_handler(s_http_server, &log_uri);

	ESP_LOGI(LOG_HTTP_TAG, "HTTP log server started on port %d", config.server_port);
	return ESP_OK;
}
