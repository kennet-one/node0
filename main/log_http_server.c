// log_http_server.c
#include "log_http_server.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "esp_log.h"
#include "esp_http_server.h"
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

// частота опитування в браузері (мс)
#ifndef WEB_POLL_MS
	#define WEB_POLL_MS				500
#endif

static httpd_handle_t s_http_server = NULL;

static portMUX_TYPE s_log_lock = portMUX_INITIALIZER_UNLOCKED;
static char s_lines[LOG_HTTP_LINES][LOG_HTTP_LINE_MAX];
static uint32_t s_write_idx = 0;		// sequence (0..)
static uint32_t s_total_lines = 0;

/* ---------- snapshot buffer (reused) ---------- */
static char *s_snap = NULL;
static size_t s_snap_sz = 0;

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

	size_t n = strftime(out, out_sz, "[%Y-%m-%d %H:%M:%S] ", &tm_now);
	if (n == 0) {
		snprintf(out, out_sz, "[no-time] ");
	}
	return true;
}

static void log_buffer_append_line(const char *line, size_t len)
{
	if (!line || len == 0) return;

	portENTER_CRITICAL(&s_log_lock);
	{
		uint32_t idx = s_write_idx % LOG_HTTP_LINES;

		size_t copy_len = (len >= (LOG_HTTP_LINE_MAX - 1)) ? (LOG_HTTP_LINE_MAX - 1) : len;
		memcpy(s_lines[idx], line, copy_len);
		s_lines[idx][copy_len] = '\0';

		s_write_idx++;
		if (s_total_lines < LOG_HTTP_LINES) s_total_lines++;
	}
	portEXIT_CRITICAL(&s_log_lock);
}

static uint32_t log_buffer_start_seq(uint32_t write_idx, uint32_t total_lines)
{
	if (write_idx >= total_lines) return write_idx - total_lines;
	return 0;
}

/* зібрати снапшот (або весь, або від from_seq) у s_snap, повернути len */
static size_t log_buffer_build_snapshot(uint32_t from_seq, bool *out_truncated, uint32_t *out_next_seq)
{
	uint32_t start_seq = 0;
	uint32_t end_seq = 0;
	uint32_t total_lines = 0;

	portENTER_CRITICAL(&s_log_lock);
	{
		end_seq = s_write_idx;
		total_lines = s_total_lines;
		start_seq = log_buffer_start_seq(end_seq, total_lines);
	}
	portEXIT_CRITICAL(&s_log_lock);

	bool truncated = false;
	uint32_t eff_from = from_seq;

	if (eff_from < start_seq) {
		eff_from = start_seq;
		truncated = (from_seq != 0);
	}

	if (eff_from > end_seq) eff_from = end_seq;

	uint32_t count = (end_seq > eff_from) ? (end_seq - eff_from) : 0;
	size_t need_sz = (size_t)count * (size_t)(LOG_HTTP_LINE_MAX + 1) + 1;
	if (need_sz < 1) need_sz = 1;

	if (!s_snap || s_snap_sz < need_sz) {
		free(s_snap);
		s_snap = (char *)malloc(need_sz);
		if (!s_snap) {
			s_snap_sz = 0;
			if (out_truncated) *out_truncated = truncated;
			if (out_next_seq) *out_next_seq = end_seq;
			return 0;
		}
		s_snap_sz = need_sz;
	}

	size_t pos = 0;

	portENTER_CRITICAL(&s_log_lock);
	{
		for (uint32_t seq = eff_from; seq < end_seq; seq++) {
			uint32_t idx = seq % LOG_HTTP_LINES;
			const char *line = s_lines[idx];
			size_t l = strnlen(line, LOG_HTTP_LINE_MAX);

			if (pos + l + 2 >= s_snap_sz) break;

			memcpy(s_snap + pos, line, l);
			pos += l;

			if (pos == 0 || s_snap[pos - 1] != '\n') {
				s_snap[pos++] = '\n';
			}
		}
	}
	portEXIT_CRITICAL(&s_log_lock);

	s_snap[pos] = '\0';

	if (out_truncated) *out_truncated = truncated;
	if (out_next_seq) *out_next_seq = end_seq;

	return pos;
}

/* ---------- vprintf hook: UART + HTTP buffer ---------- */

static int log_http_vprintf(const char *fmt, va_list ap)
{
	// 1) друк у попередній sink (UART/інший vprintf)
	int ret = 0;
	if (s_orig_vprintf) {
		va_list ap_copy;
		va_copy(ap_copy, ap);
		ret = s_orig_vprintf(fmt, ap_copy);
		va_end(ap_copy);
	}

	// 2) запис у HTTP-кільцевий буфер (додаємо локальний час)
	char tprefix[40];
	build_time_prefix(tprefix, sizeof(tprefix));
	size_t tlen = strnlen(tprefix, sizeof(tprefix));

	char stack_buf[LOG_HTTP_STACK_TMP];
	size_t cap = sizeof(stack_buf);

	size_t copy_t = (tlen < (cap - 1)) ? tlen : (cap - 1);
	memcpy(stack_buf, tprefix, copy_t);
	stack_buf[copy_t] = '\0';

	va_list ap_copy2;
	va_copy(ap_copy2, ap);
	int w = vsnprintf(stack_buf + copy_t, cap - copy_t, fmt, ap_copy2);
	va_end(ap_copy2);

	if (w < 0) {
		log_buffer_append_line(stack_buf, strnlen(stack_buf, cap));
		return ret;
	}

	if ((size_t)w < (cap - copy_t)) {
		size_t total = copy_t + (size_t)w;
		log_buffer_append_line(stack_buf, total);
		return ret;
	}

	size_t need = copy_t + (size_t)w + 1;
	if (need > LOG_HTTP_HEAP_MAX) need = LOG_HTTP_HEAP_MAX;

	char *heap_buf = (char *)malloc(need);
	if (!heap_buf) {
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

#ifndef STR
	#define STR(x) #x
#endif
#ifndef XSTR
	#define XSTR(x) STR(x)
#endif

static esp_err_t http_root_get(httpd_req_t *req)
{
	// HTML + JS: append-only, /log?from=N
	// Колір робимо по патерну "] I (" / "] W (" / "] E ("
	static const char html[] =
		"<!doctype html>\n"
		"<html><head><meta charset='utf-8'>\n"
		"<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
		"<title>keeMASH logs</title>\n"
		"<style>\n"
		"body{font-family:monospace;background:#111;color:#ddd;margin:0;padding:0}\n"
		"#top{padding:10px;background:#1b1b1b;position:sticky;top:0;z-index:10}\n"
		"#log{white-space:pre;overflow:auto;height:calc(100vh - 60px);padding:10px}\n"
		"button{margin-right:10px}\n"
		".l{display:block}\n"
		".i{color:#59d185}\n"
		".w{color:#f2d15c}\n"
		".e{color:#ff6b6b}\n"
		".d{color:#6bdcff}\n"
		".v{color:#9aa0a6}\n"
		".t{color:#6bdcff}\n"
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
		"let nextSeq=0;\n"
		"const MAX_DOM_LINES=2000;\n"
		"function toggleFollow(){follow=!follow;document.getElementById('f').textContent=follow?'ON':'OFF'}\n"
		"function clearLog(){document.getElementById('log').innerHTML=''}\n"
		"function esc(s){return s.replace(/[&<>\\\"']/g,m=>({\"&\":\"&amp;\",\"<\":\"&lt;\",\">\":\"&gt;\",\"\\\"\":\"&quot;\",\"'\":\"&#39;\"}[m]))}\n"
		"function classify(line){\n"
		"  const m=line.match(/\\]\\s([IWEVD])\\s\\(/);\n"
		"  if(!m) return '';\n"
		"  if(m[1]==='I') return 'i';\n"
		"  if(m[1]==='W') return 'w';\n"
		"  if(m[1]==='E') return 'e';\n"
		"  if(m[1]==='D') return 'd';\n"
		"  return 'v';\n"
		"}\n"
		"function renderLine(raw){\n"
		"  const line=esc(raw);\n"
		"  const cls=classify(raw);\n"
		"  // підсвітимо timestamp, якщо є на початку\n"
		"  if(line.startsWith('[')){\n"
		"    const p=line.indexOf(']');\n"
		"    if(p>0){\n"
		"      const ts=line.slice(0,p+1);\n"
		"      const rest=line.slice(p+1);\n"
		"      return `<span class=\"l ${cls}\"><span class=\"t\">${ts}</span>${rest}</span>`;\n"
		"    }\n"
		"  }\n"
		"  return `<span class=\"l ${cls}\">${line}</span>`;\n"
		"}\n"
		"function appendLines(text){\n"
		"  if(!text) return;\n"
		"  const el=document.getElementById('log');\n"
		"  const lines=text.split(/\\n/);\n"
		"  for(const ln of lines){\n"
		"    if(ln.length===0) continue;\n"
		"    el.insertAdjacentHTML('beforeend', renderLine(ln));\n"
		"  }\n"
		"  // prune DOM\n"
		"  while(el.childNodes.length>MAX_DOM_LINES){\n"
		"    el.removeChild(el.firstChild);\n"
		"  }\n"
		"  if(follow) el.scrollTop=el.scrollHeight;\n"
		"}\n"
		"async function tick(){\n"
		"  try{\n"
		"    const r=await fetch('/log?from='+nextSeq);\n"
		"    const nx=r.headers.get('X-Log-Next');\n"
		"    const tr=r.headers.get('X-Log-Truncated');\n"
		"    const t=await r.text();\n"
		"    if(nx) nextSeq=parseInt(nx)||nextSeq;\n"
		"    if(tr==='1') document.getElementById('st').textContent='TRUNC';\n"
		"    else document.getElementById('st').textContent='OK';\n"
		"    appendLines(t);\n"
		"  }catch(e){document.getElementById('st').textContent='ERR'}\n"
		"}\n"
		"setInterval(tick," XSTR(WEB_POLL_MS) ");\n"
		"tick();\n"
		"</script>\n"
		"</body></html>\n";

	// NOTE: XSTR макрос нижче (щоб WEB_POLL_MS вставився як текст)
	httpd_resp_set_type(req, "text/html");
	return httpd_resp_send(req, html, HTTPD_RESP_USE_STRLEN);
}


static esp_err_t http_log_get(httpd_req_t *req)
{
	char q[64];
	uint32_t from = 0;

	if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
		char v[16];
		if (httpd_query_key_value(q, "from", v, sizeof(v)) == ESP_OK) {
			from = (uint32_t)strtoul(v, NULL, 10);
		}
	}

	bool truncated = false;
	uint32_t next_seq = 0;
	size_t len = log_buffer_build_snapshot(from, &truncated, &next_seq);

	char hdr[16];
	snprintf(hdr, sizeof(hdr), "%u", (unsigned)next_seq);
	httpd_resp_set_hdr(req, "X-Log-Next", hdr);
	httpd_resp_set_hdr(req, "X-Log-Truncated", truncated ? "1" : "0");

	httpd_resp_set_type(req, "text/plain; charset=utf-8");

	if (len == 0) {
		// якщо немає нових рядків або немає пам’яті — повернемо пусто
		return httpd_resp_send(req, "", 0);
	}

	return httpd_resp_send(req, s_snap, len);
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
	config.stack_size = 4096;
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
