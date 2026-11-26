#include "heater_climate_cache.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include "mesh_root_bcast.h"

static const char *TAG = "hclim_cache";

#define CLIM_SELF_POLL_MS (45000U)
#define CLIM_RELAY_POLL_MS (120000U)
#define CLIM_ZONE_POLL_MS (120000U)
#define CLIM_TICK_MS (10000U)
#define CLIM_INFLIGHT_MS (30000U)
#define CLIM_TASK_STACK (4096)

static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static heater_climate_sample_t s_climate;
static heater_relay_sample_t s_relay;
static heater_zone_sample_t s_zone;
static bool s_have_climate, s_have_relay, s_have_zone;
static bool s_inflight;
static uint64_t s_inflight_ms;
static bool s_task_started;
static uint8_t s_rr;	// self-poll rotation cursor: 0 climate, 1 relay, 2 zone
static uint32_t s_last_cmd_id;	// last self-poll command id (for unsupported match)
static uint8_t s_last_stream;	// stream of last self-poll command
static uint8_t s_unsupported;	// bitmask: streams answered 'unsupported'

static uint64_t now_ms(void)
{
	return (uint64_t)esp_timer_get_time() / 1000ULL;
}

static bool all_hex(const char *s, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		char c = s[i];
		bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
			  (c >= 'A' && c <= 'F');
		if (!ok) return false;
	}
	return true;
}

static int32_t field_i32(const char *s)
{
	if (!s || !*s) return 0;
	return (int32_t)strtol(s, NULL, 10);
}

// desktop heaterClimate.ts: hundredths field, 32767 means null
static int32_t field_hundredths(const char *s)
{
	if (!s || !*s) return HEATER_CLIMATE_INVALID;
	return (int32_t)strtol(s, NULL, 10);
}

static bool token_key_value(const char *token, char *key, size_t key_cap,
			    const char **value)
{
	const char *eq = strchr(token, '=');
	if (!eq) {
		if (key_cap) key[0] = '\0';
		return false;
	}
	size_t key_len = (size_t)(eq - token);
	if (key_len == 0 || key_len >= key_cap) {
		if (key_cap) key[0] = '\0';
		return false;
	}
	memcpy(key, token, key_len);
	key[key_len] = '\0';
	*value = eq + 1;
	return (*value)[0] != '\0';
}

static void parse_hc1(const char *text)
{
	heater_climate_sample_t out;
	memset(&out, 0, sizeof(out));
	out.int_temp_m100 = HEATER_CLIMATE_INVALID;
	out.int_hum_m100 = HEATER_CLIMATE_INVALID;
	out.ext_temp_m100 = HEATER_CLIMATE_INVALID;
	out.eff_temp_m100 = HEATER_CLIMATE_INVALID;
	out.int_age_s = -1;
	out.ext_age_s = -1;
	out.updated_ms = now_ms();
	out.revision = 0;

	bool seen_s = false, seen_r = false, seen_z = false, seen_v = false,
	     seen_m = false, seen_i = false, seen_h = false, seen_ia = false,
	     seen_e = false, seen_ea = false, seen_t = false;
	char key[8];
	const char *val;
	char buf[32];
	char mac_buf[13] = {0};
	int source = -1, fallback = -1, zone = -1;
	bool ok = true;

	char work[192];
	strncpy(work, text, sizeof(work) - 1);
	work[sizeof(work) - 1] = '\0';
	char *save = NULL;
	for (char *tok = strtok_r(work, " \t", &save); tok;
	     tok = strtok_r(NULL, " \t", &save)) {
		if (!token_key_value(tok, key, sizeof(key), &val))
			continue;
		strncpy(buf, val, sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = '\0';
		if (strcmp(key, "s") == 0 && !seen_s) {
			seen_s = true;
			source = field_i32(buf);
			if (source < 0 || source > 2) ok = false;
		} else if (strcmp(key, "r") == 0 && !seen_r) {
			seen_r = true;
			fallback = field_i32(buf);
			if (fallback < 0 || fallback > 3) ok = false;
		} else if (strcmp(key, "z") == 0 && !seen_z) {
			seen_z = true;
			zone = field_i32(buf);
			if (zone < 0 || zone > 1) ok = false;
		} else if (strcmp(key, "v") == 0 && !seen_v) {
			seen_v = true;
			if (strlen(buf) != 8 || !all_hex(buf, 8)) ok = false;
			else out.revision = (uint32_t)strtoul(buf, NULL, 16);
		} else if (strcmp(key, "m") == 0 && !seen_m) {
			seen_m = true;
			if (strlen(buf) != 12 || !all_hex(buf, 12)) ok = false;
			else if (strcmp(buf, "000000000000") != 0)
				strncpy(mac_buf, buf, sizeof(mac_buf) - 1);
		} else if (strcmp(key, "i") == 0 && !seen_i) {
			seen_i = true;
			out.int_temp_m100 = field_hundredths(buf);
		} else if (strcmp(key, "h") == 0 && !seen_h) {
			seen_h = true;
			out.int_hum_m100 = field_hundredths(buf);
		} else if (strcmp(key, "ia") == 0 && !seen_ia) {
			seen_ia = true;
			int age = (int)field_i32(buf);
			if (age < 0 || age >= 65535) age = -1;
			out.int_age_s = age;
		} else if (strcmp(key, "e") == 0 && !seen_e) {
			seen_e = true;
			out.ext_temp_m100 = field_hundredths(buf);
		} else if (strcmp(key, "ea") == 0 && !seen_ea) {
			seen_ea = true;
			int age = (int)field_i32(buf);
			if (age < 0 || age >= 65535) age = -1;
			out.ext_age_s = age;
		} else if (strcmp(key, "t") == 0 && !seen_t) {
			seen_t = true;
			out.eff_temp_m100 = field_hundredths(buf);
		}
	}

	if (!ok || !seen_s || !seen_r || !seen_z || !seen_v || !seen_m ||
	    !seen_i || !seen_h || !seen_ia || !seen_e || !seen_ea || !seen_t)
		return;
	if (out.int_hum_m100 != HEATER_CLIMATE_INVALID &&
	    (out.int_hum_m100 < 0 || out.int_hum_m100 > 10000))
		return;

	out.source = source;
	out.fallback = fallback;
	out.zone_enabled = zone == 1;
	strncpy(out.source_mac, mac_buf, sizeof(out.source_mac) - 1);

	portENTER_CRITICAL(&s_lock);
	s_climate = out;
	s_have_climate = true;
	s_inflight = false;
	portEXIT_CRITICAL(&s_lock);
}

static void parse_hp1(const char *text)
{
	heater_relay_sample_t out;
	memset(&out, 0, sizeof(out));
	out.updated_ms = now_ms();
	int interval = 0, hold = -1, hyst = -1;
	char key[16];
	const char *val;
	char buf[32];
	char work[128];
	strncpy(work, text, sizeof(work) - 1);
	work[sizeof(work) - 1] = '\0';
	char *save = NULL;
	for (char *tok = strtok_r(work, " \t", &save); tok;
	     tok = strtok_r(NULL, " \t", &save)) {
		if (!token_key_value(tok, key, sizeof(key), &val))
			continue;
		strncpy(buf, val, sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = '\0';
		if (strcmp(key, "interval") == 0)
			interval = (int)field_i32(buf);
		else if (strcmp(key, "hold") == 0)
			hold = (int)field_i32(buf);
		else if (strcmp(key, "hysteresis") == 0)
			hyst = (int)field_i32(buf);
	}
	if ((interval != 10 && interval != 30 && interval != 60) ||
	    hold < 0 || hold > 60 || hyst < 0 || hyst > 100) {
		ESP_LOGW(TAG, "hp1 rejected: interval=%d hold=%d hyst=%d", interval, hold, hyst);
		return;
	}
	out.valid = true;
	out.interval_s = interval;
	out.hold_s = hold;
	out.hysteresis_m100 = hyst;

	portENTER_CRITICAL(&s_lock);
	s_relay = out;
	s_have_relay = true;
	portEXIT_CRITICAL(&s_lock);
}

static void parse_hz1(const char *text)
{
	heater_zone_sample_t out;
	memset(&out, 0, sizeof(out));
	out.updated_ms = now_ms();
	int saved = -1, applied = -1, enabled = -1, error = -1;
	uint32_t rev = 0;
	char mac_buf[13] = {0};
	char key[8];
	const char *val;
	char buf[40];
	char work[160];
	strncpy(work, text, sizeof(work) - 1);
	work[sizeof(work) - 1] = '\0';
	char *save = NULL;
	for (char *tok = strtok_r(work, " \t", &save); tok;
	     tok = strtok_r(NULL, " \t", &save)) {
		if (!token_key_value(tok, key, sizeof(key), &val))
			continue;
		strncpy(buf, val, sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = '\0';
		if (strcmp(key, "saved") == 0)
			saved = (int)field_i32(buf);
		else if (strcmp(key, "applied") == 0)
			applied = (int)field_i32(buf);
		else if (strcmp(key, "rev") == 0) {
			if (strlen(buf) == 8 && all_hex(buf, 8))
				rev = (uint32_t)strtoul(buf, NULL, 16);
		} else if (strcmp(key, "enabled") == 0)
			enabled = (int)field_i32(buf);
		else if (strcmp(key, "source") == 0) {
			if (strlen(buf) == 12 && all_hex(buf, 12) &&
			    strcmp(buf, "000000000000") != 0)
				strncpy(mac_buf, buf, 12);
		} else if (strcmp(key, "err") == 0)
			error = (int)field_i32(buf);
	}
	if (saved < 0 || saved > 1 || applied < 0 || applied > 1 ||
	    enabled < 0 || enabled > 1 || error < 0 || rev == 0)
		return;
	out.valid = true;
	out.saved = saved == 1;
	out.applied = applied == 1;
	out.enabled = enabled == 1;
	out.revision = rev;
	out.error = error;
	strncpy(out.source_mac, mac_buf, sizeof(out.source_mac) - 1);

	portENTER_CRITICAL(&s_lock);
	s_zone = out;
	s_have_zone = true;
	portEXIT_CRITICAL(&s_lock);
}

void heater_climate_cache_on_result_text(const char *text)
{
	if (!text || !s_task_started) return;
	const char *hc1 = strstr(text, "HC1 ");
	const char *hp1 = strstr(text, "HP1 ");
	const char *hz1 = strstr(text, "HZ1 ");
	if (hc1) {
		parse_hc1(hc1);
		return;
	}
	if (hp1) {
		ESP_LOGI(TAG, "hp1 seen: %.80s", text);
		parse_hp1(hp1);
		return;
	}
	if (hz1) {
		ESP_LOGI(TAG, "hz1 seen: %.80s", text);
		parse_hz1(hz1);
	}
}

void heater_climate_cache_note_result(uint32_t command_id, uint8_t status,
				       const char *text)
{
	(void)status;
	if (!s_task_started || command_id == 0)
		return;
	portENTER_CRITICAL(&s_lock);
	uint32_t mine = s_last_cmd_id;
	uint8_t stream = s_last_stream;
	portEXIT_CRITICAL(&s_lock);
	if (command_id != mine)
		return;
	if (text && strcmp(text, "unsupported") == 0) {
		portENTER_CRITICAL(&s_lock);
		s_unsupported |= (uint8_t)(1u << stream);
		s_inflight = false;
		portEXIT_CRITICAL(&s_lock);
		ESP_LOGW(TAG, "stream %u answered unsupported, self-poll skips it", stream);
	}
}

void heater_climate_cache_snapshot(heater_climate_sample_t *out_climate,
				   bool *have_climate,
				   heater_relay_sample_t *out_relay,
				   bool *have_relay,
				   heater_zone_sample_t *out_zone,
				   bool *have_zone)
{
	portENTER_CRITICAL(&s_lock);
	if (out_climate) {
		if (s_have_climate)
			*out_climate = s_climate;
		else {
			memset(out_climate, 0, sizeof(*out_climate));
			out_climate->int_temp_m100 = HEATER_CLIMATE_INVALID;
			out_climate->int_hum_m100 = HEATER_CLIMATE_INVALID;
			out_climate->ext_temp_m100 = HEATER_CLIMATE_INVALID;
			out_climate->eff_temp_m100 = HEATER_CLIMATE_INVALID;
			out_climate->int_age_s = -1;
			out_climate->ext_age_s = -1;
		}
	}
	if (have_climate) *have_climate = s_have_climate;
	if (out_relay) {
		if (s_have_relay) *out_relay = s_relay;
		else memset(out_relay, 0, sizeof(*out_relay));
	}
	if (have_relay) *have_relay = s_have_relay;
	if (out_zone) {
		if (s_have_zone) *out_zone = s_zone;
		else memset(out_zone, 0, sizeof(*out_zone));
	}
	if (have_zone) *have_zone = s_have_zone;
	portEXIT_CRITICAL(&s_lock);
}

static const char *source_name(int source)
{
	switch (source) {
	case 1: return "internal";
	case 2: return "zone";
	default: return "none";
	}
}

static const char *fallback_name(int fallback)
{
	switch (fallback) {
	case 1: return "externalUnavailable";
	case 2: return "confirmingExternal";
	case 3: return "noUsableSource";
	default: return "none";
	}
}

static void json_num(int32_t value_m100, char *out, size_t cap)
{
	if (value_m100 == HEATER_CLIMATE_INVALID) {
		snprintf(out, cap, "null");
		return;
	}
	int32_t whole = value_m100 / 100;
	int32_t frac = value_m100 % 100;
	if (frac < 0) frac = -frac;
	snprintf(out, cap, "%s%ld.%02ld",
		 value_m100 < 0 && whole == 0 ? "-" : "",
		 (long)whole, (long)frac);
}

static void json_age(int32_t age_s, char *out, size_t cap)
{
	if (age_s < 0) snprintf(out, cap, "null");
	else snprintf(out, cap, "%ld", (long)age_s);
}

int heater_climate_cache_json(char *out, size_t cap)
{
	heater_climate_sample_t cl;
	heater_relay_sample_t rl;
	heater_zone_sample_t zn;
	bool have_c, have_r, have_z;
	heater_climate_cache_snapshot(&cl, &have_c, &rl, &have_r, &zn,
				      &have_z);
	uint64_t now = now_ms();
	uint64_t age_ms = have_c ? now - cl.updated_ms : 0;
	uint64_t relay_age = have_r ? now - rl.updated_ms : 0;
	uint64_t zone_age = have_z ? now - zn.updated_ms : 0;

	char num[24], agebuf[16];
	size_t pos = 0;
	pos += (size_t)snprintf(out + pos, cap - pos,
				"{\"valid\":%s,\"age_ms\":%llu",
				have_c ? "true" : "false",
				(unsigned long long)age_ms);
	if (have_c) {
		pos += (size_t)snprintf(
			out + pos, cap - pos,
			",\"source\":\"%s\",\"fallback\":\"%s\","
			"\"zone_enabled\":%s,\"revision\":\"%08lx\"",
			source_name(cl.source), fallback_name(cl.fallback),
			cl.zone_enabled ? "true" : "false",
			(unsigned long)cl.revision);
		if (cl.source_mac[0])
			pos += (size_t)snprintf(out + pos, cap - pos,
						",\"source_mac\":\"%s\"",
						cl.source_mac);
		else
			pos += (size_t)snprintf(out + pos, cap - pos,
						",\"source_mac\":null");
		json_num(cl.int_temp_m100, num, sizeof(num));
		pos += (size_t)snprintf(out + pos, cap - pos, ",\"int_t_c\":%s",
					num);
		json_num(cl.int_hum_m100, num, sizeof(num));
		pos += (size_t)snprintf(out + pos, cap - pos,
					",\"int_h_pct\":%s", num);
		json_age(cl.int_age_s, agebuf, sizeof(agebuf));
		pos += (size_t)snprintf(out + pos, cap - pos,
					",\"int_age_s\":%s", agebuf);
		json_num(cl.ext_temp_m100, num, sizeof(num));
		pos += (size_t)snprintf(out + pos, cap - pos,
					",\"ext_t_c\":%s", num);
		json_age(cl.ext_age_s, agebuf, sizeof(agebuf));
		pos += (size_t)snprintf(out + pos, cap - pos,
					",\"ext_age_s\":%s", agebuf);
		json_num(cl.eff_temp_m100, num, sizeof(num));
		pos += (size_t)snprintf(out + pos, cap - pos,
					",\"eff_t_c\":%s", num);
	} else {
		pos += (size_t)snprintf(
			out + pos, cap - pos,
			",\"source\":null,\"fallback\":null,"
			"\"zone_enabled\":null,\"int_t_c\":null,"
			"\"int_h_pct\":null,\"int_age_s\":null,"
			"\"ext_t_c\":null,\"ext_age_s\":null,"
			"\"eff_t_c\":null,\"source_mac\":null,"
			"\"revision\":null");
	}
	if (have_r) {
		json_num(rl.hysteresis_m100, num, sizeof(num));
		pos += (size_t)snprintf(out + pos, cap - pos,
					",\"relay\":{\"valid\":true,"
					"\"interval_s\":%ld,\"hold_s\":%ld,"
					"\"hysteresis_c\":%s,"
					"\"age_ms\":%llu}",
					(long)rl.interval_s,
					(long)rl.hold_s, num,
					(unsigned long long)relay_age);
	} else {
		pos += (size_t)snprintf(out + pos, cap - pos,
					",\"relay\":{\"valid\":false,"
					"\"interval_s\":null,"
					"\"hold_s\":null,"
					"\"hysteresis_c\":null,"
					"\"age_ms\":null}");
	}
	if (have_z) {
		pos += (size_t)snprintf(
			out + pos, cap - pos,
			",\"zone\":{\"valid\":true,\"saved\":%s,"
			"\"applied\":%s,\"enabled\":%s,"
			"\"revision\":\"%08lx\",\"err\":%ld,"
			"\"age_ms\":%llu}",
			zn.saved ? "true" : "false",
			zn.applied ? "true" : "false",
			zn.enabled ? "true" : "false",
			(unsigned long)zn.revision, (long)zn.error,
			(unsigned long long)zone_age);
	} else {
		pos += (size_t)snprintf(out + pos, cap - pos,
					",\"zone\":{\"valid\":false}");
	}
	pos += (size_t)snprintf(out + pos, cap - pos, "}");
	if (pos >= cap) return -1;
	return (int)pos;
}

static void self_poll_tick(void)
{
	heater_climate_sample_t cl;
	heater_relay_sample_t rl;
	heater_zone_sample_t zn;
	bool have_c, have_r, have_z;
	heater_climate_cache_snapshot(&cl, &have_c, &rl, &have_r, &zn,
				      &have_z);
	uint64_t now = now_ms();
	portENTER_CRITICAL(&s_lock);
	bool inflight = s_inflight;
	uint64_t since_inflight = now - s_inflight_ms;
	portEXIT_CRITICAL(&s_lock);
	if (inflight && since_inflight < CLIM_INFLIGHT_MS) return;
	/* Rotation: one command per tick; fair even while Kheater is offline
	 * (each stream still gets its turn). Climate wins by age, relay/zone
	 * refresh on their own windows. */
	portENTER_CRITICAL(&s_lock);
	uint8_t unsupported = s_unsupported;
	portEXIT_CRITICAL(&s_lock);
	const char *cmd = NULL;
	uint8_t picked = 3;
	for (uint8_t k = 0; k < 3 && !cmd; k++) {
		uint8_t idx = (uint8_t)((s_rr + k) % 3);
		if (unsupported & (1u << idx))
			continue;
		switch (idx) {
		case 0:
			if (!have_c || now - cl.updated_ms >= CLIM_SELF_POLL_MS)
				cmd = "heater.climate?";
			break;
		case 1:
			if (!have_r || now - rl.updated_ms >= CLIM_RELAY_POLL_MS)
				cmd = "heater.relay?";
			break;
		default:
			if (!have_z || now - zn.updated_ms >= CLIM_ZONE_POLL_MS)
				cmd = "heater.source?";
			break;
		}
		if (cmd) {
			picked = idx;
			s_rr = (uint8_t)((idx + 1) % 3);
		}
	}
	if (!cmd) return;
	ESP_LOGI(TAG, "self-poll -> %s", cmd);
	// Returns NOT_FOUND when Kheater is offline via lossless route.
	uint32_t cid = 0;
	esp_err_t err = mesh_root_submit_owner_command_ex("Kheater", cmd, &cid);
	if (err != ESP_OK) {
		ESP_LOGW(TAG, "self-poll %s failed: %s", cmd, esp_err_to_name(err));
		return;
	}
	portENTER_CRITICAL(&s_lock);
	s_inflight = true;
	s_inflight_ms = now;
	s_last_cmd_id = cid;
	s_last_stream = picked;
	portEXIT_CRITICAL(&s_lock);
}

static void clim_task(void *arg)
{
	(void)arg;
	for (;;) {
		vTaskDelay(pdMS_TO_TICKS(CLIM_TICK_MS));
		self_poll_tick();
	}
}

void heater_climate_cache_init(void)
{
	memset(&s_climate, 0, sizeof(s_climate));
	memset(&s_relay, 0, sizeof(s_relay));
	memset(&s_zone, 0, sizeof(s_zone));
	s_climate.int_temp_m100 = HEATER_CLIMATE_INVALID;
	s_climate.int_hum_m100 = HEATER_CLIMATE_INVALID;
	s_climate.ext_temp_m100 = HEATER_CLIMATE_INVALID;
	s_climate.eff_temp_m100 = HEATER_CLIMATE_INVALID;
	s_climate.int_age_s = -1;
	s_climate.ext_age_s = -1;
	if (xTaskCreate(clim_task, "clim_cache", CLIM_TASK_STACK, NULL, 4,
			NULL) != pdPASS) {
		ESP_LOGE(TAG, "clim_cache task create failed");
		return;
	}
	s_task_started = true;
	ESP_LOGI(TAG, "climate cache ready (HC1/HP1/HZ1)");
}
