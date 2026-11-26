#include "mesh_sensors_cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include "keemash_mesh_root.h"
#include "mesh_root_bcast.h"

static const char *TAG = "mesh_sensors";

#define SENS_POLL_MS (90000U)	// per-node refresh window
#define SENS_TICK_MS (10000U)
#define SENS_INFLIGHT_MS (8000U)
#define SENS_TASK_STACK (4096)
#define SENS_PENDING_MAX 8
#define SENS_INVALID (-2147483647)

typedef struct {
	const char *tag;
	const char *cmds[4];
	uint8_t cmd_count;
} node_cmd_def_t;

// Echo commands per sensor node (desktop operationalGraph.ts parity).
// Kheater is covered by heater_climate_cache; node0 itself is the root.
static const node_cmd_def_t s_defs[] = {
	{ "esp_mixer",   { "sens_echo", "ppm_echo", "temp_echo", "humi_echo", "lux_echo" }, 5 },
	{ "humidifier",  { "echo_turb", "pm1" }, 2 },
	{ "choinka",     { "choinka.status" }, 1 },
	{ "lampk",       { "lamech" }, 1 },
	{ "kPowerLed",   { "pwech", "PSQ" }, 2 },
};
#define NODE_DEF_COUNT (sizeof(s_defs) / sizeof(s_defs[0]))

static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static mesh_node_sensors_t s_nodes[NODE_DEF_COUNT];
static uint8_t s_unsupported[NODE_DEF_COUNT];	// bitmask per command
static bool s_task_started;

static bool s_inflight;
static uint64_t s_inflight_ms;
static uint32_t s_rr;	// flattened (node,cmd) cursor

typedef struct {
	uint32_t command_id;
	uint8_t node;
	uint8_t cmd;
	bool used;
} pending_t;
static pending_t s_pending[SENS_PENDING_MAX];

static uint64_t now_ms(void)
{
	return (uint64_t)esp_timer_get_time() / 1000ULL;
}

static void reset_node(mesh_node_sensors_t *n)
{
	memset(n, 0, sizeof(*n));
	n->ppm_x10 = SENS_INVALID;
	n->temp_m100 = SENS_INVALID;
	n->hum_m100 = SENS_INVALID;
	n->lux = SENS_INVALID;
	n->pressure_m100 = SENS_INVALID;
	n->pm1_x10 = SENS_INVALID;
	n->pm25_x10 = SENS_INVALID;
	n->pm10_x10 = SENS_INVALID;
	n->pump = -1;
	n->turbo = -1;
	n->flow = -1;
	n->ion = -1;
	n->water_level = -1;
	n->lamp = -1;
	n->powled = -1;
	n->choinka_pump = -1;
	n->choinka_level = -1;
}

static int node_index_by_mac(const uint8_t mac[6])
{
	for (size_t i = 0; i < NODE_DEF_COUNT; i++) {
		if (s_nodes[i].have_mac && memcmp(s_nodes[i].mac, mac, 6) == 0)
			return (int)i;
	}
	return -1;
}

static int node_index_by_tag(const char *tag)
{
	for (size_t i = 0; i < NODE_DEF_COUNT; i++) {
		if (strcmp(s_defs[i].tag, tag) == 0)
			return (int)i;
	}
	return -1;
}

static void mac_hex(const uint8_t mac[6], char *out, size_t cap)
{
	snprintf(out, cap, "%02x%02x%02x%02x%02x%02x", mac[0], mac[1],
		 mac[2], mac[3], mac[4], mac[5]);
}

// Parse one reply line per desktop protocol.ts prefixes.
static void parse_line(mesh_node_sensors_t *n, const char *line, size_t len)
{
	if (len < 2)
		return;
	char buf[64];
	if (len >= sizeof(buf))
		len = sizeof(buf) - 1;
	memcpy(buf, line, len);
	buf[len] = '\0';

	char prefix[3] = { buf[0], buf[1], '\0' };
	const char *payload = buf + 2;
	char *end = NULL;
	double num = strtod(payload, &end);
	bool is_num = end != payload && *end == '\0';

	if (is_num) {
		if (strcmp(prefix, "04") == 0) n->ppm_x10 = (int32_t)(num * 10);
		else if (strcmp(prefix, "05") == 0) n->temp_m100 = (int32_t)(num * 100);
		else if (strcmp(prefix, "06") == 0) n->hum_m100 = (int32_t)(num * 100);
		else if (strcmp(prefix, "07") == 0) n->lux = (int32_t)num;
		else if (strcmp(prefix, "08") == 0) n->pressure_m100 = (int32_t)(num * 100);
		else if (strcmp(prefix, "10") == 0) n->pm1_x10 = (int32_t)(num * 10);
		else if (strcmp(prefix, "11") == 0) n->pm25_x10 = (int32_t)(num * 10);
		else if (strcmp(prefix, "12") == 0) n->pm10_x10 = (int32_t)(num * 10);
		else if (strcmp(prefix, "13") == 0) n->pump = (int)(num != 0);
		else if (strcmp(prefix, "14") == 0) n->turbo = (int)num;
		else if (strcmp(prefix, "16") == 0) n->flow = (int)(num != 0);
		else if (strcmp(prefix, "17") == 0) n->ion = (int)(num != 0);
		else if (strcmp(prefix, "20") == 0 || strcmp(prefix, "21") == 0)
			n->water_level = (int)num;
	}
	// humidifier combined frame 15XXXX: turbo=d0, pump=d1=='0', flow=d2=='0', ion=d3=='0'
	if (strcmp(prefix, "15") == 0 && strlen(payload) >= 4) {
		n->turbo = payload[0] - '0';
		n->pump = (int)(payload[1] == '0');
		n->flow = (int)(payload[2] == '0');
		n->ion = (int)(payload[3] == '0');
	}
	// choinka compact status frame: "C6 exec=.. l=<0-2> p=<0/1> .."
	if (strncmp(buf, "C6 ", 3) == 0) {
		char *save = NULL;
		for (char *tok = strtok_r(buf + 3, " ", &save); tok;
		     tok = strtok_r(NULL, " ", &save)) {
			if (tok[0] == 'l' && tok[1] == '=')
				n->choinka_level = (int)strtol(tok + 2, NULL, 10);
			else if (tok[0] == 'p' && tok[1] == '=')
				n->choinka_pump = (int)(tok[2] == '1');
		}
	}
	if (strcmp(prefix, "La") == 0) n->lamp = (int)(payload[0] == '1');
	if (strncmp(buf, "powled", 6) == 0) n->powled = (int)(buf[6] == '1');
	if (strncmp(buf, "feedpowled", 10) == 0) n->powled = (int)(buf[10] == '1');
	if (strncmp(buf, "pomp", 4) == 0) n->choinka_pump = (int)(buf[4] == '1');
	if (strncmp(buf, "pimpa", 5) == 0 && is_num) n->choinka_level = (int)num;
}

void mesh_sensors_cache_on_result(const uint8_t peer[6], uint32_t command_id,
				  uint8_t status, const char *text)
{
	(void)status;
	if (!s_task_started || !peer || !text)
		return;
	portENTER_CRITICAL(&s_lock);
	int ni = node_index_by_mac(peer);
	// match pending command id for unsupported detection
	pending_t *pend = NULL;
	for (int i = 0; i < SENS_PENDING_MAX; i++) {
		if (s_pending[i].used && s_pending[i].command_id == command_id)
			pend = &s_pending[i];
	}
	portEXIT_CRITICAL(&s_lock);

	if (pend && strcmp(text, "unsupported") == 0) {
		portENTER_CRITICAL(&s_lock);
		if (pend->node < NODE_DEF_COUNT)
			s_unsupported[pend->node] |= (uint8_t)(1u << pend->cmd);
		s_inflight = false;
		portEXIT_CRITICAL(&s_lock);
		ESP_LOGW(TAG, "%s cmd %u unsupported, skip", s_defs[pend->node].tag,
			 pend->cmd);
		return;
	}
	if (pend) {
		portENTER_CRITICAL(&s_lock);
		pend->used = false;
		s_inflight = false;
		portEXIT_CRITICAL(&s_lock);
	}
	if (ni < 0)
		return;
	if (strcmp(text, "accepted") == 0)
		return; // ack only, not a sensor frame

	portENTER_CRITICAL(&s_lock);
	mesh_node_sensors_t *n = &s_nodes[ni];
	// scan all lines of the reply
	const char *p = text;
	while (p && *p) {
		const char *eol = strchr(p, '\n');
		size_t len = eol ? (size_t)(eol - p) : strlen(p);
		while (len > 0 && (p[len - 1] == '\r' || p[len - 1] == ' '))
			len--;
		if (len > 0)
			parse_line(n, p, len);
		p = eol ? eol + 1 : NULL;
	}
	n->valid = true;
	n->updated_ms = now_ms();
	snprintf(n->last_reply, sizeof(n->last_reply), "%.63s", text);
	portEXIT_CRITICAL(&s_lock);
}

bool mesh_sensors_cache_get(const char *tag, mesh_node_sensors_t *out)
{
	int ni = node_index_by_tag(tag);
	if (ni < 0)
		return false;
	portENTER_CRITICAL(&s_lock);
	*out = s_nodes[ni];
	portEXIT_CRITICAL(&s_lock);
	return true;
}

static void self_poll_tick(void)
{
	uint64_t now = now_ms();
	portENTER_CRITICAL(&s_lock);
	bool inflight = s_inflight;
	uint64_t since = now - s_inflight_ms;
	portEXIT_CRITICAL(&s_lock);
	if (inflight && since < SENS_INFLIGHT_MS)
		return;

	// flattened cursor over (node, cmd)
	uint32_t total = 0;
	for (size_t i = 0; i < NODE_DEF_COUNT; i++)
		total += s_defs[i].cmd_count;

	for (uint32_t tries = 0; tries < total; tries++) {
		uint32_t flat = (s_rr + tries) % total;
		uint32_t acc = 0;
		uint8_t ni = 0, ci = 0;
		for (ni = 0; ni < NODE_DEF_COUNT; ni++) {
			if (flat < acc + s_defs[ni].cmd_count) {
				ci = (uint8_t)(flat - acc);
				break;
			}
			acc += s_defs[ni].cmd_count;
		}
		if (ni >= NODE_DEF_COUNT)
			break;
		portENTER_CRITICAL(&s_lock);
		bool have_mac = s_nodes[ni].have_mac;
		uint8_t unsup = s_unsupported[ni];
		uint64_t upd = s_nodes[ni].updated_ms;
		bool valid = s_nodes[ni].valid;
		portEXIT_CRITICAL(&s_lock);
		if (unsup & (1u << ci))
			continue;
		if (!have_mac) {
			uint8_t mac[6];
			if (mesh_v2_root_find_lossless_by_tag(s_defs[ni].tag, mac,
							      MESH_V2_CAP_TYPED_CONTROL)) {
				portENTER_CRITICAL(&s_lock);
				memcpy(s_nodes[ni].mac, mac, 6);
				s_nodes[ni].have_mac = true;
				portEXIT_CRITICAL(&s_lock);
			} else {
				continue; // node not up; try next
			}
		}
		if (valid && now - upd < SENS_POLL_MS)
			continue; // fresh enough
		// submit this one
		uint32_t cid = 0;
		esp_err_t err = mesh_root_submit_owner_command_ex(s_defs[ni].tag,
								 s_defs[ni].cmds[ci],
								 &cid);
		if (err != ESP_OK)
			continue;
		portENTER_CRITICAL(&s_lock);
		int slot = -1;
		for (int i = 0; i < SENS_PENDING_MAX; i++)
			if (!s_pending[i].used) { slot = i; break; }
		if (slot >= 0) {
			s_pending[slot].used = true;
			s_pending[slot].command_id = cid;
			s_pending[slot].node = ni;
			s_pending[slot].cmd = ci;
		}
		s_inflight = true;
		s_inflight_ms = now;
		s_rr = (flat + 1) % total;
		portEXIT_CRITICAL(&s_lock);
		ESP_LOGI(TAG, "self-poll %s -> %s", s_defs[ni].tag, s_defs[ni].cmds[ci]);
		return;
	}
}

static void sensors_task(void *arg)
{
	(void)arg;
	for (;;) {
		vTaskDelay(pdMS_TO_TICKS(SENS_TICK_MS));
		self_poll_tick();
	}
}

void mesh_sensors_cache_init(void)
{
	for (size_t i = 0; i < NODE_DEF_COUNT; i++) {
		reset_node(&s_nodes[i]);
		strncpy(s_nodes[i].tag, s_defs[i].tag, sizeof(s_nodes[i].tag) - 1);
		s_unsupported[i] = 0;
	}
	if (xTaskCreate(sensors_task, "sens_cache", SENS_TASK_STACK, NULL, 4,
			NULL) != pdPASS) {
		ESP_LOGE(TAG, "task create failed");
		return;
	}
	s_task_started = true;
	ESP_LOGI(TAG, "mesh sensors cache ready (%u nodes)", (unsigned)NODE_DEF_COUNT);
}

static void json_num(char **p, size_t *left, const char *key, int32_t v_m,
		     int scale)
{
	int written;
	if (v_m == SENS_INVALID || v_m == -1) {
		written = snprintf(*p, *left, "\"%s\":null,", key);
	} else {
		written = snprintf(*p, *left, "\"%s\":%ld.%02ld,", key,
				   (long)(v_m / scale),
				   (long)(v_m % scale < 0 ? -(v_m % scale) : v_m % scale));
	}
	if (written > 0) {
		*p += (size_t)written < *left ? (size_t)written : *left - 1;
		*left = *left > (size_t)written ? *left - (size_t)written : 1;
	}
}

int mesh_sensors_cache_json(char *out, size_t cap)
{
	char *p = out;
	size_t left = cap;
	int w = snprintf(p, left, "{\"nodes\":[");
	p += w; left -= (size_t)w;
	uint64_t now = now_ms();
	for (size_t i = 0; i < NODE_DEF_COUNT; i++) {
		portENTER_CRITICAL(&s_lock);
		mesh_node_sensors_t n = s_nodes[i];
		bool have_mac = n.have_mac;
		portEXIT_CRITICAL(&s_lock);

		mesh_v2_root_stats_t st;
		bool seen = have_mac && mesh_v2_root_stats_for_mac(n.mac, &st);
		bool online = seen && st.seen && st.ping_age_ms < 180000;

		char macs[13] = "";
		if (have_mac)
			mac_hex(n.mac, macs, sizeof(macs));

		w = snprintf(p, left, "%s{\"tag\":\"%s\",\"mac\":\"%s\",\"online\":%s,"
			     "\"ping_ms\":%u,\"rtt_ms\":%u,\"reliable_ready\":%s,"
			     "\"age_ms\":%llu,\"last_reply\":\"%.63s\",\"sensors\":{",
			     i ? "," : "", n.tag, macs, online ? "true" : "false",
			     seen && st.ping_valid ? (unsigned)st.ping_ms : 0u,
			     seen ? (unsigned)st.rtt_ms : 0u,
			     seen && st.reliable_ready ? "true" : "false",
			     (unsigned long long)(n.valid ? now - n.updated_ms : 0),
			     n.last_reply);
		if (w < 0) return -1;
		if ((size_t)w >= left) { *p = '\0'; return -1; }
		p += w; left -= (size_t)w;

		json_num(&p, &left, "ppm", n.ppm_x10, 10);
		json_num(&p, &left, "temp_c", n.temp_m100, 100);
		json_num(&p, &left, "hum_pct", n.hum_m100, 100);
		json_num(&p, &left, "lux", n.lux, 1);
		json_num(&p, &left, "pm1", n.pm1_x10, 10);
		json_num(&p, &left, "pm25", n.pm25_x10, 10);
		json_num(&p, &left, "pm10", n.pm10_x10, 10);
		json_num(&p, &left, "pump", n.pump == -1 ? SENS_INVALID : n.pump, 1);
		json_num(&p, &left, "turbo", n.turbo == -1 ? SENS_INVALID : n.turbo, 1);
		json_num(&p, &left, "flow", n.flow == -1 ? SENS_INVALID : n.flow, 1);
		json_num(&p, &left, "ion", n.ion == -1 ? SENS_INVALID : n.ion, 1);
		json_num(&p, &left, "water", n.water_level == -1 ? SENS_INVALID : n.water_level, 1);
		json_num(&p, &left, "lamp", n.lamp == -1 ? SENS_INVALID : n.lamp, 1);
		json_num(&p, &left, "powled", n.powled == -1 ? SENS_INVALID : n.powled, 1);
		json_num(&p, &left, "choinka_pump", n.choinka_pump == -1 ? SENS_INVALID : n.choinka_pump, 1);
		json_num(&p, &left, "choinka_level", n.choinka_level == -1 ? SENS_INVALID : n.choinka_level, 1);

		// strip trailing comma
		if (left > 1 && p[-1] == ',') p--, left++;
		w = snprintf(p, left, "}}");
		if (w < 0) return -1;
		if ((size_t)w >= left) { *p = '\0'; return -1; }
		p += w; left -= (size_t)w;
	}
	w = snprintf(p, left, "]}");
	if (w < 0 || (size_t)w >= left) { *p = '\0'; return -1; }
	p += w;
	return (int)(p - out);
}
