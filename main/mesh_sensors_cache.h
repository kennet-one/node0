#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Passive per-node sensor cache at the mesh root. Self-polls the known
// sensor nodes with their echo commands (round-robin, one per tick) and
// caches parsed replies, so a wall panel can render mesh sensors without
// the desktop app. Replies also arrive from desktop-issued commands via
// the root result hook.

#define MESH_SENSOR_NODE_MAX 8

typedef struct {
	char tag[16];
	uint8_t mac[6];
	bool have_mac;
	bool valid;		// any parsed reply seen
	uint64_t updated_ms;	// last parsed reply
	char last_reply[64];

	// esp_mixer style environment (prefixes 04-08)
	int32_t ppm_x10;	// 04, x10 ppm
	int32_t temp_m100;	// 05, C x100
	int32_t hum_m100;	// 06, % x100
	int32_t lux;		// 07
	int32_t pressure_m100;	// 08
	// humidifier (10-17, 20-21)
	int32_t pm1_x10;	// 10
	int32_t pm25_x10;	// 11
	int32_t pm10_x10;	// 12
	int pump;		// 13
	int turbo;		// 14 (0-3)
	int flow;		// 16
	int ion;		// 17
	int water_level;	// 20/21 raw
	// lampk / kPowerLed / choinka device states (-1 unknown)
	int lamp;		// La0/La1
	int powled;		// powled0/1
	int choinka_pump;	// pomp0/1
	int choinka_level;	// pimpa payload numeric
} mesh_node_sensors_t;

void mesh_sensors_cache_init(void);

// Called from the root command-result path with the replying peer.
void mesh_sensors_cache_on_result(const uint8_t peer[6], uint32_t command_id,
				  uint8_t status, const char *text);

// Snapshot for one node by tag; returns false when unknown.
bool mesh_sensors_cache_get(const char *tag, mesh_node_sensors_t *out);

// JSON: {"nodes":[{tag,mac,online,ping_ms,rtt_ms,reliable_ready,age_ms,
//                 last_reply,sensors:{...}}]}
int mesh_sensors_cache_json(char *out, size_t cap);
