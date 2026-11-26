#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Passive cache of Kheater climate command results seen at the mesh root.
// Fills from HC1/HP1/HZ1 texts arriving through mesh_root_command_result and
// optionally self-polls Kheater when the desktop app is not polling.

#define HEATER_CLIMATE_INVALID (32767)

typedef struct {
	int source;                // 0 none, 1 internal, 2 zone
	int fallback;              // 0 none, 1 externalUnavailable, 2 confirmingExternal, 3 noUsableSource
	bool zone_enabled;
	uint32_t revision;
	char source_mac[13];       // 12 hex chars + NUL, "" when unknown/000000000000
	int32_t int_temp_m100;     // temperature * 100 (HEATER_CLIMATE_INVALID when null)
	int32_t int_hum_m100;
	int32_t ext_temp_m100;
	int32_t eff_temp_m100;
	int32_t int_age_s;         // -1 when unknown
	int32_t ext_age_s;
	uint64_t updated_ms;       // esp_timer_get_time()/1000 of last HC1
} heater_climate_sample_t;

typedef struct {
	bool valid;
	int interval_s;            // 0 unknown, else 10/30/60
	int32_t hold_s;
	int32_t hysteresis_m100;
	uint64_t updated_ms;
} heater_relay_sample_t;

typedef struct {
	bool valid;
	bool saved;
	bool applied;
	bool enabled;
	uint32_t revision;
	char source_mac[13];
	int32_t error;
	uint64_t updated_ms;
} heater_zone_sample_t;

void heater_climate_cache_init(void);
void heater_climate_cache_on_result_text(const char *text);
/* Called next to on_result_text with the result metadata, so the self-poll
 * rotation can stop polling streams the node answers 'unsupported' to. */
void heater_climate_cache_note_result(uint32_t command_id, uint8_t status,
				       const char *text);
void heater_climate_cache_snapshot(heater_climate_sample_t *out_climate,
				   bool *have_climate,
				   heater_relay_sample_t *out_relay,
				   bool *have_relay,
				   heater_zone_sample_t *out_zone,
				   bool *have_zone);
int heater_climate_cache_json(char *out, size_t cap);
