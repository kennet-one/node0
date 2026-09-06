#pragma once
#include "keemash_mesh_root.h"

esp_err_t heater_zone_init(void);
void heater_zone_node(const uint8_t mac[6], const char *tag, bool uptime_valid, uint32_t uptime_s);
void heater_zone_sensor(const uint8_t mac[6], const mesh_v2_sensor_snapshot_payload_t *sample);
bool heater_zone_command(const uint8_t target[6], const char *text, char *out, size_t size, esp_err_t *error);
void heater_zone_result(const uint8_t peer[6], uint32_t root_session, uint32_t command_id, uint8_t status);
