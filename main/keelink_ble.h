#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

esp_err_t keelink_ble_init(void);
esp_err_t keelink_ble_start_host(void);
esp_err_t keelink_ble_enable(void);
void keelink_ble_disable(void);
bool keelink_ble_ready(void);
esp_err_t keelink_ble_last_error(void);
const char *keelink_ble_state(void);
uint32_t keelink_ble_boot_checkpoint(void);
void keelink_ble_note_boot_checkpoint(uint32_t checkpoint);
