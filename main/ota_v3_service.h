// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "keemash_fabric.h"
#include "keemash_ota_v3.h"
#include "ota_v3_vault.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	bool ready;
	bool active;
	uint8_t target_mac[6];
	uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN];
	keemash_fabric_v2_Id128 operation_id;
	keemash_fabric_v2_OtaPhase phase;
	uint32_t raw_offset;
	uint32_t encoded_offset;
	uint32_t raw_size;
	uint32_t encoded_size;
	uint32_t retries;
	uint32_t resume_count;
	uint32_t status;
	char project_name[33];
	char firmware_version[33];
	char message[96];
} ota_v3_service_status_t;

esp_err_t ota_v3_service_init(void);

esp_err_t ota_v3_service_stage_begin(
	const uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN],
	uint32_t package_size, uint32_t *resume_offset);
esp_err_t ota_v3_service_stage_write(uint32_t offset,
	const uint8_t *bytes, size_t length);
esp_err_t ota_v3_service_stage_finish(
	keemash_ota_v3_signed_fields_t *verified_fields);
esp_err_t ota_v3_service_stage_abort(void);
esp_err_t ota_v3_service_artifact_info(
	const uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN],
	keemash_ota_v3_signed_fields_t *fields);
esp_err_t ota_v3_service_vault_entry(size_t index,
	ota_v3_vault_entry_t *entry, keemash_ota_v3_signed_fields_t *fields);

esp_err_t ota_v3_service_deploy(const uint8_t target_mac[6],
	const char *expected_project,
	const uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN]);
esp_err_t ota_v3_service_cancel(const char *reason);
esp_err_t ota_v3_service_abort_operation(const uint8_t target_mac[6],
	const uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN],
	const uint8_t operation_id[16]);
void ota_v3_service_status(ota_v3_service_status_t *status);

void ota_v3_service_on_mesh_message(const uint8_t mac[6],
	const void *payload, size_t payload_len);

#ifdef __cplusplus
}
#endif
