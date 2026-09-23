// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_partition.h"

#define OTA_V3_VAULT_SHA256_LEN 32U
#define OTA_V3_VAULT_MAX_CHUNK 2048U
#define OTA_V3_VAULT_MAX_ENTRIES 8U

typedef struct ota_v3_vault ota_v3_vault_t;

typedef struct {
	uint8_t sha256[OTA_V3_VAULT_SHA256_LEN];
	uint32_t offset;
	uint32_t size;
} ota_v3_vault_entry_t;

/* This callback must verify the signed .kota3 manifest and all block/image
 * hashes from vault flash. A hash match alone does not authorize an artifact. */
typedef esp_err_t (*ota_v3_vault_verify_fn)(const esp_partition_t *partition,
	uint32_t offset, uint32_t size, void *context);

esp_err_t ota_v3_vault_open(ota_v3_vault_t **out);
void ota_v3_vault_close(ota_v3_vault_t *vault);
esp_err_t ota_v3_vault_stage_begin(ota_v3_vault_t *vault,
	const uint8_t sha256[OTA_V3_VAULT_SHA256_LEN], uint32_t size,
	uint32_t *resume_offset);
esp_err_t ota_v3_vault_stage_write(ota_v3_vault_t *vault,
	uint32_t offset, const uint8_t *bytes, size_t length);
esp_err_t ota_v3_vault_stage_finish(ota_v3_vault_t *vault,
	ota_v3_vault_verify_fn verify, void *context);
esp_err_t ota_v3_vault_stage_abort(ota_v3_vault_t *vault);
esp_err_t ota_v3_vault_find(ota_v3_vault_t *vault,
	const uint8_t sha256[OTA_V3_VAULT_SHA256_LEN],
	ota_v3_vault_entry_t *entry);
esp_err_t ota_v3_vault_entry(ota_v3_vault_t *vault, size_t index,
	ota_v3_vault_entry_t *entry);
esp_err_t ota_v3_vault_read(ota_v3_vault_t *vault,
	const ota_v3_vault_entry_t *entry, uint32_t offset,
	uint8_t *bytes, size_t length);
