// SPDX-License-Identifier: GPL-2.0-only

#include "ota_v3_vault_verify.h"

#include <string.h>

#include "esp_partition.h"

typedef struct {
	const esp_partition_t *partition;
	uint32_t offset;
	uint32_t size;
	const char *expected_project;
	const char *expected_chip;
	keemash_ota_v3_signed_fields_t fields;
} verification_context_t;

static esp_err_t read_package(uint32_t offset, uint8_t *bytes,
	size_t length, void *context)
{
	verification_context_t *verification = context;
	if (!bytes || offset > verification->size ||
	    length > verification->size - offset) return ESP_ERR_INVALID_SIZE;
	return esp_partition_read(verification->partition,
		verification->offset + offset, bytes, length);
}

static esp_err_t verify_package(const esp_partition_t *partition,
	uint32_t offset, uint32_t size, void *context)
{
	verification_context_t *verification = context;
	verification->partition = partition;
	verification->offset = offset;
	verification->size = size;
	esp_err_t err = keemash_ota_v3_verify_package(read_package,
		verification, size, &verification->fields);
	if (err != ESP_OK) return err;
	if (verification->expected_project &&
	    strcmp(verification->fields.project_name,
		verification->expected_project) != 0) return ESP_ERR_INVALID_ARG;
	if (verification->expected_chip &&
	    strcmp(verification->fields.chip_target,
		verification->expected_chip) != 0) return ESP_ERR_INVALID_ARG;
	return ESP_OK;
}

esp_err_t ota_v3_vault_finish_verified_any(ota_v3_vault_t *vault,
	keemash_ota_v3_signed_fields_t *verified_fields)
{
	if (!vault || !verified_fields) return ESP_ERR_INVALID_ARG;
	verification_context_t verification = {0};
	esp_err_t err = ota_v3_vault_stage_finish(vault, verify_package,
		&verification);
	if (err == ESP_OK) *verified_fields = verification.fields;
	return err;
}

esp_err_t ota_v3_vault_finish_verified(ota_v3_vault_t *vault,
	const char *expected_project, const char *expected_chip,
	keemash_ota_v3_signed_fields_t *verified_fields)
{
	if (!vault || !expected_project || !expected_project[0] ||
	    !expected_chip || !expected_chip[0] || !verified_fields)
		return ESP_ERR_INVALID_ARG;
	verification_context_t verification = {
		.expected_project = expected_project,
		.expected_chip = expected_chip,
	};
	esp_err_t err = ota_v3_vault_stage_finish(vault, verify_package,
		&verification);
	if (err == ESP_OK) *verified_fields = verification.fields;
	return err;
}
