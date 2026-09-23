// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include "keemash_ota_v3.h"
#include "ota_v3_vault.h"

/* Requires a configured production trust key before a staged artifact can
 * become committed. The vault remains unconnected to any live OTA endpoint. */
esp_err_t ota_v3_vault_finish_verified(ota_v3_vault_t *vault,
	const char *expected_project, const char *expected_chip,
	keemash_ota_v3_signed_fields_t *verified_fields);
esp_err_t ota_v3_vault_finish_verified_any(ota_v3_vault_t *vault,
	keemash_ota_v3_signed_fields_t *verified_fields);
