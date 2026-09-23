// SPDX-License-Identifier: GPL-2.0-only

#include "ota_v3_vault.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "esp_rom_crc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "mbedtls/md.h"
#include "nvs.h"
#include "nvs_flash.h"

#define VAULT_MAGIC 0x33544c56U
#define VAULT_VERSION 1U
#define VAULT_PARTITION "ota_vault"
#define STATE_PARTITION "ota_state"
#define STATE_NAMESPACE "vault3"
#define CHECKPOINT_BYTES 65536U
#define FLASH_SECTOR 4096U
#define MAX_ARTIFACT_BYTES (16U * 1024U * 1024U)

typedef struct {
	uint8_t active;
	uint8_t reserved[3];
	ota_v3_vault_entry_t entry;
	uint32_t checkpoint;
	uint8_t prefix_sha256[OTA_V3_VAULT_SHA256_LEN];
} vault_stage_t;

typedef struct {
	uint32_t magic;
	uint16_t version;
	uint16_t count;
	uint32_t generation;
	uint32_t head;
	vault_stage_t stage;
	ota_v3_vault_entry_t entries[OTA_V3_VAULT_MAX_ENTRIES];
	uint32_t crc32;
} vault_state_t;

struct ota_v3_vault {
	const esp_partition_t *partition;
	SemaphoreHandle_t mutex;
	vault_state_t state;
	uint32_t cursor;
	bool write_failed;
	bool metadata_uncertain;
	bool recovery_read_only;
};

_Static_assert(CHECKPOINT_BYTES % FLASH_SECTOR == 0U,
	"Vault checkpoint must align to erase sectors");
_Static_assert(sizeof(vault_state_t) < 1024U,
	"Vault state must fit comfortably in NVS");

static uint32_t align_sector(uint32_t value)
{
	return (value + FLASH_SECTOR - 1U) & ~(FLASH_SECTOR - 1U);
}

static bool newer(uint32_t a, uint32_t b)
{
	return (int32_t)(a - b) > 0;
}

static bool state_valid(const vault_state_t *state, uint32_t capacity)
{
	if (state->magic != VAULT_MAGIC || state->version != VAULT_VERSION ||
	    state->generation == 0U || state->count > OTA_V3_VAULT_MAX_ENTRIES ||
	    state->head > capacity || state->head % FLASH_SECTOR != 0U ||
	    esp_rom_crc32_le(0U, (const uint8_t *)state,
		offsetof(vault_state_t, crc32)) != state->crc32) return false;
	uint32_t next = 0U;
	for (size_t i = 0; i < state->count; ++i) {
		const ota_v3_vault_entry_t *entry = &state->entries[i];
		if (entry->offset != next || entry->size == 0U ||
		    entry->size > MAX_ARTIFACT_BYTES ||
		    entry->size > capacity - entry->offset) return false;
		next = align_sector(entry->offset + entry->size);
	}
	if (next != state->head || state->stage.active > 1U) return false;
	if (!state->stage.active) return true;
	const vault_stage_t *stage = &state->stage;
	return stage->entry.offset == state->head &&
		stage->entry.size > 0U &&
		stage->entry.size <= MAX_ARTIFACT_BYTES &&
		stage->entry.size <= capacity - state->head &&
		stage->checkpoint <= stage->entry.size &&
		stage->checkpoint % CHECKPOINT_BYTES == 0U;
}

static esp_err_t read_slot(nvs_handle_t nvs, const char *key,
	vault_state_t *state, bool *present, uint32_t capacity)
{
	size_t size = sizeof(*state);
	esp_err_t err = nvs_get_blob(nvs, key, state, &size);
	if (err == ESP_ERR_NVS_NOT_FOUND) {
		*present = false;
		return ESP_OK;
	}
	if (err != ESP_OK && err != ESP_ERR_NVS_INVALID_LENGTH) return err;
	*present = true;
	return err == ESP_OK && size == sizeof(*state) &&
		state_valid(state, capacity) ? ESP_OK : ESP_ERR_INVALID_CRC;
}

static esp_err_t load_state(ota_v3_vault_t *vault)
{
	nvs_handle_t nvs;
	esp_err_t err = nvs_open_from_partition(STATE_PARTITION,
		STATE_NAMESPACE, NVS_READONLY, &nvs);
	if (err == ESP_ERR_NVS_NOT_FOUND) {
		vault->state.magic = VAULT_MAGIC;
		vault->state.version = VAULT_VERSION;
		return ESP_OK;
	}
	if (err != ESP_OK) return err;
	vault_state_t *other = calloc(1U, sizeof(*other));
	if (!other) {
		nvs_close(nvs);
		return ESP_ERR_NO_MEM;
	}
	bool a = false, b = false;
	esp_err_t ea = read_slot(nvs, "a", &vault->state, &a,
		vault->partition->size);
	esp_err_t eb = read_slot(nvs, "b", other, &b,
		vault->partition->size);
	if ((a && ea != ESP_OK) || (b && eb != ESP_OK))
		vault->recovery_read_only = true;
	nvs_close(nvs);
	if (eb == ESP_OK && b && (ea != ESP_OK || !a ||
	    newer(other->generation, vault->state.generation))) {
		vault->state = *other;
	}
	free(other);
	if ((ea != ESP_OK || !a) && (eb != ESP_OK || !b)) {
		if (a || b) return ESP_ERR_INVALID_CRC;
		if (ea != ESP_OK) return ea;
		if (eb != ESP_OK) return eb;
		memset(&vault->state, 0, sizeof(vault->state));
		vault->state.magic = VAULT_MAGIC;
		vault->state.version = VAULT_VERSION;
	}
	return ESP_OK;
}

static esp_err_t save_state(ota_v3_vault_t *vault,
	const vault_state_t *candidate)
{
	vault_state_t next = *candidate;
	next.generation = vault->state.generation + 1U;
	if (next.generation == 0U) next.generation = 1U;
	next.crc32 = esp_rom_crc32_le(0U, (const uint8_t *)&next,
		offsetof(vault_state_t, crc32));
	if (!state_valid(&next, vault->partition->size))
		return ESP_ERR_INVALID_ARG;
	nvs_handle_t nvs;
	esp_err_t err = nvs_open_from_partition(STATE_PARTITION,
		STATE_NAMESPACE, NVS_READWRITE, &nvs);
	if (err != ESP_OK) return err;
	err = nvs_set_blob(nvs, (next.generation & 1U) ? "a" : "b",
		&next, sizeof(next));
	if (err == ESP_OK) err = nvs_commit(nvs);
	nvs_close(nvs);
	if (err == ESP_OK) vault->state = next;
	else vault->metadata_uncertain = true;
	return err;
}

static esp_err_t hash_region(const esp_partition_t *partition,
	uint32_t offset, uint32_t length,
	uint8_t digest[OTA_V3_VAULT_SHA256_LEN])
{
	const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!info) return ESP_FAIL;
	mbedtls_md_context_t hash;
	mbedtls_md_init(&hash);
	uint8_t *buffer = malloc(OTA_V3_VAULT_MAX_CHUNK);
	if (!buffer) return ESP_ERR_NO_MEM;
	esp_err_t err = ESP_OK;
	if (mbedtls_md_setup(&hash, info, 0) != 0 ||
	    mbedtls_md_starts(&hash) != 0) err = ESP_FAIL;
	while (err == ESP_OK && length > 0U) {
		size_t count = length < OTA_V3_VAULT_MAX_CHUNK ? length :
			OTA_V3_VAULT_MAX_CHUNK;
		err = esp_partition_read(partition, offset, buffer, count);
		if (err == ESP_OK && mbedtls_md_update(&hash, buffer, count) != 0)
			err = ESP_FAIL;
		offset += count;
		length -= count;
	}
	if (err == ESP_OK && mbedtls_md_finish(&hash, digest) != 0)
		err = ESP_FAIL;
	mbedtls_md_free(&hash);
	free(buffer);
	return err;
}

esp_err_t ota_v3_vault_open(ota_v3_vault_t **out)
{
	if (!out) return ESP_ERR_INVALID_ARG;
	*out = NULL;
	const esp_partition_t *partition = esp_partition_find_first(
		ESP_PARTITION_TYPE_DATA, 0x40, VAULT_PARTITION);
	if (!partition || partition->size < FLASH_SECTOR) return ESP_ERR_NOT_FOUND;
	esp_err_t err = nvs_flash_init_partition(STATE_PARTITION);
	if (err != ESP_OK) return err;
	ota_v3_vault_t *vault = calloc(1U, sizeof(*vault));
	if (!vault) return ESP_ERR_NO_MEM;
	vault->partition = partition;
	vault->mutex = xSemaphoreCreateMutex();
	if (!vault->mutex) {
		free(vault);
		return ESP_ERR_NO_MEM;
	}
	err = load_state(vault);
	if (err == ESP_OK && vault->state.stage.active) {
		vault_stage_t *stage = &vault->state.stage;
		uint8_t digest[OTA_V3_VAULT_SHA256_LEN];
		err = hash_region(partition, stage->entry.offset,
			stage->checkpoint, digest);
		if (err == ESP_OK && memcmp(digest, stage->prefix_sha256,
			sizeof(digest)) != 0) err = ESP_ERR_INVALID_CRC;
		if (err == ESP_OK) vault->cursor = stage->checkpoint;
	}
	if (err != ESP_OK) {
		ota_v3_vault_close(vault);
		return err;
	}
	*out = vault;
	return ESP_OK;
}

void ota_v3_vault_close(ota_v3_vault_t *vault)
{
	if (!vault) return;
	if (vault->mutex) vSemaphoreDelete(vault->mutex);
	free(vault);
}

esp_err_t ota_v3_vault_stage_begin(ota_v3_vault_t *vault,
	const uint8_t sha256[OTA_V3_VAULT_SHA256_LEN], uint32_t size,
	uint32_t *resume_offset)
{
	if (!vault || !sha256 || !resume_offset || size == 0U ||
	    size > MAX_ARTIFACT_BYTES) return ESP_ERR_INVALID_ARG;
	xSemaphoreTake(vault->mutex, portMAX_DELAY);
	esp_err_t err = ESP_OK;
	if (vault->metadata_uncertain || vault->recovery_read_only) {
		err = ESP_ERR_INVALID_STATE;
		goto done;
	}
	for (size_t i = 0; i < vault->state.count; ++i) {
		if (memcmp(vault->state.entries[i].sha256, sha256,
		    OTA_V3_VAULT_SHA256_LEN) == 0) {
			err = ESP_ERR_INVALID_STATE;
			goto done;
		}
	}
	vault_stage_t *stage = &vault->state.stage;
	if (stage->active) {
		if (stage->entry.size != size ||
		    memcmp(stage->entry.sha256, sha256,
			OTA_V3_VAULT_SHA256_LEN) != 0 || vault->write_failed) {
			err = ESP_ERR_INVALID_STATE;
			goto done;
		}
		*resume_offset = vault->cursor;
		goto done;
	}
	if (vault->state.count == OTA_V3_VAULT_MAX_ENTRIES ||
	    size > vault->partition->size - vault->state.head) {
		err = ESP_ERR_NO_MEM;
		goto done;
	}
	vault_state_t next = vault->state;
	next.stage.active = 1U;
	next.stage.entry.offset = next.head;
	next.stage.entry.size = size;
	memcpy(next.stage.entry.sha256, sha256, OTA_V3_VAULT_SHA256_LEN);
	/* SHA-256 of the empty prefix; no flash is trusted at this point. */
	err = hash_region(vault->partition, next.head, 0U,
		next.stage.prefix_sha256);
	if (err == ESP_OK) err = save_state(vault, &next);
	if (err == ESP_OK) {
		vault->cursor = 0U;
		vault->write_failed = false;
		*resume_offset = 0U;
	}
done:
	xSemaphoreGive(vault->mutex);
	return err;
}

esp_err_t ota_v3_vault_stage_write(ota_v3_vault_t *vault,
	uint32_t offset, const uint8_t *bytes, size_t length)
{
	if (!vault || !bytes || length == 0U ||
	    length > OTA_V3_VAULT_MAX_CHUNK) return ESP_ERR_INVALID_ARG;
	xSemaphoreTake(vault->mutex, portMAX_DELAY);
	vault_stage_t *stage = &vault->state.stage;
	esp_err_t err = ESP_OK;
	if (!stage->active || vault->write_failed || vault->metadata_uncertain ||
	    vault->recovery_read_only ||
	    offset > stage->entry.size || length > stage->entry.size - offset) {
		err = ESP_ERR_INVALID_STATE;
		goto done;
	}
	if (offset < vault->cursor &&
	    length <= vault->cursor - offset) {
		uint8_t previous[OTA_V3_VAULT_MAX_CHUNK];
		err = esp_partition_read(vault->partition,
			stage->entry.offset + offset, previous, length);
		if (err == ESP_OK && memcmp(previous, bytes, length) != 0)
			err = ESP_ERR_INVALID_CRC;
		goto done;
	}
	if (offset != vault->cursor) {
		err = ESP_ERR_INVALID_ARG;
		goto done;
	}
	uint32_t first = offset / FLASH_SECTOR;
	uint32_t last = (offset + length - 1U) / FLASH_SECTOR;
	for (uint32_t sector = first; sector <= last; ++sector) {
		if (sector == first && offset % FLASH_SECTOR != 0U) continue;
		err = esp_partition_erase_range(vault->partition,
			stage->entry.offset + sector * FLASH_SECTOR, FLASH_SECTOR);
		if (err != ESP_OK) goto failed;
	}
	err = esp_partition_write(vault->partition,
		stage->entry.offset + offset, bytes, length);
	if (err != ESP_OK) goto failed;
	vault->cursor += length;
	uint32_t checkpoint = vault->cursor / CHECKPOINT_BYTES * CHECKPOINT_BYTES;
	if (checkpoint > stage->checkpoint) {
		vault_state_t next = vault->state;
		next.stage.checkpoint = checkpoint;
		err = hash_region(vault->partition, stage->entry.offset,
			checkpoint, next.stage.prefix_sha256);
		if (err == ESP_OK) err = save_state(vault, &next);
		if (err != ESP_OK) goto failed;
	}
	goto done;
failed:
	vault->write_failed = true;
done:
	xSemaphoreGive(vault->mutex);
	return err;
}

esp_err_t ota_v3_vault_stage_finish(ota_v3_vault_t *vault,
	ota_v3_vault_verify_fn verify, void *context)
{
	if (!vault || !verify) return ESP_ERR_INVALID_ARG;
	xSemaphoreTake(vault->mutex, portMAX_DELAY);
	vault_stage_t *stage = &vault->state.stage;
	esp_err_t err = ESP_ERR_INVALID_STATE;
	if (!stage->active || vault->write_failed || vault->metadata_uncertain ||
	    vault->recovery_read_only ||
	    vault->cursor != stage->entry.size) goto done;
	uint8_t digest[OTA_V3_VAULT_SHA256_LEN];
	err = hash_region(vault->partition, stage->entry.offset,
		stage->entry.size, digest);
	if (err != ESP_OK) goto done;
	if (memcmp(digest, stage->entry.sha256, sizeof(digest)) != 0) {
		err = ESP_ERR_INVALID_CRC;
		goto done;
	}
	err = verify(vault->partition, stage->entry.offset,
		stage->entry.size, context);
	if (err != ESP_OK) goto done;
	vault_state_t next = vault->state;
	next.entries[next.count++] = stage->entry;
	next.head = align_sector(stage->entry.offset + stage->entry.size);
	memset(&next.stage, 0, sizeof(next.stage));
	err = save_state(vault, &next);
	if (err == ESP_OK) vault->cursor = 0U;
done:
	xSemaphoreGive(vault->mutex);
	return err;
}

esp_err_t ota_v3_vault_stage_abort(ota_v3_vault_t *vault)
{
	if (!vault) return ESP_ERR_INVALID_ARG;
	xSemaphoreTake(vault->mutex, portMAX_DELAY);
	if (vault->metadata_uncertain || vault->recovery_read_only) {
		xSemaphoreGive(vault->mutex);
		return ESP_ERR_INVALID_STATE;
	}
	vault_state_t next = vault->state;
	memset(&next.stage, 0, sizeof(next.stage));
	esp_err_t err = next.stage.active == vault->state.stage.active ?
		ESP_OK : save_state(vault, &next);
	if (err == ESP_OK) {
		vault->cursor = 0U;
		vault->write_failed = false;
	}
	xSemaphoreGive(vault->mutex);
	return err;
}

esp_err_t ota_v3_vault_find(ota_v3_vault_t *vault,
	const uint8_t sha256[OTA_V3_VAULT_SHA256_LEN],
	ota_v3_vault_entry_t *entry)
{
	if (!vault || !sha256 || !entry) return ESP_ERR_INVALID_ARG;
	xSemaphoreTake(vault->mutex, portMAX_DELAY);
	esp_err_t err = ESP_ERR_NOT_FOUND;
	for (size_t i = 0; i < vault->state.count; ++i) {
		if (memcmp(vault->state.entries[i].sha256, sha256,
		    OTA_V3_VAULT_SHA256_LEN) == 0) {
			*entry = vault->state.entries[i];
			err = ESP_OK;
			break;
		}
	}
	xSemaphoreGive(vault->mutex);
	return err;
}

esp_err_t ota_v3_vault_entry(ota_v3_vault_t *vault, size_t index,
	ota_v3_vault_entry_t *entry)
{
	if (!vault || !entry) return ESP_ERR_INVALID_ARG;
	xSemaphoreTake(vault->mutex, portMAX_DELAY);
	esp_err_t err = ESP_ERR_NOT_FOUND;
	if (index < vault->state.count) {
		*entry = vault->state.entries[index];
		err = ESP_OK;
	}
	xSemaphoreGive(vault->mutex);
	return err;
}

esp_err_t ota_v3_vault_read(ota_v3_vault_t *vault,
	const ota_v3_vault_entry_t *entry, uint32_t offset,
	uint8_t *bytes, size_t length)
{
	if (!vault || !entry || !bytes || length == 0U ||
	    offset > entry->size || length > entry->size - offset)
		return ESP_ERR_INVALID_ARG;
	xSemaphoreTake(vault->mutex, portMAX_DELAY);
	bool committed = false;
	for (size_t i = 0; i < vault->state.count; ++i) {
		if (vault->state.entries[i].offset == entry->offset &&
		    vault->state.entries[i].size == entry->size &&
		    memcmp(vault->state.entries[i].sha256, entry->sha256,
			OTA_V3_VAULT_SHA256_LEN) == 0) {
			committed = true;
			break;
		}
	}
	esp_err_t err = committed ? esp_partition_read(vault->partition,
		entry->offset + offset, bytes, length) : ESP_ERR_NOT_FOUND;
	xSemaphoreGive(vault->mutex);
	return err;
}
