// SPDX-License-Identifier: GPL-2.0-only

#include "ota_v3_service.h"

#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_rom_crc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "keemash_mesh_root.h"
#include "nvs.h"
#include "ota_v3_vault.h"
#include "ota_v3_vault_verify.h"

#define OTA3_TASK_STACK 10240U
#define OTA3_TASK_PRIORITY 5U
#define OTA3_RX_QUEUE_LEN 8U
#define OTA3_DEPLOY_QUEUE_LEN 1U
#define OTA3_CHUNK_BYTES 1024U
#define OTA3_STATUS_TIMEOUT_MS 5000U
#define OTA3_BOOT_TIMEOUT_MS 120000U
#define OTA3_SEND_RETRIES 5U
#define OTA3_STATE_MAGIC 0x3350444fU
#define OTA3_STATE_VERSION 1U
#define OTA3_STATE_PARTITION "ota_state"
#define OTA3_STATE_NAMESPACE "deploy3"

static const char *TAG = "ota_v3_service";

typedef struct {
	uint8_t mac[6];
	uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN];
	char expected_project[33];
	keemash_fabric_v2_Id128 operation_id;
	bool resume;
} deploy_request_t;

typedef enum {
	RX_STATUS,
	RX_BOOT_REPORT,
	RX_ANY,
} rx_kind_t;

typedef struct {
	rx_kind_t kind;
	uint8_t mac[6];
	union {
		keemash_fabric_v2_OtaTransferStatus status;
		keemash_fabric_v2_OtaBootReport report;
	} body;
} rx_event_t;

typedef struct {
	uint32_t magic;
	uint16_t version;
	uint8_t active;
	uint8_t reserved;
	deploy_request_t request;
	ota_v3_service_status_t status;
	uint32_t crc32;
} persistent_state_t;

typedef struct {
	ota_v3_vault_t *vault;
	ota_v3_vault_entry_t entry;
} package_reader_t;

typedef struct {
	deploy_request_t request;
	package_reader_t reader;
	keemash_ota_v3_package_info_t package;
	uint32_t resume_encoded_offset;
	uint32_t resume_block_index;
	uint8_t *chunk;
} deploy_context_t;

static ota_v3_vault_t *s_vault;
static SemaphoreHandle_t s_lock;
static QueueHandle_t s_rx_queue;
static QueueHandle_t s_deploy_queue;
static TaskHandle_t s_task;
static ota_v3_service_status_t s_status;
static deploy_request_t s_last_request;
static bool s_last_request_valid;
static rx_event_t s_deferred_event;
static bool s_deferred_event_valid;
static atomic_bool s_cancel;
static uint32_t s_last_persisted_raw_offset;

static bool id_equal(const keemash_fabric_v2_Id128 *a,
	const keemash_fabric_v2_Id128 *b)
{
	return a->high == b->high && a->low == b->low;
}

static bool bytes_equal(const pb_size_t size, const uint8_t *bytes,
	const uint8_t expected[KEEMASH_OTA_V3_SHA256_LEN])
{
	return size == KEEMASH_OTA_V3_SHA256_LEN &&
		memcmp(bytes, expected, KEEMASH_OTA_V3_SHA256_LEN) == 0;
}

static esp_err_t package_read(uint32_t offset, uint8_t *bytes,
	size_t length, void *context)
{
	package_reader_t *reader = context;
	return ota_v3_vault_read(reader->vault, &reader->entry, offset,
		bytes, length);
}

static uint32_t persistent_crc(const persistent_state_t *state)
{
	return esp_rom_crc32_le(0U, (const uint8_t *)state,
		offsetof(persistent_state_t, crc32));
}

static esp_err_t save_persistent(const deploy_request_t *request,
	const ota_v3_service_status_t *status, bool active)
{
	persistent_state_t state = {
		.magic = OTA3_STATE_MAGIC,
		.version = OTA3_STATE_VERSION,
		.active = active ? 1U : 0U,
		.request = *request,
		.status = *status,
	};
	state.crc32 = persistent_crc(&state);
	nvs_handle_t nvs;
	esp_err_t err = nvs_open_from_partition(OTA3_STATE_PARTITION,
		OTA3_STATE_NAMESPACE, NVS_READWRITE, &nvs);
	if (err != ESP_OK) return err;
	err = nvs_set_blob(nvs, "state", &state, sizeof(state));
	if (err == ESP_OK) err = nvs_commit(nvs);
	nvs_close(nvs);
	return err;
}

static bool load_persistent(persistent_state_t *state)
{
	nvs_handle_t nvs;
	if (nvs_open_from_partition(OTA3_STATE_PARTITION,
		OTA3_STATE_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK) return false;
	size_t size = sizeof(*state);
	esp_err_t err = nvs_get_blob(nvs, "state", state, &size);
	nvs_close(nvs);
	return err == ESP_OK && size == sizeof(*state) &&
		state->magic == OTA3_STATE_MAGIC &&
		state->version == OTA3_STATE_VERSION &&
		state->active <= 1U && persistent_crc(state) == state->crc32;
}

static void status_set(const deploy_request_t *request,
	keemash_fabric_v2_OtaPhase phase, uint32_t code, const char *message,
	bool active, bool persist)
{
	ota_v3_service_status_t snapshot;
	xSemaphoreTake(s_lock, portMAX_DELAY);
	s_status.ready = true;
	s_status.active = active;
	if (request) {
		memcpy(s_status.target_mac, request->mac, sizeof(request->mac));
		memcpy(s_status.artifact_id, request->artifact_id,
			sizeof(request->artifact_id));
		s_status.operation_id = request->operation_id;
		strncpy(s_status.project_name, request->expected_project,
			sizeof(s_status.project_name) - 1U);
	}
	s_status.phase = phase;
	s_status.status = code;
	if (message) {
		strncpy(s_status.message, message, sizeof(s_status.message) - 1U);
		s_status.message[sizeof(s_status.message) - 1U] = '\0';
	}
	snapshot = s_status;
	xSemaphoreGive(s_lock);
	if (persist && request) (void)save_persistent(request, &snapshot, active);
}

static void status_from_transfer(const deploy_request_t *request,
	const keemash_fabric_v2_OtaTransferStatus *remote)
{
	xSemaphoreTake(s_lock, portMAX_DELAY);
	s_status.phase = remote->phase;
	s_status.status = remote->status;
	s_status.raw_offset = remote->raw_offset;
	s_status.encoded_offset = remote->encoded_offset;
	s_status.retries = remote->retries;
	s_status.resume_count = remote->resume_count;
	snprintf(s_status.message, sizeof(s_status.message), "target: %.*s",
		(int)sizeof(s_status.message) - 9,
		remote->message[0] ? remote->message :
		esp_err_to_name((esp_err_t)(int32_t)remote->status));
	ota_v3_service_status_t snapshot = s_status;
	xSemaphoreGive(s_lock);
	if (remote->raw_offset != 0U &&
	    remote->raw_offset % (64U * 1024U) == 0U &&
	    remote->raw_offset != s_last_persisted_raw_offset) {
		if (save_persistent(request, &snapshot, true) == ESP_OK)
			s_last_persisted_raw_offset = remote->raw_offset;
	}
}

static void random_operation(keemash_fabric_v2_Id128 *operation)
{
	esp_fill_random(operation, sizeof(*operation));
	if (operation->high == 0U && operation->low == 0U)
		operation->low = 1U;
}

static bool event_matches(const rx_event_t *event,
	const deploy_request_t *request)
{
	if (memcmp(event->mac, request->mac, sizeof(request->mac)) != 0)
		return false;
	if (event->kind == RX_STATUS) {
		return event->body.status.has_operation_id &&
			id_equal(&event->body.status.operation_id,
				&request->operation_id) &&
			bytes_equal(event->body.status.artifact_id.size,
				event->body.status.artifact_id.bytes,
				request->artifact_id);
	}
	return event->body.report.has_operation_id &&
		id_equal(&event->body.report.operation_id,
			&request->operation_id) &&
		bytes_equal(event->body.report.artifact_id.size,
			event->body.report.artifact_id.bytes,
			request->artifact_id);
}

static esp_err_t wait_event(const deploy_request_t *request,
	rx_kind_t expected_kind, uint32_t timeout_ms, rx_event_t *matched)
{
	TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
	for (;;) {
		if (s_deferred_event_valid &&
		    (expected_kind == RX_ANY ||
		     s_deferred_event.kind == expected_kind) &&
		    event_matches(&s_deferred_event, request)) {
			*matched = s_deferred_event;
			s_deferred_event_valid = false;
			return ESP_OK;
		}
		TickType_t now = xTaskGetTickCount();
		if ((int32_t)(deadline - now) <= 0) return ESP_ERR_TIMEOUT;
		rx_event_t event;
		if (xQueueReceive(s_rx_queue, &event, deadline - now) != pdTRUE)
			return ESP_ERR_TIMEOUT;
		if (!event_matches(&event, request)) continue;
		if (expected_kind != RX_ANY && event.kind != expected_kind) {
			if (!s_deferred_event_valid) {
				s_deferred_event = event;
				s_deferred_event_valid = true;
			} else {
				ESP_LOGW(TAG, "dropping deferred OTA v3 event: slot busy");
			}
			continue;
		}
		*matched = event;
		return ESP_OK;
	}
}

static esp_err_t send_wait_transfer(const deploy_request_t *request,
	keemash_fabric_v2_OtaMeshMessage *message,
	keemash_fabric_v2_OtaTransferStatus *status,
	uint32_t minimum_encoded_offset, bool commit_ack)
{
	esp_err_t last_err = ESP_ERR_TIMEOUT;
	uint32_t accepted = 0U;
	for (uint32_t attempt = 0; attempt < OTA3_SEND_RETRIES; ++attempt) {
		if (atomic_load(&s_cancel)) return ESP_ERR_INVALID_STATE;
		esp_err_t err = mesh_v2_root_send_ota_v3_message(request->mac,
			message);
		if (err != ESP_OK) {
			last_err = err;
			vTaskDelay(pdMS_TO_TICKS(1000U));
			continue;
		}
		accepted++;
		rx_event_t event;
		err = wait_event(request, RX_STATUS, OTA3_STATUS_TIMEOUT_MS, &event);
		if (err != ESP_OK) {
			last_err = err;
			continue;
		}
		if (event.body.status.status == ESP_OK &&
		    event.body.status.encoded_offset < minimum_encoded_offset)
			continue;
		if (commit_ack && event.body.status.status == ESP_OK &&
		    event.body.status.phase !=
			keemash_fabric_v2_OtaPhase_OTA_PHASE_VERIFYING &&
		    event.body.status.phase !=
			keemash_fabric_v2_OtaPhase_OTA_PHASE_REBOOTING)
			continue;
		*status = event.body.status;
		status_from_transfer(request, status);
		return status->status == ESP_OK ? ESP_OK :
			(esp_err_t)(int32_t)status->status;
	}
	ESP_LOGW(TAG, "transfer failed target=" MACSTR " kind=%u accepted=%lu/%u offset=%lu error=%s",
		MAC2STR(request->mac),
		(unsigned)message->body.transfer.which_body,
		(unsigned long)accepted, OTA3_SEND_RETRIES,
		(unsigned long)minimum_encoded_offset, esp_err_to_name(last_err));
	return last_err;
}

static esp_err_t send_prepare(deploy_context_t *context)
{
	keemash_fabric_v2_OtaMeshMessage *message =
		calloc(1U, sizeof(*message));
	if (!message) return ESP_ERR_NO_MEM;
	message->which_body = keemash_fabric_v2_OtaMeshMessage_transfer_tag;
	keemash_fabric_v2_OtaTransfer *transfer = &message->body.transfer;
	transfer->which_body = keemash_fabric_v2_OtaTransfer_prepare_tag;
	keemash_fabric_v2_OtaPrepare *prepare = &transfer->body.prepare;
	prepare->has_operation_id = true;
	prepare->operation_id = context->request.operation_id;
	prepare->artifact_id.size = KEEMASH_OTA_V3_SHA256_LEN;
	memcpy(prepare->artifact_id.bytes, context->request.artifact_id,
		KEEMASH_OTA_V3_SHA256_LEN);
	prepare->signed_fields.size = context->package.signed_fields_len;
	memcpy(prepare->signed_fields.bytes, context->package.signed_fields,
		context->package.signed_fields_len);
	prepare->signature.size = context->package.signature_len;
	memcpy(prepare->signature.bytes, context->package.signature,
		context->package.signature_len);
	prepare->requested_chunk_size = OTA3_CHUNK_BYTES;
	prepare->requested_window = 2U;
	keemash_fabric_v2_OtaTransferStatus status = {0};
	esp_err_t err = send_wait_transfer(&context->request, message, &status,
		0U, false);
	if (err == ESP_OK) {
		context->resume_encoded_offset = status.encoded_offset;
		context->resume_block_index = status.next_block_index;
	}
	free(message);
	return err;
}

static esp_err_t send_block(
	const keemash_fabric_v2_FirmwareBlockDescriptor *descriptor,
	uint32_t payload_offset, void *opaque)
{
	deploy_context_t *context = opaque;
	if (descriptor->index < context->resume_block_index) return ESP_OK;
	uint32_t consumed = 0U;
	if (descriptor->index == context->resume_block_index &&
	    context->resume_encoded_offset > descriptor->encoded_offset) {
		consumed = context->resume_encoded_offset - descriptor->encoded_offset;
		if (consumed > descriptor->encoded_size) return ESP_ERR_INVALID_SIZE;
	}
	while (consumed < descriptor->encoded_size) {
		if (atomic_load(&s_cancel)) return ESP_ERR_INVALID_STATE;
		size_t length = descriptor->encoded_size - consumed;
		if (length > OTA3_CHUNK_BYTES) length = OTA3_CHUNK_BYTES;
		esp_err_t err = package_read(payload_offset + consumed,
			context->chunk, length, &context->reader);
		if (err != ESP_OK) return err;
		keemash_fabric_v2_OtaMeshMessage *message =
			calloc(1U, sizeof(*message));
		if (!message) return ESP_ERR_NO_MEM;
		message->which_body =
			keemash_fabric_v2_OtaMeshMessage_transfer_tag;
		keemash_fabric_v2_OtaTransfer *transfer = &message->body.transfer;
		transfer->which_body = keemash_fabric_v2_OtaTransfer_data_tag;
		keemash_fabric_v2_OtaBlockChunk *data = &transfer->body.data;
		data->has_operation_id = true;
		data->operation_id = context->request.operation_id;
		data->artifact_id.size = KEEMASH_OTA_V3_SHA256_LEN;
		memcpy(data->artifact_id.bytes, context->request.artifact_id,
			KEEMASH_OTA_V3_SHA256_LEN);
		data->has_block = true;
		data->block = *descriptor;
		data->block_encoded_offset = consumed;
		data->data.size = length;
		memcpy(data->data.bytes, context->chunk, length);
		data->final_chunk = consumed + length == descriptor->encoded_size;
		keemash_fabric_v2_OtaTransferStatus status = {0};
		err = send_wait_transfer(&context->request, message, &status,
			descriptor->encoded_offset + consumed + length, false);
		free(message);
		if (err != ESP_OK) return err;
		consumed += length;
		context->resume_encoded_offset = status.encoded_offset;
		context->resume_block_index = status.next_block_index;
	}
	return ESP_OK;
}

static esp_err_t send_commit(deploy_context_t *context)
{
	keemash_fabric_v2_OtaMeshMessage *message =
		calloc(1U, sizeof(*message));
	if (!message) return ESP_ERR_NO_MEM;
	message->which_body = keemash_fabric_v2_OtaMeshMessage_transfer_tag;
	keemash_fabric_v2_OtaTransfer *transfer = &message->body.transfer;
	transfer->which_body = keemash_fabric_v2_OtaTransfer_commit_tag;
	keemash_fabric_v2_OtaCommit *commit = &transfer->body.commit;
	commit->has_operation_id = true;
	commit->operation_id = context->request.operation_id;
	commit->artifact_id.size = KEEMASH_OTA_V3_SHA256_LEN;
	memcpy(commit->artifact_id.bytes, context->request.artifact_id,
		KEEMASH_OTA_V3_SHA256_LEN);
	commit->block_table_sha256.size = KEEMASH_OTA_V3_SHA256_LEN;
	memcpy(commit->block_table_sha256.bytes,
		context->package.fields.block_table_sha256,
		KEEMASH_OTA_V3_SHA256_LEN);
	commit->image_sha256.size = KEEMASH_OTA_V3_SHA256_LEN;
	memcpy(commit->image_sha256.bytes,
		context->package.fields.image_sha256,
		KEEMASH_OTA_V3_SHA256_LEN);
	keemash_fabric_v2_OtaTransferStatus status = {0};
	esp_err_t err = send_wait_transfer(&context->request, message, &status,
		context->package.fields.encoded_size, true);
	free(message);
	return err;
}

static esp_err_t send_abort(const deploy_request_t *request,
	const char *reason)
{
	keemash_fabric_v2_OtaMeshMessage *message =
		calloc(1U, sizeof(*message));
	if (!message) return ESP_ERR_NO_MEM;
	message->which_body = keemash_fabric_v2_OtaMeshMessage_transfer_tag;
	keemash_fabric_v2_OtaTransfer *transfer = &message->body.transfer;
	transfer->which_body = keemash_fabric_v2_OtaTransfer_abort_tag;
	keemash_fabric_v2_OtaAbort *abort = &transfer->body.abort;
	abort->has_operation_id = true;
	abort->operation_id = request->operation_id;
	abort->artifact_id.size = KEEMASH_OTA_V3_SHA256_LEN;
	memcpy(abort->artifact_id.bytes, request->artifact_id,
		KEEMASH_OTA_V3_SHA256_LEN);
	strncpy(abort->reason, reason ? reason : "cancelled",
		sizeof(abort->reason) - 1U);
	esp_err_t err = mesh_v2_root_send_ota_v3_message(request->mac,
		message);
	free(message);
	return err;
}

static esp_err_t send_boot_ack(const deploy_request_t *request,
	const keemash_fabric_v2_OtaBootReport *report)
{
	keemash_fabric_v2_OtaMeshMessage message =
		keemash_fabric_v2_OtaMeshMessage_init_zero;
	message.which_body = keemash_fabric_v2_OtaMeshMessage_boot_ack_tag;
	message.body.boot_ack.has_operation_id = true;
	message.body.boot_ack.operation_id = request->operation_id;
	message.body.boot_ack.artifact_id.size = report->artifact_id.size;
	memcpy(message.body.boot_ack.artifact_id.bytes,
		report->artifact_id.bytes, report->artifact_id.size);
	message.body.boot_ack.state = report->state;
	return mesh_v2_root_send_ota_v3_message(request->mac, &message);
}

static esp_err_t wait_boot_report(const deploy_request_t *request)
{
	TickType_t deadline = xTaskGetTickCount() +
		pdMS_TO_TICKS(OTA3_BOOT_TIMEOUT_MS);
	while ((int32_t)(deadline - xTaskGetTickCount()) > 0) {
		rx_event_t event;
		esp_err_t err = wait_event(request, RX_ANY, 5000U, &event);
		if (err != ESP_OK) continue;
		if (event.kind == RX_STATUS) {
			const keemash_fabric_v2_OtaTransferStatus *status =
				&event.body.status;
			if (status->phase ==
			    keemash_fabric_v2_OtaPhase_OTA_PHASE_FAILED ||
			    status->phase ==
			    keemash_fabric_v2_OtaPhase_OTA_PHASE_ABORTED) {
				status_set(request, status->phase,
					status->status, status->message, false, true);
				return ESP_OK;
			}
			if (status->phase ==
			    keemash_fabric_v2_OtaPhase_OTA_PHASE_REBOOTING)
				status_set(request, status->phase, ESP_OK,
					status->message, true, true);
			continue;
		}
		const keemash_fabric_v2_OtaBootReport *report = &event.body.report;
		if (report->state ==
		    keemash_fabric_v2_OtaBootState_OTA_BOOT_PENDING_VERIFY) {
			status_set(request,
				keemash_fabric_v2_OtaPhase_OTA_PHASE_BOOT_VALIDATING,
				ESP_OK, report->message, true, true);
			continue;
		}
		(void)send_boot_ack(request, report);
		if (report->state ==
		    keemash_fabric_v2_OtaBootState_OTA_BOOT_VALIDATED) {
			status_set(request,
				keemash_fabric_v2_OtaPhase_OTA_PHASE_COMPLETE,
				ESP_OK, report->message, false, true);
			return ESP_OK;
		}
		status_set(request,
			report->state ==
			keemash_fabric_v2_OtaBootState_OTA_BOOT_ROLLED_BACK ?
			keemash_fabric_v2_OtaPhase_OTA_PHASE_ROLLED_BACK :
			keemash_fabric_v2_OtaPhase_OTA_PHASE_FAILED,
			report->health_status, report->message, false, true);
		return ESP_OK;
	}
	status_set(request,
		keemash_fabric_v2_OtaPhase_OTA_PHASE_OUTCOME_UNKNOWN,
		ESP_ERR_TIMEOUT, "boot validation report timeout", false, true);
	return ESP_OK;
}

static esp_err_t run_deploy(const deploy_request_t *request)
{
	deploy_context_t *context = calloc(1U, sizeof(*context));
	if (!context) return ESP_ERR_NO_MEM;
	bool abort_before_commit = false;
	context->request = *request;
	context->reader.vault = s_vault;
	esp_err_t err = ota_v3_vault_find(s_vault, request->artifact_id,
		&context->reader.entry);
	if (err != ESP_OK) goto done;
	err = keemash_ota_v3_package_inspect(package_read, &context->reader,
		context->reader.entry.size, &context->package);
	if (err != ESP_OK) goto done;
	if (strcmp(context->package.fields.project_name,
		request->expected_project) != 0) {
		err = ESP_ERR_INVALID_ARG;
		goto done;
	}
	context->chunk = heap_caps_malloc(OTA3_CHUNK_BYTES,
		MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
	if (!context->chunk) context->chunk = malloc(OTA3_CHUNK_BYTES);
	if (!context->chunk) {
		err = ESP_ERR_NO_MEM;
		goto done;
	}
	xSemaphoreTake(s_lock, portMAX_DELAY);
	s_status.raw_size = context->package.fields.raw_size;
	s_status.encoded_size = context->package.fields.encoded_size;
	strncpy(s_status.firmware_version,
		context->package.fields.firmware_version,
		sizeof(s_status.firmware_version) - 1U);
	xSemaphoreGive(s_lock);
	status_set(request,
		keemash_fabric_v2_OtaPhase_OTA_PHASE_TRANSFERRING,
		ESP_OK, "preparing target", true, true);
	abort_before_commit = true;
	err = send_prepare(context);
	if (err != ESP_OK) goto done;
	err = keemash_ota_v3_package_for_each_block(package_read,
		&context->reader, &context->package, send_block, context);
	if (err != ESP_OK) goto done;
	status_set(request,
		keemash_fabric_v2_OtaPhase_OTA_PHASE_VERIFYING,
		ESP_OK, "verifying target image", true, true);
	abort_before_commit = false;
	err = send_commit(context);
	if (err != ESP_OK) goto done;
	status_set(request,
		keemash_fabric_v2_OtaPhase_OTA_PHASE_REBOOTING,
		ESP_OK, "waiting for validated boot", true, true);
	err = wait_boot_report(request);
done:
	if (err != ESP_OK && abort_before_commit) {
		esp_err_t abort_err = send_abort(request,
			atomic_load(&s_cancel) ? "deployment cancelled" :
			"deployment failed");
		ESP_LOGW(TAG, "pre-commit abort queued: %s",
			esp_err_to_name(abort_err));
	}
	free(context->chunk);
	free(context);
	return err;
}

static void service_task(void *context)
{
	(void)context;
	for (;;) {
		deploy_request_t request;
		if (xQueueReceive(s_deploy_queue, &request,
			pdMS_TO_TICKS(500U)) != pdTRUE) {
			rx_event_t event;
			if (xQueueReceive(s_rx_queue, &event, 0) == pdTRUE &&
			    event.kind == RX_BOOT_REPORT &&
			    s_last_request_valid &&
			    event_matches(&event, &s_last_request) &&
			    event.body.report.state !=
				keemash_fabric_v2_OtaBootState_OTA_BOOT_PENDING_VERIFY) {
				(void)send_boot_ack(&s_last_request,
					&event.body.report);
			}
			continue;
		}
		atomic_store(&s_cancel, false);
		s_last_persisted_raw_offset = 0U;
		s_last_request = request;
		s_last_request_valid = true;
		esp_err_t err = run_deploy(&request);
		if (err != ESP_OK) {
			char message[sizeof(s_status.message)] = {0};
			xSemaphoreTake(s_lock, portMAX_DELAY);
			if (s_status.status == (uint32_t)err &&
			    s_status.message[0] != '\0')
				memcpy(message, s_status.message,
					sizeof(message));
			xSemaphoreGive(s_lock);
			status_set(&request,
				atomic_load(&s_cancel) ?
				keemash_fabric_v2_OtaPhase_OTA_PHASE_ABORTED :
				keemash_fabric_v2_OtaPhase_OTA_PHASE_FAILED,
				err, message[0] ? message : esp_err_to_name(err),
				false, true);
		}
	}
}

esp_err_t ota_v3_service_init(void)
{
	if (s_task) return ESP_OK;
	esp_err_t err = ota_v3_vault_open(&s_vault);
	if (err != ESP_OK) return err;
	s_lock = xSemaphoreCreateMutex();
	s_rx_queue = xQueueCreate(OTA3_RX_QUEUE_LEN, sizeof(rx_event_t));
	s_deploy_queue = xQueueCreate(OTA3_DEPLOY_QUEUE_LEN,
		sizeof(deploy_request_t));
	if (!s_lock || !s_rx_queue || !s_deploy_queue) {
		err = ESP_ERR_NO_MEM;
		goto failed;
	}
	memset(&s_status, 0, sizeof(s_status));
	s_status.ready = true;
	s_status.phase = keemash_fabric_v2_OtaPhase_OTA_PHASE_UNSPECIFIED;
	persistent_state_t persisted;
	bool persisted_valid = load_persistent(&persisted);
	bool resume = persisted_valid && persisted.active;
	if (persisted_valid) {
		s_status = persisted.status;
		s_last_request = persisted.request;
		s_last_request_valid = true;
		if (persisted.active) persisted.request.resume = true;
	}
	if (xTaskCreate(service_task, "ota_v3_root", OTA3_TASK_STACK, NULL,
		OTA3_TASK_PRIORITY, &s_task) != pdPASS) {
		err = ESP_ERR_NO_MEM;
		goto failed;
	}
	if (resume && xQueueSend(s_deploy_queue, &persisted.request, 0) != pdTRUE)
		ESP_LOGE(TAG, "failed to resume persisted deployment");
	return ESP_OK;
failed:
	if (s_deploy_queue) vQueueDelete(s_deploy_queue);
	if (s_rx_queue) vQueueDelete(s_rx_queue);
	if (s_lock) vSemaphoreDelete(s_lock);
	s_deploy_queue = NULL;
	s_rx_queue = NULL;
	s_lock = NULL;
	ota_v3_vault_close(s_vault);
	s_vault = NULL;
	return err;
}

esp_err_t ota_v3_service_stage_begin(
	const uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN],
	uint32_t package_size, uint32_t *resume_offset)
{
	if (!s_vault) return ESP_ERR_INVALID_STATE;
	return ota_v3_vault_stage_begin(s_vault, artifact_id, package_size,
		resume_offset);
}

esp_err_t ota_v3_service_stage_write(uint32_t offset,
	const uint8_t *bytes, size_t length)
{
	if (!s_vault) return ESP_ERR_INVALID_STATE;
	return ota_v3_vault_stage_write(s_vault, offset, bytes, length);
}

esp_err_t ota_v3_service_stage_finish(
	keemash_ota_v3_signed_fields_t *verified_fields)
{
	if (!s_vault) return ESP_ERR_INVALID_STATE;
	return ota_v3_vault_finish_verified_any(s_vault, verified_fields);
}

esp_err_t ota_v3_service_stage_abort(void)
{
	if (!s_vault) return ESP_ERR_INVALID_STATE;
	return ota_v3_vault_stage_abort(s_vault);
}

esp_err_t ota_v3_service_artifact_info(
	const uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN],
	keemash_ota_v3_signed_fields_t *fields)
{
	if (!s_vault) return ESP_ERR_INVALID_STATE;
	if (!artifact_id || !fields) return ESP_ERR_INVALID_ARG;
	package_reader_t reader = {.vault = s_vault};
	esp_err_t err = ota_v3_vault_find(s_vault, artifact_id, &reader.entry);
	if (err != ESP_OK) return err;
	keemash_ota_v3_package_info_t package = {0};
	err = keemash_ota_v3_package_inspect(package_read, &reader,
		reader.entry.size, &package);
	if (err == ESP_OK) *fields = package.fields;
	return err;
}

esp_err_t ota_v3_service_vault_entry(size_t index,
	ota_v3_vault_entry_t *entry, keemash_ota_v3_signed_fields_t *fields)
{
	if (!s_vault) return ESP_ERR_INVALID_STATE;
	if (!entry || !fields) return ESP_ERR_INVALID_ARG;
	esp_err_t err = ota_v3_vault_entry(s_vault, index, entry);
	if (err != ESP_OK) return err;
	package_reader_t reader = {.vault = s_vault, .entry = *entry};
	keemash_ota_v3_package_info_t package = {0};
	err = keemash_ota_v3_package_inspect(package_read, &reader,
		entry->size, &package);
	if (err == ESP_OK) *fields = package.fields;
	return err;
}

esp_err_t ota_v3_service_deploy(const uint8_t target_mac[6],
	const char *expected_project,
	const uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN])
{
	if (!s_task || !target_mac || !expected_project || !expected_project[0] ||
	    strlen(expected_project) > 32U || !artifact_id)
		return ESP_ERR_INVALID_ARG;
	xSemaphoreTake(s_lock, portMAX_DELAY);
	bool busy = s_status.active;
	xSemaphoreGive(s_lock);
	if (busy) return ESP_ERR_INVALID_STATE;
	deploy_request_t request = {0};
	memcpy(request.mac, target_mac, sizeof(request.mac));
	memcpy(request.artifact_id, artifact_id, sizeof(request.artifact_id));
	strncpy(request.expected_project, expected_project,
		sizeof(request.expected_project) - 1U);
	random_operation(&request.operation_id);
	status_set(&request,
		keemash_fabric_v2_OtaPhase_OTA_PHASE_WAITING_ROUTE,
		ESP_OK, "deployment queued", true, true);
	if (xQueueSend(s_deploy_queue, &request, 0) != pdTRUE) {
		status_set(&request,
			keemash_fabric_v2_OtaPhase_OTA_PHASE_FAILED,
			ESP_ERR_TIMEOUT, "deployment queue busy", false, true);
		return ESP_ERR_TIMEOUT;
	}
	return ESP_OK;
}

esp_err_t ota_v3_service_cancel(const char *reason)
{
	if (!s_task) return ESP_ERR_INVALID_STATE;
	xSemaphoreTake(s_lock, portMAX_DELAY);
	bool cancellable = s_status.active &&
		s_status.phase != keemash_fabric_v2_OtaPhase_OTA_PHASE_VERIFYING &&
		s_status.phase != keemash_fabric_v2_OtaPhase_OTA_PHASE_REBOOTING &&
		s_status.phase != keemash_fabric_v2_OtaPhase_OTA_PHASE_BOOT_VALIDATING;
	if (cancellable) atomic_store(&s_cancel, true);
	xSemaphoreGive(s_lock);
	if (!cancellable) return ESP_ERR_INVALID_STATE;
	if (reason && reason[0]) ESP_LOGI(TAG, "cancel requested: %s", reason);
	return ESP_OK;
}

void ota_v3_service_status(ota_v3_service_status_t *status)
{
	if (!status) return;
	if (!s_lock) {
		memset(status, 0, sizeof(*status));
		return;
	}
	xSemaphoreTake(s_lock, portMAX_DELAY);
	*status = s_status;
	xSemaphoreGive(s_lock);
}

void ota_v3_service_on_mesh_message(const uint8_t mac[6],
	const void *payload, size_t payload_len)
{
	if (!s_rx_queue || !mac || !payload || payload_len == 0U ||
	    payload_len > keemash_fabric_v2_OtaMeshMessage_size) return;
	keemash_fabric_v2_OtaMeshMessage *message = heap_caps_calloc(1U,
		sizeof(*message), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
	if (!message) message = calloc(1U, sizeof(*message));
	if (!message) return;
	if (keemash_ota_v3_decode_mesh_message(payload, payload_len, message) !=
	    ESP_OK) {
		free(message);
		return;
	}
	rx_event_t event = {0};
	memcpy(event.mac, mac, sizeof(event.mac));
	if (message->which_body ==
	    keemash_fabric_v2_OtaMeshMessage_transfer_tag &&
	    message->body.transfer.which_body ==
	    keemash_fabric_v2_OtaTransfer_status_tag) {
		event.kind = RX_STATUS;
		event.body.status = message->body.transfer.body.status;
	} else if (message->which_body ==
	    keemash_fabric_v2_OtaMeshMessage_boot_report_tag) {
		event.kind = RX_BOOT_REPORT;
		event.body.report = message->body.boot_report;
	} else {
		free(message);
		return;
	}
	free(message);
	if (xQueueSend(s_rx_queue, &event, 0) != pdTRUE)
		ESP_LOGW(TAG, "dropping OTA v3 status: queue full");
}
