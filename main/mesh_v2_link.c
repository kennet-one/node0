#include "mesh_v2_link.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_mesh.h"
#include "esp_wifi.h"
#include "sdkconfig.h"

#include "keemash_mesh_hooks.h"
#include "keemash_mesh_tx_broker.h"
#include "keemash_keelink.h"
#include "keelink_server.h"
#include "legacy_proto.h"
#include "log_http_server.h"
#include "mesh_root_bcast.h"
#include "uart_bridge.h"

static keemash_mesh_tx_broker_t *s_tx_broker;
static const char *TAG = "mesh_v2_link";

static esp_err_t raw_mesh_send(void *user, const uint8_t dst[6],
			       const void *packet, size_t packet_len)
{
	(void)user;
	mesh_addr_t dest = {0};
	if (dst) memcpy(dest.addr, dst, 6);
	mesh_data_t data = {
		.data = (uint8_t *)packet,
		.size = packet_len,
		.proto = MESH_PROTO_BIN,
		.tos = MESH_TOS_P2P,
	};
	return esp_mesh_send(&dest, &data, MESH_DATA_P2P, NULL, 0);
}

void mesh_v2_link_require(void)
{
	if (s_tx_broker) return;
	keemash_mesh_tx_broker_config_t cfg = {
		.slots = 32,
		.control_reserved_slots = 4,
		.max_packet_size = 512,
		.task_stack_words = 4096,
		.task_priority = 7,
		.task_name = "mesh_tx",
		.raw_send = raw_mesh_send,
	};
	ESP_ERROR_CHECK(keemash_mesh_tx_broker_init(&s_tx_broker, &cfg));
}

void mesh_v2_link_refresh_routes(void)
{
	mesh_addr_t routes[CONFIG_MESH_ROUTE_TABLE_SIZE];
	int count = 0;
	if (esp_mesh_get_routing_table(routes, sizeof(routes), &count) != ESP_OK) return;
	uint8_t local[6] = {0};
	esp_wifi_get_mac(WIFI_IF_STA, local);
	uint8_t macs[CONFIG_MESH_ROUTE_TABLE_SIZE][6];
	size_t remote_count = 0;
	for (int i = 0; i < count && remote_count < CONFIG_MESH_ROUTE_TABLE_SIZE; i++) {
		if (memcmp(routes[i].addr, local, 6) == 0) continue;
		memcpy(macs[remote_count++], routes[i].addr, 6);
	}
	mesh_v2_root_sync_routes(remote_count ? &macs[0][0] : NULL, remote_count);
}

esp_err_t keemash_mesh_transport_send(const uint8_t dst[6], const void *packet, size_t packet_len)
{
	if (!packet || packet_len == 0) return ESP_ERR_INVALID_ARG;
	if (!s_tx_broker) return ESP_ERR_INVALID_STATE;
	return keemash_mesh_tx_broker_submit_auto(s_tx_broker, dst, packet, packet_len);
}

esp_err_t mesh_v2_link_send(const uint8_t dst[6], const void *packet,
			    size_t packet_len, uint8_t priority)
{
	if (!packet || packet_len == 0) return ESP_ERR_INVALID_ARG;
	if (!s_tx_broker) return ESP_ERR_INVALID_STATE;
	return keemash_mesh_tx_broker_submit(s_tx_broker, dst, packet, packet_len,
					     priority);
}

void mesh_v2_link_tx_stats(keemash_mesh_tx_broker_stats_t *out)
{
	keemash_mesh_tx_broker_stats(s_tx_broker, out);
}

void keemash_mesh_get_local_mac(uint8_t mac[6])
{
	esp_wifi_get_mac(WIFI_IF_STA, mac);
}

void keemash_mesh_root_on_node_seen_uptime(const uint8_t mac[6], const char *tag,
                                           bool uptime_valid, uint32_t uptime_s)
{
	log_http_server_node_seen_uptime(mac, tag, uptime_valid, uptime_s);
}

void keemash_mesh_root_on_node_seen(const uint8_t mac[6], const char *tag)
{
	log_http_server_node_seen(mac, tag);
}

void keemash_mesh_root_on_log_line(const uint8_t mac[6], const char *tag, const char *line)
{
	log_http_server_node_seen(mac, tag);
	log_http_server_remote_line(mac, tag, line);
}

void keemash_mesh_root_on_task_snapshot(const uint8_t mac[6],
                                        const mesh_v2_task_snapshot_payload_t *snapshot)
{
	log_http_server_task_snapshot_v2(mac, snapshot);
	char tag[MESH_V2_TAG_MAX + 1] = {0};
	char event[192];
	memcpy(tag, snapshot->tag, MESH_V2_TAG_MAX);
	snprintf(event, sizeof(event),
		 "{\"requestId\":%lu,\"updatedMs\":%lu,\"uptimeS\":%lu,"
		 "\"cpuX10\":%lu,\"cpuValid\":%s,\"total\":%u,"
		 "\"index\":%u,\"count\":%u,\"last\":%s}",
		 (unsigned long)snapshot->request_id,
		 (unsigned long)snapshot->updated_ms,
		 (unsigned long)snapshot->uptime_s,
		 (unsigned long)snapshot->cpu_load_x10,
		 snapshot->cpu_valid ? "true" : "false",
		 (unsigned)snapshot->task_total, (unsigned)snapshot->task_index,
		 (unsigned)snapshot->task_count,
		 (snapshot->flags & MESH_V2_TASK_SNAPSHOT_FLAG_LAST) ? "true" : "false");
	keelink_server_publish_text_event(KEEMASH_KEELINK_CH_TASK, mac, tag, event);
}

void keemash_mesh_root_on_memory_snapshot(const uint8_t mac[6],
                                          const mesh_v2_memory_payload_t *snapshot)
{
	log_http_server_memory_snapshot_v2(mac, snapshot);
	char tag[MESH_V2_TAG_MAX + 1] = {0};
	char event[384];
	memcpy(tag, snapshot->tag, MESH_V2_TAG_MAX);
	snprintf(event, sizeof(event),
		 "{\"uptimeS\":%lu,\"heapFree\":%lu,\"heapMin\":%lu,"
		 "\"heapTotal\":%lu,\"internalFree\":%lu,\"internalTotal\":%lu,"
		 "\"psramEnabled\":%s,\"psramFree\":%lu,\"psramTotal\":%lu,"
		 "\"flashChip\":%lu,\"appUsed\":%lu,\"appSlot\":%lu,"
		 "\"nvsUsed\":%lu,\"nvsTotal\":%lu}",
		 (unsigned long)snapshot->uptime_s,
		 (unsigned long)snapshot->heap_free,
		 (unsigned long)snapshot->heap_min_free,
		 (unsigned long)snapshot->heap_total,
		 (unsigned long)snapshot->internal_free,
		 (unsigned long)snapshot->internal_total,
		 snapshot->psram_enabled ? "true" : "false",
		 (unsigned long)snapshot->psram_free,
		 (unsigned long)snapshot->psram_total,
		 (unsigned long)snapshot->flash_chip,
		 (unsigned long)snapshot->app_used,
		 (unsigned long)snapshot->app_slot,
		 (unsigned long)snapshot->nvs_used,
		 (unsigned long)snapshot->nvs_total);
	keelink_server_publish_text_event(KEEMASH_KEELINK_CH_MEMORY, mac, tag, event);
}

static double sensor_value(const mesh_v2_sensor_entry_t *entry)
{
	double value = entry->value;
	if (entry->scale10 < 0) {
		for (int i = 0; i < -entry->scale10; i++) value /= 10.0;
	} else {
		for (int i = 0; i < entry->scale10; i++) value *= 10.0;
	}
	return value;
}

static bool sensor_legacy_line(const mesh_v2_sensor_entry_t *entry,
			       char *line, size_t line_size)
{
	if (!entry || !line || line_size == 0 ||
	    (entry->status & MESH_V2_SENSOR_STATUS_VALID) == 0) {
		return false;
	}

	double value = sensor_value(entry);
	int n = -1;
	switch (entry->metric_id) {
	case MESH_V2_SENSOR_METRIC_CO2_PPM:
		n = snprintf(line, line_size, "04%.0f", value);
		break;
	case MESH_V2_SENSOR_METRIC_TEMPERATURE_C:
		n = snprintf(line, line_size, "05%.2f", value);
		break;
	case MESH_V2_SENSOR_METRIC_HUMIDITY_RH:
		n = snprintf(line, line_size, "06%.2f", value);
		break;
	case MESH_V2_SENSOR_METRIC_ILLUMINANCE_LUX:
		n = snprintf(line, line_size, "07%.2f", value);
		break;
	default:
		return false;
	}
	return n > 0 && (size_t)n < line_size;
}

void keemash_mesh_root_on_sensor_snapshot(
	const uint8_t mac[6],
	const mesh_v2_sensor_snapshot_payload_t *snapshot)
{
	if (mac && snapshot) {
		for (uint8_t i = 0; i < snapshot->count; i++) {
			const mesh_v2_sensor_entry_t *entry = &snapshot->entries[i];
			char event[192];
			snprintf(event, sizeof(event),
				"{\"generation\":%lu,\"sampleUptimeMs\":%lu,\"requestId\":%lu,"
				"\"id\":%u,\"status\":%u,\"scale10\":%d,\"value\":%ld}",
				(unsigned long)snapshot->generation,
				(unsigned long)snapshot->sample_uptime_ms,
				(unsigned long)snapshot->request_id,
				(unsigned)entry->metric_id,
				(unsigned)entry->status, (int)entry->scale10,
				(long)entry->value);
			keelink_server_publish_text_event(KEEMASH_KEELINK_CH_SENSOR,
				mac, NULL, event);
		}
	}

	uint8_t mixer_mac[6] = {0};
	if (!mac || !snapshot ||
	    !mesh_v2_root_find_lossless_by_tag(
		    "esp_mixer", mixer_mac, MESH_V2_CAP_TYPED_SENSOR) ||
	    memcmp(mac, mixer_mac, sizeof(mixer_mac)) != 0) {
		return;
	}

	bool legacy_reply =
		(snapshot->flags & MESH_V2_SENSOR_FLAG_LEGACY_REPLY) != 0;
	bool automation =
		(snapshot->flags & MESH_V2_SENSOR_FLAG_AUTOMATION_UPDATE) != 0;
	if (!legacy_reply && !automation) return;

	for (uint8_t i = 0; i < snapshot->count; i++) {
		char line[32];
		if (!sensor_legacy_line(&snapshot->entries[i], line, sizeof(line))) {
			continue;
		}
		if (legacy_reply) uart_bridge_send_line(line);
		if (automation &&
		    snapshot->entries[i].metric_id ==
			    MESH_V2_SENSOR_METRIC_TEMPERATURE_C) {
			mesh_root_broadcast_text(line);
		}
	}
}

void keemash_mesh_root_on_ota_status(const uint8_t mac[6],
                                     const mesh_v2_ota_status_payload_t *status,
                                     size_t status_len)
{
	log_http_server_remote_ota_status_v2(mac, status, status_len);
	char event[256];
	snprintf(event, sizeof(event),
		 "{\"op\":%u,\"status\":%u,\"opId\":%lu,\"imageSize\":%lu,"
		 "\"offset\":%lu,\"length\":%lu}",
		 (unsigned)status->c.op, (unsigned)status->c.status,
		 (unsigned long)status->c.op_id,
		 (unsigned long)status->c.image_size,
		 (unsigned long)status->c.offset,
		 (unsigned long)status->c.len);
	keelink_server_publish_text_event(KEEMASH_KEELINK_CH_OTA_STATUS,
		mac, NULL, event);
}

void keemash_mesh_root_on_topology(const uint8_t mac[6], const void *payload, size_t payload_len)
{
	log_http_server_node_topology(mac, payload, payload_len);
	keelink_server_publish_text_event(KEEMASH_KEELINK_CH_TOPOLOGY,
		mac, NULL, "{\"changed\":true}");
}

void keemash_mesh_root_on_control_event(const char *text)
{
	legacy_handle_text(text);
	keelink_server_publish_text_event(KEEMASH_KEELINK_CH_STATE,
		NULL, NULL, text);
	if (text && (strcmp(text, "garland_on") == 0 ||
		     strcmp(text, "garland_off") == 0)) {
		(void)mesh_root_send_state_to_mixer(text);
	}
}

void keemash_mesh_root_on_control(const uint8_t peer[6], uint32_t root_session,
				  uint32_t node_session, uint8_t kind,
				  uint32_t command_id, uint8_t status,
				  const char *text)
{
	(void)node_session;
	if (kind == MESH_V2_CONTROL_RESULT) {
		mesh_root_command_result(peer, root_session, command_id, status, text);
	} else if (kind == MESH_V2_CONTROL_EVENT) {
		uint8_t mixer_mac[6] = {0};
		bool from_mixer = mesh_v2_root_find_lossless_by_tag(
			"esp_mixer", mixer_mac, MESH_V2_CAP_TYPED_CONTROL) &&
			memcmp(peer, mixer_mac, sizeof(mixer_mac)) == 0;
		if (from_mixer && text && strncmp(text, "cmd:", 4) == 0) {
			const char *command = text + 4;
			if (strcmp(command, "garland") == 0 ||
			    strcmp(command, "garland_echo") == 0) {
				mesh_root_broadcast_text(command);
				return;
			}
			ESP_LOGW(TAG, "ignored unsupported controller event \"%s\"",
				 command);
			return;
		}
		keemash_mesh_root_on_control_event(text);
	}
}

void keemash_mesh_root_on_state_changed(void)
{
	log_http_server_mesh_state_changed();
}
