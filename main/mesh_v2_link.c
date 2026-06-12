#include "mesh_v2_link.h"

#include <stddef.h>
#include <string.h>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"

#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "freertos/task.h"

#include "log_http_server.h"
#include "mesh_proto.h"

static const char *TAG = "mesh_v2";

#ifndef MESH_V2_MAX_NODES
#define MESH_V2_MAX_NODES 24
#endif

#ifndef MESH_V2_DEBUG_DROP_EVERY
#define MESH_V2_DEBUG_DROP_EVERY 0
#endif

typedef struct {
	bool used;
	uint8_t mac[6];
	uint32_t session_id;
	uint32_t expected_seq;
	uint32_t highest_seen_seq;
	uint32_t gap_count;
	uint32_t replay_count;
	uint32_t lost_count;
	uint32_t last_v2_ms;
	bool has_gap;
} root_node_state_t;

static root_node_state_t s_nodes[MESH_V2_MAX_NODES];
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

static uint32_t ms_now(void)
{
	return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

static bool mac_eq(const uint8_t a[6], const uint8_t b[6])
{
	return memcmp(a, b, 6) == 0;
}

static void mac_copy(uint8_t dst[6], const uint8_t src[6])
{
	memcpy(dst, src, 6);
}

static void copy_packet_text(char *dst, size_t dst_sz, const char *src, size_t src_sz)
{
	size_t n = 0;

	if (!dst || dst_sz == 0) {
		return;
	}

	if (src && src_sz > 0) {
		n = strnlen(src, src_sz);
		if (n >= dst_sz) {
			n = dst_sz - 1;
		}
		memcpy(dst, src, n);
	}
	dst[n] = '\0';
}

static uint16_t crc16_update(uint16_t crc, const uint8_t *data, size_t len)
{
	while (len--) {
		crc ^= (uint16_t)(*data++) << 8;
		for (int i = 0; i < 8; i++) {
			crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
		}
	}
	return crc;
}

static uint16_t packet_crc(const mesh_v2_hdr_t *h, const uint8_t *payload)
{
	mesh_v2_hdr_t tmp = *h;
	tmp.crc16 = 0;

	uint16_t crc = 0xffff;
	crc = crc16_update(crc, (const uint8_t *)&tmp, sizeof(tmp));
	if (tmp.payload_len > 0 && payload) {
		crc = crc16_update(crc, payload, tmp.payload_len);
	}
	return crc;
}

static bool validate_packet(const void *pkt_buf, size_t pkt_len, const mesh_v2_hdr_t **out_h,
                            const uint8_t **out_payload)
{
	if (!pkt_buf || pkt_len < sizeof(mesh_v2_hdr_t)) {
		return false;
	}

	const mesh_v2_hdr_t *h = (const mesh_v2_hdr_t *)pkt_buf;
	if (h->magic != MESH_PKT_MAGIC || h->version != MESH_PKT_VERSION_V2) {
		return false;
	}
	if (h->payload_len > MESH_V2_PAYLOAD_MAX) {
		return false;
	}
	if (pkt_len != sizeof(mesh_v2_hdr_t) + h->payload_len || pkt_len > MESH_V2_PACKET_MAX) {
		return false;
	}

	const uint8_t *payload = (const uint8_t *)pkt_buf + sizeof(mesh_v2_hdr_t);
	if (packet_crc(h, payload) != h->crc16) {
		ESP_LOGW(TAG, "CRC mismatch from " MACSTR " type=%u seq=%lu",
		         MAC2STR(h->src_mac), (unsigned)h->type, (unsigned long)h->seq);
		return false;
	}

	if (out_h) {
		*out_h = h;
	}
	if (out_payload) {
		*out_payload = payload;
	}
	return true;
}

static root_node_state_t *find_node_locked(const uint8_t mac[6], bool create)
{
	root_node_state_t *free_slot = NULL;

	for (uint32_t i = 0; i < MESH_V2_MAX_NODES; i++) {
		if (s_nodes[i].used && mac_eq(s_nodes[i].mac, mac)) {
			return &s_nodes[i];
		}
		if (!s_nodes[i].used && !free_slot) {
			free_slot = &s_nodes[i];
		}
	}

	if (!create || !free_slot) {
		return NULL;
	}

	memset(free_slot, 0, sizeof(*free_slot));
	free_slot->used = true;
	mac_copy(free_slot->mac, mac);
	free_slot->expected_seq = 1;
	return free_slot;
}

static esp_err_t send_control(const mesh_addr_t *to, const uint8_t mac[6], uint8_t type,
                              uint32_t session_id, uint32_t ack_seq, uint32_t missing_seq)
{
	uint8_t buf[MESH_V2_PACKET_MAX];
	mesh_v2_hdr_t *h = (mesh_v2_hdr_t *)buf;
	size_t payload_len = 0;

	memset(buf, 0, sizeof(buf));

	if (type == MESH_V2_TYPE_NACK) {
		mesh_v2_nack_payload_t p = {
			.missing_seq = missing_seq,
		};
		memcpy(buf + sizeof(mesh_v2_hdr_t), &p, sizeof(p));
		payload_len = sizeof(p);
	}

	h->magic = MESH_PKT_MAGIC;
	h->version = MESH_PKT_VERSION_V2;
	h->type = type;
	h->session_id = session_id;
	h->seq = 0;
	h->ack_seq = ack_seq;
	h->payload_len = (uint16_t)payload_len;
	esp_wifi_get_mac(WIFI_IF_STA, h->src_mac);
	h->crc16 = packet_crc(h, buf + sizeof(mesh_v2_hdr_t));

	mesh_addr_t dest = {0};
	if (to) {
		dest = *to;
	} else if (mac) {
		memcpy(dest.addr, mac, 6);
	}

	mesh_data_t data = {
		.data = buf,
		.size = sizeof(mesh_v2_hdr_t) + payload_len,
		.proto = MESH_PROTO_BIN,
		.tos = MESH_TOS_P2P,
	};

	return esp_mesh_send(&dest, &data, MESH_DATA_P2P, NULL, 0);
}

static void reset_session_locked(root_node_state_t *st, const mesh_v2_hdr_t *h)
{
	st->session_id = h->session_id;
	st->expected_seq = 1;
	st->highest_seen_seq = 0;
	st->gap_count = 0;
	st->replay_count = 0;
	st->lost_count = 0;
	st->has_gap = false;
	st->last_v2_ms = ms_now();
}

static void handle_hello(const mesh_addr_t *from, const mesh_v2_hdr_t *h, const uint8_t *payload)
{
	char tag[MESH_V2_TAG_MAX + 1] = "node";
	uint32_t uptime_s = 0;

	if (h->payload_len >= sizeof(mesh_v2_hello_payload_t)) {
		const mesh_v2_hello_payload_t *p = (const mesh_v2_hello_payload_t *)payload;
		copy_packet_text(tag, sizeof(tag), p->tag, sizeof(p->tag));
		uptime_s = p->uptime_s;
	}

	portENTER_CRITICAL(&s_lock);
	root_node_state_t *st = find_node_locked(h->src_mac, true);
	if (st) {
		reset_session_locked(st, h);
	}
	portEXIT_CRITICAL(&s_lock);

	log_http_server_node_seen_uptime(h->src_mac, tag, true, uptime_s);
	send_control(from, h->src_mac, MESH_V2_TYPE_ACK, h->session_id, 0, 0);
	ESP_LOGI(TAG, "HELLO from " MACSTR " tag=%s session=%lu",
	         MAC2STR(h->src_mac), tag, (unsigned long)h->session_id);
}

static void deliver_payload(const mesh_v2_hdr_t *h, const uint8_t *payload)
{
	if (h->type == MESH_V2_TYPE_NODEINFO) {
		if (h->payload_len < sizeof(mesh_v2_nodeinfo_payload_t)) {
			return;
		}
		const mesh_v2_nodeinfo_payload_t *p = (const mesh_v2_nodeinfo_payload_t *)payload;
		char tag[MESH_V2_TAG_MAX + 1];
		copy_packet_text(tag, sizeof(tag), p->tag, sizeof(p->tag));
		log_http_server_node_seen_uptime(h->src_mac, tag, true, p->uptime_s);
		return;
	}

	if (h->type == MESH_V2_TYPE_LOG_LINE) {
		if (h->payload_len < sizeof(mesh_v2_log_line_payload_t)) {
			return;
		}
		const mesh_v2_log_line_payload_t *p = (const mesh_v2_log_line_payload_t *)payload;
		char tag[MESH_V2_TAG_MAX + 1];
		char line[MESH_V2_LOG_LINE_MAX + 1];
		copy_packet_text(tag, sizeof(tag), p->tag, sizeof(p->tag));
		copy_packet_text(line, sizeof(line), p->line, sizeof(p->line));
		log_http_server_node_seen(h->src_mac, tag);
		log_http_server_remote_line(h->src_mac, tag, line);
	}
}

static void handle_lost(const mesh_addr_t *from, const mesh_v2_hdr_t *h, const uint8_t *payload)
{
	if (h->payload_len < sizeof(mesh_v2_lost_payload_t)) {
		return;
	}

	const mesh_v2_lost_payload_t *p = (const mesh_v2_lost_payload_t *)payload;
	uint32_t ack_seq = 0;

	portENTER_CRITICAL(&s_lock);
	root_node_state_t *st = find_node_locked(h->src_mac, true);
	if (st && st->session_id == h->session_id) {
		st->last_v2_ms = ms_now();
		st->lost_count++;
		st->has_gap = true;
		if (p->missing_seq == st->expected_seq) {
			st->expected_seq = st->highest_seen_seq >= p->missing_seq
				? st->highest_seen_seq + 1
				: p->missing_seq + 1;
		}
		ack_seq = st->expected_seq ? st->expected_seq - 1 : 0;
	}
	portEXIT_CRITICAL(&s_lock);

	send_control(from, h->src_mac, MESH_V2_TYPE_ACK, h->session_id, ack_seq, 0);
	ESP_LOGW(TAG, "sender lost seq=%lu from " MACSTR,
	         (unsigned long)p->missing_seq, MAC2STR(h->src_mac));
}

esp_err_t mesh_v2_root_handle_rx(const mesh_addr_t *from, const void *pkt_buf, size_t pkt_len)
{
	const mesh_v2_hdr_t *h = NULL;
	const uint8_t *payload = NULL;

	if (!validate_packet(pkt_buf, pkt_len, &h, &payload)) {
		return ESP_ERR_INVALID_ARG;
	}

#if MESH_V2_DEBUG_DROP_EVERY > 0
	static uint32_t drop_counter = 0;
	if ((h->type == MESH_V2_TYPE_NODEINFO || h->type == MESH_V2_TYPE_LOG_LINE) &&
	    (++drop_counter % MESH_V2_DEBUG_DROP_EVERY) == 0) {
		ESP_LOGW(TAG, "debug drop type=%u seq=%lu", (unsigned)h->type, (unsigned long)h->seq);
		return ESP_OK;
	}
#endif

	if (h->type == MESH_V2_TYPE_HELLO) {
		handle_hello(from, h, payload);
		return ESP_OK;
	}

	if (h->type == MESH_V2_TYPE_LOST) {
		handle_lost(from, h, payload);
		return ESP_OK;
	}

	if (h->type == MESH_V2_TYPE_ACK || h->type == MESH_V2_TYPE_NACK) {
		return ESP_OK;
	}

	if (h->type != MESH_V2_TYPE_NODEINFO && h->type != MESH_V2_TYPE_LOG_LINE) {
		return ESP_OK;
	}

	bool deliver = false;
	bool send_nack = false;
	uint32_t ack_seq = 0;
	uint32_t missing_seq = 0;

	portENTER_CRITICAL(&s_lock);
	root_node_state_t *st = find_node_locked(h->src_mac, true);
	if (st) {
		if (st->session_id != h->session_id) {
			reset_session_locked(st, h);
			if (h->seq > st->expected_seq) {
				st->gap_count++;
				st->lost_count++;
				st->has_gap = true;
				st->expected_seq = h->seq;
				st->highest_seen_seq = h->seq;
			}
		}

		st->last_v2_ms = ms_now();
		if (h->flags & MESH_V2_FLAG_REPLAY) {
			st->replay_count++;
		}
		if (h->seq > st->highest_seen_seq) {
			st->highest_seen_seq = h->seq;
		}

		if (h->seq == st->expected_seq) {
			deliver = true;
			st->expected_seq++;
			ack_seq = h->seq;
			if (st->expected_seq <= st->highest_seen_seq) {
				st->gap_count++;
				st->has_gap = true;
				missing_seq = st->expected_seq;
				send_nack = true;
			}
		} else if (h->seq < st->expected_seq) {
			ack_seq = st->expected_seq - 1;
		} else {
			st->gap_count++;
			st->has_gap = true;
			missing_seq = st->expected_seq;
			ack_seq = st->expected_seq ? st->expected_seq - 1 : 0;
			send_nack = true;
		}
	}
	portEXIT_CRITICAL(&s_lock);

	if (send_nack) {
		send_control(from, h->src_mac, MESH_V2_TYPE_NACK, h->session_id, ack_seq, missing_seq);
	} else {
		send_control(from, h->src_mac, MESH_V2_TYPE_ACK, h->session_id, ack_seq, 0);
	}

	if (deliver) {
		deliver_payload(h, payload);
	}

	return ESP_OK;
}

bool mesh_v2_root_stats_for_mac(const uint8_t mac[6], mesh_v2_root_stats_t *out)
{
	if (!mac || !out) {
		return false;
	}

	memset(out, 0, sizeof(*out));

	portENTER_CRITICAL(&s_lock);
	root_node_state_t *st = find_node_locked(mac, false);
	if (st) {
		out->seen = true;
		out->has_gap = st->has_gap;
		out->session_id = st->session_id;
		out->expected_seq = st->expected_seq;
		out->gap_count = st->gap_count;
		out->replay_count = st->replay_count;
		out->lost_count = st->lost_count;
		out->last_v2_ms = st->last_v2_ms;
	}
	portEXIT_CRITICAL(&s_lock);

	return out->seen;
}
