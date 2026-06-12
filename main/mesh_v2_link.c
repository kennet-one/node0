#include "mesh_v2_link.h"

#include <stddef.h>
#include <string.h>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_mesh.h"
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
	uint32_t expected_seq;
	uint32_t highest_seen_seq;
	uint32_t gap_count;
	uint32_t replay_count;
	uint32_t lost_count;
	uint32_t last_ms;
	bool has_gap;
} tunnel_rx_channel_t;

typedef struct {
	uint32_t next_seq;
	uint32_t last_ack_seq;
} tunnel_tx_channel_t;

typedef struct {
	bool used;
	uint8_t mac[6];
	char tag[MESH_V2_TAG_MAX];
	uint32_t session_id;
	uint32_t expected_seq;
	uint32_t highest_seen_seq;
	uint32_t gap_count;
	uint32_t replay_count;
	uint32_t lost_count;
	uint32_t last_v2_ms;
	bool has_gap;
	bool tunnel_seen;
	uint32_t last_tunnel_ms;
	uint32_t capabilities;
	tunnel_rx_channel_t rx[MESH_V2_TUNNEL_CHANNEL_MAX + 1];
	tunnel_tx_channel_t tx[MESH_V2_TUNNEL_CHANNEL_MAX + 1];
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

static bool mac_is_zero(const uint8_t mac[6])
{
	static const uint8_t zero[6] = {0};
	return mac_eq(mac, zero);
}

static void mac_copy(uint8_t dst[6], const uint8_t src[6])
{
	memcpy(dst, src, 6);
}

static void local_mac(uint8_t mac[6])
{
	esp_wifi_get_mac(WIFI_IF_STA, mac);
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
	for (uint32_t ch = 0; ch <= MESH_V2_TUNNEL_CHANNEL_MAX; ch++) {
		free_slot->rx[ch].expected_seq = 1;
		free_slot->tx[ch].next_seq = 1;
	}
	copy_packet_text(free_slot->tag, sizeof(free_slot->tag), "node", 4);
	return free_slot;
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
	st->last_tunnel_ms = 0;
	st->tunnel_seen = false;
	for (uint32_t ch = 0; ch <= MESH_V2_TUNNEL_CHANNEL_MAX; ch++) {
		memset(&st->rx[ch], 0, sizeof(st->rx[ch]));
		memset(&st->tx[ch], 0, sizeof(st->tx[ch]));
		st->rx[ch].expected_seq = 1;
		st->tx[ch].next_seq = 1;
	}
}

static esp_err_t send_packet_to_mac(const uint8_t mac[6], uint8_t type, uint32_t session_id,
                                    uint32_t seq, uint32_t ack_seq,
                                    const void *payload, size_t payload_len)
{
	if (!mac || payload_len > MESH_V2_PAYLOAD_MAX ||
	    sizeof(mesh_v2_hdr_t) + payload_len > MESH_V2_PACKET_MAX) {
		return ESP_ERR_INVALID_ARG;
	}

	uint8_t buf[MESH_V2_PACKET_MAX];
	memset(buf, 0, sizeof(buf));

	mesh_v2_hdr_t *h = (mesh_v2_hdr_t *)buf;
	h->magic = MESH_PKT_MAGIC;
	h->version = MESH_PKT_VERSION_V2;
	h->type = type;
	h->session_id = session_id;
	h->seq = seq;
	h->ack_seq = ack_seq;
	h->payload_len = (uint16_t)payload_len;
	local_mac(h->src_mac);

	if (payload && payload_len > 0) {
		memcpy(buf + sizeof(mesh_v2_hdr_t), payload, payload_len);
	}
	h->crc16 = packet_crc(h, buf + sizeof(mesh_v2_hdr_t));

	mesh_addr_t dest = {0};
	memcpy(dest.addr, mac, 6);
	mesh_data_t data = {
		.data = buf,
		.size = sizeof(mesh_v2_hdr_t) + payload_len,
		.proto = MESH_PROTO_BIN,
		.tos = MESH_TOS_P2P,
	};

	return esp_mesh_send(&dest, &data, MESH_DATA_P2P, NULL, 0);
}

static esp_err_t send_control(const mesh_addr_t *to, const uint8_t mac[6], uint8_t type,
                              uint32_t session_id, uint32_t ack_seq, uint32_t missing_seq)
{
	uint8_t dst[6] = {0};
	uint8_t buf[sizeof(mesh_v2_nack_payload_t)] = {0};
	const void *payload = NULL;
	size_t payload_len = 0;

	if (to) {
		mac_copy(dst, to->addr);
	} else if (mac) {
		mac_copy(dst, mac);
	}
	if (mac_is_zero(dst)) {
		return ESP_ERR_INVALID_ARG;
	}

	if (type == MESH_V2_TYPE_NACK) {
		mesh_v2_nack_payload_t p = {
			.missing_seq = missing_seq,
		};
		memcpy(buf, &p, sizeof(p));
		payload = buf;
		payload_len = sizeof(p);
	}

	return send_packet_to_mac(dst, type, session_id, 0, ack_seq, payload, payload_len);
}

static esp_err_t send_tunnel_control_packet(const uint8_t dst[6], uint8_t type,
                                            uint32_t session_id, const void *payload,
                                            size_t payload_len)
{
	return send_packet_to_mac(dst, type, session_id, 0, 0, payload, payload_len);
}

static esp_err_t send_tunnel_ack(const uint8_t dst[6], const mesh_v2_hdr_t *h,
                                 const mesh_v2_tunnel_hdr_t *t, uint32_t ack_seq)
{
	mesh_v2_tunnel_ack_payload_t p;
	memset(&p, 0, sizeof(p));
	p.channel_id = t->channel_id;
	p.flags = MESH_V2_TUNNEL_FLAG_E2E_ACK | MESH_V2_TUNNEL_FLAG_HOP_ACK;
	p.seq = t->seq;
	p.ack_seq = ack_seq;
	p.sack_bitmap = 0;
	mac_copy(p.origin_mac, t->origin_mac);
	mac_copy(p.target_mac, t->target_mac);
	return send_tunnel_control_packet(dst, MESH_V2_TYPE_TUNNEL_ACK,
	                                  h->session_id, &p, sizeof(p));
}

static esp_err_t send_tunnel_nack(const uint8_t dst[6], const mesh_v2_hdr_t *h,
                                  const mesh_v2_tunnel_hdr_t *t, uint32_t missing_seq)
{
	mesh_v2_tunnel_nack_payload_t p;
	memset(&p, 0, sizeof(p));
	p.channel_id = t->channel_id;
	p.missing_seq = missing_seq;
	mac_copy(p.origin_mac, t->origin_mac);
	mac_copy(p.target_mac, t->target_mac);
	return send_tunnel_control_packet(dst, MESH_V2_TYPE_TUNNEL_NACK,
	                                  h->session_id, &p, sizeof(p));
}

static void handle_hello(const mesh_addr_t *from, const mesh_v2_hdr_t *h, const uint8_t *payload)
{
	char tag[MESH_V2_TAG_MAX + 1] = "node";
	uint32_t uptime_s = 0;
	uint32_t capabilities = 0;

	if (h->payload_len >= sizeof(mesh_v2_hello_payload_t)) {
		const mesh_v2_hello_payload_t *p = (const mesh_v2_hello_payload_t *)payload;
		copy_packet_text(tag, sizeof(tag), p->tag, sizeof(p->tag));
		uptime_s = p->uptime_s;
		capabilities = p->capabilities;
	}

	portENTER_CRITICAL(&s_lock);
	root_node_state_t *st = find_node_locked(h->src_mac, true);
	if (st) {
		reset_session_locked(st, h);
		st->capabilities = capabilities;
		st->tunnel_seen = (capabilities & MESH_V2_CAP_TUNNEL) != 0;
		if (st->tunnel_seen) {
			st->last_tunnel_ms = ms_now();
		}
		copy_packet_text(st->tag, sizeof(st->tag), tag, sizeof(tag));
	}
	portEXIT_CRITICAL(&s_lock);

	log_http_server_node_seen_uptime(h->src_mac, tag, true, uptime_s);
	send_control(from, h->src_mac, MESH_V2_TYPE_ACK, h->session_id, 0, 0);
	ESP_LOGI(TAG, "HELLO from " MACSTR " tag=%s session=%lu cap=0x%08lx",
	         MAC2STR(h->src_mac), tag, (unsigned long)h->session_id,
	         (unsigned long)capabilities);
}

static void deliver_legacy_v2_payload(const mesh_v2_hdr_t *h, const uint8_t *payload)
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

static void deliver_tunnel_payload(const mesh_v2_tunnel_hdr_t *t, const uint8_t *payload)
{
	if (t->channel_id == MESH_V2_TUNNEL_CHANNEL_NODEINFO) {
		if (t->payload_len < sizeof(mesh_v2_tunnel_nodeinfo_payload_t)) {
			return;
		}
		const mesh_v2_tunnel_nodeinfo_payload_t *p =
			(const mesh_v2_tunnel_nodeinfo_payload_t *)payload;
		char tag[MESH_V2_TAG_MAX + 1];
		copy_packet_text(tag, sizeof(tag), p->tag, sizeof(p->tag));
		log_http_server_node_seen_uptime(t->origin_mac, tag, true, p->uptime_s);
		return;
	}

	if (t->channel_id == MESH_V2_TUNNEL_CHANNEL_LOG) {
		if (t->payload_len < sizeof(mesh_v2_tunnel_log_payload_t)) {
			return;
		}
		const mesh_v2_tunnel_log_payload_t *p =
			(const mesh_v2_tunnel_log_payload_t *)payload;
		char tag[MESH_V2_TAG_MAX + 1];
		char line[MESH_V2_TUNNEL_LOG_LINE_MAX + 1];
		copy_packet_text(tag, sizeof(tag), p->tag, sizeof(p->tag));
		copy_packet_text(line, sizeof(line), p->line, sizeof(p->line));
		log_http_server_node_seen(t->origin_mac, tag);
		log_http_server_remote_line(t->origin_mac, tag, line);
		return;
	}

	if (t->channel_id == MESH_V2_TUNNEL_CHANNEL_TOPOLOGY) {
		if (t->payload_len < sizeof(mesh_v2_topology_payload_t)) {
			return;
		}
		const mesh_v2_topology_payload_t *p = (const mesh_v2_topology_payload_t *)payload;
		log_http_server_node_topology(t->origin_mac, p);
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

static void handle_tunnel_lost(const mesh_v2_hdr_t *h, const uint8_t *payload)
{
	if (h->payload_len < sizeof(mesh_v2_tunnel_lost_payload_t)) {
		return;
	}

	const mesh_v2_tunnel_lost_payload_t *p =
		(const mesh_v2_tunnel_lost_payload_t *)payload;
	uint8_t ch = p->channel_id;
	if (ch == 0 || ch > MESH_V2_TUNNEL_CHANNEL_MAX) {
		return;
	}

	portENTER_CRITICAL(&s_lock);
	root_node_state_t *st = find_node_locked(p->origin_mac, true);
	if (st && st->session_id == h->session_id) {
		tunnel_rx_channel_t *rx = &st->rx[ch];
		rx->lost_count++;
		rx->has_gap = true;
		rx->last_ms = ms_now();
		st->last_tunnel_ms = rx->last_ms;
		st->tunnel_seen = true;
		if (p->missing_seq == rx->expected_seq) {
			rx->expected_seq = rx->highest_seen_seq >= p->missing_seq
				? rx->highest_seen_seq + 1
				: p->missing_seq + 1;
		}
	}
	portEXIT_CRITICAL(&s_lock);
}

static void handle_tunnel_ack(const mesh_v2_hdr_t *h, const uint8_t *payload)
{
	if (h->payload_len < sizeof(mesh_v2_tunnel_ack_payload_t)) {
		return;
	}

	const mesh_v2_tunnel_ack_payload_t *p =
		(const mesh_v2_tunnel_ack_payload_t *)payload;
	uint8_t ch = p->channel_id;
	if (ch == 0 || ch > MESH_V2_TUNNEL_CHANNEL_MAX) {
		return;
	}

	portENTER_CRITICAL(&s_lock);
	root_node_state_t *st = find_node_locked(h->src_mac, false);
	if (st && st->session_id == h->session_id) {
		st->tx[ch].last_ack_seq = p->ack_seq;
		st->last_tunnel_ms = ms_now();
		st->tunnel_seen = true;
	}
	portEXIT_CRITICAL(&s_lock);
}

static void handle_tunnel_data(const mesh_v2_hdr_t *h, const uint8_t *payload)
{
	if (h->payload_len < sizeof(mesh_v2_tunnel_hdr_t)) {
		return;
	}

	const mesh_v2_tunnel_hdr_t *t = (const mesh_v2_tunnel_hdr_t *)payload;
	const uint8_t *inner = payload + sizeof(mesh_v2_tunnel_hdr_t);
	size_t inner_space = h->payload_len - sizeof(mesh_v2_tunnel_hdr_t);

	if (t->channel_id == 0 || t->channel_id > MESH_V2_TUNNEL_CHANNEL_MAX ||
	    t->payload_len > inner_space ||
	    t->payload_len > MESH_V2_TUNNEL_INNER_MAX) {
		return;
	}

	uint8_t root_mac[6];
	local_mac(root_mac);
	if (!mac_is_zero(t->target_mac) && !mac_eq(t->target_mac, root_mac)) {
		ESP_LOGD(TAG, "tunnel frame for non-root target " MACSTR,
		         MAC2STR(t->target_mac));
		return;
	}

#if MESH_V2_DEBUG_DROP_EVERY > 0
	static uint32_t tunnel_drop_counter = 0;
	if (++tunnel_drop_counter % MESH_V2_DEBUG_DROP_EVERY == 0) {
		ESP_LOGW(TAG, "debug drop tunnel ch=%u seq=%lu",
		         (unsigned)t->channel_id, (unsigned long)t->seq);
		return;
	}
#endif

	bool deliver = false;
	bool send_nack = false;
	uint32_t ack_seq = 0;
	uint32_t missing_seq = 0;

	portENTER_CRITICAL(&s_lock);
	root_node_state_t *st = find_node_locked(t->origin_mac, true);
	if (st) {
		if (st->session_id != h->session_id) {
			reset_session_locked(st, h);
		}
		st->tunnel_seen = true;
		st->last_tunnel_ms = ms_now();
		st->last_v2_ms = st->last_tunnel_ms;
		tunnel_rx_channel_t *rx = &st->rx[t->channel_id];
		rx->last_ms = st->last_tunnel_ms;
		if (t->flags & MESH_V2_TUNNEL_FLAG_REPLAY) {
			rx->replay_count++;
		}
		if (t->seq > rx->highest_seen_seq) {
			rx->highest_seen_seq = t->seq;
		}

		if (t->seq == rx->expected_seq) {
			deliver = true;
			rx->expected_seq++;
			ack_seq = t->seq;
			if (rx->expected_seq <= rx->highest_seen_seq) {
				rx->gap_count++;
				rx->has_gap = true;
				missing_seq = rx->expected_seq;
				send_nack = true;
			}
		} else if (t->seq < rx->expected_seq) {
			ack_seq = rx->expected_seq - 1;
		} else {
			rx->gap_count++;
			rx->has_gap = true;
			missing_seq = rx->expected_seq;
			ack_seq = rx->expected_seq ? rx->expected_seq - 1 : 0;
			send_nack = true;
		}
	}
	portEXIT_CRITICAL(&s_lock);

	if (send_nack) {
		send_tunnel_nack(h->src_mac, h, t, missing_seq);
	} else {
		send_tunnel_ack(h->src_mac, h, t, ack_seq);
	}

	if (deliver) {
		deliver_tunnel_payload(t, inner);
	}
}

static void handle_reliable_legacy_v2(const mesh_addr_t *from, const mesh_v2_hdr_t *h,
                                      const uint8_t *payload)
{
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
		deliver_legacy_v2_payload(h, payload);
	}
}

esp_err_t mesh_v2_root_handle_rx(const mesh_addr_t *from, const void *pkt_buf, size_t pkt_len)
{
	const mesh_v2_hdr_t *h = NULL;
	const uint8_t *payload = NULL;

	if (!validate_packet(pkt_buf, pkt_len, &h, &payload)) {
		return ESP_ERR_INVALID_ARG;
	}

	if (h->type == MESH_V2_TYPE_HELLO) {
		handle_hello(from, h, payload);
		return ESP_OK;
	}

	if (h->type == MESH_V2_TYPE_TUNNEL_DATA) {
		handle_tunnel_data(h, payload);
		return ESP_OK;
	}

	if (h->type == MESH_V2_TYPE_TUNNEL_ACK) {
		handle_tunnel_ack(h, payload);
		return ESP_OK;
	}

	if (h->type == MESH_V2_TYPE_TUNNEL_LOST) {
		handle_tunnel_lost(h, payload);
		return ESP_OK;
	}

	if (h->type == MESH_V2_TYPE_TUNNEL_NACK) {
		ESP_LOGW(TAG, "root tunnel TX NACK from " MACSTR, MAC2STR(h->src_mac));
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

	handle_reliable_legacy_v2(from, h, payload);
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
		out->tunnel_seen = st->tunnel_seen;
		out->has_gap = st->has_gap;
		out->session_id = st->session_id;
		out->expected_seq = st->expected_seq;
		out->gap_count = st->gap_count;
		out->replay_count = st->replay_count;
		out->lost_count = st->lost_count;
		out->last_v2_ms = st->last_v2_ms;
		out->last_tunnel_ms = st->last_tunnel_ms;
		for (uint32_t ch = 1; ch <= MESH_V2_TUNNEL_CHANNEL_MAX; ch++) {
			const tunnel_rx_channel_t *rx = &st->rx[ch];
			out->gap_count += rx->gap_count;
			out->replay_count += rx->replay_count;
			out->lost_count += rx->lost_count;
			out->has_gap = out->has_gap || rx->has_gap;
			if (rx->last_ms > out->last_tunnel_ms) {
				out->last_tunnel_ms = rx->last_ms;
			}
		}
		if (out->last_tunnel_ms > out->last_v2_ms) {
			out->last_v2_ms = out->last_tunnel_ms;
		}
	}
	portEXIT_CRITICAL(&s_lock);

	return out->seen;
}

bool mesh_v2_root_tunnel_ready_for_mac(const uint8_t mac[6])
{
	bool ready = false;

	if (!mac) {
		return false;
	}

	portENTER_CRITICAL(&s_lock);
	root_node_state_t *st = find_node_locked(mac, false);
	ready = st && st->tunnel_seen && st->session_id != 0;
	portEXIT_CRITICAL(&s_lock);

	return ready;
}

esp_err_t mesh_v2_root_send_log_ctrl(const uint8_t mac[6], bool enable)
{
	if (!mac) {
		return ESP_ERR_INVALID_ARG;
	}

	uint32_t session_id = 0;
	uint32_t seq = 0;
	uint8_t root_mac[6];
	local_mac(root_mac);

	portENTER_CRITICAL(&s_lock);
	root_node_state_t *st = find_node_locked(mac, false);
	if (st && st->tunnel_seen && st->session_id != 0) {
		tunnel_tx_channel_t *tx = &st->tx[MESH_V2_TUNNEL_CHANNEL_CONTROL];
		session_id = st->session_id;
		seq = tx->next_seq++;
	}
	portEXIT_CRITICAL(&s_lock);

	if (session_id == 0 || seq == 0) {
		return ESP_ERR_INVALID_STATE;
	}

	uint8_t payload[MESH_V2_PAYLOAD_MAX];
	memset(payload, 0, sizeof(payload));

	mesh_v2_tunnel_hdr_t *t = (mesh_v2_tunnel_hdr_t *)payload;
	mesh_v2_tunnel_log_ctrl_payload_t ctrl = {
		.enable = enable ? 1 : 0,
	};

	t->channel_id = MESH_V2_TUNNEL_CHANNEL_CONTROL;
	t->flags = MESH_V2_TUNNEL_FLAG_E2E_ACK | MESH_V2_TUNNEL_FLAG_HOP_ACK;
	t->ttl = MESH_V2_TUNNEL_TTL_DEFAULT;
	t->fragment_count = 1;
	t->payload_len = sizeof(ctrl);
	t->fragment_index = 0;
	t->stream_id = MESH_V2_TUNNEL_CHANNEL_CONTROL;
	t->seq = seq;
	t->ack_seq = 0;
	t->sack_bitmap = 0;
	mac_copy(t->origin_mac, root_mac);
	mac_copy(t->target_mac, mac);
	memcpy(payload + sizeof(*t), &ctrl, sizeof(ctrl));

	return send_packet_to_mac(mac, MESH_V2_TYPE_TUNNEL_DATA, session_id, 0, 0,
	                          payload, sizeof(*t) + sizeof(ctrl));
}
