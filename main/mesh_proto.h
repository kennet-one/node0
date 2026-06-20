#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_PKT_MAGIC			0xA5
#define MESH_PKT_VERSION		1
#define MESH_PKT_VERSION_V2		2

// Legacy text packet.
#define MESH_PKT_TYPE_TEXT		1

// Mesh time sync packet.
#define MESH_TIME_SYNC_TYPE_TIME	2

// Web log stream v1 packets.
#define MESH_LOG_TYPE_LINE		3
#define MESH_LOG_TYPE_NODEINFO		4
#define MESH_LOG_TYPE_CTRL		5

// Remote OTA v1 (root -> node, node -> root status).
#define MESH_OTA_TYPE_BEGIN		6
#define MESH_OTA_TYPE_DATA		7
#define MESH_OTA_TYPE_END		8
#define MESH_OTA_TYPE_ABORT		9
#define MESH_OTA_TYPE_STATUS		10

// Manual remote reboot v1 (root -> node, node -> root status).
#define MESH_REBOOT_TYPE_REQUEST	11
#define MESH_REBOOT_TYPE_STATUS	12

#define MESH_OTA_CHUNK_MAX		192
#define MESH_OTA_PROJECT_MAX		32
#define MESH_OTA_VERSION_MAX		32
#define MESH_OTA_STATUS_MSG_MAX		64
#define MESH_OTA_ABORT_MSG_MAX		48
#define MESH_REBOOT_REASON_MAX		48
#define MESH_REBOOT_STATUS_MSG_MAX	64

#define MESH_OTA_OP_BEGIN		1
#define MESH_OTA_OP_DATA		2
#define MESH_OTA_OP_END		3
#define MESH_OTA_OP_ABORT		4

#define MESH_OTA_STATUS_OK		0
#define MESH_OTA_STATUS_ERROR		1
#define MESH_OTA_STATUS_BUSY		2

#define MESH_REBOOT_STATUS_OK		0
#define MESH_REBOOT_STATUS_ERROR	1
#define MESH_REBOOT_STATUS_BUSY		2

// Reliable mesh v2 (kept next to v1; packet types 1..10 stay intact).
#define MESH_V2_TYPE_HELLO		32
#define MESH_V2_TYPE_ACK		33
#define MESH_V2_TYPE_NACK		34
#define MESH_V2_TYPE_NODEINFO		35
#define MESH_V2_TYPE_LOG_LINE		36
#define MESH_V2_TYPE_LOST		37

#define MESH_V2_TYPE_TASK_SNAPSHOT	40
#define MESH_V2_TYPE_MEM_STATUS		41
#define MESH_V2_TYPE_LEGACY_TEXT	42
#define MESH_V2_TYPE_TOPOLOGY		43
#define MESH_V2_TYPE_PING		44
#define MESH_V2_TYPE_PONG		45
#define MESH_V2_TYPE_OTA_BEGIN		48
#define MESH_V2_TYPE_OTA_DATA		49
#define MESH_V2_TYPE_OTA_END		50
#define MESH_V2_TYPE_OTA_STATUS		51
#define MESH_V2_TYPE_TUNNEL_DATA	52
#define MESH_V2_TYPE_TUNNEL_ACK		53
#define MESH_V2_TYPE_TUNNEL_NACK	54
#define MESH_V2_TYPE_TUNNEL_LOST	55

#define MESH_V2_FLAG_REPLAY		0x01

#define MESH_V2_PACKET_MAX		224
#define MESH_V2_PAYLOAD_MAX		192
#define MESH_V2_TAG_MAX			16
#define MESH_V2_LOG_LINE_MAX		176
#define MESH_V2_REPLAY_RING_SIZE	32

#define MESH_V2_CAP_TUNNEL		0x00000001UL
#define MESH_V2_CAP_RELAY		0x00000002UL
#define MESH_V2_CAP_TOPOLOGY		0x00000004UL

#define MESH_V2_TUNNEL_CHANNEL_NODEINFO	1
#define MESH_V2_TUNNEL_CHANNEL_LOG	2
#define MESH_V2_TUNNEL_CHANNEL_CONTROL	3
#define MESH_V2_TUNNEL_CHANNEL_TASK	4
#define MESH_V2_TUNNEL_CHANNEL_MEMORY	5
#define MESH_V2_TUNNEL_CHANNEL_TOPOLOGY	6
#define MESH_V2_TUNNEL_CHANNEL_OTA	7
#define MESH_V2_TUNNEL_CHANNEL_MAX	7
#define MESH_V2_TUNNEL_REPLAY_RING_SIZE	8
#define MESH_V2_TUNNEL_INNER_MAX	156
#define MESH_V2_TUNNEL_LOG_LINE_MAX	128
#define MESH_V2_TASK_NAME_MAX		16
#define MESH_V2_TASK_SNAPSHOT_MAX_ENTRIES	4

#define MESH_V2_TUNNEL_FLAG_REPLAY	0x01
#define MESH_V2_TUNNEL_FLAG_E2E_ACK	0x02
#define MESH_V2_TUNNEL_FLAG_HOP_ACK	0x04
#define MESH_V2_TUNNEL_FLAG_FRAGMENT	0x08
#define MESH_V2_TUNNEL_TTL_DEFAULT	8
#define MESH_V2_TASK_SNAPSHOT_FLAG_LAST	0x01

typedef struct __attribute__((packed)) {
	uint8_t		magic;
	uint8_t		version;
	uint8_t		type;
	uint8_t		reserved;
	uint32_t	counter;
	uint8_t		src_mac[6];
} mesh_pkt_hdr_t;

// Legacy text payload kept for v1 compatibility.
typedef struct __attribute__((packed)) {
	uint8_t		magic;
	uint8_t		version;
	uint8_t		type;
	uint8_t		reserved;
	uint32_t	counter;
	uint8_t		src_mac[6];
	char		payload[32];
} mesh_packet_t;

// Node announcement: "which node is this" => tag.
typedef struct __attribute__((packed)) {
	mesh_pkt_hdr_t	h;
	char		tag[16];		// MESH_TAG, truncated if longer.
} mesh_nodeinfo_packet_t;

typedef struct __attribute__((packed)) {
	mesh_pkt_hdr_t	h;
	char		tag[16];		// MESH_TAG
	uint32_t	uptime_s;		// seconds since node boot
} mesh_nodeinfo_v2_packet_t;

// One log line.
typedef struct __attribute__((packed)) {
	mesh_pkt_hdr_t	h;
	char		tag[16];		// MESH_TAG
	char		line[192];		// Text line; root normalizes newline.
} mesh_log_line_packet_t;

// Log stream control (root -> node).
typedef struct __attribute__((packed)) {
	mesh_pkt_hdr_t	h;
	uint8_t		enable;			// 0/1
	uint8_t		rsv[3];
} mesh_log_ctrl_packet_t;

typedef struct __attribute__((packed)) {
	mesh_pkt_hdr_t	h;
	uint16_t	seq;
	uint16_t	chunk_size;
	uint32_t	image_size;
	char		project_name[MESH_OTA_PROJECT_MAX];
	char		version[MESH_OTA_VERSION_MAX];
} mesh_ota_begin_packet_t;

typedef struct __attribute__((packed)) {
	mesh_pkt_hdr_t	h;
	uint16_t	seq;
	uint16_t	len;
	uint32_t	offset;
	uint8_t		data[MESH_OTA_CHUNK_MAX];
} mesh_ota_data_packet_t;

typedef struct __attribute__((packed)) {
	mesh_pkt_hdr_t	h;
	uint16_t	seq;
	uint16_t	rsv;
	uint32_t	image_size;
} mesh_ota_end_packet_t;

typedef struct __attribute__((packed)) {
	mesh_pkt_hdr_t	h;
	uint16_t	seq;
	uint16_t	rsv;
	char		reason[MESH_OTA_ABORT_MSG_MAX];
} mesh_ota_abort_packet_t;

typedef struct __attribute__((packed)) {
	mesh_pkt_hdr_t	h;
	uint8_t		op;
	uint8_t		code;
	uint16_t	seq;
	uint32_t	offset;
	uint32_t	total;
	char		message[MESH_OTA_STATUS_MSG_MAX];
} mesh_ota_status_packet_t;

typedef struct __attribute__((packed)) {
	mesh_pkt_hdr_t	h;
	uint16_t	seq;
	uint16_t	delay_ms;
	char		reason[MESH_REBOOT_REASON_MAX];
} mesh_reboot_request_packet_t;

typedef struct __attribute__((packed)) {
	mesh_pkt_hdr_t	h;
	uint8_t		code;
	uint8_t		rsv;
	uint16_t	seq;
	char		message[MESH_REBOOT_STATUS_MSG_MAX];
} mesh_reboot_status_packet_t;

typedef struct __attribute__((packed)) {
	uint8_t		magic;
	uint8_t		version;
	uint8_t		type;
	uint8_t		flags;
	uint32_t	session_id;
	uint32_t	seq;
	uint32_t	ack_seq;
	uint16_t	payload_len;
	uint8_t		src_mac[6];
	uint16_t	crc16;
} mesh_v2_hdr_t;

typedef struct __attribute__((packed)) {
	mesh_v2_hdr_t	h;
	uint8_t		payload[MESH_V2_PAYLOAD_MAX];
} mesh_v2_packet_t;

typedef struct __attribute__((packed)) {
	char		tag[MESH_V2_TAG_MAX];
	uint32_t	uptime_s;
	uint16_t	mtu;
	uint16_t	ring_size;
	uint32_t	capabilities;
} mesh_v2_hello_payload_t;

typedef struct __attribute__((packed)) {
	char		tag[MESH_V2_TAG_MAX];
	uint32_t	uptime_s;
} mesh_v2_nodeinfo_payload_t;

typedef struct __attribute__((packed)) {
	char		tag[MESH_V2_TAG_MAX];
	char		line[MESH_V2_LOG_LINE_MAX];
} mesh_v2_log_line_payload_t;

typedef struct __attribute__((packed)) {
	uint32_t	missing_seq;
} mesh_v2_nack_payload_t;

typedef struct __attribute__((packed)) {
	uint32_t	missing_seq;
} mesh_v2_lost_payload_t;

typedef struct __attribute__((packed)) {
	uint8_t		channel_id;
	uint8_t		flags;
	uint8_t		ttl;
	uint8_t		fragment_count;
	uint16_t	payload_len;
	uint16_t	fragment_index;
	uint32_t	stream_id;
	uint32_t	seq;
	uint32_t	ack_seq;
	uint32_t	sack_bitmap;
	uint8_t		origin_mac[6];
	uint8_t		target_mac[6];
} mesh_v2_tunnel_hdr_t;

typedef struct __attribute__((packed)) {
	mesh_v2_tunnel_hdr_t t;
	uint8_t		payload[MESH_V2_TUNNEL_INNER_MAX];
} mesh_v2_tunnel_packet_t;

typedef struct __attribute__((packed)) {
	char		tag[MESH_V2_TAG_MAX];
	uint32_t	uptime_s;
} mesh_v2_tunnel_nodeinfo_payload_t;

typedef struct __attribute__((packed)) {
	char		tag[MESH_V2_TAG_MAX];
	char		line[MESH_V2_TUNNEL_LOG_LINE_MAX];
} mesh_v2_tunnel_log_payload_t;

typedef struct __attribute__((packed)) {
	uint8_t		enable;
	uint8_t		rsv[3];
} mesh_v2_tunnel_log_ctrl_payload_t;

typedef struct __attribute__((packed)) {
	uint32_t	request_id;
	uint8_t		detail;
	uint8_t		rsv[3];
} mesh_v2_task_request_payload_t;

typedef struct __attribute__((packed)) {
	char		name[MESH_V2_TASK_NAME_MAX];
	uint32_t	priority;
	uint32_t	free_words;
	int16_t		cpu_x10;
	uint16_t	rsv;
} mesh_v2_task_entry_t;

typedef struct __attribute__((packed)) {
	char		tag[MESH_V2_TAG_MAX];
	uint32_t	request_id;
	uint32_t	updated_ms;
	uint32_t	uptime_s;
	uint32_t	cpu_load_x10;
	uint16_t	slot_count;
	uint16_t	task_total;
	uint16_t	task_index;
	uint8_t		task_count;
	uint8_t		flags;
	uint8_t		cpu_valid;
	uint8_t		rsv[3];
	mesh_v2_task_entry_t tasks[MESH_V2_TASK_SNAPSHOT_MAX_ENTRIES];
} mesh_v2_task_snapshot_payload_t;

typedef struct __attribute__((packed)) {
	char		tag[MESH_V2_TAG_MAX];
	uint32_t	uptime_s;
	uint8_t		parent_mac[6];
	uint8_t		root_mac[6];
	uint16_t	layer;
	uint16_t	max_layer;
	int8_t		parent_rssi;
	uint8_t		child_count;
	uint8_t		flags;
	uint32_t	capabilities;
	uint32_t	gap_count;
	uint32_t	lost_count;
	uint32_t	replay_count;
	uint32_t	v1_ok_age_ms;
	uint32_t	v2_ack_age_ms;
	int32_t		last_send_err;
	uint8_t		recovery_phase;
	uint8_t		log_stream_enabled;
	uint16_t	diag_flags;
} mesh_v2_topology_payload_t;

typedef struct __attribute__((packed)) {
	uint8_t		channel_id;
	uint8_t		flags;
	uint16_t	rsv;
	uint32_t	seq;
	uint32_t	ack_seq;
	uint32_t	sack_bitmap;
	uint8_t		origin_mac[6];
	uint8_t		target_mac[6];
} mesh_v2_tunnel_ack_payload_t;

typedef struct __attribute__((packed)) {
	uint8_t		channel_id;
	uint8_t		rsv[3];
	uint32_t	missing_seq;
	uint8_t		origin_mac[6];
	uint8_t		target_mac[6];
} mesh_v2_tunnel_nack_payload_t;

typedef struct __attribute__((packed)) {
	uint8_t		channel_id;
	uint8_t		rsv[3];
	uint32_t	missing_seq;
	uint8_t		origin_mac[6];
	uint8_t		target_mac[6];
} mesh_v2_tunnel_lost_payload_t;

#ifdef __cplusplus
}
#endif
