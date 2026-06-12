#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_PKT_MAGIC			0xA5
#define MESH_PKT_VERSION		1
#define MESH_PKT_VERSION_V2		2

// Уже було
#define MESH_PKT_TYPE_TEXT		1

// Уже використовується твоїм mesh_time_sync.c
#define MESH_TIME_SYNC_TYPE_TIME	2

// Нове для веб-логів
#define MESH_LOG_TYPE_LINE		3
#define MESH_LOG_TYPE_NODEINFO		4
#define MESH_LOG_TYPE_CTRL		5

// Remote OTA v1 (root -> node, node -> root status)
#define MESH_OTA_TYPE_BEGIN		6
#define MESH_OTA_TYPE_DATA		7
#define MESH_OTA_TYPE_END		8
#define MESH_OTA_TYPE_ABORT		9
#define MESH_OTA_TYPE_STATUS		10

#define MESH_OTA_CHUNK_MAX		192
#define MESH_OTA_PROJECT_MAX		32
#define MESH_OTA_VERSION_MAX		32
#define MESH_OTA_STATUS_MSG_MAX		64
#define MESH_OTA_ABORT_MSG_MAX		48

#define MESH_OTA_OP_BEGIN		1
#define MESH_OTA_OP_DATA		2
#define MESH_OTA_OP_END		3
#define MESH_OTA_OP_ABORT		4

#define MESH_OTA_STATUS_OK		0
#define MESH_OTA_STATUS_ERROR		1
#define MESH_OTA_STATUS_BUSY		2

// Reliable mesh v2 (kept next to v1, does not replace packet types 1..10 yet)
#define MESH_V2_TYPE_HELLO		32
#define MESH_V2_TYPE_ACK		33
#define MESH_V2_TYPE_NACK		34
#define MESH_V2_TYPE_NODEINFO		35
#define MESH_V2_TYPE_LOG_LINE		36
#define MESH_V2_TYPE_LOST		37

#define MESH_V2_TYPE_TASK_SNAPSHOT	40
#define MESH_V2_TYPE_MEM_STATUS		41
#define MESH_V2_TYPE_LEGACY_TEXT	42
#define MESH_V2_TYPE_OTA_BEGIN		48
#define MESH_V2_TYPE_OTA_DATA		49
#define MESH_V2_TYPE_OTA_END		50
#define MESH_V2_TYPE_OTA_STATUS		51

#define MESH_V2_FLAG_REPLAY		0x01

#define MESH_V2_PACKET_MAX		224
#define MESH_V2_PAYLOAD_MAX		192
#define MESH_V2_TAG_MAX		16
#define MESH_V2_LOG_LINE_MAX		176
#define MESH_V2_REPLAY_RING_SIZE	32

typedef struct __attribute__((packed)) {
	uint8_t		magic;
	uint8_t		version;
	uint8_t		type;
	uint8_t		reserved;
	uint32_t	counter;
	uint8_t		src_mac[6];
} mesh_pkt_hdr_t;

// Твій старий текстовий пакет (залишаємо)
typedef struct __attribute__((packed)) {
	uint8_t		magic;
	uint8_t		version;
	uint8_t		type;
	uint8_t		reserved;
	uint32_t	counter;
	uint8_t		src_mac[6];
	char		payload[32];
} mesh_packet_t;

// Анонс "яка це нода" => tag
typedef struct __attribute__((packed)) {
	mesh_pkt_hdr_t	h;
	char		tag[16];		// MESH_TAG (обрізаємо якщо довше)
} mesh_nodeinfo_packet_t;

typedef struct __attribute__((packed)) {
	mesh_pkt_hdr_t	h;
	char		tag[16];		// MESH_TAG
	uint32_t	uptime_s;		// seconds since node boot
} mesh_nodeinfo_v2_packet_t;

// Одна строка лога
typedef struct __attribute__((packed)) {
	mesh_pkt_hdr_t	h;
	char		tag[16];		// MESH_TAG
	char		line[192];		// сама строка (з '\n' або без — root нормалізує)
} mesh_log_line_packet_t;

// Керування стрімом лога (root -> node)
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

#ifdef __cplusplus
}
#endif
