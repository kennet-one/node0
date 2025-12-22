#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_PKT_MAGIC			0xA5
#define MESH_PKT_VERSION		1

// Уже було
#define MESH_PKT_TYPE_TEXT		1

// Уже використовується твоїм mesh_time_sync.c
#define MESH_TIME_SYNC_TYPE_TIME	2

// Нове для веб-логів
#define MESH_LOG_TYPE_LINE		3
#define MESH_LOG_TYPE_NODEINFO		4
#define MESH_LOG_TYPE_CTRL		5

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

#ifdef __cplusplus
}
#endif
