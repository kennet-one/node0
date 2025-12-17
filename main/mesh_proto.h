#pragma once

#include <stdint.h>

#define MESH_PKT_MAGIC			0xA5
#define MESH_PKT_VERSION		1

#define MESH_PKT_TYPE_TEXT		1
#define MESH_PKT_TYPE_TIME		2	// <- синхронізація часу

typedef struct __attribute__((packed)) {
	uint8_t		magic;
	uint8_t		version;
	uint8_t		type;
	uint8_t		reserved;
	uint32_t	counter;
	uint8_t		src_mac[6];
	char		payload[32];
} mesh_packet_t;
