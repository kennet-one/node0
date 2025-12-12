#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// Ініціалізація перехоплення логів (ставить свій vprintf-хук)
esp_err_t log_http_server_init(void);

// Старт HTTP-сервера (можна викликати після отримання IP)
esp_err_t log_http_server_start(void);

#ifdef __cplusplus
}
#endif
