#pragma once

/* Install the split (PSRAM/internal) mbedtls allocator. Must be called once
 * at the very top of app_main(), before any TLS/crypto use. */
void keemash_mbedtls_alloc_init(void);
