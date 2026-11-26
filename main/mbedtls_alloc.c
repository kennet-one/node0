/*
 * Split mbedtls allocator for node0 (2026-02 TLS stability fix).
 *
 * Background: MBEDTLS_DYNAMIC_BUFFER (async wrapper) had a double-free bug in
 * IDF v6.0.1 (tlsf_free/block_merge_prev/block_next asserts in psa fail-path
 * and session cleanup). It is now disabled; mbedtls uses the classic path.
 *
 * This allocator is installed at the top of app_main() via
 * mbedtls_platform_set_calloc_free(). Before that point mbedtls falls back to
 * its compiled-in default (libc calloc in DEFAULT_MEM_ALLOC mode), which is the
 * exact behavior of the previously stable build.
 *
 * Split policy:
 *  - >= 8192 B (TLS in/out content buffers, session transforms) -> PSRAM,
 *    protecting internal heap headroom for WiFi/BT stacks and ISR needs;
 *  - < 8192 B (psa key slots, small crypto contexts, incl. WPA beacon decrypt
 *    running in the WiFi RX task) -> INTERNAL memory (PSRAM-free context safe).
 */

#include <stdint.h>
#include <stddef.h>
#include "esp_heap_caps.h"
#include "mbedtls/platform.h"

static void *keemash_mbedtls_calloc(size_t n, size_t size)
{
    if (n != 0 && size != 0 && n > (SIZE_MAX / size)) {
        return NULL;
    }
    const size_t bytes = n * size;
    if (bytes >= 8192) {
        return heap_caps_calloc(n, size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    }
    return heap_caps_calloc(n, size, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
}

static void keemash_mbedtls_free(void *ptr)
{
    heap_caps_free(ptr);
}

void keemash_mbedtls_alloc_init(void)
{
    /* Keep the platform hook alive (the linker would otherwise GC it) and
     * reroute all mbedtls allocations made after app_main start. */
    mbedtls_platform_set_calloc_free(keemash_mbedtls_calloc, keemash_mbedtls_free);
}
