#include "heater_zone.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include "esp_timer.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs.h"

#define ANCHORS 16
#define FRESH_MS 30000U
typedef struct {
    uint32_t version, revision;
    uint8_t target[6], source[6];
    uint8_t enabled, reserved[3];
} binding_t;
typedef struct {
    bool used, anchor_valid;
    uint8_t mac[6];
    uint32_t session;
    int64_t boot_upper_ms;
    uint64_t updated_ms;
    uint8_t confirmations;
} anchor_t;
typedef struct {
    binding_t binding;
    anchor_t anchors[ANCHORS];
    uint8_t heater_mac[6];
    bool known, applied, sample_pending, invalid_pending, invalid_sent;
    uint32_t applied_session, config_id, config_root_session;
    uint32_t sample_session, generation;
    uint64_t epoch_ms, last_sample_ms;
    int32_t temperature;
    int32_t last_error;
    uint32_t sample_checks;
    int32_t sample_delta;
    uint8_t sample_reject;
} zone_state_t;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static zone_state_t s;
static SemaphoreHandle_t s_config_lock;
static TaskHandle_t s_task;

static uint64_t now_ms(void) { return (uint64_t)esp_timer_get_time() / 1000; }
static uint64_t wall_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}
static bool valid_mac(const uint8_t mac[6])
{
    static const uint8_t zero[6];
    return mac && !(mac[0] & 1) && memcmp(mac, zero, 6);
}
static bool parse_mac(const char *text, uint8_t out[6])
{
    if (strlen(text) != 12) return false;
    for (unsigned i = 0; i < 6; ++i) {
        unsigned value;
        if (!isxdigit((unsigned char)text[i*2]) || !isxdigit((unsigned char)text[i*2+1]) ||
            sscanf(text + i*2, "%2x", &value) != 1) return false;
        out[i] = value;
    }
    return valid_mac(out);
}
static unsigned long long mac_number(const uint8_t mac[6])
{
    unsigned long long value = 0;
    for (unsigned i = 0; i < 6; ++i) value = (value << 8) | mac[i];
    return value;
}

void heater_zone_node(const uint8_t mac[6], const char *tag, bool valid, uint32_t uptime)
{
    if (!mac) return;
    mesh_v2_root_stats_t stats = {0};
    (void)mesh_v2_root_stats_for_mac(mac, &stats);
    uint64_t now = now_ms();
    portENTER_CRITICAL(&s_lock);
    if (tag && strcmp(tag, "Kheater") == 0) {
        memcpy(s.heater_mac, mac, 6);
        s.known = true;
    }
    if (valid && stats.node_session_id && stats.route_up) {
        anchor_t *a = NULL;
        for (unsigned i = 0; i < ANCHORS; ++i)
            if (s.anchors[i].used && !memcmp(mac, s.anchors[i].mac, 6)) { a = &s.anchors[i]; break; }
        if (!a) for (unsigned i = 0; i < ANCHORS; ++i)
            if (!s.anchors[i].used) { a = &s.anchors[i]; break; }
        if (a) {
            int64_t upper = (int64_t)now - (int64_t)uptime * 1000;
            if (!a->used || a->session != stats.node_session_id) {
                *a = (anchor_t){ .used = true, .session = stats.node_session_id, .boot_upper_ms = upper };
                memcpy(a->mac, mac, 6);
            }
            if (a->updated_ms && now - a->updated_ms >= 4000 &&
                upper >= a->boot_upper_ms - 1000 && upper <= a->boot_upper_ms + 1000) {
                if (a->confirmations < 2) ++a->confirmations;
            } else if (upper < a->boot_upper_ms - 1000) a->confirmations = 0;
            /* Never move a boot-time anchor forward because a heartbeat was delayed. */
            if (upper < a->boot_upper_ms) a->boot_upper_ms = upper;
            a->anchor_valid = true;
            a->updated_ms = now;
        }
    }
    portEXIT_CRITICAL(&s_lock);
}

void heater_zone_sensor(const uint8_t mac[6], const mesh_v2_sensor_snapshot_payload_t *packet)
{
    if (!mac || !packet || packet->count > MESH_V2_SENSOR_MAX_ENTRIES) return;
    mesh_v2_root_stats_t stats = {0};
    (void)mesh_v2_root_stats_for_mac(mac, &stats);
    uint64_t now = now_ms(), wall = wall_ms();
    portENTER_CRITICAL(&s_lock);
    if (!s.binding.enabled || memcmp(mac, s.binding.source, 6)) {
        portEXIT_CRITICAL(&s_lock);
        return;
    }
    const anchor_t *a = NULL;
    for (unsigned i = 0; i < ANCHORS; ++i)
        if (s.anchors[i].used && !memcmp(mac, s.anchors[i].mac, 6)) { a = &s.anchors[i]; break; }
    bool trustworthy = a && a->anchor_valid && a->confirmations >= 2 && a->session == stats.node_session_id &&
        stats.route_up && stats.reliable_ready && stats.ack_age_ms < 15000 &&
        stats.rtt_ms <= 1000 && now - a->updated_ms < 30000 && wall >= 1700000000000ULL;
    s.sample_checks++;
    s.sample_reject = !a ? 1 : a->confirmations < 2 ? 2 : !trustworthy ? 3 : 0;
    int64_t sample_mono = 0;
    if (trustworthy) {
        /* Resolve the 32-bit sample uptime near the current uptime (wrap every 49 days). */
        int64_t current_uptime = (int64_t)now - a->boot_upper_ms;
        int32_t delta = (int32_t)(packet->sample_uptime_ms - (uint32_t)current_uptime);
        s.sample_delta = delta;
        sample_mono = (int64_t)now + delta - 5000; /* conservative clock/transport allowance */
        trustworthy = delta <= 1000 && delta > -(int32_t)(FRESH_MS - 5000);
        if (!trustworthy) s.sample_reject = 4;
    }
    for (uint8_t i = 0; i < packet->count; ++i) {
        const mesh_v2_sensor_entry_t *e = &packet->entries[i];
        if (e->metric_id != MESH_V2_SENSOR_METRIC_TEMPERATURE_C) continue;
        if (s.sample_session == stats.node_session_id && s.last_sample_ms &&
            (int32_t)(packet->generation - s.generation) <= 0) break;
        bool valid = trustworthy && (e->status & MESH_V2_SENSOR_STATUS_VALID) &&
            !(e->status & (MESH_V2_SENSOR_STATUS_STALE | MESH_V2_SENSOR_STATUS_ERROR)) &&
            e->scale10 >= -4 && e->scale10 <= 2;
        int64_t value = valid ? e->value : 0;
        if (valid) {
            for (int shift = e->scale10 + 2; shift > 0; --shift) value *= 10;
            for (int shift = e->scale10 + 2; shift < 0; ++shift) value /= 10;
        }
        valid = valid && value >= -4000 && value <= 8000;
        if (trustworthy && !valid) s.sample_reject = 5;
        s.sample_session = stats.node_session_id;
        s.generation = packet->generation;
        s.last_sample_ms = now;
        if (valid) {
            s.temperature = (int32_t)value;
            s.epoch_ms = wall - (uint64_t)((int64_t)now - sample_mono);
            s.sample_pending = true;
            s.invalid_pending = false;
            s.invalid_sent = false;
        } else {
            s.sample_pending = false;
            s.invalid_pending = true;
        }
        break;
    }
    portEXIT_CRITICAL(&s_lock);
}

bool heater_zone_command(const uint8_t target[6], const char *text, char *out,
                         size_t size, esp_err_t *error)
{
    if (!text || strncmp(text, "heater.source", 13)) return false;
    *error = ESP_ERR_INVALID_ARG;
    if (!s_config_lock || xSemaphoreTake(s_config_lock, pdMS_TO_TICKS(500)) != pdTRUE) {
        *error = ESP_ERR_INVALID_STATE;
        snprintf(out, size, "zone service unavailable");
        return true;
    }
    binding_t binding;
    bool known;
    portENTER_CRITICAL(&s_lock);
    binding = s.binding;
    known = (s.known && !memcmp(target, s.heater_mac, 6)) ||
        (binding.revision && !memcmp(target, binding.target, 6));
    portEXIT_CRITICAL(&s_lock);
    if (!known) goto done;
    if (!strcmp(text, "heater.source.debug?")) {
        uint64_t now = now_ms();
        portENTER_CRITICAL(&s_lock);
        const anchor_t *a = NULL;
        for (unsigned i = 0; i < ANCHORS; ++i)
            if (s.anchors[i].used && !memcmp(s.anchors[i].mac, s.binding.source, 6)) {
                a = &s.anchors[i]; break;
            }
        snprintf(out, size, "HZD checks=%lu reject=%u confirmations=%u anchor_age=%lu delta=%ld pending=%u err=%ld",
            (unsigned long)s.sample_checks, s.sample_reject, a ? a->confirmations : 0,
            (unsigned long)(a ? now - a->updated_ms : UINT32_MAX),
            (long)s.sample_delta, s.sample_pending, (long)s.last_error);
        portEXIT_CRITICAL(&s_lock);
        *error = ESP_OK;
        xSemaphoreGive(s_config_lock);
        return true;
    }
    if (!strcmp(text, "heater.source?")) { *error = ESP_OK; goto done; }
    binding_t next = binding;
    if (!strcmp(text, "heater.source:internal")) {
        next.enabled = 0;
        memset(next.source, 0, 6);
    } else if (!strncmp(text, "heater.source:zone:", 19) &&
               parse_mac(text + 19, next.source) && memcmp(target, next.source, 6)) {
        next.enabled = 1;
    } else goto done;
    next.version = 1;
    memcpy(next.target, target, 6);
    if (binding.revision && next.enabled == binding.enabled &&
        !memcmp(next.source, binding.source, 6) && !memcmp(next.target, binding.target, 6)) {
        *error = ESP_OK;
        goto done;
    }
    if (binding.revision == UINT32_MAX) { *error = ESP_ERR_INVALID_STATE; goto done; }
    next.revision = binding.revision + 1;
    nvs_handle_t handle;
    *error = nvs_open("heater_zone", NVS_READWRITE, &handle);
    if (*error != ESP_OK) goto done;
    *error = nvs_set_blob(handle, "binding", &next, sizeof(next));
    if (*error == ESP_OK) *error = nvs_commit(handle);
    nvs_close(handle);
    if (*error == ESP_OK) {
        portENTER_CRITICAL(&s_lock);
        s.binding = next;
        s.applied = s.sample_pending = false;
        s.invalid_pending = false;
        s.invalid_sent = false;
        s.last_sample_ms = 0;
        s.config_id = 0;
        portEXIT_CRITICAL(&s_lock);
        xTaskNotifyGive(s_task);
    }
done:
    if (*error == ESP_OK) {
        bool applied;
        int32_t last;
        portENTER_CRITICAL(&s_lock);
        binding = s.binding;
        applied = s.applied;
        last = s.last_error;
        portEXIT_CRITICAL(&s_lock);
        snprintf(out, size, "HZ1 saved=%u applied=%u rev=%08lx enabled=%u source=%012llx err=%ld",
            binding.revision != 0, applied, (unsigned long)binding.revision,
            binding.enabled, mac_number(binding.source), (long)last);
    } else snprintf(out, size, "%s", esp_err_to_name(*error));
    xSemaphoreGive(s_config_lock);
    return true;
}

void heater_zone_result(const uint8_t peer[6], uint32_t session, uint32_t id, uint8_t status)
{
    portENTER_CRITICAL(&s_lock);
    if (id && id == s.config_id && session == s.config_root_session &&
        !memcmp(peer, s.binding.target, 6)) {
        s.applied = status == MESH_V2_CONTROL_STATUS_OK;
        s.last_error = s.applied ? ESP_OK : ESP_FAIL;
        s.config_id = 0;
    }
    portEXIT_CRITICAL(&s_lock);
}

static void zone_task(void *arg)
{
    (void)arg;
    uint64_t last_config = 0;
    uint64_t last_source_request = 0;
    uint32_t last_revision = 0;
    for (;;) {
        (void)ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(500));
        binding_t b;
        bool applied, pending, invalid, invalid_sent;
        uint32_t node_session, source_session, generation;
        uint64_t epoch, last_sample;
        int32_t temperature;
        portENTER_CRITICAL(&s_lock);
        b = s.binding; applied = s.applied; node_session = s.applied_session;
        pending = s.sample_pending; invalid = s.invalid_pending;
        invalid_sent = s.invalid_sent;
        source_session = s.sample_session; generation = s.generation;
        epoch = s.epoch_ms; temperature = s.temperature; last_sample = s.last_sample_ms;
        portEXIT_CRITICAL(&s_lock);
        if (!b.revision) continue;
        mesh_v2_root_stats_t target = {0}, source = {0};
        (void)mesh_v2_root_stats_for_mac(b.target, &target);
        if (b.enabled) (void)mesh_v2_root_stats_for_mac(b.source, &source);
        uint64_t now = now_ms();
        if (target.node_session_id != node_session || !target.route_up || !target.reliable_ready) {
            applied = false;
            portENTER_CRITICAL(&s_lock);
            s.applied = false;
            if (target.node_session_id != node_session) {
                s.applied_session = target.node_session_id;
                s.config_id = 0;
                s.sample_pending = false;
                s.invalid_sent = false;
                pending = false;
                last_config = 0;
            }
            portEXIT_CRITICAL(&s_lock);
        }
        if (!target.route_up || !target.reliable_ready) continue;
        char command[128];
        if (!applied && (b.revision != last_revision || !last_config || now - last_config >= 5000)) {
            uint32_t id = mesh_v2_root_next_command_id();
            snprintf(command, sizeof(command), "HC:%08lx:%u:%012llx",
                (unsigned long)b.revision, b.enabled, mac_number(b.source));
            portENTER_CRITICAL(&s_lock);
            if (s.binding.revision == b.revision) {
                s.config_id = id;
                s.config_root_session = target.root_session_id;
            }
            portEXIT_CRITICAL(&s_lock);
            esp_err_t err = mesh_v2_root_send_command(b.target, id, command);
            portENTER_CRITICAL(&s_lock);
            s.last_error = err;
            portEXIT_CRITICAL(&s_lock);
            last_config = now; last_revision = b.revision;
            continue;
        }
        if (!applied || !b.enabled) continue;
        /* Existing typed sensor providers answer this read-only query with SENSOR.
         * Own the cadence here: an attached GUI must not be the heartbeat source. */
        if (source.route_up && source.reliable_ready &&
            (source.capabilities & MESH_V2_CAP_TYPED_SENSOR) &&
            (!last_source_request || now - last_source_request >= 5000)) {
            (void)mesh_v2_root_send_command(b.source,
                mesh_v2_root_next_command_id(), "temp_echo");
            last_source_request = now;
        }
        if (!source.route_up || !source.reliable_ready ||
            (last_sample && now - last_sample >= FRESH_MS)) invalid = true;
        if (invalid) {
            if (invalid_sent) continue;
            snprintf(command, sizeof(command), "HX:%08lx", (unsigned long)b.revision);
        } else if (pending) {
            uint64_t wall = wall_ms();
            if (wall < epoch || wall - epoch >= FRESH_MS) continue;
            snprintf(command, sizeof(command), "HT:%08lx:%08lx:%08lx:%llu:%ld",
                (unsigned long)b.revision, (unsigned long)source_session,
                (unsigned long)generation, (unsigned long long)epoch, (long)temperature);
        } else continue;
        esp_err_t err = mesh_v2_root_send_command(b.target, mesh_v2_root_next_command_id(), command);
        portENTER_CRITICAL(&s_lock);
        s.last_error = err;
        if (err == ESP_OK && s.binding.revision == b.revision && s.generation == generation) {
            s.sample_pending = false;
            s.invalid_pending = false;
            if (invalid) { s.last_sample_ms = 0; s.invalid_sent = true; }
        }
        portEXIT_CRITICAL(&s_lock);
        if (invalid) vTaskDelay(pdMS_TO_TICKS(4500));
    }
}

esp_err_t heater_zone_init(void)
{
    if (s_task) return ESP_OK;
    if (!s_config_lock) s_config_lock = xSemaphoreCreateMutex();
    if (!s_config_lock) return ESP_ERR_NO_MEM;
    binding_t loaded = {0};
    nvs_handle_t handle;
    if (nvs_open("heater_zone", NVS_READONLY, &handle) == ESP_OK) {
        size_t length = sizeof(loaded);
        esp_err_t err = nvs_get_blob(handle, "binding", &loaded, &length);
        nvs_close(handle);
        if (err == ESP_OK && length == sizeof(loaded) && loaded.version == 1 &&
            loaded.revision && loaded.enabled <= 1 && valid_mac(loaded.target) &&
            (!loaded.enabled || (valid_mac(loaded.source) && memcmp(loaded.target, loaded.source, 6)))) {
            portENTER_CRITICAL(&s_lock);
            s.binding = loaded;
            portEXIT_CRITICAL(&s_lock);
        }
    }
    if (xTaskCreate(zone_task, "heater_zone", 4096, NULL, 4, &s_task) != pdPASS) {
        s_task = NULL;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
