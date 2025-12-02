#include "legacy_proto.h"
#include "esp_log.h"

#include <string.h>
#include <stdlib.h>   // atof

static const char *LEG_TAG = "legacy";

static void trim(char *s)
{
    if (!s) return;
    int len = strlen(s);
    // прибираємо пробіли/переноси з кінця
    while (len > 0) {
        char c = s[len - 1];
        if (c == ' ' || c == '\r' || c == '\n' || c == '\t') {
            s[len - 1] = '\0';
            len--;
        } else break;
    }
}

static bool starts_with(const char *s, const char *prefix)
{
    if (!s || !prefix) return false;
    size_t l = strlen(prefix);
    return strncmp(s, prefix, l) == 0;
}

bool legacy_is_sensor_value(const char *msg)
{
    if (!msg || !msg[0]) return false;
    if (starts_with(msg, "TDSB")) return true;
    if (starts_with(msg, "TDS"))  return true;
    if (starts_with(msg, "ttds")) return true;
    return false;
}

void legacy_handle_text(const char *msg)
{
    if (!msg) return;

    char buf[64];
    strncpy(buf, msg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    trim(buf);
    if (!buf[0]) return;

    // ---- Сенсорні значення (мінімальна логіка) ----
    if (starts_with(buf, "TDSB")) {
        float v = atof(buf + 4);
        ESP_LOGI(LEG_TAG, "[SENSOR] TDS broth ≈ %.1f ppm (%s)", v, buf);
        return;
    }

    if (starts_with(buf, "TDS")) {
        float v = atof(buf + 3);
        ESP_LOGI(LEG_TAG, "[SENSOR] TDS ≈ %.1f ppm (%s)", v, buf);
        return;
    }

    if (starts_with(buf, "ttds")) {
        float t = atof(buf + 4);
        ESP_LOGI(LEG_TAG, "[SENSOR] temp for TDS ≈ %.2f °C (%s)", t, buf);
        return;
    }

    // ---- Команди (поки тільки лог, без дій) ----
    if (!strcmp(buf, "readtds")   ||
        !strcmp(buf, "pm1")       ||
        !strcmp(buf, "pomp")      ||
        !strcmp(buf, "140")       ||
        !strcmp(buf, "141")       ||
        !strcmp(buf, "142")       ||
        !strcmp(buf, "143")       ||
        !strcmp(buf, "flow")      ||
        !strcmp(buf, "ion")       ||
        !strcmp(buf, "echo_turb") ||
        !strcmp(buf, "huOn"))
    {
        ESP_LOGI(LEG_TAG, "[CMD] legacy cmd \"%s\" (root поки тільки логить)", buf);
        return;
    }

    // ---- Все інше ----
    ESP_LOGW(LEG_TAG, "unknown legacy msg: \"%s\"", buf);
}
