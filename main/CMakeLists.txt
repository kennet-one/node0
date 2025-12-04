idf_component_register(SRCS "stack_monitor.c" "mesh_main.c"
                        "legacy_proto.c"
                        "stack_monitor.c"
                        "uart_bridge.c"
                    PRIV_REQUIRES esp_wifi esp_driver_gpio esp_driver_ledc driver nvs_flash
                    INCLUDE_DIRS "." "include")
