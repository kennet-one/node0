idf_component_register(SRCS "time_sync.c" "log_http_server.c" "stack_monitor.c" "mesh_main.c"
                        "legacy_proto.c"
                        "stack_monitor.c"
                        "uart_bridge.c"
                        "mesh_root_bcast.c"
                        "log_http_server.c"
                        "time_sync.c"
                        "log_time_vprintf.c"
                        "mesh_time_sync.c"
                    PRIV_REQUIRES esp_wifi esp_driver_gpio esp_http_server driver nvs_flash
                    INCLUDE_DIRS "." "include")
