idf_component_register(SRCS "mesh_main.c"
                        "legacy_proto.c"
                        "uart_bridge.c"
                        "mesh_root_bcast.c"
                        "log_http_server.c"
                        "log_time_vprintf.c"
                        "mesh_time_sync.c"
                        "stack_monitor.c"
                        "time_sync.c"
                    PRIV_REQUIRES esp_wifi esp_netif esp_driver_gpio esp_driver_uart esp_http_server driver nvs_flash
                    INCLUDE_DIRS "." "include")
