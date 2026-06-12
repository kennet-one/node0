set(NODE0_HTTPS_CERT "certs/node0_https_servercert.pem")
set(NODE0_HTTPS_KEY "certs/node0_https_prvtkey.pem")

if(NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/${NODE0_HTTPS_CERT}" OR
   NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/${NODE0_HTTPS_KEY}")
    message(FATAL_ERROR "Missing node0 HTTPS cert/key in main/certs. Generate node0_https_servercert.pem and node0_https_prvtkey.pem before building.")
endif()

idf_component_register(SRCS "mesh_main.c"
                        "legacy_proto.c"
                        "uart_bridge.c"
                        "mesh_root_bcast.c"
                        "mesh_v2_link.c"
                        "log_http_server.c"
                        "log_time_vprintf.c"
                        "mesh_time_sync.c"
                        "stack_monitor.c"
                        "time_sync.c"
                    PRIV_REQUIRES esp_wifi esp_netif esp_driver_gpio esp_driver_uart esp_http_server esp_https_server driver nvs_flash heap app_update esp_app_format spi_flash bootloader_support
                    INCLUDE_DIRS "." "include"
                    EMBED_TXTFILES "${NODE0_HTTPS_CERT}"
                                   "${NODE0_HTTPS_KEY}")
