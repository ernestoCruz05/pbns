cmake_minimum_required(VERSION 3.25)

set(PICO_BOARD pico_w CACHE STRING "PBNS proxy board" FORCE)
include(pico_sdk_import.cmake)

project(pbns_proxy VERSION 0.1.0 LANGUAGES C CXX ASM)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PBNS_BUILD_NETWORK_DIAGNOSTIC
    "Build isolated PBNS Pico network diagnostic" OFF)
option(PBNS_BUILD_RAW_TUNNEL_DIAGNOSTIC
    "Build isolated PBNS raw tunnel boundary diagnostic" OFF)

set(PBNS_FLASH_TOTAL_SIZE_BYTES 2097152)
set(PBNS_STACK_SIZE_BYTES 4096)
math(EXPR PBNS_LINKABLE_FLASH_SIZE
    "${PBNS_FLASH_TOTAL_SIZE_BYTES} - 2 * 4096")
set(PICO_FLASH_SIZE_BYTES "${PBNS_FLASH_TOTAL_SIZE_BYTES}"
    CACHE STRING "Physical flash size including PBNS credential sectors" FORCE)
set(PICO_MBEDTLS_CONFIG_FILE
    "${CMAKE_CURRENT_LIST_DIR}/include/mbedtls_config.h")
pico_sdk_init()

set(PBNS_ROOT "${CMAKE_CURRENT_LIST_DIR}/..")

set(PBNS_PICO_WARNING_OPTIONS
    -g
    -Og
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
    -Wshadow
    -Wvla
    -Wcast-qual
    -Wpointer-arith
    -Wmissing-prototypes
    -Wstrict-prototypes
    -Wdouble-promotion
    -Wwrite-strings
    -Werror
)

function(pbns_pico_warnings target)
    target_compile_options(${target} PRIVATE ${PBNS_PICO_WARNING_OPTIONS})
endfunction()

add_library(pbns-pico-qcbor STATIC
    "${PBNS_ROOT}/vendor/QCBOR/src/UsefulBuf.c"
    "${PBNS_ROOT}/vendor/QCBOR/src/ieee754.c"
    "${PBNS_ROOT}/vendor/QCBOR/src/qcbor_decode.c"
    "${PBNS_ROOT}/vendor/QCBOR/src/qcbor_encode.c"
    "${PBNS_ROOT}/vendor/QCBOR/src/qcbor_err_to_str.c"
)
target_include_directories(pbns-pico-qcbor PUBLIC
    "${PBNS_ROOT}/vendor/QCBOR/inc"
)
target_compile_definitions(pbns-pico-qcbor PUBLIC QCBOR_DISABLE_PREFERRED_FLOAT)
target_compile_options(pbns-pico-qcbor PRIVATE -fstack-usage)

add_library(pbns-pico-portable STATIC
    "${PBNS_ROOT}/src/core/crc32c.c"
    src/byte_ring.c
    src/byte_pump.c
    src/credentials.c
    src/diagnostic.c
    src/diagnostic_storage.c
    src/network.c
    src/provision_gate.c
    src/raw_tunnel_diagnostic.c
    src/tail_deadline.c
    src/tcp_write_outcome.c
)
target_include_directories(pbns-pico-portable PUBLIC
    "${PBNS_ROOT}/include"
    "${CMAKE_CURRENT_LIST_DIR}/include"
)
target_link_libraries(pbns-pico-portable PUBLIC pbns-pico-qcbor)
target_compile_definitions(pbns-pico-portable PRIVATE
    PBNS_CREDENTIALS_STATIC_WORKSPACE
)
target_compile_options(pbns-pico-portable PRIVATE -fstack-usage)
pbns_pico_warnings(pbns-pico-portable)

add_executable(pbns-proxy
    src/main.c
    src/pico_network.c
    src/usb_descriptors.c
)
target_include_directories(pbns-proxy PRIVATE
    "${PBNS_ROOT}/include"
    "${CMAKE_CURRENT_LIST_DIR}/include"
)
target_compile_definitions(pbns-proxy PRIVATE
    PBNS_FLASH_TOTAL_SIZE_BYTES=${PBNS_FLASH_TOTAL_SIZE_BYTES}
    PBNS_PICO_FIRMWARE
    PICO_STACK_SIZE=${PBNS_STACK_SIZE_BYTES}
)
target_compile_options(pbns-proxy PRIVATE -fstack-usage)
target_link_libraries(pbns-proxy PRIVATE
    pbns-pico-portable
    hardware_flash
    hardware_watchdog
    pico_cyw43_arch_lwip_threadsafe_background
    pico_flash
    pico_mbedtls_crypto
    pico_mbedtls_headers
    pico_rand
    pico_stdlib
    pico_unique_id
    tinyusb_board
    tinyusb_device
)
set_source_files_properties(
    src/diagnostic_main.c
    src/diagnostic_usb_descriptors.c
    src/entropy.c
    src/main.c
    src/pico_network.c
    src/pico_tls_diagnostic_baseline.c
    src/raw_tunnel_diagnostic_main.c
    src/raw_tunnel_diagnostic_usb_descriptors.c
    src/tls_client.c
    src/usb_descriptors.c
    PROPERTIES COMPILE_OPTIONS "${PBNS_PICO_WARNING_OPTIONS}"
)
set(PBNS_LINKER_DIR "${CMAKE_CURRENT_BINARY_DIR}/pbns-linker")
file(MAKE_DIRECTORY "${PBNS_LINKER_DIR}")
configure_file(
    linker/pico_flash_region.ld.in
    "${PBNS_LINKER_DIR}/pico_flash_region.ld"
    @ONLY
)
pico_add_linker_script_override_path(
    pbns-proxy
    "${PBNS_LINKER_DIR}"
    FILES pico_flash_region.ld
)
pico_enable_stdio_uart(pbns-proxy 0)
pico_enable_stdio_usb(pbns-proxy 0)
pico_add_extra_outputs(pbns-proxy)

if(PBNS_BUILD_RAW_TUNNEL_DIAGNOSTIC)
    add_executable(pbns-raw-tunnel-diagnostic
        src/pico_network.c
        src/raw_tunnel_diagnostic_main.c
        src/raw_tunnel_diagnostic_usb_descriptors.c
    )
    target_include_directories(pbns-raw-tunnel-diagnostic PRIVATE
        "${PBNS_ROOT}/include"
        "${CMAKE_CURRENT_LIST_DIR}/include"
    )
    target_compile_definitions(pbns-raw-tunnel-diagnostic PRIVATE
        PBNS_FLASH_TOTAL_SIZE_BYTES=${PBNS_FLASH_TOTAL_SIZE_BYTES}
        PBNS_PICO_FIRMWARE
        PBNS_RAW_TUNNEL_DIAGNOSTIC
        PICO_STACK_SIZE=${PBNS_STACK_SIZE_BYTES}
    )
    target_compile_options(pbns-raw-tunnel-diagnostic PRIVATE -fstack-usage)
    target_link_libraries(pbns-raw-tunnel-diagnostic PRIVATE
        pbns-pico-portable
        hardware_watchdog
        pico_cyw43_arch_lwip_threadsafe_background
        pico_rand
        pico_stdlib
        pico_unique_id
        tinyusb_board
        tinyusb_device
    )
    pico_add_linker_script_override_path(
        pbns-raw-tunnel-diagnostic
        "${PBNS_LINKER_DIR}"
        FILES pico_flash_region.ld
    )
    pico_enable_stdio_uart(pbns-raw-tunnel-diagnostic 0)
    pico_enable_stdio_usb(pbns-raw-tunnel-diagnostic 0)
    pico_add_extra_outputs(pbns-raw-tunnel-diagnostic)
endif()

if(PBNS_BUILD_NETWORK_DIAGNOSTIC)
    add_executable(pbns-proxy-diagnostic
        src/diagnostic_main.c
        src/diagnostic_usb_descriptors.c
        src/entropy.c
        src/pico_tls_diagnostic_baseline.c
        src/tls_client.c
    )
    target_include_directories(pbns-proxy-diagnostic PRIVATE
        "${PBNS_ROOT}/include"
        "${CMAKE_CURRENT_LIST_DIR}/include"
    )
    target_compile_definitions(pbns-proxy-diagnostic PRIVATE
        PBNS_FLASH_TOTAL_SIZE_BYTES=${PBNS_FLASH_TOTAL_SIZE_BYTES}
        PBNS_NETWORK_DIAGNOSTIC
        PBNS_PICO_FIRMWARE
        PICO_STACK_SIZE=${PBNS_STACK_SIZE_BYTES}
    )
    target_compile_options(pbns-proxy-diagnostic PRIVATE -fstack-usage)
    target_link_libraries(pbns-proxy-diagnostic PRIVATE
        pbns-pico-portable
        hardware_watchdog
        pico_cyw43_arch_lwip_threadsafe_background
        pico_mbedtls_crypto
        pico_mbedtls_headers
        pico_mbedtls_tls
        pico_mbedtls_x509
        pico_rand
        pico_stdlib
        pico_unique_id
        tinyusb_board
        tinyusb_device
    )
    pico_add_linker_script_override_path(
        pbns-proxy-diagnostic
        "${PBNS_LINKER_DIR}"
        FILES pico_flash_region.ld
    )
    pico_enable_stdio_uart(pbns-proxy-diagnostic 0)
    pico_enable_stdio_usb(pbns-proxy-diagnostic 0)
    pico_add_extra_outputs(pbns-proxy-diagnostic)
endif()
