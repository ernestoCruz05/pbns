cmake_minimum_required(VERSION 3.25)
project(pbns VERSION 0.1.0 LANGUAGES C CXX)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Hosted PBNS build type" FORCE)
endif()

option(PBNS_WERROR "Treat project warnings as errors" ON)
set(PBNS_SANITIZE "" CACHE STRING "Sanitizers for hosted project targets")
option(PBNS_BUILD_FUZZERS "Build libFuzzer targets" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(PbnsWarnings)

enable_testing()
include(ExternalProject)

set(PBNS_COSE_ROOT "${CMAKE_CURRENT_BINARY_DIR}/cose-c")
set(PBNS_COSE_SOURCE "${PBNS_COSE_ROOT}/source")
set(PBNS_CN_CBOR_SOURCE "${PBNS_COSE_ROOT}/cn-cbor-source")
set(PBNS_COSE_INSTALL "${PBNS_COSE_ROOT}/install")
set(PBNS_COSE_SANITIZER_FLAGS "")
if(PBNS_SANITIZE STREQUAL "address,undefined")
    set(PBNS_COSE_SANITIZER_FLAGS
        "-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer")
elseif(PBNS_SANITIZE STREQUAL "thread")
    set(PBNS_COSE_SANITIZER_FLAGS "-fsanitize=thread -fno-omit-frame-pointer")
endif()
set(PBNS_COSE_EXTERNAL_ARGS
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5
    -DCMAKE_BUILD_TYPE=Debug
    -DCMAKE_INSTALL_PREFIX=${PBNS_COSE_INSTALL}
    -DCMAKE_INSTALL_LIBDIR=lib
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    "-DCMAKE_C_FLAGS=${PBNS_COSE_SANITIZER_FLAGS} -I${PBNS_COSE_INSTALL}/include"
    "-DCMAKE_CXX_FLAGS=${PBNS_COSE_SANITIZER_FLAGS} -I${PBNS_COSE_INSTALL}/include"
    "-DCMAKE_EXE_LINKER_FLAGS=${PBNS_COSE_SANITIZER_FLAGS}"
    "-DCMAKE_SHARED_LINKER_FLAGS=${PBNS_COSE_SANITIZER_FLAGS}"
)

set(PBNS_MBEDTLS_SOURCE
    "${CMAKE_CURRENT_SOURCE_DIR}/.deps/pico_sdk/lib/mbedtls"
    CACHE PATH "Pinned Mbed TLS source used by hosted Pico tests"
)
if(NOT EXISTS "${PBNS_MBEDTLS_SOURCE}/library/ssl_tls.c")
    message(FATAL_ERROR
        "Pinned Mbed TLS is missing; fetch the Pico SDK external dependency")
endif()
set(PBNS_MBEDTLS_ROOT "${CMAKE_CURRENT_BINARY_DIR}/mbedtls")
set(PBNS_MBEDTLS_BUILD "${PBNS_MBEDTLS_ROOT}/build")
set(PBNS_MBEDTLS_CONFIG
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/include/mbedtls_config.h")
set(PBNS_MBEDTLS_HOST_DEBUG_FLAGS
    "-ffile-prefix-map=${CMAKE_BINARY_DIR}=. -fdebug-prefix-map=${CMAKE_BINARY_DIR}=. -fmacro-prefix-map=${CMAKE_BINARY_DIR}=.")
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PBNS_MBEDTLS_HOST_ALIGNMENT_FLAG
        "-DMBEDTLS_MEMORY_ALIGN_MULTIPLE=8")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(PBNS_MBEDTLS_HOST_ALIGNMENT_FLAG
        "-DMBEDTLS_MEMORY_ALIGN_MULTIPLE=4")
else()
    message(FATAL_ERROR "Unsupported hosted pointer size for Mbed TLS")
endif()
ExternalProject_Add(pbns-mbedtls-external
    SOURCE_DIR "${PBNS_MBEDTLS_SOURCE}"
    DOWNLOAD_COMMAND ""
    UPDATE_COMMAND ""
    PATCH_COMMAND ""
    BINARY_DIR "${PBNS_MBEDTLS_BUILD}"
    INSTALL_COMMAND ""
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=Debug
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        "-DCMAKE_C_FLAGS=${PBNS_COSE_SANITIZER_FLAGS} ${PBNS_MBEDTLS_HOST_ALIGNMENT_FLAG} ${PBNS_MBEDTLS_HOST_DEBUG_FLAGS}"
        "-DCMAKE_EXE_LINKER_FLAGS=${PBNS_COSE_SANITIZER_FLAGS}"
        -DENABLE_PROGRAMS=OFF
        -DENABLE_TESTING=OFF
        -DMBEDTLS_FATAL_WARNINGS=OFF
        -DMBEDTLS_CONFIG_FILE=${PBNS_MBEDTLS_CONFIG}
    BUILD_BYPRODUCTS
        "${PBNS_MBEDTLS_BUILD}/library/libmbedcrypto.a"
        "${PBNS_MBEDTLS_BUILD}/library/libmbedx509.a"
        "${PBNS_MBEDTLS_BUILD}/library/libmbedtls.a"
)
ExternalProject_Add_StepDependencies(pbns-mbedtls-external configure
    "${PBNS_MBEDTLS_CONFIG}"
)
foreach(component IN ITEMS mbedcrypto mbedx509 mbedtls)
    add_library(pbns-${component}-host STATIC IMPORTED GLOBAL)
    set_target_properties(pbns-${component}-host PROPERTIES
        IMPORTED_LOCATION
            "${PBNS_MBEDTLS_BUILD}/library/lib${component}.a"
        INTERFACE_INCLUDE_DIRECTORIES "${PBNS_MBEDTLS_SOURCE}/include"
    )
    target_compile_definitions(pbns-${component}-host INTERFACE
        MBEDTLS_CONFIG_FILE="${PBNS_MBEDTLS_CONFIG}"
    )
    add_dependencies(pbns-${component}-host pbns-mbedtls-external)
endforeach()

set(PBNS_TLS_TRANSPORT_MBEDTLS_ROOT "${CMAKE_CURRENT_BINARY_DIR}/mbedtls-tls-transport")
set(PBNS_TLS_TRANSPORT_MBEDTLS_BUILD "${PBNS_TLS_TRANSPORT_MBEDTLS_ROOT}/build")
set(PBNS_TLS_TRANSPORT_MBEDTLS_CONFIG
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/hosted/mbedtls_tls_transport_config.h")
ExternalProject_Add(pbns-mbedtls-tls-transport-external
    SOURCE_DIR "${PBNS_MBEDTLS_SOURCE}"
    DOWNLOAD_COMMAND ""
    UPDATE_COMMAND ""
    PATCH_COMMAND ""
    BINARY_DIR "${PBNS_TLS_TRANSPORT_MBEDTLS_BUILD}"
    INSTALL_COMMAND ""
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=Debug
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        "-DCMAKE_C_FLAGS=${PBNS_COSE_SANITIZER_FLAGS} ${PBNS_MBEDTLS_HOST_ALIGNMENT_FLAG} ${PBNS_MBEDTLS_HOST_DEBUG_FLAGS}"
        "-DCMAKE_EXE_LINKER_FLAGS=${PBNS_COSE_SANITIZER_FLAGS}"
        -DENABLE_PROGRAMS=OFF
        -DENABLE_TESTING=OFF
        -DMBEDTLS_FATAL_WARNINGS=OFF
        -DMBEDTLS_CONFIG_FILE=${PBNS_TLS_TRANSPORT_MBEDTLS_CONFIG}
    BUILD_BYPRODUCTS
        "${PBNS_TLS_TRANSPORT_MBEDTLS_BUILD}/library/libmbedcrypto.a"
        "${PBNS_TLS_TRANSPORT_MBEDTLS_BUILD}/library/libmbedx509.a"
        "${PBNS_TLS_TRANSPORT_MBEDTLS_BUILD}/library/libmbedtls.a"
)
ExternalProject_Add_StepDependencies(pbns-mbedtls-tls-transport-external configure
    "${PBNS_TLS_TRANSPORT_MBEDTLS_CONFIG}")
foreach(component IN ITEMS mbedcrypto mbedx509 mbedtls)
    add_library(pbns-${component}-tls-transport-host STATIC IMPORTED GLOBAL)
    set_target_properties(pbns-${component}-tls-transport-host PROPERTIES
        IMPORTED_LOCATION
            "${PBNS_TLS_TRANSPORT_MBEDTLS_BUILD}/library/lib${component}.a"
        INTERFACE_INCLUDE_DIRECTORIES "${PBNS_MBEDTLS_SOURCE}/include"
    )
    target_compile_definitions(pbns-${component}-tls-transport-host INTERFACE
        MBEDTLS_CONFIG_FILE="${PBNS_TLS_TRANSPORT_MBEDTLS_CONFIG}"
    )
    add_dependencies(pbns-${component}-tls-transport-host
        pbns-mbedtls-tls-transport-external)
endforeach()

ExternalProject_Add(pbns-cn-cbor
    SOURCE_DIR "${PBNS_CN_CBOR_SOURCE}"
    DOWNLOAD_COMMAND
        "${CMAKE_COMMAND}"
        -DPBNS_CN_CBOR_SOURCE=${CMAKE_CURRENT_SOURCE_DIR}/vendor/cn-cbor
        -DPBNS_CN_CBOR_DESTINATION=${PBNS_CN_CBOR_SOURCE}
        -DPBNS_CN_CBOR_PATCH=${CMAKE_CURRENT_SOURCE_DIR}/patches/cn-cbor/0001-guard-zero-length-copy.patch
        -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/PrepareCnCbor.cmake"
    UPDATE_COMMAND ""
    PATCH_COMMAND ""
    BINARY_DIR "${PBNS_COSE_ROOT}/cn-cbor-build"
    INSTALL_DIR "${PBNS_COSE_INSTALL}"
    CMAKE_ARGS
        ${PBNS_COSE_EXTERNAL_ARGS}
        -DBUILD_SHARED_LIBS=OFF
        -DCN_CBOR_USE_CONTEXT=ON
        -DCN_CBOR_FATAL_WARNINGS=OFF
        -DCN_CBOR_COVERALLS=OFF
        -DCN_CBOR_BUILD_DOCS=OFF
        -DCN_CBOR_BUILD_TESTS=OFF
    BUILD_BYPRODUCTS "${PBNS_COSE_INSTALL}/lib/libcn-cbor.a"
)
ExternalProject_Add_StepDependencies(pbns-cn-cbor download
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/PrepareCnCbor.cmake"
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/cn-cbor/0001-guard-zero-length-copy.patch"
)
ExternalProject_Add(pbns-cose-c-external
    DEPENDS pbns-cn-cbor
    SOURCE_DIR "${PBNS_COSE_SOURCE}"
    DOWNLOAD_COMMAND
        "${CMAKE_COMMAND}"
        -DPBNS_COSE_SOURCE=${CMAKE_CURRENT_SOURCE_DIR}/vendor/COSE-C
        -DPBNS_COSE_DESTINATION=${PBNS_COSE_SOURCE}
        -DPBNS_COSE_PATCH1=${CMAKE_CURRENT_SOURCE_DIR}/patches/COSE-C/0001-openssl3-const-public-key.patch
        -DPBNS_COSE_PATCH2=${CMAKE_CURRENT_SOURCE_DIR}/patches/COSE-C/0002-implement-enveloped-content-getter.patch
        -DPBNS_COSE_PATCH3=${CMAKE_CURRENT_SOURCE_DIR}/patches/COSE-C/0003-fix-gcm-plaintext-length.patch
        -DPBNS_COSE_PATCH4=${CMAKE_CURRENT_SOURCE_DIR}/patches/COSE-C/0004-free-openssl-key-resources.patch
        -DPBNS_COSE_EXAMPLES=${CMAKE_CURRENT_SOURCE_DIR}/vendor/cose-examples
        -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/PrepareCoseC.cmake"
    UPDATE_COMMAND ""
    PATCH_COMMAND ""
    BINARY_DIR "${PBNS_COSE_ROOT}/cose-c-build"
    INSTALL_DIR "${PBNS_COSE_INSTALL}"
    CMAKE_ARGS
        ${PBNS_COSE_EXTERNAL_ARGS}
        -DCMAKE_PREFIX_PATH=${PBNS_COSE_INSTALL}
        -Dcn-cbor_DIR=${PBNS_COSE_INSTALL}/lib/cmake/cn-cbor
        -DBUILD_SHARED_LIBS=OFF
        -DCOSE_C_USE_CONTEXT=ON
        -DCOSE_C_USE_FIND_PACKAGE=ON
        -DCOSE_C_EXPORT_TARGETS=ON
        -DCOSE_C_FATAL_WARNINGS=OFF
        -DCOSE_C_COVERALLS=OFF
        -DCOSE_C_BUILD_DOCS=OFF
        -DCOSE_C_BUILD_DUMPER=OFF
        -DCOSE_C_BUILD_TESTS=ON
    BUILD_BYPRODUCTS "${PBNS_COSE_INSTALL}/lib/libcose-c.a"
)
ExternalProject_Add_StepDependencies(pbns-cose-c-external download
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/PrepareCoseC.cmake"
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/COSE-C/0001-openssl3-const-public-key.patch"
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/COSE-C/0002-implement-enveloped-content-getter.patch"
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/COSE-C/0003-fix-gcm-plaintext-length.patch"
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/COSE-C/0004-free-openssl-key-resources.patch"
)
add_custom_target(pbns-cose-upstream-tests
    COMMAND "${CMAKE_CTEST_COMMAND}"
        --test-dir "${PBNS_COSE_ROOT}/cose-c-build"
        --output-on-failure
        -R "^(aes-gcm|aes-wrap|ecdh-direct|ecdh-wrap|Memory-encrypt-gcm|Memory-ecdh|Memory-aes-kw)$"
    DEPENDS pbns-cose-c-external
    VERBATIM
)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(TSS2_MU REQUIRED IMPORTED_TARGET tss2-mu)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_package(Threads REQUIRED)
find_program(GO_EXECUTABLE go REQUIRED)
file(MAKE_DIRECTORY "${PBNS_COSE_INSTALL}/include")
add_library(pbns-cose-c-imported STATIC IMPORTED GLOBAL)
set_target_properties(pbns-cose-c-imported PROPERTIES
    IMPORTED_LOCATION "${PBNS_COSE_INSTALL}/lib/libcose-c.a"
)
add_library(pbns-cn-cbor-imported STATIC IMPORTED GLOBAL)
set_target_properties(pbns-cn-cbor-imported PROPERTIES
    IMPORTED_LOCATION "${PBNS_COSE_INSTALL}/lib/libcn-cbor.a"
)
add_dependencies(pbns-cose-c-imported pbns-cose-c-external)
add_dependencies(pbns-cn-cbor-imported pbns-cn-cbor)

add_library(pbns-cosebridge STATIC gateway/internal/cosebridge/bridge.cc)
target_include_directories(pbns-cosebridge
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/gateway/internal/cosebridge"
    PRIVATE "${PBNS_COSE_INSTALL}/include"
)
target_compile_definitions(pbns-cosebridge PRIVATE USE_CBOR_CONTEXT)
target_link_libraries(pbns-cosebridge PRIVATE
    pbns-cose-c-imported
    pbns-cn-cbor-imported
    OpenSSL::Crypto
    Threads::Threads
)
add_dependencies(pbns-cosebridge pbns-cose-c-external)
pbns_target_cxx_warnings(pbns-cosebridge)

add_test(
    NAME upstream-cose-c
    COMMAND "${CMAKE_CTEST_COMMAND}"
        --test-dir "${PBNS_COSE_ROOT}/cose-c-build"
        --output-on-failure
        -R "^(aes-gcm|aes-wrap|ecdh-direct|ecdh-wrap|Memory-encrypt-gcm|Memory-ecdh|Memory-aes-kw)$"
)

set(BUILD_QCBOR_TEST "APP" CACHE STRING "Build pinned QCBOR tests" FORCE)
set(QCBOR_DISABLE_PREFERRED_FLOAT ON CACHE BOOL "Disable unused QCBOR float reduction" FORCE)
set(CRYPTO_PROVIDER "OpenSSL" CACHE STRING "Pinned t_cose crypto provider" FORCE)
set(BUILD_TESTS ON CACHE BOOL "Build pinned t_cose tests" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "Do not build pinned t_cose examples" FORCE)
add_subdirectory(vendor/QCBOR vendor-build/QCBOR)
set(QCBOR_LIBRARY qcbor)
set(QCBOR_INCLUDE_DIR "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/vendor/QCBOR/inc>")
set(qcbor_FOUND TRUE)
set(PBNS_T_COSE_SOURCE "${CMAKE_CURRENT_BINARY_DIR}/t-cose/source")
set(PBNS_T_COSE_PATCHES
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/t_cose/0001-free-openssl-ec-temporaries.patch"
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/t_cose/0002-zero-transient-encryption-material.patch")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    ${PBNS_T_COSE_PATCHES}
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/PrepareTCose.cmake"
)
execute_process(
    COMMAND "${CMAKE_COMMAND}"
        -DPBNS_T_COSE_SOURCE=${CMAKE_CURRENT_SOURCE_DIR}/vendor/t_cose
        -DPBNS_T_COSE_DESTINATION=${PBNS_T_COSE_SOURCE}
        "-DPBNS_T_COSE_PATCHES=${PBNS_T_COSE_PATCHES}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/PrepareTCose.cmake"
    RESULT_VARIABLE PBNS_T_COSE_PREPARE_STATUS
)
if(NOT PBNS_T_COSE_PREPARE_STATUS EQUAL 0)
    message(FATAL_ERROR "Unable to prepare pinned t_cose source")
endif()
add_subdirectory("${PBNS_T_COSE_SOURCE}" vendor-build/t_cose)
target_compile_definitions(t_cose PRIVATE OPENSSL_SUPPRESS_DEPRECATED)
pbns_target_sanitizers(qcbor)
pbns_target_sanitizers(t_cose)
pbns_target_sanitizer_link(qcbortest)
pbns_target_sanitizer_link(t_cose_test)
add_library(QCBOR::qcbor ALIAS qcbor)
add_library(tcose::tcose ALIAS t_cose)
add_test(NAME upstream-qcbor COMMAND qcbortest)
add_test(NAME upstream-t-cose COMMAND t_cose_test)

add_library(pbns-core STATIC
    src/core/anti_rollback.c
    src/core/attestation.c
    src/core/attestation_run.c
    src/core/attestation_receipt.c
    src/core/attestation_upload.c
    src/core/attestation_wire.c
    src/core/boot_config.c
    src/core/broker.c
    src/core/identity.c
    src/core/launcher.c
    src/core/random.c
    src/core/recovery_assurance.c
    src/core/recovery_service_adapter.c
    src/core/recovery_live.c
    src/core/recovery_manifest.c
    src/core/recovery_request.c
    src/core/recovery_stream.c
    src/core/status.c
    src/core/crc32c.c
    src/core/cobs.c
    src/core/crypto.c
    src/core/frame.c
    src/core/record_reader.c
    src/core/stream.c
    src/core/object.c
    src/core/encrypt.c
    src/core/enrollment.c
    src/core/enrollment_wire.c
    src/core/enrollment_baseline.c
    src/core/controlled_baseline.c
    src/core/inventory.c
    src/core/measured_boot.c
    src/core/trusted_time.c
)
target_include_directories(pbns-core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(pbns-core SYSTEM PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/QCBOR/inc")
target_link_libraries(pbns-core PRIVATE QCBOR::qcbor)
pbns_target_warnings(pbns-core)
add_library(PBNS::core ALIAS pbns-core)

add_library(pbns-tcp-write-outcome STATIC
    pico/src/tcp_write_outcome.c
)
target_include_directories(pbns-tcp-write-outcome
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
)
target_link_libraries(pbns-tcp-write-outcome PUBLIC PBNS::core)
pbns_target_warnings(pbns-tcp-write-outcome)
add_library(PBNS::tcp-write-outcome ALIAS pbns-tcp-write-outcome)

add_library(pbns-raw-tunnel-diagnostic STATIC
    pico/src/raw_tunnel_diagnostic.c
)
target_include_directories(pbns-raw-tunnel-diagnostic
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
)
target_link_libraries(pbns-raw-tunnel-diagnostic PUBLIC
    PBNS::core
    PBNS::tcp-write-outcome
)
pbns_target_warnings(pbns-raw-tunnel-diagnostic)
add_library(PBNS::raw-tunnel-diagnostic ALIAS pbns-raw-tunnel-diagnostic)

add_library(pbns-byte-pump STATIC
    pico/src/byte_ring.c
    pico/src/byte_pump.c
    pico/src/tail_deadline.c
)
target_include_directories(pbns-byte-pump
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
)
target_link_libraries(pbns-byte-pump PUBLIC PBNS::core)
pbns_target_warnings(pbns-byte-pump)
add_library(PBNS::byte-pump ALIAS pbns-byte-pump)

add_library(pbns-usb-transport STATIC
    uefi/Library/PbnsUsbTransportLib/PbnsUsbTransportLib.c
)
target_include_directories(pbns-usb-transport
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsUsbTransportLib"
)
target_link_libraries(pbns-usb-transport PUBLIC PBNS::core)
pbns_target_warnings(pbns-usb-transport)
add_library(PBNS::usb-transport ALIAS pbns-usb-transport)

add_library(pbns-credentials STATIC pico/src/credentials.c)
target_include_directories(pbns-credentials
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
)
target_link_libraries(pbns-credentials PUBLIC PBNS::core QCBOR::qcbor)
pbns_target_warnings(pbns-credentials)
add_library(PBNS::credentials ALIAS pbns-credentials)

add_executable(pbns-pico-record-validate tools/pico_record_validate.c)
target_link_libraries(pbns-pico-record-validate PRIVATE PBNS::credentials)
pbns_target_warnings(pbns-pico-record-validate)
add_test(NAME pico-record-validate COMMAND pbns-pico-record-validate --self-test)

add_library(pbns-network STATIC pico/src/network.c)
target_include_directories(pbns-network
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
)
target_link_libraries(pbns-network PUBLIC PBNS::core)
pbns_target_warnings(pbns-network)
add_library(PBNS::network ALIAS pbns-network)

add_library(pbns-diagnostic STATIC pico/src/diagnostic.c)
target_include_directories(pbns-diagnostic
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
)
target_link_libraries(pbns-diagnostic PUBLIC PBNS::network)
pbns_target_warnings(pbns-diagnostic)
add_library(PBNS::diagnostic ALIAS pbns-diagnostic)

add_library(pbns-diagnostic-storage STATIC pico/src/diagnostic_storage.c)
target_include_directories(pbns-diagnostic-storage
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
)
target_link_libraries(pbns-diagnostic-storage PUBLIC PBNS::credentials)
pbns_target_warnings(pbns-diagnostic-storage)
add_library(PBNS::diagnostic-storage ALIAS pbns-diagnostic-storage)

add_executable(pbns-test-diagnostic pico/tests/test_diagnostic.c)
target_link_libraries(pbns-test-diagnostic PRIVATE
    PBNS::diagnostic
    PBNS::diagnostic-storage
)
pbns_target_warnings(pbns-test-diagnostic)
add_test(NAME diagnostic COMMAND pbns-test-diagnostic)

add_library(pbns-provision-gate STATIC pico/src/provision_gate.c)
target_include_directories(pbns-provision-gate
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
)
target_link_libraries(pbns-provision-gate PUBLIC PBNS::core)
pbns_target_warnings(pbns-provision-gate)
add_library(PBNS::provision-gate ALIAS pbns-provision-gate)

add_library(pbns-tls-client STATIC pico/src/tls_client.c)
target_include_directories(pbns-tls-client
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
)
target_link_libraries(pbns-tls-client
    PUBLIC PBNS::core
    PRIVATE pbns-mbedtls-host pbns-mbedx509-host pbns-mbedcrypto-host
)
pbns_target_warnings(pbns-tls-client)
add_library(PBNS::tls-client ALIAS pbns-tls-client)

add_library(pbns-tls-transport STATIC
    src/transport/tls_handshake_observer.c
    src/transport/tls_policy.c
    src/transport/tls_transport.c
)
target_include_directories(pbns-tls-transport PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_link_libraries(pbns-tls-transport PUBLIC
    pbns-mbedtls-tls-transport-host
    pbns-mbedx509-tls-transport-host
    pbns-mbedcrypto-tls-transport-host
)
pbns_target_warnings(pbns-tls-transport)
add_library(PBNS::tls-transport ALIAS pbns-tls-transport)

add_library(pbns-entropy-host STATIC pico/src/entropy.c)
target_include_directories(pbns-entropy-host
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/pico/tests/stubs"
)
target_link_libraries(pbns-entropy-host PRIVATE pbns-mbedcrypto-host)
pbns_target_warnings(pbns-entropy-host)
add_library(PBNS::entropy-host ALIAS pbns-entropy-host)

add_library(pbns-hosted-crypto STATIC src/crypto/openssl_crypto.c)
target_include_directories(pbns-hosted-crypto PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(pbns-hosted-crypto PRIVATE PBNS::core tcose::tcose OpenSSL::Crypto)
pbns_target_warnings(pbns-hosted-crypto)
add_library(PBNS::hosted-crypto ALIAS pbns-hosted-crypto)

add_library(pbns-cose-c INTERFACE)
add_library(COSEC::cose-c ALIAS pbns-cose-c)

add_executable(pbns-test-primitives tests/hosted/test_primitives.c)
target_include_directories(pbns-test-primitives PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(pbns-test-primitives PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-primitives)
add_test(NAME primitives COMMAND pbns-test-primitives)

add_executable(pbns-test-frame tests/hosted/test_frame.c)
target_link_libraries(pbns-test-frame PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-frame)
add_test(NAME frame COMMAND pbns-test-frame)

add_executable(pbns-test-record-reader tests/hosted/test_record_reader.c)
target_link_libraries(pbns-test-record-reader PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-record-reader)
add_test(NAME record-reader COMMAND pbns-test-record-reader)

add_executable(pbns-test-stream tests/hosted/test_stream.c)
target_link_libraries(pbns-test-stream PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-stream)
add_test(NAME stream COMMAND pbns-test-stream)

add_executable(pbns-test-broker tests/hosted/test_broker.c)
target_link_libraries(pbns-test-broker PRIVATE PBNS::core QCBOR::qcbor)
pbns_target_warnings(pbns-test-broker)
add_test(NAME broker COMMAND pbns-test-broker)

add_executable(pbns-test-tcp-write-outcome
    pico/tests/test_tcp_write_outcome.c)
target_include_directories(pbns-test-tcp-write-outcome PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
)
target_link_libraries(pbns-test-tcp-write-outcome PRIVATE
    PBNS::tcp-write-outcome)
pbns_target_warnings(pbns-test-tcp-write-outcome)
add_test(NAME tcp-write-outcome COMMAND pbns-test-tcp-write-outcome)

add_executable(pbns-test-raw-tunnel-diagnostic
    pico/tests/test_raw_tunnel_diagnostic.c)
target_include_directories(pbns-test-raw-tunnel-diagnostic PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
)
target_link_libraries(pbns-test-raw-tunnel-diagnostic PRIVATE
    PBNS::raw-tunnel-diagnostic
)
pbns_target_warnings(pbns-test-raw-tunnel-diagnostic)
add_test(NAME raw-tunnel-diagnostic COMMAND pbns-test-raw-tunnel-diagnostic)

add_library(pbns-pico-network-adapter-under-test OBJECT
    pico/src/pico_network.c
)
target_compile_definitions(pbns-pico-network-adapter-under-test PRIVATE
    PBNS_PICO_FIRMWARE=1
)
target_include_directories(pbns-pico-network-adapter-under-test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/tests/stubs/pico_network"
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_compile_options(pbns-pico-network-adapter-under-test PRIVATE
    -ffunction-sections
    -fdata-sections
)
pbns_target_warnings(pbns-pico-network-adapter-under-test)

add_executable(pbns-test-pico-network-adapter
    pico/tests/test_pico_network_adapter.c
    $<TARGET_OBJECTS:pbns-pico-network-adapter-under-test>
)
target_compile_definitions(pbns-test-pico-network-adapter PRIVATE
    PBNS_PICO_FIRMWARE=1
)
target_include_directories(pbns-test-pico-network-adapter PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/tests/stubs/pico_network"
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
)
target_link_libraries(pbns-test-pico-network-adapter PRIVATE
    PBNS::byte-pump
    PBNS::tcp-write-outcome
)
target_link_options(pbns-test-pico-network-adapter PRIVATE
    -Wl,--gc-sections
)
pbns_target_warnings(pbns-test-pico-network-adapter)
add_test(NAME pico-network-adapter COMMAND pbns-test-pico-network-adapter)

add_library(pbns-pico-network-diagnostic-adapter-under-test OBJECT
    pico/src/pico_network.c
)
target_compile_definitions(
    pbns-pico-network-diagnostic-adapter-under-test PRIVATE
    PBNS_PICO_FIRMWARE=1
    PBNS_PICO_NETWORK_TEST=1
    PBNS_RAW_TUNNEL_DIAGNOSTIC=1
)
target_include_directories(
    pbns-pico-network-diagnostic-adapter-under-test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/tests/stubs/pico_network"
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_compile_options(
    pbns-pico-network-diagnostic-adapter-under-test PRIVATE
    -ffunction-sections
    -fdata-sections
)
pbns_target_warnings(pbns-pico-network-diagnostic-adapter-under-test)

add_executable(pbns-test-pico-network-diagnostic-adapter
    pico/tests/test_pico_network_adapter.c
    $<TARGET_OBJECTS:pbns-pico-network-diagnostic-adapter-under-test>
)
target_compile_definitions(
    pbns-test-pico-network-diagnostic-adapter PRIVATE
    PBNS_PICO_FIRMWARE=1
    PBNS_PICO_NETWORK_TEST=1
    PBNS_RAW_TUNNEL_DIAGNOSTIC=1
)
target_include_directories(
    pbns-test-pico-network-diagnostic-adapter PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/tests/stubs/pico_network"
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
)
target_link_libraries(pbns-test-pico-network-diagnostic-adapter PRIVATE
    PBNS::byte-pump
    PBNS::raw-tunnel-diagnostic
    PBNS::tcp-write-outcome
)
target_link_options(pbns-test-pico-network-diagnostic-adapter PRIVATE
    -Wl,--gc-sections
)
pbns_target_warnings(pbns-test-pico-network-diagnostic-adapter)
add_test(NAME pico-network-diagnostic-adapter
    COMMAND pbns-test-pico-network-diagnostic-adapter)

add_executable(pbns-test-byte-pump tests/hosted/test_byte_pump.c)
target_link_libraries(pbns-test-byte-pump PRIVATE
    PBNS::byte-pump
    PBNS::tcp-write-outcome
)
pbns_target_warnings(pbns-test-byte-pump)
add_test(NAME byte-pump COMMAND pbns-test-byte-pump)

add_executable(pbns-test-usb-transport tests/hosted/test_usb_transport.c)
target_link_libraries(pbns-test-usb-transport PRIVATE PBNS::usb-transport)
pbns_target_warnings(pbns-test-usb-transport)
add_test(NAME usb-transport COMMAND pbns-test-usb-transport)

add_executable(pbns-test-boot-config tests/hosted/test_boot_config.c)
target_link_libraries(pbns-test-boot-config PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-boot-config)
add_test(NAME boot-config COMMAND pbns-test-boot-config)

add_executable(pbns-test-launcher-policy tests/hosted/test_launcher_policy.c)
target_link_libraries(pbns-test-launcher-policy PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-launcher-policy)
add_test(NAME launcher-policy COMMAND pbns-test-launcher-policy)

add_executable(pbns-test-uefi-clock-math
    tests/hosted/test_uefi_clock_math.c
    uefi/Library/PbnsUefiPlatformLib/PbnsUefiClockMath.c
)
target_include_directories(pbns-test-uefi-clock-math PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsUefiPlatformLib"
)
pbns_target_warnings(pbns-test-uefi-clock-math)
add_test(NAME uefi-clock-math COMMAND pbns-test-uefi-clock-math)

add_executable(pbns-test-identity
    tests/hosted/test_identity.c
    uefi/Library/PbnsIdentityLib/PbnsRandomPolicy.c)
target_include_directories(pbns-test-identity PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsIdentityLib)
target_link_libraries(pbns-test-identity PRIVATE PBNS::core QCBOR::qcbor OpenSSL::Crypto)
pbns_target_warnings(pbns-test-identity)
add_test(NAME identity COMMAND pbns-test-identity)

add_executable(pbns-test-identity-record
    tests/hosted/test_identity_record.c
    uefi/Library/PbnsIdentityLib/PbnsIdentityRecord.c)
target_include_directories(pbns-test-identity-record PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsIdentityLib)
target_link_libraries(pbns-test-identity-record PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-identity-record)
add_test(NAME identity-record COMMAND pbns-test-identity-record)

add_executable(pbns-test-software-identity
    tests/hosted/test_software_identity.c
    uefi/Library/PbnsIdentityLib/PbnsIdentityRecord.c
    uefi/Library/PbnsIdentityLib/PbnsSoftwareIdentity.c)
target_include_directories(pbns-test-software-identity PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsIdentityLib)
target_link_libraries(pbns-test-software-identity PRIVATE
    PBNS::core QCBOR::qcbor pbns-mbedcrypto-host OpenSSL::Crypto)
pbns_target_warnings(pbns-test-software-identity)
add_test(NAME software-identity COMMAND pbns-test-software-identity)

add_executable(pbns-test-tss2-tcti
    tests/hosted/test_tss2_tcti.c
    uefi/Library/PbnsTss2TctiLib/PbnsTss2Tcti.c)
target_include_directories(pbns-test-tss2-tcti PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsTss2TctiLib)
target_include_directories(pbns-test-tss2-tcti SYSTEM PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/.deps/tpm2-tss/include)
target_link_libraries(pbns-test-tss2-tcti PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-tss2-tcti)
add_test(NAME tss2-tcti COMMAND pbns-test-tss2-tcti)

add_executable(pbns-test-tpm-policy
    tests/hosted/test_tpm_policy.c
    src/core/tpm_profile.c)
target_link_libraries(pbns-test-tpm-policy PRIVATE
    PBNS::core PkgConfig::TSS2_MU OpenSSL::Crypto)
pbns_target_warnings(pbns-test-tpm-policy)
add_test(NAME tpm-policy COMMAND pbns-test-tpm-policy)

add_executable(pbns-test-tpm-storage
    tests/hosted/test_tpm_storage.c
    uefi/Library/PbnsTpmIdentityLib/PbnsTpmStorage.c)
target_include_directories(pbns-test-tpm-storage PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsTpmIdentityLib)
target_link_libraries(pbns-test-tpm-storage PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-tpm-storage)
add_test(NAME tpm-storage COMMAND pbns-test-tpm-storage)

add_executable(pbns-test-trusted-time
    tests/hosted/test_trusted_time.c)
target_link_libraries(pbns-test-trusted-time PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-trusted-time)
add_test(NAME trusted-time COMMAND pbns-test-trusted-time)

add_executable(pbns-test-controlled-baseline
    tests/hosted/test_controlled_baseline.c)
target_link_libraries(pbns-test-controlled-baseline PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-controlled-baseline)
add_test(NAME controlled-baseline COMMAND pbns-test-controlled-baseline)

add_executable(pbns-test-enrollment-baseline
    tests/hosted/test_enrollment_baseline.c)
target_link_libraries(pbns-test-enrollment-baseline PRIVATE PBNS::core QCBOR::qcbor)
pbns_target_warnings(pbns-test-enrollment-baseline)
add_test(NAME enrollment-baseline COMMAND pbns-test-enrollment-baseline
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/tcg-event-log")

add_executable(pbns-test-measured-boot-selection
    tests/hosted/test_measured_boot_selection.c)
target_link_libraries(pbns-test-measured-boot-selection PRIVATE
    PBNS::core OpenSSL::Crypto)
pbns_target_warnings(pbns-test-measured-boot-selection)
add_test(NAME measured-boot-selection COMMAND pbns-test-measured-boot-selection
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/tcg-event-log")

add_executable(pbns-test-measured-boot-adapter
    tests/hosted/test_measured_boot_adapter.c
    uefi/Library/PbnsMeasuredBootLib/PbnsMeasuredBootAdapterCore.c)
target_include_directories(pbns-test-measured-boot-adapter PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsMeasuredBootLib")
target_link_libraries(pbns-test-measured-boot-adapter PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-measured-boot-adapter)
add_test(NAME measured-boot-adapter COMMAND pbns-test-measured-boot-adapter)

add_executable(pbns-test-measured-boot-uefi-adapter
    tests/hosted/test_measured_boot_uefi_adapter.c
    uefi/Library/PbnsMeasuredBootLib/PbnsMeasuredBootAdapterCore.c
    uefi/Library/PbnsMeasuredBootLib/PbnsMeasuredBootUefiAdapter.c)
target_include_directories(pbns-test-measured-boot-uefi-adapter PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/hosted/uefi_stubs"
    "${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsMeasuredBootLib")
target_link_libraries(pbns-test-measured-boot-uefi-adapter PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-measured-boot-uefi-adapter)
add_test(NAME measured-boot-uefi-adapter
    COMMAND pbns-test-measured-boot-uefi-adapter)

add_executable(pbns-test-inventory tests/hosted/test_inventory.c)
target_link_libraries(pbns-test-inventory PRIVATE
    PBNS::core QCBOR::qcbor OpenSSL::Crypto)
pbns_target_warnings(pbns-test-inventory)
add_test(NAME inventory COMMAND pbns-test-inventory)

add_executable(pbns-test-attestation tests/hosted/test_attestation.c)
target_link_libraries(pbns-test-attestation PRIVATE
    PBNS::core PBNS::hosted-crypto QCBOR::qcbor OpenSSL::Crypto)
pbns_target_warnings(pbns-test-attestation)
add_test(NAME attestation COMMAND pbns-test-attestation)

add_executable(pbns-test-attestation-run
    tests/hosted/test_attestation_run.c)
target_link_libraries(pbns-test-attestation-run PRIVATE
    PBNS::core QCBOR::qcbor OpenSSL::Crypto)
pbns_target_warnings(pbns-test-attestation-run)
add_test(NAME attestation-run COMMAND pbns-test-attestation-run)

add_executable(pbns-test-uefi-attestation-adapter
    tests/hosted/test_uefi_attestation_adapter.c
    uefi/Library/PbnsAttestationClientLib/PbnsAttestationClientLib.c)
target_include_directories(pbns-test-uefi-attestation-adapter PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/hosted/uefi_shim"
    "${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsAttestationClientLib")
target_link_libraries(pbns-test-uefi-attestation-adapter PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-uefi-attestation-adapter)
add_test(NAME uefi-attestation-adapter COMMAND pbns-test-uefi-attestation-adapter)

add_executable(pbns-test-uefi-enrollment-adapter
    tests/hosted/test_uefi_enrollment_adapter.c
    uefi/Library/PbnsEnrollmentClientLib/PbnsEnrollmentClientLib.c)
target_include_directories(pbns-test-uefi-enrollment-adapter PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/hosted/uefi_shim"
    "${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsEnrollmentClientLib"
    "${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsTlsTransportLib")
target_link_libraries(pbns-test-uefi-enrollment-adapter PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-uefi-enrollment-adapter)
add_test(NAME uefi-enrollment-adapter COMMAND pbns-test-uefi-enrollment-adapter)

add_executable(pbns-test-attestation-upload
    tests/hosted/test_attestation_upload.c)
target_link_libraries(pbns-test-attestation-upload PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-attestation-upload)
add_test(NAME attestation-upload COMMAND pbns-test-attestation-upload)

add_executable(pbns-test-attestation-wire
    tests/hosted/test_attestation_wire.c)
target_link_libraries(pbns-test-attestation-wire PRIVATE
    PBNS::core QCBOR::qcbor)
pbns_target_warnings(pbns-test-attestation-wire)
add_test(NAME attestation-wire COMMAND pbns-test-attestation-wire)

add_executable(pbns-test-attestation-receipt
    tests/hosted/test_attestation_receipt.c)
target_link_libraries(pbns-test-attestation-receipt PRIVATE
    PBNS::core PBNS::hosted-crypto QCBOR::qcbor OpenSSL::Crypto)
pbns_target_warnings(pbns-test-attestation-receipt)
add_test(NAME attestation-receipt COMMAND pbns-test-attestation-receipt)
set_tests_properties(attestation-receipt PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(pbns-test-attestation-quote
    tests/hosted/test_attestation_quote.c
    src/core/tpm_profile.c
    uefi/Library/PbnsTpmIdentityLib/PbnsTpmQuoteCore.c)
target_include_directories(pbns-test-attestation-quote PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsTpmIdentityLib")
target_link_libraries(pbns-test-attestation-quote PRIVATE
    PBNS::core PkgConfig::TSS2_MU)
pbns_target_warnings(pbns-test-attestation-quote)
add_test(NAME attestation-quote COMMAND pbns-test-attestation-quote)

add_executable(pbns-test-inventory-adapter
    tests/hosted/test_inventory_adapter.c
    uefi/Library/PbnsInventoryLib/PbnsInventoryAdapterCore.c)
target_include_directories(pbns-test-inventory-adapter PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsInventoryLib")
target_link_libraries(pbns-test-inventory-adapter PRIVATE
    PBNS::core OpenSSL::Crypto)
pbns_target_warnings(pbns-test-inventory-adapter)
add_test(NAME inventory-adapter COMMAND pbns-test-inventory-adapter)

add_executable(pbns-test-inventory-uefi-adapter
    tests/hosted/test_inventory_uefi_adapter.c
    tests/hosted/uefi_stubs/stubs.c
    uefi/Library/PbnsInventoryLib/PbnsInventoryAdapterCore.c
    uefi/Library/PbnsInventoryLib/PbnsInventoryLib.c
    uefi/Library/PbnsInventoryLib/PbnsPci.c
    uefi/Library/PbnsInventoryLib/PbnsSecureBoot.c
    uefi/Library/PbnsInventoryLib/PbnsSmbios.c
    uefi/Library/PbnsInventoryLib/PbnsStorage.c)
target_include_directories(pbns-test-inventory-uefi-adapter PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/hosted/uefi_stubs"
    "${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsInventoryLib")
target_compile_definitions(pbns-test-inventory-uefi-adapter PRIVATE _GNU_SOURCE)
target_compile_options(pbns-test-inventory-uefi-adapter PRIVATE -fshort-wchar)
target_link_libraries(pbns-test-inventory-uefi-adapter PRIVATE
    PBNS::core pbns-mbedcrypto-host OpenSSL::Crypto)
pbns_target_warnings(pbns-test-inventory-uefi-adapter)
add_test(NAME inventory-uefi-adapter COMMAND pbns-test-inventory-uefi-adapter)

add_executable(pbns-test-tpm-ek-certificate
    tests/hosted/test_tpm_ek_certificate.c
    tests/hosted/uefi_stubs/stubs.c
    uefi/Library/PbnsTpmEkCertificateLib/PbnsTpmEkCertificateLib.c)
target_include_directories(pbns-test-tpm-ek-certificate PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/hosted/uefi_stubs"
    "${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsTpmEkCertificateLib")
target_link_libraries(pbns-test-tpm-ek-certificate PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-tpm-ek-certificate)
add_test(NAME tpm-ek-certificate COMMAND pbns-test-tpm-ek-certificate)

add_executable(pbns-test-enrollment tests/hosted/test_enrollment.c)
target_link_libraries(pbns-test-enrollment PRIVATE PBNS::core QCBOR::qcbor)
pbns_target_warnings(pbns-test-enrollment)
add_test(NAME enrollment COMMAND pbns-test-enrollment)

add_executable(pbns-test-credentials pico/tests/test_credentials.c)
target_link_libraries(pbns-test-credentials PRIVATE PBNS::credentials QCBOR::qcbor)
pbns_target_warnings(pbns-test-credentials)
add_test(NAME credentials COMMAND pbns-test-credentials)

set(PBNS_TLS_FIXTURE_DIR "${CMAKE_CURRENT_BINARY_DIR}/tls-test-pki")
set(PBNS_TLS_SPKI_FIXTURES
    "${PBNS_TLS_FIXTURE_DIR}/gateway-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/gateway-reissued-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/wrong-key-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/rsa-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/malformed-cert.der"
)
set(PBNS_TLS_POLICY_FIXTURES
    "${PBNS_TLS_FIXTURE_DIR}/gateway-reissued-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/ipv4-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/ipv6-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/wrong-san-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/cn-only-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/missing-ku-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/wrong-ku-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/missing-eku-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/wrong-eku-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/p384-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/ca-true-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/missing-basic-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/noncritical-basic-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/corrupt-signature-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/wrong-key-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/rsa-cert.der"
    "${PBNS_TLS_FIXTURE_DIR}/malformed-cert.der"
)
set(PBNS_TLS_FIXTURES ${PBNS_TLS_SPKI_FIXTURES} ${PBNS_TLS_POLICY_FIXTURES})
list(REMOVE_DUPLICATES PBNS_TLS_FIXTURES)
set(PBNS_TLS_SERVER_KEY_DER "${PBNS_TLS_FIXTURE_DIR}/gateway-key.der")
add_custom_command(
    OUTPUT ${PBNS_TLS_FIXTURES} ${PBNS_TLS_SERVER_KEY_DER}
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/integration/tls/make-test-pki.sh"
        "${PBNS_TLS_FIXTURE_DIR}"
    COMMAND openssl pkey -in "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/keys/tls-gateway-test-key.pem"
        -outform DER -out "${PBNS_TLS_SERVER_KEY_DER}"
    COMMAND chmod 600 "${PBNS_TLS_SERVER_KEY_DER}"
    DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/integration/tls/make-test-pki.sh"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/keys/tls-gateway-test-cert.pem"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/keys/tls-gateway-test-key.pem"
    VERBATIM
)
add_custom_target(pbns-tls-test-pki DEPENDS ${PBNS_TLS_FIXTURES} ${PBNS_TLS_SERVER_KEY_DER})

add_executable(pbns-test-spki-pin pico/tests/test_spki_pin.c)
target_link_libraries(pbns-test-spki-pin PRIVATE
    PBNS::tls-client
    pbns-mbedx509-host
)
add_dependencies(pbns-test-spki-pin pbns-tls-test-pki)
pbns_target_warnings(pbns-test-spki-pin)
add_test(NAME spki-pin COMMAND pbns-test-spki-pin ${PBNS_TLS_SPKI_FIXTURES})

add_executable(pbns-test-tls-policy tests/hosted/test_tls_policy.c)
target_link_libraries(pbns-test-tls-policy PRIVATE PBNS::tls-transport)
add_dependencies(pbns-test-tls-policy pbns-tls-test-pki)
pbns_target_warnings(pbns-test-tls-policy)
add_test(NAME tls-policy COMMAND pbns-test-tls-policy ${PBNS_TLS_POLICY_FIXTURES})

add_executable(pbns-test-tls-handshake-observer
    tests/hosted/test_tls_handshake_observer.c)
target_link_libraries(pbns-test-tls-handshake-observer PRIVATE PBNS::tls-transport)
pbns_target_warnings(pbns-test-tls-handshake-observer)
add_test(NAME tls-handshake-observer COMMAND pbns-test-tls-handshake-observer)

add_executable(pbns-test-tls-transport tests/hosted/test_tls_transport.c)
target_link_libraries(pbns-test-tls-transport PRIVATE PBNS::tls-transport PBNS::core QCBOR::qcbor)
add_dependencies(pbns-test-tls-transport pbns-tls-test-pki)
pbns_target_warnings(pbns-test-tls-transport)
add_test(NAME tls-transport COMMAND pbns-test-tls-transport
    "${PBNS_TLS_FIXTURE_DIR}/gateway-reissued-cert.der"
    "${PBNS_TLS_SERVER_KEY_DER}")

add_executable(pbns-test-tls-context-region
    tests/hosted/test_tls_context_region.c
    uefi/Library/PbnsTlsTransportLib/PbnsTlsTransportContextRegionCore.c)
target_include_directories(pbns-test-tls-context-region PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsTlsTransportLib")
target_link_libraries(pbns-test-tls-context-region PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-tls-context-region)
add_test(NAME tls-context-region COMMAND pbns-test-tls-context-region)

add_executable(pbns-test-mbedtls-host-config
    pico/tests/test_mbedtls_host_config.c)
target_link_libraries(pbns-test-mbedtls-host-config PRIVATE pbns-mbedtls-host)
pbns_target_warnings(pbns-test-mbedtls-host-config)
add_test(NAME mbedtls-host-config COMMAND pbns-test-mbedtls-host-config)

add_executable(pbns-test-tls-replay-observer
    pico/tests/test_tls_replay_observer.c
    pico/tests/tls_replay/observer.c
)
target_include_directories(pbns-test-tls-replay-observer PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/tests/include"
    "${PBNS_MBEDTLS_SOURCE}/include"
)
target_link_libraries(pbns-test-tls-replay-observer PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-tls-replay-observer)
add_test(NAME tls-replay-observer COMMAND pbns-test-tls-replay-observer)

add_executable(pbns-test-tls-replay-endpoint
    pico/tests/test_tls_replay_endpoint.c
    pico/tests/tls_replay/endpoint.c
    pico/tests/tls_replay/entropy.c
)
target_include_directories(pbns-test-tls-replay-endpoint PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/tests/include"
    "${PBNS_MBEDTLS_SOURCE}/include"
)
target_link_libraries(pbns-test-tls-replay-endpoint PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-tls-replay-endpoint)
add_test(NAME tls-replay-endpoint COMMAND pbns-test-tls-replay-endpoint)

add_library(pbns-tls-replay-client STATIC
    pico/src/tls_client.c
    pico/tests/tls_replay/observer.c
)
target_include_directories(pbns-tls-replay-client
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/pico/tests/include"
    PRIVATE "${PBNS_MBEDTLS_SOURCE}/include"
)
target_compile_definitions(pbns-tls-replay-client PUBLIC
    PBNS_PICO_FIRMWARE
    PBNS_TLS_REPLAY_OBSERVER
)
target_link_libraries(pbns-tls-replay-client
    PUBLIC PBNS::core
    PRIVATE pbns-mbedtls-host pbns-mbedx509-host pbns-mbedcrypto-host
)
pbns_target_warnings(pbns-tls-replay-client)

add_executable(pbns-pico-tls-replay
    pico/tests/tls_replay/main.c
    pico/tests/tls_replay/endpoint.c
    pico/tests/tls_replay/entropy.c
)
target_include_directories(pbns-pico-tls-replay PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/tests/include"
    "${PBNS_MBEDTLS_SOURCE}/include"
)
target_compile_definitions(pbns-pico-tls-replay PRIVATE PBNS_PICO_FIRMWARE)
target_link_libraries(pbns-pico-tls-replay PRIVATE pbns-tls-replay-client)
pbns_target_warnings(pbns-pico-tls-replay)
add_test(NAME tls-replay-integration
    COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/integration/tls/hosted_replay.py"
        self-test
        --executable "$<TARGET_FILE:pbns-pico-tls-replay>"
        --pin-file
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/keys/tls-gateway-test-spki.sha256"
)
set_tests_properties(tls-replay-integration PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    ENVIRONMENT "PYTHONPATH=${CMAKE_CURRENT_SOURCE_DIR}"
)

add_executable(pbns-test-reconnect pico/tests/test_reconnect.c)
target_link_libraries(pbns-test-reconnect PRIVATE PBNS::network)
pbns_target_warnings(pbns-test-reconnect)
add_test(NAME reconnect COMMAND pbns-test-reconnect)

add_executable(pbns-test-provision-gate pico/tests/test_provision_gate.c)
target_link_libraries(pbns-test-provision-gate PRIVATE PBNS::provision-gate)
pbns_target_warnings(pbns-test-provision-gate)
add_test(NAME provision-gate COMMAND pbns-test-provision-gate)

add_executable(pbns-test-entropy pico/tests/test_entropy.c)
target_include_directories(pbns-test-entropy PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/pico/tests/stubs"
)
target_link_libraries(pbns-test-entropy PRIVATE PBNS::entropy-host)
pbns_target_warnings(pbns-test-entropy)
add_test(NAME entropy COMMAND pbns-test-entropy)

add_executable(pbns-test-object tests/hosted/test_object.c)
target_link_libraries(pbns-test-object PRIVATE PBNS::core QCBOR::qcbor)
pbns_target_warnings(pbns-test-object)
add_test(NAME object COMMAND pbns-test-object)

add_executable(pbns-test-recovery-policy-wire
    tests/hosted/test_recovery_policy_wire.c
    uefi/Library/PbnsAntiRollbackLib/PbnsRecoveryPolicyWire.c)
target_include_directories(pbns-test-recovery-policy-wire PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsAntiRollbackLib)
target_link_libraries(pbns-test-recovery-policy-wire PRIVATE
    PBNS::core
    PkgConfig::TSS2_MU
    QCBOR::qcbor
)
pbns_target_warnings(pbns-test-recovery-policy-wire)
add_test(NAME recovery-policy-wire COMMAND pbns-test-recovery-policy-wire)
set_tests_properties(recovery-policy-wire PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(pbns-test-anti-rollback
    tests/hosted/test_anti_rollback.c)
target_link_libraries(pbns-test-anti-rollback PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-anti-rollback)
add_test(NAME anti-rollback COMMAND pbns-test-anti-rollback)

add_executable(pbns-test-recovery-assurance
    tests/hosted/test_recovery_assurance.c)
target_link_libraries(pbns-test-recovery-assurance PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-recovery-assurance)
add_test(NAME recovery-assurance COMMAND pbns-test-recovery-assurance)

add_executable(pbns-test-recovery-service-adapter
    tests/hosted/test_recovery_service_adapter.c)
target_include_directories(pbns-test-recovery-service-adapter PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/core")
target_link_libraries(pbns-test-recovery-service-adapter PRIVATE
    PBNS::core PBNS::hosted-crypto OpenSSL::Crypto)
pbns_target_warnings(pbns-test-recovery-service-adapter)
add_test(NAME recovery-service-adapter COMMAND pbns-test-recovery-service-adapter)

add_executable(pbns-test-recovery-client
    tests/hosted/test_recovery_client.c
    uefi/Library/PbnsRecoveryClientLib/PbnsRecoveryClientLib.c)
target_include_directories(pbns-test-recovery-client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/uefi/Library/PbnsRecoveryClientLib)
target_link_libraries(pbns-test-recovery-client PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-recovery-client)
add_test(NAME recovery-client COMMAND pbns-test-recovery-client)

add_executable(pbns-test-recovery-stream
    tests/hosted/test_recovery_stream.c)
target_link_libraries(pbns-test-recovery-stream PRIVATE
    PBNS::core
    OpenSSL::Crypto
)
pbns_target_warnings(pbns-test-recovery-stream)
add_test(NAME recovery-stream COMMAND pbns-test-recovery-stream)

add_executable(pbns-test-recovery-request
    tests/hosted/test_recovery_request.c)
target_link_libraries(pbns-test-recovery-request PRIVATE PBNS::core)
pbns_target_warnings(pbns-test-recovery-request)
add_test(NAME recovery-request COMMAND pbns-test-recovery-request)

add_executable(pbns-test-recovery-live tests/hosted/test_recovery_live.c)
target_link_libraries(pbns-test-recovery-live PRIVATE
    PBNS::core
    PBNS::hosted-crypto
    OpenSSL::Crypto
)
pbns_target_warnings(pbns-test-recovery-live)
add_test(NAME recovery-live COMMAND pbns-test-recovery-live)

add_executable(pbns-test-recovery-manifest
    tests/hosted/test_recovery_manifest.c)
target_link_libraries(pbns-test-recovery-manifest PRIVATE
    PBNS::hosted-crypto
    OpenSSL::Crypto
)
pbns_target_warnings(pbns-test-recovery-manifest)
add_test(NAME recovery-manifest COMMAND pbns-test-recovery-manifest)
set_tests_properties(recovery-manifest PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(pbns-test-sign1 tests/hosted/test_sign1.c)
target_link_libraries(pbns-test-sign1 PRIVATE PBNS::hosted-crypto OpenSSL::Crypto)
pbns_target_warnings(pbns-test-sign1)
add_test(NAME sign1 COMMAND pbns-test-sign1)
set_tests_properties(sign1 PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(pbns-test-encrypt tests/hosted/test_encrypt.c)
target_link_libraries(pbns-test-encrypt PRIVATE
    PBNS::hosted-crypto
    pbns-cosebridge
    QCBOR::qcbor
    OpenSSL::Crypto
    Threads::Threads
)
pbns_target_warnings(pbns-test-encrypt)
add_test(NAME encrypt COMMAND pbns-test-encrypt)
set_tests_properties(encrypt PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

add_custom_target(pbns-cose-vectors
    COMMAND "${CMAKE_CTEST_COMMAND}"
        --test-dir "${CMAKE_CURRENT_BINARY_DIR}"
        --output-on-failure
        -R "^encrypt$"
    COMMAND "${CMAKE_COMMAND}" -E env CGO_ENABLED=1
        "${GO_EXECUTABLE}" test ./internal/cosebridge -count=1
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/gateway"
    DEPENDS pbns-test-encrypt pbns-cose-c-external
    VERBATIM
)
