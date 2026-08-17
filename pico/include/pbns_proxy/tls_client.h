#ifndef PBNS_PROXY_TLS_CLIENT_H
#define PBNS_PROXY_TLS_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

typedef struct mbedtls_x509_crt mbedtls_x509_crt;

#define PBNS_TLS_SPKI_SHA256_SIZE 32U
#define PBNS_TLS_CERTIFICATE_DER_MAX 4096U
#define PBNS_TLS_VERSION_1_2 UINT16_C(0x0303)
#define PBNS_TLS_ECDHE_ECDSA_AES128_GCM_SHA256 UINT16_C(0xc02b)
#define PBNS_TLS_ALPN_PROTOCOL "pbns/1"

#define PBNS_TLS_VERIFY_EXPIRED (UINT32_C(1) << 0U)
#define PBNS_TLS_VERIFY_FUTURE (UINT32_C(1) << 1U)
#define PBNS_TLS_VERIFY_NOT_TRUSTED (UINT32_C(1) << 2U)
#define PBNS_TLS_VERIFY_CN_MISMATCH (UINT32_C(1) << 3U)

typedef struct pbns_tls_pin_verifier {
  uint8_t expected_spki[PBNS_TLS_SPKI_SHA256_SIZE];
  pbns_status status;
  bool matched;
  bool initialized;
} pbns_tls_pin_verifier;

pbns_status pbns_tls_certificate_spki_sha256(pbns_view certificate_der,
                                             pbns_buffer output,
                                             size_t *written);
pbns_status pbns_tls_verify_certificate(pbns_view certificate_der,
                                        uint32_t verification_flags,
                                        pbns_view expected_spki);
pbns_status pbns_tls_validate_profile(uint16_t protocol_version,
                                      uint16_t cipher_suite,
                                      const char *alpn_protocol);
pbns_status pbns_tls_pin_verifier_init(pbns_tls_pin_verifier *verifier,
                                       pbns_view expected_spki);
int pbns_tls_certificate_verify_callback(void *context,
                                         mbedtls_x509_crt *certificate,
                                         int certificate_depth,
                                         uint32_t *verification_flags);

#if defined(PBNS_PICO_FIRMWARE)
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ssl.h"
#include "pbns_proxy/byte_pump.h"

#ifndef PBNS_TLS_HEAP_WORDS
#define PBNS_TLS_HEAP_WORDS 16384U
#endif

typedef struct pbns_tls_client {
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config config;
  mbedtls_ctr_drbg_context random;
  mbedtls_entropy_context entropy;
  pbns_tls_pin_verifier pin_verifier;
  pbns_pump_endpoint encrypted;
#if defined(PBNS_TLS_REPLAY_OBSERVER)
  _Alignas(max_align_t) uint32_t heap[PBNS_TLS_HEAP_WORDS];
#else
  uint32_t heap[PBNS_TLS_HEAP_WORDS];
#endif
  pbns_status failure;
  bool initialized;
  bool ready;
} pbns_tls_client;

pbns_status pbns_tls_client_init(pbns_tls_client *client, pbns_view hostname,
                                 pbns_view expected_spki,
                                 pbns_pump_endpoint encrypted);
pbns_status pbns_tls_client_step(pbns_tls_client *client);
void pbns_tls_client_free(pbns_tls_client *client);
pbns_pump_endpoint pbns_tls_client_plaintext_endpoint(pbns_tls_client *client);
#endif

#endif
