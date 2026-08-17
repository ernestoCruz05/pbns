#ifndef PBNS_TLS_POLICY_H
#define PBNS_TLS_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef PBNS_EDK2
#include <CrtLibSupport.h>
#endif
#include <mbedtls/x509_crt.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_TLS_SPKI_SHA256_SIZE 32U
#define PBNS_TLS_SERVER_NAME_MAX 255U
#define PBNS_TLS_CERTIFICATE_DER_MAX 4096U
#define PBNS_TLS_VERSION_1_2 ((uint16_t)0x0303U)
#define PBNS_TLS_ECDHE_ECDSA_AES128_GCM_SHA256 ((uint16_t)0xc02bU)
#define PBNS_TLS_ALPN_PROTOCOL "pbns/1"

#define PBNS_TLS_VERIFY_EXPIRED ((uint32_t)1U << 0U)
#define PBNS_TLS_VERIFY_FUTURE ((uint32_t)1U << 1U)
#define PBNS_TLS_VERIFY_NOT_TRUSTED ((uint32_t)1U << 2U)

typedef struct pbns_tls_certificate_policy {
  uint8_t expected_server_name[PBNS_TLS_SERVER_NAME_MAX];
  size_t expected_server_name_len;
  uint8_t pinned_leaf_spki_sha256[PBNS_TLS_SPKI_SHA256_SIZE];
  uint32_t mbedtls_verify_flags;
  pbns_status status;
  bool matched;
  bool initialized;
} pbns_tls_certificate_policy;

pbns_status
pbns_tls_certificate_policy_init(pbns_tls_certificate_policy *policy,
                                 pbns_view expected_server_name,
                                 pbns_view pinned_leaf_spki_sha256);
void pbns_tls_certificate_policy_wipe(pbns_tls_certificate_policy *policy);
int pbns_tls_certificate_verify_callback(void *context,
                                         mbedtls_x509_crt *certificate,
                                         int certificate_depth,
                                         uint32_t *verification_flags);
pbns_status pbns_tls_validate_negotiated_profile(uint16_t protocol_version,
                                                 uint16_t cipher_suite,
                                                 const char *alpn_protocol);
pbns_status pbns_tls_validate_certificate_der(pbns_view certificate_der,
                                              pbns_view expected_server_name,
                                              pbns_view pinned_leaf_spki_sha256,
                                              uint32_t verification_flags);

#endif
