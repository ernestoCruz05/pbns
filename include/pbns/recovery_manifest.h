#ifndef PBNS_RECOVERY_MANIFEST_H
#define PBNS_RECOVERY_MANIFEST_H

#include <stddef.h>
#include <stdint.h>

#include "pbns/crypto.h"
#include "pbns/trusted_time.h"

#define PBNS_RECOVERY_MANIFEST_DOMAIN "PBNS-RECOVERY-MANIFEST-v1"
#define PBNS_RECOVERY_MANIFEST_AAD "PBNS-RECOVERY-MANIFEST-AAD-v1"
#define PBNS_RECOVERY_MANIFEST_VERSION UINT64_C(1)
#define PBNS_RECOVERY_MANIFEST_SERVICE UINT64_C(2)
#define PBNS_RECOVERY_MANIFEST_DIGEST_SIZE 32U
#define PBNS_RECOVERY_MANIFEST_HOST_SIZE 32U
#define PBNS_RECOVERY_MANIFEST_NONCE_SIZE 32U
#define PBNS_RECOVERY_MANIFEST_REQUEST_ID_SIZE 16U
#define PBNS_RECOVERY_MANIFEST_CHUNK_SIZE UINT32_C(16384)
#define PBNS_RECOVERY_MANIFEST_IMAGE_MAX UINT64_C(268435456)
#define PBNS_RECOVERY_MANIFEST_POLICY_MAX_SIZE 4096U
#define PBNS_RECOVERY_MANIFEST_KEY_ID_MAX_SIZE 64U
#define PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE 8192U
#define PBNS_RECOVERY_MANIFEST_SIGNED_MAX_SIZE 65536U
#define PBNS_RECOVERY_MANIFEST_AAD_MAX_SIZE 192U
#define PBNS_RECOVERY_ARCHITECTURE "x86_64"
#define PBNS_RECOVERY_FORMAT "uki-pe-coff"

typedef struct pbns_recovery_manifest {
  uint8_t request_id[PBNS_RECOVERY_MANIFEST_REQUEST_ID_SIZE];
  uint8_t host_binding[PBNS_RECOVERY_MANIFEST_HOST_SIZE];
  uint8_t nonce[PBNS_RECOVERY_MANIFEST_NONCE_SIZE];
  uint8_t artifact_digest[PBNS_RECOVERY_MANIFEST_DIGEST_SIZE];
  uint64_t artifact_version;
  uint64_t image_size;
  uint32_t chunk_size;
  uint64_t minimum_version;
  int64_t not_before_ns;
  int64_t not_after_ns;
  pbns_view policy_authorization;
  pbns_view policy_key_id;
} pbns_recovery_manifest;

typedef struct pbns_recovery_manifest_expectation {
  uint8_t request_id[PBNS_RECOVERY_MANIFEST_REQUEST_ID_SIZE];
  uint8_t host_binding[PBNS_RECOVERY_MANIFEST_HOST_SIZE];
  uint8_t nonce[PBNS_RECOVERY_MANIFEST_NONCE_SIZE];
  pbns_view recovery_signing_key_id;
  pbns_view expected_policy_key_id;
  uint64_t current_version;
  pbns_time_interval trusted_time;
} pbns_recovery_manifest_expectation;

pbns_status
pbns_recovery_manifest_encode(const pbns_recovery_manifest *manifest,
                              pbns_buffer output, size_t *written);

pbns_status pbns_recovery_manifest_aad(
    const pbns_recovery_manifest_expectation *expectation, pbns_buffer output,
    size_t *written);

/* As vistas devolvidas referenciam a carga fornecida pelo chamador. */
pbns_status pbns_recovery_manifest_decode_verified(
    pbns_view verified_payload,
    const pbns_recovery_manifest_expectation *expectation,
    pbns_buffer canonical_scratch, pbns_recovery_manifest *manifest);

/* As vistas devolvidas referenciam a mensagem COSE fornecida pelo chamador. */
pbns_status pbns_recovery_manifest_verify_signed(
    const pbns_crypto *verifier, pbns_view signed_manifest,
    const pbns_recovery_manifest_expectation *expectation,
    pbns_buffer canonical_scratch, pbns_buffer aad_scratch,
    pbns_recovery_manifest *manifest);

#endif
