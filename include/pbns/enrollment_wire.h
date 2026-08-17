#ifndef PBNS_ENROLLMENT_WIRE_H
#define PBNS_ENROLLMENT_WIRE_H

#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_ENROLLMENT_DOMAIN "PBNS-ENROLLMENT-v1"
#define PBNS_ENROLLMENT_VERSION UINT64_C(1)
#define PBNS_ENROLLMENT_SERVICE UINT64_C(4)
#define PBNS_ENROLLMENT_STAGE_INIT UINT64_C(1)
#define PBNS_ENROLLMENT_STAGE_CHALLENGE UINT64_C(2)
#define PBNS_ENROLLMENT_STAGE_PROOF UINT64_C(3)
#define PBNS_ENROLLMENT_STAGE_RECEIPT UINT64_C(4)
#define PBNS_ENROLLMENT_FLOW_SOFTWARE UINT64_C(1)
#define PBNS_ENROLLMENT_FLOW_TPM UINT64_C(2)
#define PBNS_ENROLLMENT_KEY_ID_MAX_SIZE 64U
#define PBNS_ENROLLMENT_PUBLIC_KEY_MAX_SIZE 16384U
#define PBNS_ENROLLMENT_BASELINE_MAX_SIZE ((size_t)60U * (size_t)1024U)
#define PBNS_ENROLLMENT_OBJECT_MAX_SIZE 65536U
#define PBNS_ENROLLMENT_REQUEST_ID_SIZE 16U
#define PBNS_ENROLLMENT_NONCE_SIZE 32U
#define PBNS_ENROLLMENT_DIGEST_SIZE 32U

typedef struct pbns_enrollment_common_context {
  uint8_t request_id[PBNS_ENROLLMENT_REQUEST_ID_SIZE];
  uint8_t host_fingerprint[PBNS_ENROLLMENT_DIGEST_SIZE];
  uint8_t nonce[PBNS_ENROLLMENT_NONCE_SIZE];
  uint64_t stage;
  uint64_t sequence;
  pbns_view key_id;
} pbns_enrollment_common_context;

typedef struct pbns_enrollment_software_init {
  pbns_enrollment_common_context context;
  uint8_t token[PBNS_ENROLLMENT_DIGEST_SIZE];
  pbns_view identity_cose_key;
  uint8_t initial_evidence_digest[PBNS_ENROLLMENT_DIGEST_SIZE];
  uint8_t host_nonce[PBNS_ENROLLMENT_NONCE_SIZE];
} pbns_enrollment_software_init;

typedef struct pbns_enrollment_tpm_init {
  pbns_enrollment_common_context context;
  uint8_t token[PBNS_ENROLLMENT_DIGEST_SIZE];
  pbns_view ek_public;
  pbns_view ak_public;
  pbns_view ak_name;
  pbns_view ek_certificate;
  pbns_view identity_cose_key;
  uint8_t initial_evidence_digest[PBNS_ENROLLMENT_DIGEST_SIZE];
  uint8_t host_nonce[PBNS_ENROLLMENT_NONCE_SIZE];
  pbns_view identity_tpm_public;
} pbns_enrollment_tpm_init;

typedef struct pbns_enrollment_challenge_object {
  pbns_enrollment_common_context context;
  uint8_t host_nonce[PBNS_ENROLLMENT_NONCE_SIZE];
  uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE];
  uint8_t init_digest[PBNS_ENROLLMENT_DIGEST_SIZE];
  pbns_view credential_blob;
  pbns_view encrypted_secret;
  uint64_t flow;
} pbns_enrollment_challenge_object;

typedef struct pbns_enrollment_software_proof {
  pbns_enrollment_common_context context;
  uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE];
  uint8_t init_digest[PBNS_ENROLLMENT_DIGEST_SIZE];
  uint8_t baseline_digest[PBNS_ENROLLMENT_DIGEST_SIZE];
  pbns_view baseline_evidence;
} pbns_enrollment_software_proof;

typedef struct pbns_enrollment_tpm_proof {
  pbns_enrollment_common_context context;
  uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE];
  uint8_t init_digest[PBNS_ENROLLMENT_DIGEST_SIZE];
  pbns_view activated_credential;
  pbns_view certify_attestation;
  pbns_view certify_signature;
  uint8_t baseline_digest[PBNS_ENROLLMENT_DIGEST_SIZE];
  pbns_view baseline_evidence;
} pbns_enrollment_tpm_proof;

typedef struct pbns_enrollment_receipt_object {
  pbns_enrollment_common_context context;
  uint8_t fingerprint[PBNS_ENROLLMENT_DIGEST_SIZE];
  pbns_view assurance;
  uint8_t baseline_digest[PBNS_ENROLLMENT_DIGEST_SIZE];
  int64_t enrolled_at_unix;
  pbns_view key_id;
} pbns_enrollment_receipt_object;

typedef struct pbns_enrollment_encrypted_envelope {
  uint8_t request_id[PBNS_ENROLLMENT_REQUEST_ID_SIZE];
  uint8_t host_nonce[PBNS_ENROLLMENT_NONCE_SIZE];
  pbns_view recipient_key_id;
  pbns_view ciphertext;
} pbns_enrollment_encrypted_envelope;

typedef struct pbns_enrollment_wire_object {
  uint64_t operation;
  pbns_view object;
} pbns_enrollment_wire_object;

pbns_status
pbns_enrollment_software_init_encode(const pbns_enrollment_software_init *value,
                                     pbns_buffer output, size_t *written);
pbns_status
pbns_enrollment_tpm_init_encode(const pbns_enrollment_tpm_init *value,
                                pbns_buffer output, size_t *written);
pbns_status
pbns_enrollment_challenge_encode(const pbns_enrollment_challenge_object *value,
                                 pbns_buffer output, size_t *written);
pbns_status pbns_enrollment_challenge_decode(
    pbns_view encoded, pbns_view expected_signing_key_id,
    pbns_buffer canonical_scratch, pbns_enrollment_challenge_object *value);
pbns_status pbns_enrollment_software_proof_encode(
    const pbns_enrollment_software_proof *value, pbns_buffer output,
    size_t *written);
pbns_status
pbns_enrollment_tpm_proof_encode(const pbns_enrollment_tpm_proof *value,
                                 pbns_buffer output, size_t *written);
pbns_status
pbns_enrollment_tpm_proof_aad(const pbns_enrollment_tpm_proof *proof,
                              pbns_buffer output, size_t *written);
pbns_status
pbns_enrollment_receipt_encode(const pbns_enrollment_receipt_object *value,
                               pbns_buffer output, size_t *written);
pbns_status pbns_enrollment_receipt_decode(
    pbns_view encoded, pbns_view expected_signing_key_id,
    pbns_buffer canonical_scratch, pbns_enrollment_receipt_object *value);
pbns_status
pbns_enrollment_envelope_encode(const pbns_enrollment_encrypted_envelope *value,
                                pbns_buffer output, size_t *written);
pbns_status pbns_enrollment_envelope_decode(
    pbns_view encoded, pbns_view expected_recipient_key_id,
    pbns_buffer canonical_scratch, pbns_enrollment_encrypted_envelope *value);
pbns_status
pbns_enrollment_wire_object_encode(const pbns_enrollment_wire_object *value,
                                   pbns_buffer output, size_t *written);
pbns_status pbns_enrollment_wire_object_decode(
    pbns_view encoded, uint64_t expected_operation,
    pbns_buffer canonical_scratch, pbns_enrollment_wire_object *value);

pbns_status pbns_enrollment_envelope_aad(
    const uint8_t request_id[PBNS_ENROLLMENT_REQUEST_ID_SIZE],
    const uint8_t host_nonce[PBNS_ENROLLMENT_NONCE_SIZE], pbns_view key_id,
    pbns_buffer output, size_t *written);
pbns_status
pbns_enrollment_challenge_aad(const pbns_enrollment_challenge_object *challenge,
                              pbns_buffer output, size_t *written);
pbns_status
pbns_enrollment_proof_aad(const pbns_enrollment_software_proof *proof,
                          pbns_buffer output, size_t *written);
pbns_status pbns_enrollment_receipt_aad(
    const pbns_enrollment_receipt_object *receipt,
    const uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE], pbns_buffer output,
    size_t *written);

#endif
