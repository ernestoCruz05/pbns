#ifndef PBNS_ATTESTATION_RECEIPT_H
#define PBNS_ATTESTATION_RECEIPT_H

#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/crypto.h"
#include "pbns/status.h"

#define PBNS_ATTESTATION_RECEIPT_DOMAIN "PBNS-ATTESTATION-RECEIPT-v1"
#define PBNS_ATTESTATION_RECEIPT_AAD_DOMAIN \
  "PBNS-ATTESTATION-RECEIPT-SIGN-v1"
#define PBNS_ATTESTATION_RECEIPT_VERSION UINT64_C(1)
#define PBNS_ATTESTATION_RECEIPT_SERVICE UINT64_C(3)
#define PBNS_ATTESTATION_RECEIPT_REQUEST_ID_SIZE 16U
#define PBNS_ATTESTATION_RECEIPT_DIGEST_SIZE 32U
#define PBNS_ATTESTATION_RECEIPT_MAX_KEY_ID_SIZE 64U
#define PBNS_ATTESTATION_RECEIPT_MAX_REASONS 16U
#define PBNS_ATTESTATION_RECEIPT_MAX_PAYLOAD_SIZE 512U
#define PBNS_ATTESTATION_RECEIPT_MAX_SIGNED_SIZE 4096U
#define PBNS_ATTESTATION_RECEIPT_MAX_AAD_SIZE 320U

typedef enum pbns_attestation_receipt_verdict {
  PBNS_ATTESTATION_RECEIPT_FULL = 1,
  PBNS_ATTESTATION_RECEIPT_REDUCED = 2,
  PBNS_ATTESTATION_RECEIPT_FAILURE = 3
} pbns_attestation_receipt_verdict;

typedef enum pbns_attestation_display_state {
  PBNS_ATTESTATION_DISPLAY_FULL = 1,
  PBNS_ATTESTATION_DISPLAY_REDUCED = 2,
  PBNS_ATTESTATION_DISPLAY_FAILURE = 3
} pbns_attestation_display_state;

typedef struct pbns_attestation_receipt_expectation {
  uint8_t request_id[PBNS_ATTESTATION_RECEIPT_REQUEST_ID_SIZE];
  uint8_t verifier_nonce[PBNS_ATTESTATION_RECEIPT_DIGEST_SIZE];
  uint8_t host_fingerprint[PBNS_ATTESTATION_RECEIPT_DIGEST_SIZE];
  uint8_t evidence_digest[PBNS_ATTESTATION_RECEIPT_DIGEST_SIZE];
  uint8_t baseline_id[PBNS_ATTESTATION_RECEIPT_DIGEST_SIZE];
  pbns_view key_id;
} pbns_attestation_receipt_expectation;

typedef struct pbns_attestation_receipt_result {
  pbns_attestation_receipt_verdict verdict;
  uint64_t reasons[PBNS_ATTESTATION_RECEIPT_MAX_REASONS];
  size_t reason_count;
  pbns_attestation_display_state display_state;
} pbns_attestation_receipt_result;

typedef struct pbns_attestation_receipt_workspace {
  pbns_buffer canonical_payload;
  pbns_buffer canonical_cose;
  pbns_buffer aad;
} pbns_attestation_receipt_workspace;

pbns_status pbns_attestation_receipt_verify(
    const pbns_crypto *verifier, pbns_view signed_receipt,
    const pbns_attestation_receipt_expectation *expectation,
    pbns_attestation_receipt_workspace *workspace,
    pbns_attestation_receipt_result *result);

#endif
