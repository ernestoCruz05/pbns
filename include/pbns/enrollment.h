#ifndef PBNS_ENROLLMENT_H
#define PBNS_ENROLLMENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/status.h"

#define PBNS_ENROLLMENT_REQUEST_ID_SIZE 16U
#define PBNS_ENROLLMENT_NONCE_SIZE 32U
#define PBNS_ENROLLMENT_DIGEST_SIZE 32U
#define PBNS_ENROLLMENT_TOKEN_TEXT_SIZE 43U

typedef enum pbns_enrollment_token_input_action {
  PBNS_ENROLLMENT_TOKEN_CONTINUE = 0,
  PBNS_ENROLLMENT_TOKEN_SUBMIT = 1
} pbns_enrollment_token_input_action;

typedef struct pbns_enrollment_token_input {
  uint8_t text[PBNS_ENROLLMENT_TOKEN_TEXT_SIZE];
  size_t length;
} pbns_enrollment_token_input;

typedef enum pbns_enrollment_state {
  PBNS_ENROLLMENT_INIT = 0,
  PBNS_ENROLLMENT_CHALLENGE_VERIFIED = 1,
  PBNS_ENROLLMENT_PROOF_READY = 2,
  PBNS_ENROLLMENT_COMPLETE = 3,
  PBNS_ENROLLMENT_FAILED = 4
} pbns_enrollment_state;

typedef enum pbns_enrollment_assurance {
  PBNS_ENROLLMENT_ASSURANCE_INVALID = 0,
  PBNS_ENROLLMENT_ASSURANCE_SOFTWARE = 1,
  PBNS_ENROLLMENT_ASSURANCE_TPM = 2
} pbns_enrollment_assurance;

pbns_status
pbns_enrollment_token_input_key(pbns_enrollment_token_input *input,
                                uint32_t unicode_character,
                                pbns_enrollment_token_input_action *action);

typedef struct pbns_enrollment {
  pbns_enrollment_state state;
  pbns_enrollment_assurance assurance;
  uint8_t request_id[PBNS_ENROLLMENT_REQUEST_ID_SIZE];
  uint8_t host_nonce[PBNS_ENROLLMENT_NONCE_SIZE];
  uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE];
  uint8_t init_digest[PBNS_ENROLLMENT_DIGEST_SIZE];
  uint8_t baseline_digest[PBNS_ENROLLMENT_DIGEST_SIZE];
} pbns_enrollment;

pbns_status pbns_enrollment_init(
    pbns_enrollment *context, pbns_enrollment_assurance assurance,
    const uint8_t request_id[PBNS_ENROLLMENT_REQUEST_ID_SIZE],
    const uint8_t host_nonce[PBNS_ENROLLMENT_NONCE_SIZE],
    const uint8_t init_digest[PBNS_ENROLLMENT_DIGEST_SIZE],
    const uint8_t baseline_digest[PBNS_ENROLLMENT_DIGEST_SIZE]);
pbns_status pbns_enrollment_accept_challenge(
    pbns_enrollment *context,
    const uint8_t host_nonce[PBNS_ENROLLMENT_NONCE_SIZE],
    const uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE],
    const uint8_t init_digest[PBNS_ENROLLMENT_DIGEST_SIZE],
    bool signature_verified);
pbns_status pbns_enrollment_prepare_proof(
    pbns_enrollment *context,
    const uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE],
    const uint8_t init_digest[PBNS_ENROLLMENT_DIGEST_SIZE],
    const uint8_t baseline_digest[PBNS_ENROLLMENT_DIGEST_SIZE],
    bool activation_verified, bool identity_signature_verified);
pbns_status pbns_enrollment_complete(
    pbns_enrollment *context,
    const uint8_t request_id[PBNS_ENROLLMENT_REQUEST_ID_SIZE],
    const uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE],
    bool receipt_signature_verified);
void pbns_enrollment_reset(pbns_enrollment *context);

#endif
