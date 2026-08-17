#include "pbns/enrollment.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static bool all_zero(const uint8_t *value, size_t length) {
  if (value == NULL) {
    return true;
  }
  uint8_t combined = 0U;
  for (size_t index = 0U; index < length; ++index) {
    combined |= value[index];
  }
  return combined == 0U;
}

static bool equal(const uint8_t *left, const uint8_t *right, size_t length) {
  if (left == NULL || right == NULL) {
    return false;
  }
  uint8_t difference = 0U;
  for (size_t index = 0U; index < length; ++index) {
    difference |= (uint8_t)(left[index] ^ right[index]);
  }
  return difference == 0U;
}

static pbns_status fail_authentication(pbns_enrollment *context) {
  context->state = PBNS_ENROLLMENT_FAILED;
  return PBNS_ERR_AUTHENTICATION;
}

static bool token_character_valid(uint32_t character) {
  return (character >= (uint32_t)'A' && character <= (uint32_t)'Z') ||
         (character >= (uint32_t)'a' && character <= (uint32_t)'z') ||
         (character >= (uint32_t)'0' && character <= (uint32_t)'9') ||
         character == (uint32_t)'-' || character == (uint32_t)'_';
}

pbns_status
pbns_enrollment_token_input_key(pbns_enrollment_token_input *input,
                                uint32_t unicode_character,
                                pbns_enrollment_token_input_action *action) {
  if (input == NULL || action == NULL ||
      input->length > PBNS_ENROLLMENT_TOKEN_TEXT_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  *action = PBNS_ENROLLMENT_TOKEN_CONTINUE;
  if (unicode_character == 0U) {
    return PBNS_OK;
  }
  if (unicode_character == 13U) {
    if (input->length != PBNS_ENROLLMENT_TOKEN_TEXT_SIZE) {
      return PBNS_ERR_FORMAT;
    }
    *action = PBNS_ENROLLMENT_TOKEN_SUBMIT;
    return PBNS_OK;
  }
  if (unicode_character == 8U) {
    if (input->length > 0U) {
      --input->length;
      input->text[input->length] = 0U;
    }
    return PBNS_OK;
  }
  if (!token_character_valid(unicode_character) ||
      input->length >= PBNS_ENROLLMENT_TOKEN_TEXT_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  input->text[input->length] = (uint8_t)unicode_character;
  ++input->length;
  return PBNS_OK;
}

pbns_status pbns_enrollment_init(
    pbns_enrollment *context, pbns_enrollment_assurance assurance,
    const uint8_t request_id[PBNS_ENROLLMENT_REQUEST_ID_SIZE],
    const uint8_t host_nonce[PBNS_ENROLLMENT_NONCE_SIZE],
    const uint8_t init_digest[PBNS_ENROLLMENT_DIGEST_SIZE],
    const uint8_t baseline_digest[PBNS_ENROLLMENT_DIGEST_SIZE]) {
  if (context == NULL ||
      (assurance != PBNS_ENROLLMENT_ASSURANCE_SOFTWARE &&
       assurance != PBNS_ENROLLMENT_ASSURANCE_TPM) ||
      all_zero(request_id, PBNS_ENROLLMENT_REQUEST_ID_SIZE) ||
      all_zero(host_nonce, PBNS_ENROLLMENT_NONCE_SIZE) ||
      all_zero(init_digest, PBNS_ENROLLMENT_DIGEST_SIZE) ||
      all_zero(baseline_digest, PBNS_ENROLLMENT_DIGEST_SIZE)) {
    return PBNS_ERR_ARGUMENT;
  }
  *context = (pbns_enrollment){0};
  context->assurance = assurance;
  memcpy(context->request_id, request_id, sizeof(context->request_id));
  memcpy(context->host_nonce, host_nonce, sizeof(context->host_nonce));
  memcpy(context->init_digest, init_digest, sizeof(context->init_digest));
  memcpy(context->baseline_digest, baseline_digest,
         sizeof(context->baseline_digest));
  return PBNS_OK;
}

pbns_status pbns_enrollment_accept_challenge(
    pbns_enrollment *context,
    const uint8_t host_nonce[PBNS_ENROLLMENT_NONCE_SIZE],
    const uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE],
    const uint8_t init_digest[PBNS_ENROLLMENT_DIGEST_SIZE],
    bool signature_verified) {
  if (context == NULL || host_nonce == NULL ||
      all_zero(server_nonce, PBNS_ENROLLMENT_NONCE_SIZE) ||
      init_digest == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (context->state != PBNS_ENROLLMENT_INIT ||
      context->assurance == PBNS_ENROLLMENT_ASSURANCE_INVALID) {
    return PBNS_ERR_STATE;
  }
  if (!signature_verified ||
      !equal(context->host_nonce, host_nonce, sizeof(context->host_nonce)) ||
      !equal(context->init_digest, init_digest, sizeof(context->init_digest))) {
    return fail_authentication(context);
  }
  memcpy(context->server_nonce, server_nonce, sizeof(context->server_nonce));
  context->state = PBNS_ENROLLMENT_CHALLENGE_VERIFIED;
  return PBNS_OK;
}

pbns_status pbns_enrollment_prepare_proof(
    pbns_enrollment *context,
    const uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE],
    const uint8_t init_digest[PBNS_ENROLLMENT_DIGEST_SIZE],
    const uint8_t baseline_digest[PBNS_ENROLLMENT_DIGEST_SIZE],
    bool activation_verified, bool identity_signature_verified) {
  if (context == NULL || server_nonce == NULL || init_digest == NULL ||
      baseline_digest == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (context->state != PBNS_ENROLLMENT_CHALLENGE_VERIFIED) {
    return PBNS_ERR_STATE;
  }
  const bool activation_accepted =
      context->assurance == PBNS_ENROLLMENT_ASSURANCE_SOFTWARE ||
      (context->assurance == PBNS_ENROLLMENT_ASSURANCE_TPM &&
       activation_verified);
  if (!activation_accepted || !identity_signature_verified ||
      !equal(context->server_nonce, server_nonce,
             sizeof(context->server_nonce)) ||
      !equal(context->init_digest, init_digest, sizeof(context->init_digest)) ||
      !equal(context->baseline_digest, baseline_digest,
             sizeof(context->baseline_digest))) {
    return fail_authentication(context);
  }
  context->state = PBNS_ENROLLMENT_PROOF_READY;
  return PBNS_OK;
}

pbns_status pbns_enrollment_complete(
    pbns_enrollment *context,
    const uint8_t request_id[PBNS_ENROLLMENT_REQUEST_ID_SIZE],
    const uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE],
    bool receipt_signature_verified) {
  if (context == NULL || request_id == NULL || server_nonce == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (context->state != PBNS_ENROLLMENT_PROOF_READY) {
    return PBNS_ERR_STATE;
  }
  if (!receipt_signature_verified ||
      !equal(context->request_id, request_id, sizeof(context->request_id)) ||
      !equal(context->server_nonce, server_nonce,
             sizeof(context->server_nonce))) {
    return fail_authentication(context);
  }
  context->state = PBNS_ENROLLMENT_COMPLETE;
  return PBNS_OK;
}

void pbns_enrollment_reset(pbns_enrollment *context) {
  if (context == NULL) {
    return;
  }
  volatile uint8_t *bytes = (volatile uint8_t *)context;
  for (size_t index = 0U; index < sizeof(*context); ++index) {
    bytes[index] = 0U;
  }
}
