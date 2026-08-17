#include "pbns/identity.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define PBNS_IDENTITY_FINGERPRINT_SIZE 32U
#define PBNS_IDENTITY_ES256_SIGNATURE_SIZE 64U
#define PBNS_IDENTITY_SHA256_DIGEST_SIZE 32U

static bool assurance_is_valid(pbns_identity_assurance assurance) {
  return assurance >= PBNS_IDENTITY_TPM_VERIFIED &&
         assurance <= PBNS_IDENTITY_SOFTWARE;
}

static bool ops_are_complete(const pbns_identity_ops *ops) {
  return ops != NULL && ops->public_cose_key != NULL &&
         ops->fingerprint != NULL && ops->sign_digest != NULL &&
         ops->random != NULL && ops->close != NULL;
}

static bool identity_is_open(const pbns_identity *identity) {
  return identity != NULL && ops_are_complete(identity->ops) &&
         identity->context != NULL && assurance_is_valid(identity->assurance);
}

static bool buffer_is_valid(pbns_buffer buffer, size_t minimum_capacity) {
  return buffer.ptr != NULL && buffer.len == 0U &&
         buffer.cap >= minimum_capacity;
}

pbns_status pbns_identity_open(pbns_identity *identity,
                               const pbns_identity_ops *ops, void *context,
                               pbns_identity_assurance assurance) {
  if (identity == NULL || !ops_are_complete(ops) || context == NULL ||
      !assurance_is_valid(assurance)) {
    return PBNS_ERR_ARGUMENT;
  }
  if (identity->ops != NULL || identity->context != NULL ||
      identity->assurance != PBNS_IDENTITY_INVALID) {
    return PBNS_ERR_STATE;
  }
  *identity =
      (pbns_identity){.ops = ops, .context = context, .assurance = assurance};
  return PBNS_OK;
}

void pbns_identity_close(pbns_identity *identity) {
  if (identity == NULL) {
    return;
  }
  if (identity_is_open(identity)) {
    identity->ops->close(identity->context);
  }
  *identity = (pbns_identity){0};
}

pbns_status pbns_identity_public_cose_key(const pbns_identity *identity,
                                          pbns_buffer output, size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  if (!identity_is_open(identity)) {
    return PBNS_ERR_STATE;
  }
  if (!buffer_is_valid(output, 1U) || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status status =
      identity->ops->public_cose_key(identity->context, output, written);
  if (status != PBNS_OK) {
    *written = 0U;
    return status;
  }
  if (*written == 0U || *written > output.cap) {
    *written = 0U;
    return PBNS_ERR_IO;
  }
  return PBNS_OK;
}

pbns_status pbns_identity_fingerprint(const pbns_identity *identity,
                                      pbns_buffer output) {
  if (!identity_is_open(identity)) {
    return PBNS_ERR_STATE;
  }
  if (!buffer_is_valid(output, PBNS_IDENTITY_FINGERPRINT_SIZE)) {
    return output.ptr != NULL && output.len == 0U ? PBNS_ERR_LIMIT
                                                  : PBNS_ERR_ARGUMENT;
  }
  pbns_buffer bounded = {output.ptr, 0U, PBNS_IDENTITY_FINGERPRINT_SIZE};
  memset(bounded.ptr, 0, bounded.cap);
  const pbns_status status =
      identity->ops->fingerprint(identity->context, bounded);
  if (status != PBNS_OK) {
    memset(bounded.ptr, 0, bounded.cap);
  }
  return status;
}

pbns_status pbns_identity_sign(const pbns_identity *identity, pbns_view digest,
                               pbns_buffer signature, size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  if (!identity_is_open(identity)) {
    return PBNS_ERR_STATE;
  }
  if (digest.ptr == NULL || digest.len != PBNS_IDENTITY_SHA256_DIGEST_SIZE ||
      written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!buffer_is_valid(signature, PBNS_IDENTITY_ES256_SIGNATURE_SIZE)) {
    return signature.ptr != NULL && signature.len == 0U ? PBNS_ERR_LIMIT
                                                        : PBNS_ERR_ARGUMENT;
  }
  pbns_buffer bounded = {signature.ptr, 0U, PBNS_IDENTITY_ES256_SIGNATURE_SIZE};
  memset(bounded.ptr, 0, bounded.cap);
  const pbns_status status =
      identity->ops->sign_digest(identity->context, digest, bounded, written);
  if (status != PBNS_OK) {
    memset(bounded.ptr, 0, bounded.cap);
    *written = 0U;
    return status;
  }
  if (*written != PBNS_IDENTITY_ES256_SIGNATURE_SIZE) {
    memset(bounded.ptr, 0, bounded.cap);
    *written = 0U;
    return PBNS_ERR_IO;
  }
  return PBNS_OK;
}

pbns_status pbns_identity_random(const pbns_identity *identity,
                                 pbns_buffer output) {
  if (!identity_is_open(identity)) {
    return PBNS_ERR_STATE;
  }
  if (!buffer_is_valid(output, 1U)) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status status = identity->ops->random(identity->context, output);
  if (status != PBNS_OK) {
    memset(output.ptr, 0, output.cap);
  }
  return status;
}

pbns_identity_assurance
pbns_identity_assurance_level(const pbns_identity *identity) {
  return identity_is_open(identity) ? identity->assurance
                                    : PBNS_IDENTITY_INVALID;
}
