#include <Library/PbnsCoseCryptoLib.h>

#include "PbnsCoseCryptoInternal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "t_cose/t_cose_encrypt_dec.h"
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_recipient_dec_esdh.h"
#include "t_cose/t_cose_recipient_enc_esdh.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/t_cose_standard_constants.h"

static bool key_is_valid(const pbns_cose_key *key,
                         pbns_cose_key_kind expected_kind) {
  return key != NULL && key->magic == PBNS_COSE_KEY_MAGIC &&
         key->kind == expected_kind && key->native.key.ptr == key;
}

static bool ranges_overlap(pbns_view input, pbns_buffer output) {
  if (input.ptr == NULL || input.len == 0U || output.ptr == NULL ||
      output.cap == 0U) {
    return false;
  }
  const uintptr_t input_start = (uintptr_t)input.ptr;
  const uintptr_t output_start = (uintptr_t)output.ptr;
  if (input.len > UINTPTR_MAX - input_start ||
      output.cap > UINTPTR_MAX - output_start) {
    return true;
  }
  return input_start < output_start + output.cap &&
         output_start < input_start + input.len;
}

static pbns_status map_sign_error(enum t_cose_err_t error) {
  switch (error) {
  case T_COSE_SUCCESS:
    return PBNS_OK;
  case T_COSE_ERR_SIG_BUFFER_SIZE:
  case T_COSE_ERR_TOO_SMALL:
    return PBNS_ERR_LIMIT;
  default:
    return PBNS_ERR_CRYPTO;
  }
}

pbns_status pbns_cose_key_from_identity(pbns_cose_key *key,
                                        const pbns_identity *identity) {
  if (key == NULL || identity == NULL || identity->ops == NULL ||
      identity->ops->sign_digest == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  memset(key, 0, sizeof(*key));
  key->magic = PBNS_COSE_KEY_MAGIC;
  key->kind = PBNS_COSE_KEY_IDENTITY;
  key->identity = identity;
  key->native.key.ptr = key;
  return PBNS_OK;
}

pbns_status pbns_cose_key_from_p256_public(pbns_cose_key *key, pbns_view x,
                                           pbns_view y) {
  if (key == NULL || x.ptr == NULL || y.ptr == NULL ||
      x.len != PBNS_COSE_P256_COORDINATE_SIZE ||
      y.len != PBNS_COSE_P256_COORDINATE_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  memset(key, 0, sizeof(*key));
  key->magic = PBNS_COSE_KEY_MAGIC;
  key->kind = PBNS_COSE_KEY_P256_PUBLIC;
  memcpy(key->x, x.ptr, sizeof(key->x));
  memcpy(key->y, y.ptr, sizeof(key->y));
  key->native.key.ptr = key;
  return PBNS_OK;
}

pbns_status pbns_cose_p256_key_generate(pbns_cose_key *private_key,
                                        const pbns_identity *random_identity) {
  if (private_key == NULL || random_identity == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_status status = pbns_cose_crypto_random_begin(random_identity);
  if (status != PBNS_OK) {
    return status;
  }
  status = pbns_cose_crypto_private_generate(private_key);
  pbns_cose_crypto_random_end();
  return status;
}

pbns_status pbns_cose_p256_key_export_public(const pbns_cose_key *private_key,
                                             pbns_cose_key *public_key) {
  return pbns_cose_crypto_private_export(private_key, public_key);
}

void pbns_cose_key_reset(pbns_cose_key *key) {
  pbns_cose_crypto_key_release(key);
}

pbns_status pbns_cose_uefi_sign1_sign(const pbns_cose_key *key,
                                      pbns_view payload, pbns_view external_aad,
                                      pbns_buffer output, size_t *written) {
  if (!key_is_valid(key, PBNS_COSE_KEY_IDENTITY) || payload.ptr == NULL ||
      (external_aad.ptr == NULL && external_aad.len != 0U) ||
      output.ptr == NULL || output.cap == 0U || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  struct t_cose_sign1_sign_ctx context;
  t_cose_sign1_sign_init(&context, 0U, T_COSE_ALGORITHM_ES256);
  t_cose_sign1_set_signing_key(&context, key->native, NULLUsefulBufC);
  struct q_useful_buf_c result = NULLUsefulBufC;
  /* A versão fixada troca os nomes dos dois parâmetros na definição inline. */
  const enum t_cose_err_t error = t_cose_sign1_sign_aad(
      &context, (struct q_useful_buf_c){payload.ptr, payload.len},
      (struct q_useful_buf_c){external_aad.ptr, external_aad.len},
      (struct q_useful_buf){output.ptr, output.cap}, &result);
  const pbns_status status = map_sign_error(error);
  if (status != PBNS_OK) {
    return status;
  }
  if (result.ptr != output.ptr || result.len == 0U || result.len > output.cap) {
    return PBNS_ERR_CRYPTO;
  }
  *written = result.len;
  return PBNS_OK;
}

static pbns_status sign1_verify(const pbns_cose_key *key,
                                pbns_view message,
                                pbns_view external_aad,
                                pbns_view expected_kid,
                                bool enforce_profile,
                                pbns_view *payload) {
  if (!key_is_valid(key, PBNS_COSE_KEY_P256_PUBLIC) || message.ptr == NULL ||
      message.len == 0U ||
      (external_aad.ptr == NULL && external_aad.len != 0U) || payload == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *payload = (pbns_view){0};
  struct t_cose_sign1_verify_ctx context;
  t_cose_sign1_verify_init(
      &context, enforce_profile ? (T_COSE_OPT_TAG_REQUIRED | T_COSE_OPT_REQUIRE_KID)
                                : T_COSE_OPT_TAG_REQUIRED);
  t_cose_sign1_set_verification_key(&context, key->native);
  struct q_useful_buf_c verified = NULLUsefulBufC;
  struct t_cose_parameters parameters = {0};
  const enum t_cose_err_t error = t_cose_sign1_verify_aad(
      &context, (struct q_useful_buf_c){message.ptr, message.len},
      (struct q_useful_buf_c){external_aad.ptr, external_aad.len}, &verified,
      &parameters);
  if (error != T_COSE_SUCCESS) {
    return (pbns_status)(-200 - (int32_t)error);
  }
  if (parameters.cose_algorithm_id != T_COSE_ALGORITHM_ES256) {
    return (pbns_status)-250;
  }
  if (enforce_profile) {
    if (parameters.kid.ptr == NULL) {
      return (pbns_status)-251;
    }
    if (parameters.kid.len != expected_kid.len) {
      return (pbns_status)-252;
    }
    if (memcmp(parameters.kid.ptr, expected_kid.ptr, expected_kid.len) != 0) {
      return (pbns_status)-253;
    }
    if (message.len < 2U) {
      return (pbns_status)-254;
    }
    if (message.ptr[0] != 0xd2U) {
      return (pbns_status)-255;
    }
    if (message.ptr[1] != 0x84U) {
      return (pbns_status)-256;
    }
  }
  if (verified.ptr == NULL || verified.len == 0U) {
    return (pbns_status)-257;
  }
  payload->ptr = verified.ptr;
  payload->len = verified.len;
  return PBNS_OK;
}

pbns_status pbns_cose_uefi_sign1_verify(const pbns_cose_key *key,
                                        pbns_view message,
                                        pbns_view external_aad,
                                        pbns_view *payload) {
  return sign1_verify(key, message, external_aad, (pbns_view){0}, false,
                      payload);
}

pbns_status pbns_cose_uefi_sign1_verify_profile(
    const pbns_cose_key *key, pbns_view message, pbns_view external_aad,
    pbns_view expected_kid, pbns_view *payload) {
  if (expected_kid.ptr == NULL || expected_kid.len == 0U ||
      expected_kid.len > PBNS_COSE_RECIPIENT_KEY_ID_MAX_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  return sign1_verify(key, message, external_aad, expected_kid, true, payload);
}

static pbns_status map_encrypt_error(enum t_cose_err_t error, bool decrypting) {
  switch (error) {
  case T_COSE_SUCCESS:
    return PBNS_OK;
  case T_COSE_ERR_TOO_SMALL:
    return PBNS_ERR_LIMIT;
  case T_COSE_ERR_RNG_FAILED:
    return PBNS_ERR_ENTROPY;
  case T_COSE_ERR_DATA_AUTH_FAILED:
  case T_COSE_ERR_DECRYPT_FAIL:
    return decrypting ? PBNS_ERR_AUTHENTICATION : PBNS_ERR_CRYPTO;
  default:
    return PBNS_ERR_CRYPTO;
  }
}

static pbns_status cose_encrypt_for_recipient_bounded(
    const pbns_identity *random_identity, const pbns_cose_key *recipient_key,
    pbns_view recipient_key_id, pbns_view plaintext, pbns_view external_aad,
    pbns_buffer output, size_t *written, size_t message_max_size) {
  if (random_identity == NULL ||
      !key_is_valid(recipient_key, PBNS_COSE_KEY_P256_PUBLIC) ||
      recipient_key_id.ptr == NULL || recipient_key_id.len == 0U ||
      plaintext.ptr == NULL || plaintext.len == 0U ||
      (external_aad.ptr == NULL && external_aad.len != 0U) ||
      output.ptr == NULL || output.cap == 0U || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (recipient_key_id.len > PBNS_COSE_RECIPIENT_KEY_ID_MAX_SIZE ||
      external_aad.len > PBNS_COSE_EXTERNAL_AAD_MAX_SIZE ||
      plaintext.len >
          message_max_size - PBNS_COSE_ENCRYPT_OVERHEAD_RESERVE ||
      output.cap > message_max_size ||
      output.cap < plaintext.len + PBNS_COSE_ENCRYPT_OVERHEAD_RESERVE) {
    return PBNS_ERR_LIMIT;
  }
  if (ranges_overlap(plaintext, output) ||
      ranges_overlap(external_aad, output) ||
      ranges_overlap(recipient_key_id, output)) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_status status = pbns_cose_crypto_random_begin(random_identity);
  if (status != PBNS_OK) {
    return status;
  }
  struct t_cose_encrypt_enc context;
  struct t_cose_recipient_enc_esdh recipient;
  uint8_t enc_structure[512] = {0};
  t_cose_encrypt_enc_init(&context, T_COSE_OPT_MESSAGE_TYPE_ENCRYPT,
                          T_COSE_ALGORITHM_A128GCM);
  t_cose_encrypt_set_enc_struct_buffer(
      &context, (struct q_useful_buf){enc_structure, sizeof(enc_structure)});
  t_cose_recipient_enc_esdh_init(&recipient, T_COSE_ALGORITHM_ECDH_ES_A128KW,
                                 T_COSE_ELLIPTIC_CURVE_P_256);
  t_cose_recipient_enc_esdh_set_key(
      &recipient, recipient_key->native,
      (struct q_useful_buf_c){recipient_key_id.ptr, recipient_key_id.len});
  t_cose_encrypt_add_recipient(&context,
                               (struct t_cose_recipient_enc *)&recipient);
  struct q_useful_buf_c encrypted = NULLUsefulBufC;
  const enum t_cose_err_t error = t_cose_encrypt_enc(
      &context, (struct q_useful_buf_c){plaintext.ptr, plaintext.len},
      (struct q_useful_buf_c){external_aad.ptr, external_aad.len},
      (struct q_useful_buf){output.ptr, output.cap}, &encrypted);
  pbns_cose_crypto_random_end();
  memset(enc_structure, 0, sizeof(enc_structure));
  status = map_encrypt_error(error, false);
  if (status != PBNS_OK) {
    return status;
  }
  if (encrypted.ptr != output.ptr || encrypted.len == 0U ||
      encrypted.len > output.cap) {
    return PBNS_ERR_CRYPTO;
  }
  *written = encrypted.len;
  return PBNS_OK;
}

pbns_status pbns_cose_uefi_encrypt_for_recipient(
    const pbns_identity *random_identity, const pbns_cose_key *recipient_key,
    pbns_view recipient_key_id, pbns_view plaintext, pbns_view external_aad,
    pbns_buffer output, size_t *written) {
  return cose_encrypt_for_recipient_bounded(
      random_identity, recipient_key, recipient_key_id, plaintext, external_aad,
      output, written, PBNS_COSE_MESSAGE_MAX_SIZE);
}

pbns_status pbns_cose_uefi_attestation_encrypt_for_recipient(
    const pbns_identity *random_identity, const pbns_cose_key *recipient_key,
    pbns_view recipient_key_id, pbns_view plaintext, pbns_view external_aad,
    pbns_buffer output, size_t *written) {
  return cose_encrypt_for_recipient_bounded(
      random_identity, recipient_key, recipient_key_id, plaintext, external_aad,
      output, written, PBNS_COSE_ATTESTATION_MESSAGE_MAX_SIZE);
}

pbns_status pbns_cose_uefi_decrypt_for_recipient(
    const pbns_identity *random_identity, const pbns_cose_key *recipient_key,
    pbns_view recipient_key_id, pbns_view message, pbns_view external_aad,
    pbns_buffer plaintext, size_t *written) {
  if (random_identity == NULL ||
      !key_is_valid(recipient_key, PBNS_COSE_KEY_P256_PRIVATE) ||
      recipient_key_id.ptr == NULL || recipient_key_id.len == 0U ||
      message.ptr == NULL || message.len == 0U ||
      (external_aad.ptr == NULL && external_aad.len != 0U) ||
      plaintext.ptr == NULL || plaintext.cap == 0U || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (recipient_key_id.len > PBNS_COSE_RECIPIENT_KEY_ID_MAX_SIZE ||
      external_aad.len > PBNS_COSE_EXTERNAL_AAD_MAX_SIZE ||
      message.len > PBNS_COSE_MESSAGE_MAX_SIZE ||
      plaintext.cap > PBNS_COSE_MESSAGE_MAX_SIZE) {
    return PBNS_ERR_LIMIT;
  }
  if (ranges_overlap(message, plaintext) ||
      ranges_overlap(external_aad, plaintext) ||
      ranges_overlap(recipient_key_id, plaintext)) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_status status = pbns_cose_crypto_random_begin(random_identity);
  if (status != PBNS_OK) {
    return status;
  }
  struct t_cose_encrypt_dec_ctx context;
  struct t_cose_recipient_dec_esdh recipient;
  uint8_t enc_structure[512] = {0};
  t_cose_encrypt_dec_init(&context, 0U);
  t_cose_decrypt_set_enc_struct_buffer(
      &context, (struct q_useful_buf){enc_structure, sizeof(enc_structure)});
  t_cose_recipient_dec_esdh_init(&recipient);
  t_cose_recipient_dec_esdh_set_key(
      &recipient, recipient_key->native,
      (struct q_useful_buf_c){recipient_key_id.ptr, recipient_key_id.len});
  t_cose_encrypt_dec_add_recipient(&context,
                                   (struct t_cose_recipient_dec *)&recipient);
  struct q_useful_buf_c decrypted = NULLUsefulBufC;
  const enum t_cose_err_t error = t_cose_encrypt_dec_msg(
      &context, (struct q_useful_buf_c){message.ptr, message.len},
      (struct q_useful_buf_c){external_aad.ptr, external_aad.len},
      (struct q_useful_buf){plaintext.ptr, plaintext.cap}, &decrypted, NULL,
      NULL);
  pbns_cose_crypto_random_end();
  memset(enc_structure, 0, sizeof(enc_structure));
  status = map_encrypt_error(error, true);
  if (status != PBNS_OK) {
    return status;
  }
  if (decrypted.ptr != plaintext.ptr || decrypted.len == 0U ||
      decrypted.len > plaintext.cap) {
    return PBNS_ERR_CRYPTO;
  }
  *written = decrypted.len;
  return PBNS_OK;
}
