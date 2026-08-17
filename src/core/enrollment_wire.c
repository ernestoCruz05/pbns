#include "pbns/enrollment_wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_spiffy_decode.h"

static bool view_valid(pbns_view value) {
  return value.ptr != NULL || value.len == 0U;
}

static bool output_valid(pbns_buffer output) {
  return output.len == 0U && (output.ptr != NULL || output.cap == 0U);
}

static bool nonzero(const uint8_t *value, size_t length) {
  if (value == NULL) {
    return false;
  }
  uint8_t combined = 0U;
  for (size_t index = 0U; index < length; ++index) {
    combined |= value[index];
  }
  return combined != 0U;
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

static bool view_equal(pbns_view left, pbns_view right) {
  return left.len == right.len &&
         (left.len == 0U || equal(left.ptr, right.ptr, left.len));
}

static bool common_valid(const pbns_enrollment_common_context *context,
                         uint64_t stage, uint64_t sequence) {
  return context != NULL &&
         nonzero(context->request_id, sizeof(context->request_id)) &&
         nonzero(context->host_fingerprint,
                 sizeof(context->host_fingerprint)) &&
         nonzero(context->nonce, sizeof(context->nonce)) &&
         context->stage == stage && context->sequence == sequence &&
         view_valid(context->key_id) && context->key_id.len > 0U &&
         context->key_id.len <= PBNS_ENROLLMENT_KEY_ID_MAX_SIZE;
}

static void encode_common(QCBOREncodeContext *encoder,
                          const pbns_enrollment_common_context *context) {
  QCBOREncode_OpenMapInMapN(encoder, 1);
  QCBOREncode_AddSZStringToMapN(encoder, 1, PBNS_ENROLLMENT_DOMAIN);
  QCBOREncode_AddUInt64ToMapN(encoder, 2, PBNS_ENROLLMENT_VERSION);
  QCBOREncode_AddUInt64ToMapN(encoder, 3, PBNS_ENROLLMENT_SERVICE);
  QCBOREncode_AddBytesToMapN(
      encoder, 4,
      (UsefulBufC){context->request_id, sizeof(context->request_id)});
  QCBOREncode_AddBytesToMapN(encoder, 5,
                             (UsefulBufC){context->host_fingerprint,
                                          sizeof(context->host_fingerprint)});
  QCBOREncode_AddBytesToMapN(
      encoder, 6, (UsefulBufC){context->nonce, sizeof(context->nonce)});
  QCBOREncode_AddUInt64ToMapN(encoder, 7, context->stage);
  QCBOREncode_AddUInt64ToMapN(encoder, 8, context->sequence);
  QCBOREncode_AddBytesToMapN(
      encoder, 9, (UsefulBufC){context->key_id.ptr, context->key_id.len});
  QCBOREncode_CloseMap(encoder);
}

static pbns_status finish(QCBOREncodeContext *encoder, size_t *written) {
  UsefulBufC encoded = {0};
  const QCBORError error = QCBOREncode_Finish(encoder, &encoded);
  if (error == QCBOR_ERR_BUFFER_TOO_SMALL) {
    return PBNS_ERR_LIMIT;
  }
  if (error != QCBOR_SUCCESS || encoded.len == 0U ||
      encoded.len > PBNS_ENROLLMENT_OBJECT_MAX_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  *written = encoded.len;
  return PBNS_OK;
}

static pbns_status begin_encode(pbns_buffer *output, size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  if (output == NULL || !output_valid(*output) || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (output->cap > PBNS_ENROLLMENT_OBJECT_MAX_SIZE) {
    output->cap = PBNS_ENROLLMENT_OBJECT_MAX_SIZE;
  }
  return PBNS_OK;
}

pbns_status
pbns_enrollment_software_init_encode(const pbns_enrollment_software_init *value,
                                     pbns_buffer output, size_t *written) {
  if (begin_encode(&output, written) != PBNS_OK || value == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!common_valid(&value->context, PBNS_ENROLLMENT_STAGE_INIT, 0U) ||
      !nonzero(value->token, sizeof(value->token)) ||
      !view_valid(value->identity_cose_key) ||
      value->identity_cose_key.len == 0U ||
      value->identity_cose_key.len > PBNS_ENROLLMENT_PUBLIC_KEY_MAX_SIZE ||
      !nonzero(value->initial_evidence_digest,
               sizeof(value->initial_evidence_digest)) ||
      !equal(value->host_nonce, value->context.nonce,
             sizeof(value->host_nonce))) {
    return PBNS_ERR_FORMAT;
  }
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  encode_common(&encoder, &value->context);
  QCBOREncode_AddBytesToMapN(&encoder, 10,
                             (UsefulBufC){value->token, sizeof(value->token)});
  QCBOREncode_AddBytesToMapN(&encoder, 11, NULLUsefulBufC);
  QCBOREncode_OpenArrayInMapN(&encoder, 12);
  QCBOREncode_CloseArray(&encoder);
  QCBOREncode_AddBytesToMapN(&encoder, 13, NULLUsefulBufC);
  QCBOREncode_AddBytesToMapN(&encoder, 14, NULLUsefulBufC);
  QCBOREncode_AddBytesToMapN(
      &encoder, 15,
      (UsefulBufC){value->identity_cose_key.ptr, value->identity_cose_key.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 16,
      (UsefulBufC){value->initial_evidence_digest,
                   sizeof(value->initial_evidence_digest)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 17, (UsefulBufC){value->host_nonce, sizeof(value->host_nonce)});
  QCBOREncode_AddUInt64ToMapN(&encoder, 18, PBNS_ENROLLMENT_FLOW_SOFTWARE);
  QCBOREncode_AddBytesToMapN(&encoder, 19, NULLUsefulBufC);
  QCBOREncode_AddBytesToMapN(&encoder, 20, NULLUsefulBufC);
  QCBOREncode_AddBytesToMapN(&encoder, 21, NULLUsefulBufC);
  QCBOREncode_AddBytesToMapN(&encoder, 22, NULLUsefulBufC);
  QCBOREncode_CloseMap(&encoder);
  return finish(&encoder, written);
}

pbns_status
pbns_enrollment_tpm_init_encode(const pbns_enrollment_tpm_init *value,
                                pbns_buffer output, size_t *written) {
  if (begin_encode(&output, written) != PBNS_OK || value == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!common_valid(&value->context, PBNS_ENROLLMENT_STAGE_INIT, 0U) ||
      !nonzero(value->token, sizeof(value->token)) ||
      !view_valid(value->ek_public) || value->ek_public.len == 0U ||
      value->ek_public.len > PBNS_ENROLLMENT_PUBLIC_KEY_MAX_SIZE ||
      !view_valid(value->ak_public) || value->ak_public.len == 0U ||
      value->ak_public.len > PBNS_ENROLLMENT_PUBLIC_KEY_MAX_SIZE ||
      !view_valid(value->ak_name) || value->ak_name.len == 0U ||
      value->ak_name.len > 64U || !view_valid(value->ek_certificate) ||
      value->ek_certificate.len > PBNS_ENROLLMENT_PUBLIC_KEY_MAX_SIZE ||
      !view_valid(value->identity_cose_key) ||
      value->identity_cose_key.len == 0U ||
      value->identity_cose_key.len > PBNS_ENROLLMENT_PUBLIC_KEY_MAX_SIZE ||
      !view_valid(value->identity_tpm_public) ||
      value->identity_tpm_public.len == 0U ||
      value->identity_tpm_public.len > PBNS_ENROLLMENT_PUBLIC_KEY_MAX_SIZE ||
      !nonzero(value->initial_evidence_digest,
               sizeof(value->initial_evidence_digest)) ||
      !equal(value->host_nonce, value->context.nonce,
             sizeof(value->host_nonce))) {
    return PBNS_ERR_FORMAT;
  }
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  encode_common(&encoder, &value->context);
  QCBOREncode_AddBytesToMapN(&encoder, 10,
                             (UsefulBufC){value->token, sizeof(value->token)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 11, (UsefulBufC){value->ek_public.ptr, value->ek_public.len});
  QCBOREncode_OpenArrayInMapN(&encoder, 12);
  if (value->ek_certificate.len > 0U) {
    QCBOREncode_AddBytes(&encoder, (UsefulBufC){value->ek_certificate.ptr,
                                                value->ek_certificate.len});
  }
  QCBOREncode_CloseArray(&encoder);
  QCBOREncode_AddBytesToMapN(
      &encoder, 13, (UsefulBufC){value->ak_public.ptr, value->ak_public.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 14, (UsefulBufC){value->ak_name.ptr, value->ak_name.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 15,
      (UsefulBufC){value->identity_cose_key.ptr, value->identity_cose_key.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 16,
      (UsefulBufC){value->initial_evidence_digest,
                   sizeof(value->initial_evidence_digest)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 17, (UsefulBufC){value->host_nonce, sizeof(value->host_nonce)});
  QCBOREncode_AddUInt64ToMapN(&encoder, 18, PBNS_ENROLLMENT_FLOW_TPM);
  QCBOREncode_AddBytesToMapN(&encoder, 19, NULLUsefulBufC);
  QCBOREncode_AddBytesToMapN(&encoder, 20, NULLUsefulBufC);
  QCBOREncode_AddBytesToMapN(&encoder, 21, NULLUsefulBufC);
  QCBOREncode_AddBytesToMapN(&encoder, 22,
                             (UsefulBufC){value->identity_tpm_public.ptr,
                                          value->identity_tpm_public.len});
  QCBOREncode_CloseMap(&encoder);
  return finish(&encoder, written);
}

static pbns_status
challenge_encode_unchecked(const pbns_enrollment_challenge_object *value,
                           pbns_buffer output, size_t *written) {
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  encode_common(&encoder, &value->context);
  QCBOREncode_AddBytesToMapN(
      &encoder, 20, (UsefulBufC){value->host_nonce, sizeof(value->host_nonce)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 21,
      (UsefulBufC){value->server_nonce, sizeof(value->server_nonce)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 22,
      (UsefulBufC){value->init_digest, sizeof(value->init_digest)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 23,
      (UsefulBufC){value->credential_blob.ptr, value->credential_blob.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 24,
      (UsefulBufC){value->encrypted_secret.ptr, value->encrypted_secret.len});
  QCBOREncode_AddUInt64ToMapN(&encoder, 25, value->flow);
  QCBOREncode_CloseMap(&encoder);
  return finish(&encoder, written);
}

static bool challenge_valid(const pbns_enrollment_challenge_object *value) {
  return value != NULL &&
         common_valid(&value->context, PBNS_ENROLLMENT_STAGE_CHALLENGE, 0U) &&
         equal(value->host_nonce, value->context.nonce,
               sizeof(value->host_nonce)) &&
         nonzero(value->server_nonce, sizeof(value->server_nonce)) &&
         nonzero(value->init_digest, sizeof(value->init_digest)) &&
         view_valid(value->credential_blob) &&
         view_valid(value->encrypted_secret) &&
         (value->flow == PBNS_ENROLLMENT_FLOW_SOFTWARE ||
          value->flow == PBNS_ENROLLMENT_FLOW_TPM) &&
         (value->flow != PBNS_ENROLLMENT_FLOW_SOFTWARE ||
          (value->credential_blob.len == 0U &&
           value->encrypted_secret.len == 0U));
}

pbns_status
pbns_enrollment_challenge_encode(const pbns_enrollment_challenge_object *value,
                                 pbns_buffer output, size_t *written) {
  if (begin_encode(&output, written) != PBNS_OK || value == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!challenge_valid(value)) {
    return PBNS_ERR_FORMAT;
  }
  return challenge_encode_unchecked(value, output, written);
}

static pbns_status decode_common(QCBORDecodeContext *decoder,
                                 pbns_enrollment_common_context *context) {
  UsefulBufC domain = {0};
  UsefulBufC request_id = {0};
  UsefulBufC fingerprint = {0};
  UsefulBufC nonce = {0};
  UsefulBufC key_id = {0};
  uint64_t version = 0U;
  uint64_t service = 0U;
  QCBORDecode_EnterMapFromMapN(decoder, 1);
  QCBORDecode_GetTextStringInMapN(decoder, 1, &domain);
  QCBORDecode_GetUInt64InMapN(decoder, 2, &version);
  QCBORDecode_GetUInt64InMapN(decoder, 3, &service);
  QCBORDecode_GetByteStringInMapN(decoder, 4, &request_id);
  QCBORDecode_GetByteStringInMapN(decoder, 5, &fingerprint);
  QCBORDecode_GetByteStringInMapN(decoder, 6, &nonce);
  QCBORDecode_GetUInt64InMapN(decoder, 7, &context->stage);
  QCBORDecode_GetUInt64InMapN(decoder, 8, &context->sequence);
  QCBORDecode_GetByteStringInMapN(decoder, 9, &key_id);
  QCBORDecode_ExitMap(decoder);
  static const uint8_t expected_domain[] = PBNS_ENROLLMENT_DOMAIN;
  if (version != PBNS_ENROLLMENT_VERSION ||
      service != PBNS_ENROLLMENT_SERVICE ||
      domain.len != sizeof(expected_domain) - 1U ||
      memcmp(domain.ptr, expected_domain, sizeof(expected_domain) - 1U) != 0 ||
      request_id.len != sizeof(context->request_id) ||
      fingerprint.len != sizeof(context->host_fingerprint) ||
      nonce.len != sizeof(context->nonce) || key_id.len == 0U ||
      key_id.len > PBNS_ENROLLMENT_KEY_ID_MAX_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  memcpy(context->request_id, request_id.ptr, request_id.len);
  memcpy(context->host_fingerprint, fingerprint.ptr, fingerprint.len);
  memcpy(context->nonce, nonce.ptr, nonce.len);
  context->key_id = (pbns_view){key_id.ptr, key_id.len};
  return PBNS_OK;
}

static bool buffers_overlap(pbns_view input, pbns_buffer output) {
  if (input.len == 0U || output.cap == 0U) {
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

static pbns_status decode_inputs(pbns_view encoded, pbns_view expected_key_id,
                                 pbns_buffer scratch, const void *output) {
  if (!view_valid(encoded) || encoded.len == 0U ||
      encoded.len > PBNS_ENROLLMENT_OBJECT_MAX_SIZE ||
      !view_valid(expected_key_id) || expected_key_id.len == 0U ||
      expected_key_id.len > PBNS_ENROLLMENT_KEY_ID_MAX_SIZE ||
      !output_valid(scratch) || scratch.cap < encoded.len || output == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  return buffers_overlap(encoded, scratch) ? PBNS_ERR_ARGUMENT : PBNS_OK;
}

pbns_status pbns_enrollment_challenge_decode(
    pbns_view encoded, pbns_view expected_signing_key_id,
    pbns_buffer canonical_scratch, pbns_enrollment_challenge_object *value) {
  if (value != NULL) {
    *value = (pbns_enrollment_challenge_object){0};
  }
  pbns_status status =
      decode_inputs(encoded, expected_signing_key_id, canonical_scratch, value);
  if (status != PBNS_OK) {
    return status;
  }
  pbns_enrollment_challenge_object decoded = {0};
  QCBORDecodeContext decoder = {0};
  QCBORDecode_Init(&decoder, (UsefulBufC){encoded.ptr, encoded.len},
                   QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterMap(&decoder, NULL);
  status = decode_common(&decoder, &decoded.context);
  UsefulBufC host_nonce = {0};
  UsefulBufC server_nonce = {0};
  UsefulBufC init_digest = {0};
  UsefulBufC credential = {0};
  UsefulBufC encrypted = {0};
  QCBORDecode_GetByteStringInMapN(&decoder, 20, &host_nonce);
  QCBORDecode_GetByteStringInMapN(&decoder, 21, &server_nonce);
  QCBORDecode_GetByteStringInMapN(&decoder, 22, &init_digest);
  QCBORDecode_GetByteStringInMapN(&decoder, 23, &credential);
  QCBORDecode_GetByteStringInMapN(&decoder, 24, &encrypted);
  QCBORDecode_GetUInt64InMapN(&decoder, 25, &decoded.flow);
  QCBORDecode_ExitMap(&decoder);
  if (QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS || status != PBNS_OK ||
      host_nonce.len != sizeof(decoded.host_nonce) ||
      server_nonce.len != sizeof(decoded.server_nonce) ||
      init_digest.len != sizeof(decoded.init_digest)) {
    return PBNS_ERR_FORMAT;
  }
  memcpy(decoded.host_nonce, host_nonce.ptr, host_nonce.len);
  memcpy(decoded.server_nonce, server_nonce.ptr, server_nonce.len);
  memcpy(decoded.init_digest, init_digest.ptr, init_digest.len);
  decoded.credential_blob = (pbns_view){credential.ptr, credential.len};
  decoded.encrypted_secret = (pbns_view){encrypted.ptr, encrypted.len};
  if (!challenge_valid(&decoded)) {
    return PBNS_ERR_FORMAT;
  }
  size_t canonical_size = 0U;
  status =
      challenge_encode_unchecked(&decoded, canonical_scratch, &canonical_size);
  if (status != PBNS_OK || canonical_size != encoded.len ||
      memcmp(canonical_scratch.ptr, encoded.ptr, encoded.len) != 0) {
    return PBNS_ERR_FORMAT;
  }
  if (!view_equal(decoded.context.key_id, expected_signing_key_id)) {
    return PBNS_ERR_AUTHENTICATION;
  }
  *value = decoded;
  return PBNS_OK;
}

pbns_status pbns_enrollment_software_proof_encode(
    const pbns_enrollment_software_proof *value, pbns_buffer output,
    size_t *written) {
  if (begin_encode(&output, written) != PBNS_OK || value == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!common_valid(&value->context, PBNS_ENROLLMENT_STAGE_PROOF, 1U) ||
      !nonzero(value->server_nonce, sizeof(value->server_nonce)) ||
      !nonzero(value->init_digest, sizeof(value->init_digest)) ||
      !nonzero(value->baseline_digest, sizeof(value->baseline_digest)) ||
      !view_valid(value->baseline_evidence) ||
      value->baseline_evidence.len == 0U ||
      value->baseline_evidence.len > PBNS_ENROLLMENT_BASELINE_MAX_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  encode_common(&encoder, &value->context);
  QCBOREncode_AddBytesToMapN(
      &encoder, 30,
      (UsefulBufC){value->server_nonce, sizeof(value->server_nonce)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 31,
      (UsefulBufC){value->init_digest, sizeof(value->init_digest)});
  QCBOREncode_AddBytesToMapN(&encoder, 32, NULLUsefulBufC);
  QCBOREncode_AddBytesToMapN(&encoder, 33, NULLUsefulBufC);
  QCBOREncode_AddBytesToMapN(&encoder, 34, NULLUsefulBufC);
  QCBOREncode_AddBytesToMapN(
      &encoder, 35,
      (UsefulBufC){value->baseline_digest, sizeof(value->baseline_digest)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 36,
      (UsefulBufC){value->baseline_evidence.ptr, value->baseline_evidence.len});
  QCBOREncode_AddUInt64ToMapN(&encoder, 37, PBNS_ENROLLMENT_FLOW_SOFTWARE);
  QCBOREncode_CloseMap(&encoder);
  return finish(&encoder, written);
}

pbns_status
pbns_enrollment_tpm_proof_encode(const pbns_enrollment_tpm_proof *value,
                                 pbns_buffer output, size_t *written) {
  if (begin_encode(&output, written) != PBNS_OK || value == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!common_valid(&value->context, PBNS_ENROLLMENT_STAGE_PROOF, 1U) ||
      !nonzero(value->server_nonce, sizeof(value->server_nonce)) ||
      !nonzero(value->init_digest, sizeof(value->init_digest)) ||
      !view_valid(value->activated_credential) ||
      value->activated_credential.len == 0U ||
      value->activated_credential.len > 64U ||
      !view_valid(value->certify_attestation) ||
      value->certify_attestation.len == 0U ||
      value->certify_attestation.len > 2048U ||
      !view_valid(value->certify_signature) ||
      value->certify_signature.len == 0U ||
      value->certify_signature.len > 512U ||
      !nonzero(value->baseline_digest, sizeof(value->baseline_digest)) ||
      !view_valid(value->baseline_evidence) ||
      value->baseline_evidence.len == 0U ||
      value->baseline_evidence.len > PBNS_ENROLLMENT_BASELINE_MAX_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  encode_common(&encoder, &value->context);
  QCBOREncode_AddBytesToMapN(
      &encoder, 30,
      (UsefulBufC){value->server_nonce, sizeof(value->server_nonce)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 31,
      (UsefulBufC){value->init_digest, sizeof(value->init_digest)});
  QCBOREncode_AddBytesToMapN(&encoder, 32,
                             (UsefulBufC){value->activated_credential.ptr,
                                          value->activated_credential.len});
  QCBOREncode_AddBytesToMapN(&encoder, 33,
                             (UsefulBufC){value->certify_attestation.ptr,
                                          value->certify_attestation.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 34,
      (UsefulBufC){value->certify_signature.ptr, value->certify_signature.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 35,
      (UsefulBufC){value->baseline_digest, sizeof(value->baseline_digest)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 36,
      (UsefulBufC){value->baseline_evidence.ptr, value->baseline_evidence.len});
  QCBOREncode_AddUInt64ToMapN(&encoder, 37, PBNS_ENROLLMENT_FLOW_TPM);
  QCBOREncode_CloseMap(&encoder);
  return finish(&encoder, written);
}

static bool receipt_valid(const pbns_enrollment_receipt_object *value) {
  return value != NULL &&
         common_valid(&value->context, PBNS_ENROLLMENT_STAGE_RECEIPT, 2U) &&
         nonzero(value->fingerprint, sizeof(value->fingerprint)) &&
         view_valid(value->assurance) && value->assurance.len > 0U &&
         value->assurance.len <= 64U &&
         nonzero(value->baseline_digest, sizeof(value->baseline_digest)) &&
         value->enrolled_at_unix > 0 && view_valid(value->key_id) &&
         view_equal(value->context.key_id, value->key_id);
}

static pbns_status
receipt_encode_unchecked(const pbns_enrollment_receipt_object *value,
                         pbns_buffer output, size_t *written) {
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  encode_common(&encoder, &value->context);
  QCBOREncode_AddBytesToMapN(
      &encoder, 40,
      (UsefulBufC){value->fingerprint, sizeof(value->fingerprint)});
  QCBOREncode_AddTextToMapN(
      &encoder, 41, (UsefulBufC){value->assurance.ptr, value->assurance.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 42,
      (UsefulBufC){value->baseline_digest, sizeof(value->baseline_digest)});
  QCBOREncode_AddInt64ToMapN(&encoder, 43, value->enrolled_at_unix);
  QCBOREncode_AddBytesToMapN(
      &encoder, 44, (UsefulBufC){value->key_id.ptr, value->key_id.len});
  QCBOREncode_CloseMap(&encoder);
  return finish(&encoder, written);
}

pbns_status
pbns_enrollment_receipt_encode(const pbns_enrollment_receipt_object *value,
                               pbns_buffer output, size_t *written) {
  if (begin_encode(&output, written) != PBNS_OK || value == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!receipt_valid(value)) {
    return PBNS_ERR_FORMAT;
  }
  return receipt_encode_unchecked(value, output, written);
}

pbns_status pbns_enrollment_receipt_decode(
    pbns_view encoded, pbns_view expected_signing_key_id,
    pbns_buffer canonical_scratch, pbns_enrollment_receipt_object *value) {
  if (value != NULL) {
    *value = (pbns_enrollment_receipt_object){0};
  }
  pbns_status status =
      decode_inputs(encoded, expected_signing_key_id, canonical_scratch, value);
  if (status != PBNS_OK) {
    return status;
  }
  pbns_enrollment_receipt_object decoded = {0};
  QCBORDecodeContext decoder = {0};
  QCBORDecode_Init(&decoder, (UsefulBufC){encoded.ptr, encoded.len},
                   QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterMap(&decoder, NULL);
  status = decode_common(&decoder, &decoded.context);
  UsefulBufC fingerprint = {0};
  UsefulBufC assurance = {0};
  UsefulBufC baseline_digest = {0};
  UsefulBufC key_id = {0};
  QCBORDecode_GetByteStringInMapN(&decoder, 40, &fingerprint);
  QCBORDecode_GetTextStringInMapN(&decoder, 41, &assurance);
  QCBORDecode_GetByteStringInMapN(&decoder, 42, &baseline_digest);
  QCBORDecode_GetInt64InMapN(&decoder, 43, &decoded.enrolled_at_unix);
  QCBORDecode_GetByteStringInMapN(&decoder, 44, &key_id);
  QCBORDecode_ExitMap(&decoder);
  if (QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS || status != PBNS_OK ||
      fingerprint.len != sizeof(decoded.fingerprint) ||
      baseline_digest.len != sizeof(decoded.baseline_digest)) {
    return PBNS_ERR_FORMAT;
  }
  memcpy(decoded.fingerprint, fingerprint.ptr, fingerprint.len);
  decoded.assurance = (pbns_view){assurance.ptr, assurance.len};
  memcpy(decoded.baseline_digest, baseline_digest.ptr, baseline_digest.len);
  decoded.key_id = (pbns_view){key_id.ptr, key_id.len};
  if (!receipt_valid(&decoded)) {
    return PBNS_ERR_FORMAT;
  }
  size_t canonical_size = 0U;
  status =
      receipt_encode_unchecked(&decoded, canonical_scratch, &canonical_size);
  if (status != PBNS_OK || canonical_size != encoded.len ||
      memcmp(canonical_scratch.ptr, encoded.ptr, encoded.len) != 0) {
    return PBNS_ERR_FORMAT;
  }
  if (!view_equal(decoded.context.key_id, expected_signing_key_id) ||
      !view_equal(decoded.key_id, expected_signing_key_id)) {
    return PBNS_ERR_AUTHENTICATION;
  }
  *value = decoded;
  return PBNS_OK;
}

static bool envelope_valid(const pbns_enrollment_encrypted_envelope *value) {
  return value != NULL &&
         nonzero(value->request_id, sizeof(value->request_id)) &&
         nonzero(value->host_nonce, sizeof(value->host_nonce)) &&
         view_valid(value->recipient_key_id) &&
         value->recipient_key_id.len > 0U &&
         value->recipient_key_id.len <= PBNS_ENROLLMENT_KEY_ID_MAX_SIZE &&
         view_valid(value->ciphertext) && value->ciphertext.len > 0U &&
         value->ciphertext.len <= PBNS_ENROLLMENT_OBJECT_MAX_SIZE;
}

static pbns_status
envelope_encode_unchecked(const pbns_enrollment_encrypted_envelope *value,
                          pbns_buffer output, size_t *written) {
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddBytesToMapN(
      &encoder, 1, (UsefulBufC){value->request_id, sizeof(value->request_id)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 2, (UsefulBufC){value->host_nonce, sizeof(value->host_nonce)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 3,
      (UsefulBufC){value->recipient_key_id.ptr, value->recipient_key_id.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 4, (UsefulBufC){value->ciphertext.ptr, value->ciphertext.len});
  QCBOREncode_CloseMap(&encoder);
  return finish(&encoder, written);
}

pbns_status
pbns_enrollment_envelope_encode(const pbns_enrollment_encrypted_envelope *value,
                                pbns_buffer output, size_t *written) {
  if (begin_encode(&output, written) != PBNS_OK || value == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!envelope_valid(value)) {
    return PBNS_ERR_FORMAT;
  }
  return envelope_encode_unchecked(value, output, written);
}

pbns_status pbns_enrollment_envelope_decode(
    pbns_view encoded, pbns_view expected_recipient_key_id,
    pbns_buffer canonical_scratch, pbns_enrollment_encrypted_envelope *value) {
  if (value != NULL) {
    *value = (pbns_enrollment_encrypted_envelope){0};
  }
  pbns_status status = decode_inputs(encoded, expected_recipient_key_id,
                                     canonical_scratch, value);
  if (status != PBNS_OK) {
    return status;
  }
  pbns_enrollment_encrypted_envelope decoded = {0};
  UsefulBufC request_id = {0};
  UsefulBufC host_nonce = {0};
  UsefulBufC recipient_key_id = {0};
  UsefulBufC ciphertext = {0};
  QCBORDecodeContext decoder = {0};
  QCBORDecode_Init(&decoder, (UsefulBufC){encoded.ptr, encoded.len},
                   QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterMap(&decoder, NULL);
  QCBORDecode_GetByteStringInMapN(&decoder, 1, &request_id);
  QCBORDecode_GetByteStringInMapN(&decoder, 2, &host_nonce);
  QCBORDecode_GetByteStringInMapN(&decoder, 3, &recipient_key_id);
  QCBORDecode_GetByteStringInMapN(&decoder, 4, &ciphertext);
  QCBORDecode_ExitMap(&decoder);
  if (QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS ||
      request_id.len != sizeof(decoded.request_id) ||
      host_nonce.len != sizeof(decoded.host_nonce)) {
    return PBNS_ERR_FORMAT;
  }
  memcpy(decoded.request_id, request_id.ptr, request_id.len);
  memcpy(decoded.host_nonce, host_nonce.ptr, host_nonce.len);
  decoded.recipient_key_id =
      (pbns_view){recipient_key_id.ptr, recipient_key_id.len};
  decoded.ciphertext = (pbns_view){ciphertext.ptr, ciphertext.len};
  if (!envelope_valid(&decoded)) {
    return PBNS_ERR_FORMAT;
  }
  size_t canonical_size = 0U;
  status =
      envelope_encode_unchecked(&decoded, canonical_scratch, &canonical_size);
  if (status != PBNS_OK || canonical_size != encoded.len ||
      memcmp(canonical_scratch.ptr, encoded.ptr, encoded.len) != 0) {
    return PBNS_ERR_FORMAT;
  }
  if (!view_equal(decoded.recipient_key_id, expected_recipient_key_id)) {
    return PBNS_ERR_AUTHENTICATION;
  }
  *value = decoded;
  return PBNS_OK;
}

static pbns_status
wire_encode_unchecked(const pbns_enrollment_wire_object *value,
                      pbns_buffer output, size_t *written) {
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddUInt64ToMapN(&encoder, 1, value->operation);
  QCBOREncode_AddBytesToMapN(
      &encoder, 2, (UsefulBufC){value->object.ptr, value->object.len});
  QCBOREncode_CloseMap(&encoder);
  return finish(&encoder, written);
}

pbns_status
pbns_enrollment_wire_object_encode(const pbns_enrollment_wire_object *value,
                                   pbns_buffer output, size_t *written) {
  if (begin_encode(&output, written) != PBNS_OK || value == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if ((value->operation != 1U && value->operation != 2U) ||
      !view_valid(value->object) || value->object.len == 0U ||
      value->object.len > PBNS_ENROLLMENT_OBJECT_MAX_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  return wire_encode_unchecked(value, output, written);
}

pbns_status pbns_enrollment_wire_object_decode(
    pbns_view encoded, uint64_t expected_operation,
    pbns_buffer canonical_scratch, pbns_enrollment_wire_object *value) {
  if (value != NULL) {
    *value = (pbns_enrollment_wire_object){0};
  }
  static const uint8_t expected_key[] = {1U};
  const pbns_view nonempty = {expected_key, sizeof(expected_key)};
  pbns_status status =
      decode_inputs(encoded, nonempty, canonical_scratch, value);
  if (status != PBNS_OK ||
      (expected_operation != 1U && expected_operation != 2U)) {
    return status != PBNS_OK ? status : PBNS_ERR_ARGUMENT;
  }
  pbns_enrollment_wire_object decoded = {0};
  UsefulBufC object = {0};
  QCBORDecodeContext decoder = {0};
  QCBORDecode_Init(&decoder, (UsefulBufC){encoded.ptr, encoded.len},
                   QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterMap(&decoder, NULL);
  QCBORDecode_GetUInt64InMapN(&decoder, 1, &decoded.operation);
  QCBORDecode_GetByteStringInMapN(&decoder, 2, &object);
  QCBORDecode_ExitMap(&decoder);
  if (QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS || object.len == 0U ||
      object.len > PBNS_ENROLLMENT_OBJECT_MAX_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  decoded.object = (pbns_view){object.ptr, object.len};
  size_t canonical_size = 0U;
  status = wire_encode_unchecked(&decoded, canonical_scratch, &canonical_size);
  if (status != PBNS_OK || canonical_size != encoded.len ||
      memcmp(canonical_scratch.ptr, encoded.ptr, encoded.len) != 0) {
    return PBNS_ERR_FORMAT;
  }
  if (decoded.operation != expected_operation) {
    return PBNS_ERR_SERVICE;
  }
  *value = decoded;
  return PBNS_OK;
}

static pbns_status append_part(pbns_buffer output, size_t *offset,
                               const uint8_t *data, size_t length) {
  if (length > output.cap - *offset) {
    return PBNS_ERR_LIMIT;
  }
  if (length > 0U) {
    memcpy(output.ptr + *offset, data, length);
  }
  *offset += length;
  return PBNS_OK;
}

static pbns_status aad_begin(pbns_buffer output, size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  if (!output_valid(output) || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  return PBNS_OK;
}

pbns_status pbns_enrollment_envelope_aad(
    const uint8_t request_id[PBNS_ENROLLMENT_REQUEST_ID_SIZE],
    const uint8_t host_nonce[PBNS_ENROLLMENT_NONCE_SIZE], pbns_view key_id,
    pbns_buffer output, size_t *written) {
  static const uint8_t prefix[] = "PBNS-ENROLLMENT-ENVELOPE-v1";
  if (aad_begin(output, written) != PBNS_OK || request_id == NULL ||
      host_nonce == NULL ||
      !nonzero(request_id, PBNS_ENROLLMENT_REQUEST_ID_SIZE) ||
      !nonzero(host_nonce, PBNS_ENROLLMENT_NONCE_SIZE) || !view_valid(key_id) ||
      key_id.len == 0U || key_id.len > PBNS_ENROLLMENT_KEY_ID_MAX_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  size_t offset = 0U;
  pbns_status status =
      append_part(output, &offset, prefix, sizeof(prefix) - 1U);
  if (status == PBNS_OK) {
    status = append_part(output, &offset, request_id,
                         PBNS_ENROLLMENT_REQUEST_ID_SIZE);
  }
  if (status == PBNS_OK) {
    status =
        append_part(output, &offset, host_nonce, PBNS_ENROLLMENT_NONCE_SIZE);
  }
  if (status == PBNS_OK) {
    status = append_part(output, &offset, key_id.ptr, key_id.len);
  }
  if (status == PBNS_OK) {
    *written = offset;
  }
  return status;
}

pbns_status
pbns_enrollment_challenge_aad(const pbns_enrollment_challenge_object *challenge,
                              pbns_buffer output, size_t *written) {
  static const uint8_t prefix[] = "PBNS-ENROLLMENT-CHALLENGE-v1";
  if (aad_begin(output, written) != PBNS_OK || !challenge_valid(challenge)) {
    return PBNS_ERR_ARGUMENT;
  }
  size_t offset = 0U;
  const struct {
    const uint8_t *data;
    size_t length;
  } parts[] = {
      {prefix, sizeof(prefix) - 1U},
      {challenge->context.request_id, sizeof(challenge->context.request_id)},
      {challenge->host_nonce, sizeof(challenge->host_nonce)},
      {challenge->server_nonce, sizeof(challenge->server_nonce)},
      {challenge->init_digest, sizeof(challenge->init_digest)},
      {challenge->context.key_id.ptr, challenge->context.key_id.len},
  };
  for (size_t index = 0U; index < sizeof(parts) / sizeof(parts[0]); ++index) {
    const pbns_status status =
        append_part(output, &offset, parts[index].data, parts[index].length);
    if (status != PBNS_OK) {
      return status;
    }
  }
  *written = offset;
  return PBNS_OK;
}

pbns_status
pbns_enrollment_proof_aad(const pbns_enrollment_software_proof *proof,
                          pbns_buffer output, size_t *written) {
  static const uint8_t prefix[] = "PBNS-ENROLLMENT-PROOF-v1";
  if (aad_begin(output, written) != PBNS_OK || proof == NULL ||
      !common_valid(&proof->context, PBNS_ENROLLMENT_STAGE_PROOF, 1U) ||
      !nonzero(proof->server_nonce, sizeof(proof->server_nonce)) ||
      !nonzero(proof->init_digest, sizeof(proof->init_digest))) {
    return PBNS_ERR_ARGUMENT;
  }
  size_t offset = 0U;
  const struct {
    const uint8_t *data;
    size_t length;
  } parts[] = {
      {prefix, sizeof(prefix) - 1U},
      {proof->context.request_id, sizeof(proof->context.request_id)},
      {proof->context.nonce, sizeof(proof->context.nonce)},
      {proof->server_nonce, sizeof(proof->server_nonce)},
      {proof->init_digest, sizeof(proof->init_digest)},
      {proof->context.key_id.ptr, proof->context.key_id.len},
  };
  for (size_t index = 0U; index < sizeof(parts) / sizeof(parts[0]); ++index) {
    const pbns_status status =
        append_part(output, &offset, parts[index].data, parts[index].length);
    if (status != PBNS_OK) {
      return status;
    }
  }
  *written = offset;
  return PBNS_OK;
}

pbns_status
pbns_enrollment_tpm_proof_aad(const pbns_enrollment_tpm_proof *proof,
                              pbns_buffer output, size_t *written) {
  static const uint8_t prefix[] = "PBNS-ENROLLMENT-PROOF-v1";
  if (aad_begin(output, written) != PBNS_OK || proof == NULL ||
      !common_valid(&proof->context, PBNS_ENROLLMENT_STAGE_PROOF, 1U) ||
      !nonzero(proof->server_nonce, sizeof(proof->server_nonce)) ||
      !nonzero(proof->init_digest, sizeof(proof->init_digest))) {
    return PBNS_ERR_ARGUMENT;
  }
  size_t offset = 0U;
  const struct {
    const uint8_t *data;
    size_t length;
  } parts[] = {
      {prefix, sizeof(prefix) - 1U},
      {proof->context.request_id, sizeof(proof->context.request_id)},
      {proof->context.nonce, sizeof(proof->context.nonce)},
      {proof->server_nonce, sizeof(proof->server_nonce)},
      {proof->init_digest, sizeof(proof->init_digest)},
      {proof->context.key_id.ptr, proof->context.key_id.len},
  };
  for (size_t index = 0U; index < sizeof(parts) / sizeof(parts[0]); ++index) {
    const pbns_status status =
        append_part(output, &offset, parts[index].data, parts[index].length);
    if (status != PBNS_OK) {
      return status;
    }
  }
  *written = offset;
  return PBNS_OK;
}

pbns_status pbns_enrollment_receipt_aad(
    const pbns_enrollment_receipt_object *receipt,
    const uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE], pbns_buffer output,
    size_t *written) {
  static const uint8_t prefix[] = "PBNS-ENROLLMENT-RECEIPT-v1";
  if (aad_begin(output, written) != PBNS_OK || !receipt_valid(receipt) ||
      server_nonce == NULL ||
      !nonzero(server_nonce, PBNS_ENROLLMENT_NONCE_SIZE)) {
    return PBNS_ERR_ARGUMENT;
  }
  size_t offset = 0U;
  const struct {
    const uint8_t *data;
    size_t length;
  } parts[] = {
      {prefix, sizeof(prefix) - 1U},
      {receipt->context.request_id, sizeof(receipt->context.request_id)},
      {receipt->context.nonce, sizeof(receipt->context.nonce)},
      {server_nonce, PBNS_ENROLLMENT_NONCE_SIZE},
      {receipt->fingerprint, sizeof(receipt->fingerprint)},
      {receipt->key_id.ptr, receipt->key_id.len},
  };
  for (size_t index = 0U; index < sizeof(parts) / sizeof(parts[0]); ++index) {
    const pbns_status status =
        append_part(output, &offset, parts[index].data, parts[index].length);
    if (status != PBNS_OK) {
      return status;
    }
  }
  *written = offset;
  return PBNS_OK;
}
