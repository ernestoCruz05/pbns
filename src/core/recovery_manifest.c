#include "pbns/recovery_manifest.h"

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

static bool bytes_equal(const uint8_t *left, const uint8_t *right,
                        size_t length) {
  if (left == NULL || right == NULL) {
    return false;
  }
  uint8_t difference = 0U;
  for (size_t index = 0U; index < length; ++index) {
    difference |= (uint8_t)(left[index] ^ right[index]);
  }
  return difference == 0U;
}

static bool views_equal(pbns_view left, pbns_view right) {
  return left.len == right.len &&
         (left.len == 0U || bytes_equal(left.ptr, right.ptr, left.len));
}

static bool ranges_overlap(pbns_view input, pbns_buffer output) {
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

static bool manifest_valid(const pbns_recovery_manifest *manifest) {
  return manifest != NULL &&
         nonzero(manifest->request_id, sizeof(manifest->request_id)) &&
         nonzero(manifest->host_binding, sizeof(manifest->host_binding)) &&
         nonzero(manifest->nonce, sizeof(manifest->nonce)) &&
         nonzero(manifest->artifact_digest,
                 sizeof(manifest->artifact_digest)) &&
         manifest->artifact_version > 0U &&
         manifest->artifact_version >= manifest->minimum_version &&
         manifest->image_size > 0U &&
         manifest->image_size <= PBNS_RECOVERY_MANIFEST_IMAGE_MAX &&
         manifest->chunk_size == PBNS_RECOVERY_MANIFEST_CHUNK_SIZE &&
         manifest->not_before_ns >= 0 &&
         manifest->not_before_ns < manifest->not_after_ns &&
         view_valid(manifest->policy_authorization) &&
         manifest->policy_authorization.len > 0U &&
         manifest->policy_authorization.len <=
             PBNS_RECOVERY_MANIFEST_POLICY_MAX_SIZE &&
         view_valid(manifest->policy_key_id) &&
         manifest->policy_key_id.len > 0U &&
         manifest->policy_key_id.len <= PBNS_RECOVERY_MANIFEST_KEY_ID_MAX_SIZE;
}

static bool
expectation_valid(const pbns_recovery_manifest_expectation *expectation) {
  return expectation != NULL &&
         nonzero(expectation->request_id, sizeof(expectation->request_id)) &&
         nonzero(expectation->host_binding,
                 sizeof(expectation->host_binding)) &&
         nonzero(expectation->nonce, sizeof(expectation->nonce)) &&
         view_valid(expectation->recovery_signing_key_id) &&
         expectation->recovery_signing_key_id.len > 0U &&
         expectation->recovery_signing_key_id.len <=
             PBNS_RECOVERY_MANIFEST_KEY_ID_MAX_SIZE &&
         view_valid(expectation->expected_policy_key_id) &&
         expectation->expected_policy_key_id.len > 0U &&
         expectation->expected_policy_key_id.len <=
             PBNS_RECOVERY_MANIFEST_KEY_ID_MAX_SIZE &&
         expectation->trusted_time.earliest_ns >= 0 &&
         expectation->trusted_time.earliest_ns <=
             expectation->trusted_time.latest_ns;
}

static void encode_context(QCBOREncodeContext *encoder,
                           const pbns_recovery_manifest *manifest) {
  QCBOREncode_OpenMapInMapN(encoder, 1);
  QCBOREncode_AddSZStringToMapN(encoder, 1, PBNS_RECOVERY_MANIFEST_DOMAIN);
  QCBOREncode_AddUInt64ToMapN(encoder, 2, PBNS_RECOVERY_MANIFEST_VERSION);
  QCBOREncode_AddUInt64ToMapN(encoder, 3, PBNS_RECOVERY_MANIFEST_SERVICE);
  QCBOREncode_AddBytesToMapN(
      encoder, 4,
      (UsefulBufC){manifest->request_id, sizeof(manifest->request_id)});
  QCBOREncode_AddBytesToMapN(
      encoder, 5,
      (UsefulBufC){manifest->host_binding, sizeof(manifest->host_binding)});
  QCBOREncode_AddBytesToMapN(
      encoder, 6, (UsefulBufC){manifest->nonce, sizeof(manifest->nonce)});
  QCBOREncode_AddInt64ToMapN(encoder, 7, manifest->not_before_ns);
  QCBOREncode_AddInt64ToMapN(encoder, 8, manifest->not_after_ns);
  QCBOREncode_AddBytesToMapN(encoder, 9, NULLUsefulBufC);
  QCBOREncode_CloseMap(encoder);
}

static pbns_status encode_unchecked(const pbns_recovery_manifest *manifest,
                                    pbns_buffer output, size_t *written) {
  QCBOREncodeContext encoder = {0};
  UsefulBufC encoded = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  encode_context(&encoder, manifest);
  QCBOREncode_AddBytesToMapN(&encoder, 10,
                             (UsefulBufC){manifest->artifact_digest,
                                          sizeof(manifest->artifact_digest)});
  QCBOREncode_AddUInt64ToMapN(&encoder, 11, manifest->artifact_version);
  QCBOREncode_AddSZStringToMapN(&encoder, 12, PBNS_RECOVERY_ARCHITECTURE);
  QCBOREncode_AddSZStringToMapN(&encoder, 13, PBNS_RECOVERY_FORMAT);
  QCBOREncode_AddUInt64ToMapN(&encoder, 14, manifest->image_size);
  QCBOREncode_AddUInt64ToMapN(&encoder, 15, manifest->chunk_size);
  QCBOREncode_AddUInt64ToMapN(&encoder, 16, manifest->minimum_version);
  QCBOREncode_AddInt64ToMapN(&encoder, 17, manifest->not_before_ns);
  QCBOREncode_AddInt64ToMapN(&encoder, 18, manifest->not_after_ns);
  QCBOREncode_AddBytesToMapN(&encoder, 19,
                             (UsefulBufC){manifest->policy_authorization.ptr,
                                          manifest->policy_authorization.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 20,
      (UsefulBufC){manifest->policy_key_id.ptr, manifest->policy_key_id.len});
  QCBOREncode_CloseMap(&encoder);
  const QCBORError error = QCBOREncode_Finish(&encoder, &encoded);
  if (error == QCBOR_ERR_BUFFER_TOO_SMALL) {
    return PBNS_ERR_LIMIT;
  }
  if (error != QCBOR_SUCCESS || encoded.len == 0U ||
      encoded.len > PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  *written = encoded.len;
  return PBNS_OK;
}

pbns_status
pbns_recovery_manifest_encode(const pbns_recovery_manifest *manifest,
                              pbns_buffer output, size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  if (manifest == NULL || !output_valid(output) || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!manifest_valid(manifest)) {
    return PBNS_ERR_FORMAT;
  }
  if (output.cap > PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE) {
    output.cap = PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE;
  }
  return encode_unchecked(manifest, output, written);
}

pbns_status pbns_recovery_manifest_aad(
    const pbns_recovery_manifest_expectation *expectation, pbns_buffer output,
    size_t *written) {
  static const uint8_t prefix[] = PBNS_RECOVERY_MANIFEST_AAD;
  if (written != NULL) {
    *written = 0U;
  }
  if (!expectation_valid(expectation) || !output_valid(output) ||
      written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  const size_t required =
      sizeof(prefix) - 1U + sizeof(expectation->request_id) +
      sizeof(expectation->host_binding) + sizeof(expectation->nonce) +
      expectation->recovery_signing_key_id.len;
  if (required > PBNS_RECOVERY_MANIFEST_AAD_MAX_SIZE || output.cap < required) {
    return PBNS_ERR_LIMIT;
  }
  size_t offset = 0U;
  memcpy(output.ptr + offset, prefix, sizeof(prefix) - 1U);
  offset += sizeof(prefix) - 1U;
  memcpy(output.ptr + offset, expectation->request_id,
         sizeof(expectation->request_id));
  offset += sizeof(expectation->request_id);
  memcpy(output.ptr + offset, expectation->host_binding,
         sizeof(expectation->host_binding));
  offset += sizeof(expectation->host_binding);
  memcpy(output.ptr + offset, expectation->nonce, sizeof(expectation->nonce));
  offset += sizeof(expectation->nonce);
  memcpy(output.ptr + offset, expectation->recovery_signing_key_id.ptr,
         expectation->recovery_signing_key_id.len);
  *written = required;
  return PBNS_OK;
}

static pbns_status decode_context(QCBORDecodeContext *decoder,
                                  pbns_recovery_manifest *manifest) {
  UsefulBufC domain = {0};
  UsefulBufC request_id = {0};
  UsefulBufC host_binding = {0};
  UsefulBufC nonce = {0};
  UsefulBufC body = {0};
  uint64_t version = 0U;
  uint64_t service = 0U;
  int64_t issued_at = 0;
  int64_t expires_at = 0;
  QCBORDecode_EnterMapFromMapN(decoder, 1);
  QCBORDecode_GetTextStringInMapN(decoder, 1, &domain);
  QCBORDecode_GetUInt64InMapN(decoder, 2, &version);
  QCBORDecode_GetUInt64InMapN(decoder, 3, &service);
  QCBORDecode_GetByteStringInMapN(decoder, 4, &request_id);
  QCBORDecode_GetByteStringInMapN(decoder, 5, &host_binding);
  QCBORDecode_GetByteStringInMapN(decoder, 6, &nonce);
  QCBORDecode_GetInt64InMapN(decoder, 7, &issued_at);
  QCBORDecode_GetInt64InMapN(decoder, 8, &expires_at);
  QCBORDecode_GetByteStringInMapN(decoder, 9, &body);
  QCBORDecode_ExitMap(decoder);
  static const uint8_t expected_domain[] = PBNS_RECOVERY_MANIFEST_DOMAIN;
  if (domain.len != sizeof(expected_domain) - 1U ||
      memcmp(domain.ptr, expected_domain, sizeof(expected_domain) - 1U) != 0 ||
      version != PBNS_RECOVERY_MANIFEST_VERSION ||
      service != PBNS_RECOVERY_MANIFEST_SERVICE ||
      request_id.len != sizeof(manifest->request_id) ||
      host_binding.len != sizeof(manifest->host_binding) ||
      nonce.len != sizeof(manifest->nonce) || body.len != 0U || issued_at < 0 ||
      issued_at >= expires_at) {
    return PBNS_ERR_FORMAT;
  }
  memcpy(manifest->request_id, request_id.ptr, request_id.len);
  memcpy(manifest->host_binding, host_binding.ptr, host_binding.len);
  memcpy(manifest->nonce, nonce.ptr, nonce.len);
  manifest->not_before_ns = issued_at;
  manifest->not_after_ns = expires_at;
  return PBNS_OK;
}

static pbns_status decode_manifest(pbns_view encoded,
                                   pbns_recovery_manifest *manifest) {
  QCBORDecodeContext decoder = {0};
  QCBORDecode_Init(&decoder, (UsefulBufC){encoded.ptr, encoded.len},
                   QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterMap(&decoder, NULL);
  pbns_status status = decode_context(&decoder, manifest);
  UsefulBufC digest = {0};
  UsefulBufC architecture = {0};
  UsefulBufC format = {0};
  UsefulBufC policy_authorization = {0};
  UsefulBufC policy_key_id = {0};
  uint64_t chunk_size = 0U;
  int64_t not_before_ns = 0;
  int64_t not_after_ns = 0;
  QCBORDecode_GetByteStringInMapN(&decoder, 10, &digest);
  QCBORDecode_GetUInt64InMapN(&decoder, 11, &manifest->artifact_version);
  QCBORDecode_GetTextStringInMapN(&decoder, 12, &architecture);
  QCBORDecode_GetTextStringInMapN(&decoder, 13, &format);
  QCBORDecode_GetUInt64InMapN(&decoder, 14, &manifest->image_size);
  QCBORDecode_GetUInt64InMapN(&decoder, 15, &chunk_size);
  QCBORDecode_GetUInt64InMapN(&decoder, 16, &manifest->minimum_version);
  QCBORDecode_GetInt64InMapN(&decoder, 17, &not_before_ns);
  QCBORDecode_GetInt64InMapN(&decoder, 18, &not_after_ns);
  QCBORDecode_GetByteStringInMapN(&decoder, 19, &policy_authorization);
  QCBORDecode_GetByteStringInMapN(&decoder, 20, &policy_key_id);
  QCBORDecode_ExitMap(&decoder);
  static const uint8_t expected_architecture[] = PBNS_RECOVERY_ARCHITECTURE;
  static const uint8_t expected_format[] = PBNS_RECOVERY_FORMAT;
  if (QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS || status != PBNS_OK ||
      digest.len != sizeof(manifest->artifact_digest) ||
      architecture.len != sizeof(expected_architecture) - 1U ||
      memcmp(architecture.ptr, expected_architecture,
             sizeof(expected_architecture) - 1U) != 0 ||
      format.len != sizeof(expected_format) - 1U ||
      memcmp(format.ptr, expected_format, sizeof(expected_format) - 1U) != 0 ||
      chunk_size > UINT32_MAX || not_before_ns != manifest->not_before_ns ||
      not_after_ns != manifest->not_after_ns) {
    return PBNS_ERR_FORMAT;
  }
  memcpy(manifest->artifact_digest, digest.ptr, digest.len);
  manifest->chunk_size = (uint32_t)chunk_size;
  manifest->policy_authorization =
      (pbns_view){policy_authorization.ptr, policy_authorization.len};
  manifest->policy_key_id = (pbns_view){policy_key_id.ptr, policy_key_id.len};
  return manifest_valid(manifest) ? PBNS_OK : PBNS_ERR_FORMAT;
}

pbns_status pbns_recovery_manifest_decode_verified(
    pbns_view verified_payload,
    const pbns_recovery_manifest_expectation *expectation,
    pbns_buffer canonical_scratch, pbns_recovery_manifest *manifest) {
  if (manifest != NULL) {
    *manifest = (pbns_recovery_manifest){0};
  }
  if (!view_valid(verified_payload) || verified_payload.len == 0U ||
      verified_payload.len > PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE ||
      !expectation_valid(expectation) || !output_valid(canonical_scratch) ||
      canonical_scratch.cap < verified_payload.len || manifest == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (ranges_overlap(verified_payload, canonical_scratch)) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_recovery_manifest decoded = {0};
  pbns_status status = decode_manifest(verified_payload, &decoded);
  if (status != PBNS_OK) {
    return status;
  }
  size_t canonical_size = 0U;
  status = encode_unchecked(&decoded, canonical_scratch, &canonical_size);
  if (status != PBNS_OK || canonical_size != verified_payload.len ||
      memcmp(canonical_scratch.ptr, verified_payload.ptr, canonical_size) !=
          0) {
    return PBNS_ERR_FORMAT;
  }
  if (!bytes_equal(decoded.request_id, expectation->request_id,
                   sizeof(decoded.request_id)) ||
      !bytes_equal(decoded.host_binding, expectation->host_binding,
                   sizeof(decoded.host_binding)) ||
      !bytes_equal(decoded.nonce, expectation->nonce, sizeof(decoded.nonce)) ||
      !views_equal(decoded.policy_key_id,
                   expectation->expected_policy_key_id)) {
    return PBNS_ERR_AUTHENTICATION;
  }
  if (decoded.artifact_version < expectation->current_version ||
      !pbns_time_interval_within(&expectation->trusted_time,
                                 decoded.not_before_ns, decoded.not_after_ns)) {
    return PBNS_ERR_REPLAY;
  }
  *manifest = decoded;
  return PBNS_OK;
}

static bool cose_profile_valid(pbns_view signed_manifest,
                               pbns_view expected_key_id) {
  QCBORDecodeContext outer = {0};
  QCBORItem item = {0};
  QCBORDecode_Init(&outer,
                   (UsefulBufC){signed_manifest.ptr, signed_manifest.len},
                   QCBOR_DECODE_MODE_NORMAL);
  if (QCBORDecode_GetNext(&outer, &item) != QCBOR_SUCCESS ||
      item.uDataType != QCBOR_TYPE_ARRAY ||
      item.uLabelType != QCBOR_TYPE_NONE || item.val.uCount != 4U ||
      QCBORDecode_GetNthTag(&outer, &item, 0U) != 18U ||
      QCBORDecode_GetNthTag(&outer, &item, 1U) != CBOR_TAG_INVALID64 ||
      QCBORDecode_GetNext(&outer, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uLabelType != QCBOR_TYPE_NONE ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING) {
    return false;
  }
  const UsefulBufC protected_headers = item.val.string;
  if (QCBORDecode_GetNext(&outer, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uLabelType != QCBOR_TYPE_NONE ||
      item.uDataType != QCBOR_TYPE_MAP || item.val.uCount != 0U ||
      QCBORDecode_GetNext(&outer, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uLabelType != QCBOR_TYPE_NONE ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING || item.val.string.len == 0U ||
      QCBORDecode_GetNext(&outer, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uLabelType != QCBOR_TYPE_NONE ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING || item.val.string.len != 64U ||
      QCBORDecode_Finish(&outer) != QCBOR_SUCCESS) {
    return false;
  }

  QCBORDecodeContext headers = {0};
  QCBORDecode_Init(&headers, protected_headers, QCBOR_DECODE_MODE_NORMAL);
  if (QCBORDecode_GetNext(&headers, &item) != QCBOR_SUCCESS ||
      item.uDataType != QCBOR_TYPE_MAP || item.uLabelType != QCBOR_TYPE_NONE ||
      item.val.uCount != 2U ||
      QCBORDecode_GetNext(&headers, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uLabelType != QCBOR_TYPE_INT64 ||
      item.label.int64 != 1 || item.uDataType != QCBOR_TYPE_INT64 ||
      item.val.int64 != -7 ||
      QCBORDecode_GetNext(&headers, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uLabelType != QCBOR_TYPE_INT64 ||
      item.label.int64 != 4 || item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      item.val.string.len != expected_key_id.len ||
      !bytes_equal(item.val.string.ptr, expected_key_id.ptr,
                   expected_key_id.len) ||
      QCBORDecode_Finish(&headers) != QCBOR_SUCCESS) {
    return false;
  }

  uint8_t canonical[96] = {0};
  QCBOREncodeContext encoder = {0};
  UsefulBufC encoded = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){canonical, sizeof(canonical)});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddInt64ToMapN(&encoder, 1, -7);
  QCBOREncode_AddBytesToMapN(
      &encoder, 4, (UsefulBufC){expected_key_id.ptr, expected_key_id.len});
  QCBOREncode_CloseMap(&encoder);
  return QCBOREncode_Finish(&encoder, &encoded) == QCBOR_SUCCESS &&
         encoded.len == protected_headers.len &&
         memcmp(encoded.ptr, protected_headers.ptr, encoded.len) == 0;
}

pbns_status pbns_recovery_manifest_verify_signed(
    const pbns_crypto *verifier, pbns_view signed_manifest,
    const pbns_recovery_manifest_expectation *expectation,
    pbns_buffer canonical_scratch, pbns_buffer aad_scratch,
    pbns_recovery_manifest *manifest) {
  if (manifest != NULL) {
    *manifest = (pbns_recovery_manifest){0};
  }
  if (verifier == NULL || !view_valid(signed_manifest) ||
      signed_manifest.len == 0U ||
      signed_manifest.len > PBNS_RECOVERY_MANIFEST_SIGNED_MAX_SIZE ||
      !expectation_valid(expectation) || !output_valid(canonical_scratch) ||
      !output_valid(aad_scratch) || manifest == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!cose_profile_valid(signed_manifest,
                          expectation->recovery_signing_key_id)) {
    return PBNS_ERR_AUTHENTICATION;
  }
  size_t aad_size = 0U;
  pbns_status status =
      pbns_recovery_manifest_aad(expectation, aad_scratch, &aad_size);
  if (status != PBNS_OK) {
    return status;
  }
  pbns_view verified_payload = {0};
  status = pbns_sign1_verify(verifier, signed_manifest,
                             (pbns_view){aad_scratch.ptr, aad_size},
                             &verified_payload);
  if (status != PBNS_OK) {
    return status;
  }
  return pbns_recovery_manifest_decode_verified(verified_payload, expectation,
                                                canonical_scratch, manifest);
}
