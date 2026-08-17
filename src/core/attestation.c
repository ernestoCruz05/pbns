#include "pbns/attestation.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "qcbor/qcbor.h"

#define PBNS_ATTESTATION_COMMON_FIELD_COUNT 9U
#define PBNS_ATTESTATION_CHALLENGE_FIELD_COUNT 5U
#define PBNS_ATTESTATION_PCR_BANK_MAX UINT16_MAX
#define PBNS_ATTESTATION_PCR_INDEX_MAX 23U
#define PBNS_COSE_SIGN1_TAG UINT64_C(18)
#define PBNS_COSE_ES256 (-7LL)

static bool view_valid(pbns_view view) {
  return view.ptr != NULL || view.len == 0U;
}

static bool buffer_valid(pbns_buffer buffer) {
  return buffer.len == 0U && (buffer.ptr != NULL || buffer.cap == 0U);
}

static bool ranges_overlap(pbns_view left, pbns_view right) {
  if (left.len == 0U || right.len == 0U) {
    return false;
  }
  const uintptr_t left_start = (uintptr_t)left.ptr;
  const uintptr_t right_start = (uintptr_t)right.ptr;
  if (left.ptr == NULL || right.ptr == NULL ||
      left.len > UINTPTR_MAX - left_start ||
      right.len > UINTPTR_MAX - right_start) {
    return true;
  }
  return left_start < right_start + right.len &&
         right_start < left_start + left.len;
}

static pbns_view buffer_range(pbns_buffer buffer) {
  return (pbns_view){buffer.ptr, buffer.cap};
}

static void wipe_bytes(uint8_t *bytes, size_t length) {
  if (bytes == NULL) {
    return;
  }
  volatile uint8_t *cursor = bytes;
  for (size_t index = 0U; index < length; ++index) {
    cursor[index] = 0U;
  }
}

static void wipe_buffer(pbns_buffer buffer) {
  if (buffer_valid(buffer)) {
    wipe_bytes(buffer.ptr, buffer.cap);
  }
}

static pbns_status require_bounded_output(pbns_status status,
                                          pbns_buffer output,
                                          size_t *written) {
  if (status == PBNS_OK && (*written == 0U || *written > output.cap)) {
    wipe_buffer(output);
    *written = 0U;
    return PBNS_ERR_LIMIT;
  }
  return status;
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

static bool request_equal(const pbns_request_id *left,
                          const pbns_request_id *right) {
  return left != NULL && right != NULL &&
         bytes_equal(left->bytes, right->bytes, sizeof(left->bytes));
}

static pbns_status finish_encode(QCBOREncodeContext *encoder,
                                 size_t *written) {
  UsefulBufC encoded = {0};
  const QCBORError error = QCBOREncode_Finish(encoder, &encoded);
  if (error == QCBOR_ERR_BUFFER_TOO_SMALL) {
    return PBNS_ERR_LIMIT;
  }
  if (error != QCBOR_SUCCESS) {
    return PBNS_ERR_FORMAT;
  }
  *written = encoded.len;
  return PBNS_OK;
}

static void encode_common(QCBOREncodeContext *encoder,
                          const pbns_attestation_challenge *challenge) {
  static const uint8_t domain[] = PBNS_ATTESTATION_DOMAIN;
  QCBOREncode_OpenMapInMapN(encoder, 1);
  QCBOREncode_AddTextToMapN(
      encoder, 1, (UsefulBufC){domain, sizeof(domain) - 1U});
  QCBOREncode_AddUInt64ToMapN(encoder, 2,
                              PBNS_ATTESTATION_PROTOCOL_VERSION);
  QCBOREncode_AddUInt64ToMapN(
      encoder, 3, (uint64_t)PBNS_SERVICE_PLATFORM_ATTESTATION);
  QCBOREncode_AddBytesToMapN(
      encoder, 4,
      (UsefulBufC){challenge->request_id.bytes,
                   sizeof(challenge->request_id.bytes)});
  QCBOREncode_AddBytesToMapN(
      encoder, 5,
      (UsefulBufC){challenge->host_fingerprint,
                   sizeof(challenge->host_fingerprint)});
  QCBOREncode_AddBytesToMapN(
      encoder, 6,
      (UsefulBufC){challenge->verifier_nonce,
                   sizeof(challenge->verifier_nonce)});
  QCBOREncode_AddUInt64ToMapN(encoder, 7, challenge->issued_at_ns);
  QCBOREncode_AddUInt64ToMapN(encoder, 8, challenge->expiry_ns);
  QCBOREncode_AddBytesToMapN(encoder, 9, NULLUsefulBufC);
  QCBOREncode_CloseMap(encoder);
}

static bool selection_valid(const pbns_measured_boot_selection_item *items,
                            size_t count) {
  if (items == NULL || count == 0U ||
      count > PBNS_MEASURED_BOOT_SELECTION_MAX_COUNT) {
    return false;
  }
  for (size_t index = 0U; index < count; ++index) {
    if (items[index].pcr_index > PBNS_ATTESTATION_PCR_INDEX_MAX) {
      return false;
    }
    if (index > 0U) {
      const pbns_measured_boot_selection_item previous = items[index - 1U];
      if (items[index].hash_algorithm < previous.hash_algorithm ||
          (items[index].hash_algorithm == previous.hash_algorithm &&
           items[index].pcr_index <= previous.pcr_index)) {
        return false;
      }
    }
  }
  return true;
}

static void encode_selection(QCBOREncodeContext *encoder,
                             const pbns_measured_boot_selection_item *items,
                             size_t count) {
  QCBOREncode_OpenArrayInMapN(encoder, 11);
  size_t index = 0U;
  while (index < count) {
    const uint16_t algorithm = items[index].hash_algorithm;
    QCBOREncode_OpenMap(encoder);
    QCBOREncode_AddUInt64ToMapN(encoder, 1, algorithm);
    QCBOREncode_OpenArrayInMapN(encoder, 2);
    do {
      QCBOREncode_AddUInt64(encoder, items[index].pcr_index);
      ++index;
    } while (index < count && items[index].hash_algorithm == algorithm);
    QCBOREncode_CloseArray(encoder);
    QCBOREncode_CloseMap(encoder);
  }
  QCBOREncode_CloseArray(encoder);
}

pbns_status pbns_attestation_challenge_encode(
    const pbns_attestation_challenge *challenge, pbns_buffer output,
    size_t *written) {
  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (challenge == NULL || !buffer_valid(output) ||
      output.cap > PBNS_ATTESTATION_CHALLENGE_MAX_SIZE ||
      !selection_valid(challenge->selection_items, challenge->selection_count) ||
      challenge->recipient_kid_len == 0U ||
      challenge->recipient_kid_len > PBNS_ENCRYPT_MAX_RECIPIENT_KID ||
      challenge->issued_at_ns > challenge->expiry_ns ||
      challenge->expiry_ns > (uint64_t)INT64_MAX) {
    return PBNS_ERR_ARGUMENT;
  }
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  encode_common(&encoder, challenge);
  QCBOREncode_AddBytesToMapN(
      &encoder, 10,
      (UsefulBufC){challenge->verifier_nonce,
                   sizeof(challenge->verifier_nonce)});
  encode_selection(&encoder, challenge->selection_items,
                   challenge->selection_count);
  QCBOREncode_AddBytesToMapN(
      &encoder, 12,
      (UsefulBufC){challenge->recipient_kid,
                   challenge->recipient_kid_len});
  QCBOREncode_AddUInt64ToMapN(&encoder, 13, challenge->expiry_ns);
  QCBOREncode_CloseMap(&encoder);
  return finish_encode(&encoder, written);
}

static pbns_status encode_aad_prefix(QCBOREncodeContext *encoder,
                                     const char *domain, size_t domain_len,
                                     const pbns_request_id *request_id,
                                     const uint8_t host_fingerprint[32],
                                     const uint8_t verifier_nonce[32]) {
  if (encoder == NULL || domain == NULL || request_id == NULL ||
      host_fingerprint == NULL || verifier_nonce == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  QCBOREncode_AddText(
      encoder, (UsefulBufC){(const uint8_t *)domain, domain_len});
  QCBOREncode_AddUInt64(encoder, PBNS_ATTESTATION_PROTOCOL_VERSION);
  return PBNS_OK;
}

pbns_status pbns_attestation_challenge_aad(
    const pbns_attestation_challenge_expected *expected, pbns_buffer output,
    size_t *written) {
  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (expected == NULL || !buffer_valid(output) ||
      output.cap > PBNS_ATTESTATION_AAD_MAX_SIZE ||
      !view_valid(expected->recipient_kid) ||
      expected->recipient_kid.len == 0U ||
      expected->recipient_kid.len > PBNS_ENCRYPT_MAX_RECIPIENT_KID) {
    return PBNS_ERR_ARGUMENT;
  }
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenArray(&encoder);
  const pbns_status prefix = encode_aad_prefix(
      &encoder, PBNS_ATTESTATION_CHALLENGE_AAD_DOMAIN,
      sizeof(PBNS_ATTESTATION_CHALLENGE_AAD_DOMAIN) - 1U,
      &expected->request_id, expected->host_fingerprint,
      expected->verifier_nonce);
  if (prefix != PBNS_OK) {
    return prefix;
  }
  QCBOREncode_AddUInt64(&encoder,
                        (uint64_t)PBNS_SERVICE_PLATFORM_ATTESTATION);
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){expected->request_id.bytes,
                   sizeof(expected->request_id.bytes)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){expected->host_fingerprint,
                   sizeof(expected->host_fingerprint)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){expected->verifier_nonce,
                   sizeof(expected->verifier_nonce)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){expected->recipient_kid.ptr,
                   expected->recipient_kid.len});
  QCBOREncode_CloseArray(&encoder);
  return finish_encode(&encoder, written);
}

static pbns_status next_labeled(QCBORDecodeContext *decoder,
                                uint8_t nesting, int64_t label,
                                QCBORItem *item) {
  if (QCBORDecode_GetNext(decoder, item) != QCBOR_SUCCESS ||
      item->uNestingLevel != nesting ||
      item->uLabelType != QCBOR_TYPE_INT64 || item->label.int64 != label) {
    return PBNS_ERR_FORMAT;
  }
  return PBNS_OK;
}

static bool item_uint(const QCBORItem *item, uint64_t *value) {
  if (item->uDataType == QCBOR_TYPE_INT64 && item->val.int64 >= 0) {
    *value = (uint64_t)item->val.int64;
    return true;
  }
  if (item->uDataType == QCBOR_TYPE_UINT64) {
    *value = item->val.uint64;
    return true;
  }
  return false;
}

static pbns_status decode_common(QCBORDecodeContext *decoder,
                                 pbns_attestation_challenge *challenge) {
  QCBORItem item = {0};
  uint64_t value = 0U;
  static const uint8_t domain[] = PBNS_ATTESTATION_DOMAIN;
  if (next_labeled(decoder, 1U, 1, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_MAP ||
      item.val.uCount != PBNS_ATTESTATION_COMMON_FIELD_COUNT ||
      next_labeled(decoder, 2U, 1, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      !views_equal((pbns_view){item.val.string.ptr, item.val.string.len},
                   (pbns_view){domain, sizeof(domain) - 1U}) ||
      next_labeled(decoder, 2U, 2, &item) != PBNS_OK ||
      !item_uint(&item, &value) ||
      value != PBNS_ATTESTATION_PROTOCOL_VERSION ||
      next_labeled(decoder, 2U, 3, &item) != PBNS_OK ||
      !item_uint(&item, &value) ||
      value != (uint64_t)PBNS_SERVICE_PLATFORM_ATTESTATION ||
      next_labeled(decoder, 2U, 4, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      item.val.string.len != sizeof(challenge->request_id.bytes)) {
    return PBNS_ERR_FORMAT;
  }
  memcpy(challenge->request_id.bytes, item.val.string.ptr,
         sizeof(challenge->request_id.bytes));
  if (next_labeled(decoder, 2U, 5, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      item.val.string.len != sizeof(challenge->host_fingerprint)) {
    return PBNS_ERR_FORMAT;
  }
  memcpy(challenge->host_fingerprint, item.val.string.ptr,
         sizeof(challenge->host_fingerprint));
  if (next_labeled(decoder, 2U, 6, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      item.val.string.len != sizeof(challenge->verifier_nonce)) {
    return PBNS_ERR_FORMAT;
  }
  memcpy(challenge->verifier_nonce, item.val.string.ptr,
         sizeof(challenge->verifier_nonce));
  if (next_labeled(decoder, 2U, 7, &item) != PBNS_OK ||
      !item_uint(&item, &challenge->issued_at_ns) ||
      next_labeled(decoder, 2U, 8, &item) != PBNS_OK ||
      !item_uint(&item, &challenge->expiry_ns) ||
      next_labeled(decoder, 2U, 9, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING || item.val.string.len != 0U) {
    return PBNS_ERR_FORMAT;
  }
  return PBNS_OK;
}

static pbns_status decode_selection(QCBORDecodeContext *decoder,
                                    pbns_attestation_challenge *challenge) {
  QCBORItem item = {0};
  if (next_labeled(decoder, 1U, 11, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_ARRAY || item.val.uCount == 0U) {
    return PBNS_ERR_FORMAT;
  }
  const size_t bank_count = item.val.uCount;
  for (size_t bank = 0U; bank < bank_count; ++bank) {
    uint64_t algorithm = 0U;
    if (QCBORDecode_GetNext(decoder, &item) != QCBOR_SUCCESS ||
        item.uNestingLevel != 2U || item.uDataType != QCBOR_TYPE_MAP ||
        item.uLabelType != QCBOR_TYPE_NONE || item.val.uCount != 2U ||
        next_labeled(decoder, 3U, 1, &item) != PBNS_OK ||
        !item_uint(&item, &algorithm) ||
        algorithm > PBNS_ATTESTATION_PCR_BANK_MAX ||
        next_labeled(decoder, 3U, 2, &item) != PBNS_OK ||
        item.uDataType != QCBOR_TYPE_ARRAY || item.val.uCount == 0U) {
      return PBNS_ERR_FORMAT;
    }
    const size_t pcr_count = item.val.uCount;
    for (size_t pcr = 0U; pcr < pcr_count; ++pcr) {
      uint64_t index = 0U;
      if (challenge->selection_count >=
              PBNS_MEASURED_BOOT_SELECTION_MAX_COUNT ||
          QCBORDecode_GetNext(decoder, &item) != QCBOR_SUCCESS ||
          item.uNestingLevel != 4U ||
          item.uLabelType != QCBOR_TYPE_NONE || !item_uint(&item, &index) ||
          index > PBNS_ATTESTATION_PCR_INDEX_MAX) {
        return PBNS_ERR_FORMAT;
      }
      challenge->selection_items[challenge->selection_count] =
          (pbns_measured_boot_selection_item){(uint16_t)algorithm,
                                              (uint8_t)index};
      ++challenge->selection_count;
    }
  }
  return selection_valid(challenge->selection_items,
                         challenge->selection_count)
             ? PBNS_OK
             : PBNS_ERR_FORMAT;
}

static pbns_status decode_challenge(pbns_view payload,
                                    pbns_attestation_challenge *challenge) {
  QCBORDecodeContext decoder = {0};
  QCBORItem item = {0};
  QCBORDecode_Init(&decoder, (UsefulBufC){payload.ptr, payload.len},
                   QCBOR_DECODE_MODE_NORMAL);
  if (QCBORDecode_GetNext(&decoder, &item) != QCBOR_SUCCESS ||
      item.uDataType != QCBOR_TYPE_MAP ||
      item.uLabelType != QCBOR_TYPE_NONE ||
      item.val.uCount != PBNS_ATTESTATION_CHALLENGE_FIELD_COUNT ||
      decode_common(&decoder, challenge) != PBNS_OK ||
      next_labeled(&decoder, 1U, 10, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      item.val.string.len != sizeof(challenge->verifier_nonce) ||
      !bytes_equal(item.val.string.ptr, challenge->verifier_nonce,
                   sizeof(challenge->verifier_nonce)) ||
      decode_selection(&decoder, challenge) != PBNS_OK ||
      next_labeled(&decoder, 1U, 12, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING || item.val.string.len == 0U ||
      item.val.string.len > sizeof(challenge->recipient_kid)) {
    return PBNS_ERR_FORMAT;
  }
  challenge->recipient_kid_len = item.val.string.len;
  memcpy(challenge->recipient_kid, item.val.string.ptr,
         challenge->recipient_kid_len);
  uint64_t duplicated_expiry = 0U;
  if (next_labeled(&decoder, 1U, 13, &item) != PBNS_OK ||
      !item_uint(&item, &duplicated_expiry) ||
      duplicated_expiry != challenge->expiry_ns ||
      challenge->issued_at_ns > challenge->expiry_ns ||
      challenge->expiry_ns > (uint64_t)INT64_MAX ||
      QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS) {
    return PBNS_ERR_FORMAT;
  }
  return PBNS_OK;
}

static bool challenge_cose_profile_valid(pbns_view message,
                                         pbns_view expected_kid,
                                         pbns_buffer canonical_output) {
  QCBORDecodeContext decoder = {0};
  QCBORItem item = {0};
  UsefulBufC protected_headers = {0};
  UsefulBufC payload = {0};
  UsefulBufC signature = {0};
  QCBORDecode_Init(&decoder, (UsefulBufC){message.ptr, message.len},
                   QCBOR_DECODE_MODE_NORMAL);
  if (QCBORDecode_GetNext(&decoder, &item) != QCBOR_SUCCESS ||
      item.uDataType != QCBOR_TYPE_ARRAY || item.uLabelType != QCBOR_TYPE_NONE ||
      item.val.uCount != 4U ||
      QCBORDecode_GetNthTag(&decoder, &item, 0U) != PBNS_COSE_SIGN1_TAG ||
      QCBORDecode_GetNthTag(&decoder, &item, 1U) != CBOR_TAG_INVALID64 ||
      QCBORDecode_GetNext(&decoder, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uDataType != QCBOR_TYPE_BYTE_STRING) {
    return false;
  }
  protected_headers = item.val.string;
  if (QCBORDecode_GetNext(&decoder, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uDataType != QCBOR_TYPE_MAP ||
      item.val.uCount != 0U ||
      QCBORDecode_GetNext(&decoder, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      item.val.string.len == 0U) {
    return false;
  }
  payload = item.val.string;
  if (QCBORDecode_GetNext(&decoder, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      item.val.string.len != 64U ||
      QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS) {
    return false;
  }
  signature = item.val.string;
  QCBORDecodeContext headers = {0};
  QCBORDecode_Init(&headers, protected_headers, QCBOR_DECODE_MODE_NORMAL);
  if (QCBORDecode_GetNext(&headers, &item) != QCBOR_SUCCESS ||
      item.uDataType != QCBOR_TYPE_MAP || item.val.uCount != 2U ||
      next_labeled(&headers, 1U, 1, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_INT64 || item.val.int64 != PBNS_COSE_ES256 ||
      next_labeled(&headers, 1U, 4, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      !views_equal((pbns_view){item.val.string.ptr, item.val.string.len},
                   expected_kid) ||
      QCBORDecode_Finish(&headers) != QCBOR_SUCCESS) {
    return false;
  }
  uint8_t canonical[96] = {0};
  QCBOREncodeContext encoder = {0};
  UsefulBufC encoded = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){canonical, sizeof(canonical)});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddInt64ToMapN(&encoder, 1, PBNS_COSE_ES256);
  QCBOREncode_AddBytesToMapN(
      &encoder, 4, (UsefulBufC){expected_kid.ptr, expected_kid.len});
  QCBOREncode_CloseMap(&encoder);
  if (QCBOREncode_Finish(&encoder, &encoded) != QCBOR_SUCCESS ||
      encoded.len != protected_headers.len ||
      !bytes_equal(encoded.ptr, protected_headers.ptr, encoded.len)) {
    return false;
  }
  QCBOREncode_Init(
      &encoder,
      (UsefulBuf){canonical_output.ptr, canonical_output.cap});
  QCBOREncode_AddTag(&encoder, PBNS_COSE_SIGN1_TAG);
  QCBOREncode_OpenArray(&encoder);
  QCBOREncode_AddBytes(&encoder, protected_headers);
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_CloseMap(&encoder);
  QCBOREncode_AddBytes(&encoder, payload);
  QCBOREncode_AddBytes(&encoder, signature);
  QCBOREncode_CloseArray(&encoder);
  return QCBOREncode_Finish(&encoder, &encoded) == QCBOR_SUCCESS &&
         encoded.len == message.len &&
         bytes_equal(encoded.ptr, message.ptr, message.len);
}

static bool challenge_workspace_valid(
    const pbns_crypto *verifier, pbns_view signed_challenge,
    const pbns_attestation_challenge_expected *expected,
    const pbns_time_interval *trusted_time,
    const pbns_attestation_challenge_workspace *workspace,
    const pbns_attestation_challenge *challenge) {
  if (verifier == NULL || !view_valid(signed_challenge) ||
      signed_challenge.len == 0U ||
      signed_challenge.len > PBNS_ATTESTATION_CHALLENGE_MAX_SIZE ||
      expected == NULL || trusted_time == NULL || workspace == NULL ||
      challenge == NULL || !buffer_valid(workspace->canonical) ||
      !buffer_valid(workspace->aad) ||
      workspace->canonical.cap != PBNS_ATTESTATION_CHALLENGE_MAX_SIZE ||
      workspace->aad.cap != PBNS_ATTESTATION_AAD_MAX_SIZE ||
      !view_valid(expected->challenge_kid) ||
      expected->challenge_kid.len == 0U ||
      expected->challenge_kid.len > PBNS_ENCRYPT_MAX_RECIPIENT_KID) {
    return false;
  }
  const pbns_view writable[] = {buffer_range(workspace->canonical),
                                buffer_range(workspace->aad),
                                {(const uint8_t *)challenge,
                                 sizeof(*challenge)}};
  const pbns_view immutable[] = {
      signed_challenge,
      {(const uint8_t *)expected, sizeof(*expected)},
      expected->recipient_kid,
      expected->challenge_kid,
      {(const uint8_t *)trusted_time, sizeof(*trusted_time)},
      {(const uint8_t *)verifier, sizeof(*verifier)},
      {(const uint8_t *)workspace, sizeof(*workspace)},
  };
  for (size_t index = 0U; index < sizeof(writable) / sizeof(writable[0]);
       ++index) {
    for (size_t other = 0U; other < index; ++other) {
      if (ranges_overlap(writable[index], writable[other])) {
        return false;
      }
    }
    for (size_t input = 0U; input < sizeof(immutable) / sizeof(immutable[0]);
         ++input) {
      if (ranges_overlap(writable[index], immutable[input])) {
        return false;
      }
    }
  }
  return true;
}

pbns_status pbns_attestation_accept_challenge(
    const pbns_crypto *verifier, pbns_view signed_challenge,
    const pbns_attestation_challenge_expected *expected,
    const pbns_time_interval *trusted_time,
    pbns_attestation_challenge_workspace *workspace,
    pbns_attestation_challenge *challenge) {
  if (!challenge_workspace_valid(verifier, signed_challenge, expected,
                                 trusted_time, workspace, challenge)) {
    return PBNS_ERR_ARGUMENT;
  }
  *challenge = (pbns_attestation_challenge){0};
  pbns_status status = PBNS_ERR_FORMAT;
  size_t aad_size = 0U;
  pbns_view payload = {0};
  if (!challenge_cose_profile_valid(signed_challenge,
                                    expected->challenge_kid,
                                    workspace->canonical)) {
    wipe_buffer(workspace->canonical);
    wipe_buffer(workspace->aad);
    return PBNS_ERR_FORMAT;
  }
  status = pbns_attestation_challenge_aad(expected, workspace->aad,
                                          &aad_size);
  if (status == PBNS_OK) {
    status = pbns_sign1_verify_profile(
        verifier, signed_challenge,
        (pbns_view){workspace->aad.ptr, aad_size},
        expected->challenge_kid, &payload);
  }
  pbns_attestation_challenge parsed = {0};
  if (status == PBNS_OK &&
      (payload.len > PBNS_ATTESTATION_CHALLENGE_MAX_SIZE ||
       payload.len > workspace->canonical.cap)) {
    status = PBNS_ERR_LIMIT;
  }
  if (status == PBNS_OK) {
    status = decode_challenge(payload, &parsed);
  }
  size_t canonical_size = 0U;
  if (status == PBNS_OK) {
    status = pbns_attestation_challenge_encode(
        &parsed, workspace->canonical, &canonical_size);
  }
  if (status == PBNS_OK &&
      (canonical_size != payload.len ||
       !bytes_equal(workspace->canonical.ptr, payload.ptr, payload.len))) {
    status = PBNS_ERR_FORMAT;
  }
  const pbns_view parsed_recipient = {parsed.recipient_kid,
                                      parsed.recipient_kid_len};
  if (status == PBNS_OK &&
      (!request_equal(&parsed.request_id, &expected->request_id) ||
       !bytes_equal(parsed.host_fingerprint, expected->host_fingerprint,
                    sizeof(parsed.host_fingerprint)) ||
       !bytes_equal(parsed.verifier_nonce, expected->verifier_nonce,
                    sizeof(parsed.verifier_nonce)) ||
       !views_equal(parsed_recipient, expected->recipient_kid))) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  if (status == PBNS_OK &&
      (trusted_time->earliest_ns < 0 || trusted_time->latest_ns < 0 ||
       trusted_time->earliest_ns > trusted_time->latest_ns ||
       (uint64_t)trusted_time->earliest_ns < parsed.issued_at_ns ||
       (uint64_t)trusted_time->latest_ns > parsed.expiry_ns)) {
    status = PBNS_ERR_TIMEOUT;
  }
  if (status == PBNS_OK) {
    *challenge = parsed;
  } else {
    wipe_bytes((uint8_t *)&parsed, sizeof(parsed));
  }
  wipe_buffer(workspace->canonical);
  wipe_buffer(workspace->aad);
  return status;
}

pbns_status pbns_attestation_qualifying_data(
    pbns_attestation_sha256_fn sha256, void *sha256_context,
    const pbns_request_id *request_id,
    const uint8_t verifier_nonce[PBNS_ATTESTATION_NONCE_SIZE],
    const uint8_t report_digest[PBNS_ATTESTATION_DIGEST_SIZE],
    const uint8_t selection_digest[PBNS_ATTESTATION_DIGEST_SIZE],
    const uint8_t event_log_digest[PBNS_ATTESTATION_DIGEST_SIZE],
    pbns_buffer scratch,
    uint8_t qualifying_data[PBNS_ATTESTATION_DIGEST_SIZE]) {
  static const uint8_t domain[] = PBNS_ATTESTATION_QUALIFYING_DOMAIN;
  const size_t required = sizeof(domain) - 1U + PBNS_REQUEST_ID_SIZE +
                          ((size_t)4U * PBNS_ATTESTATION_DIGEST_SIZE);
  if (qualifying_data != NULL) {
    wipe_bytes(qualifying_data, PBNS_ATTESTATION_DIGEST_SIZE);
  }
  if (sha256 == NULL || request_id == NULL || verifier_nonce == NULL ||
      report_digest == NULL || selection_digest == NULL ||
      event_log_digest == NULL || qualifying_data == NULL ||
      !buffer_valid(scratch) || scratch.cap < required) {
    return PBNS_ERR_ARGUMENT;
  }
  size_t offset = 0U;
#define PBNS_COPY_QUALIFYING(source, length)                                  \
  do {                                                                        \
    memcpy(&scratch.ptr[offset], (source), (length));                          \
    offset += (length);                                                        \
  } while (false)
  PBNS_COPY_QUALIFYING(domain, sizeof(domain) - 1U);
  PBNS_COPY_QUALIFYING(request_id->bytes, sizeof(request_id->bytes));
  PBNS_COPY_QUALIFYING(verifier_nonce, PBNS_ATTESTATION_NONCE_SIZE);
  PBNS_COPY_QUALIFYING(report_digest, PBNS_ATTESTATION_DIGEST_SIZE);
  PBNS_COPY_QUALIFYING(selection_digest, PBNS_ATTESTATION_DIGEST_SIZE);
  PBNS_COPY_QUALIFYING(event_log_digest, PBNS_ATTESTATION_DIGEST_SIZE);
#undef PBNS_COPY_QUALIFYING
  const pbns_status status = sha256(
      sha256_context, (pbns_view){scratch.ptr, offset}, qualifying_data);
  wipe_buffer(scratch);
  if (status != PBNS_OK) {
    wipe_bytes(qualifying_data, PBNS_ATTESTATION_DIGEST_SIZE);
  }
  return status;
}

pbns_status pbns_attestation_sign_aad(
    const pbns_attestation_challenge *challenge, pbns_view ak_name,
    pbns_buffer output, size_t *written) {
  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (challenge == NULL || !view_valid(ak_name) || ak_name.len == 0U ||
      ak_name.len > PBNS_ATTESTATION_AK_NAME_MAX_SIZE ||
      !buffer_valid(output) || output.cap > PBNS_ATTESTATION_AAD_MAX_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenArray(&encoder);
  (void)encode_aad_prefix(&encoder, PBNS_ATTESTATION_SIGN_AAD_DOMAIN,
                          sizeof(PBNS_ATTESTATION_SIGN_AAD_DOMAIN) - 1U,
                          &challenge->request_id,
                          challenge->host_fingerprint,
                          challenge->verifier_nonce);
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){challenge->request_id.bytes,
                   sizeof(challenge->request_id.bytes)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){challenge->host_fingerprint,
                   sizeof(challenge->host_fingerprint)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){challenge->verifier_nonce,
                   sizeof(challenge->verifier_nonce)});
  QCBOREncode_AddBytes(&encoder, (UsefulBufC){ak_name.ptr, ak_name.len});
  QCBOREncode_CloseArray(&encoder);
  return finish_encode(&encoder, written);
}

pbns_status pbns_attestation_encrypt_message(
    const pbns_crypto *crypto, pbns_view recipient_kid, pbns_view plaintext,
    pbns_view external_aad, pbns_buffer output, size_t *written) {
  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (crypto == NULL || crypto->ops == NULL || crypto->context == NULL ||
      crypto->ops->encrypt_for_recipient == NULL ||
      !view_valid(recipient_kid) || recipient_kid.len == 0U ||
      recipient_kid.len > PBNS_ENCRYPT_MAX_RECIPIENT_KID ||
      !view_valid(plaintext) || plaintext.len == 0U ||
      plaintext.len > PBNS_ATTESTATION_SIGNED_MAX_SIZE ||
      !view_valid(external_aad) ||
      external_aad.len > PBNS_ATTESTATION_AAD_MAX_SIZE ||
      !buffer_valid(output) || output.cap == 0U ||
      output.cap > PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE ||
      ranges_overlap(recipient_kid, buffer_range(output)) ||
      ranges_overlap(plaintext, buffer_range(output)) ||
      ranges_overlap(external_aad, buffer_range(output))) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status status = crypto->ops->encrypt_for_recipient(
      crypto->context, recipient_kid, plaintext, external_aad, output,
      written);
  return require_bounded_output(status, output, written);
}

pbns_status pbns_attestation_encrypt_aad(
    const pbns_attestation_challenge *challenge, pbns_buffer output,
    size_t *written) {
  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (challenge == NULL || challenge->recipient_kid_len == 0U ||
      challenge->recipient_kid_len > sizeof(challenge->recipient_kid) ||
      !buffer_valid(output) || output.cap > PBNS_ATTESTATION_AAD_MAX_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenArray(&encoder);
  (void)encode_aad_prefix(&encoder, PBNS_ATTESTATION_ENCRYPT_AAD_DOMAIN,
                          sizeof(PBNS_ATTESTATION_ENCRYPT_AAD_DOMAIN) - 1U,
                          &challenge->request_id,
                          challenge->host_fingerprint,
                          challenge->verifier_nonce);
  QCBOREncode_AddUInt64(&encoder,
                        (uint64_t)PBNS_SERVICE_PLATFORM_ATTESTATION);
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){challenge->request_id.bytes,
                   sizeof(challenge->request_id.bytes)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){challenge->host_fingerprint,
                   sizeof(challenge->host_fingerprint)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){challenge->verifier_nonce,
                   sizeof(challenge->verifier_nonce)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){challenge->recipient_kid,
                   challenge->recipient_kid_len});
  QCBOREncode_CloseArray(&encoder);
  return finish_encode(&encoder, written);
}

static pbns_status encode_evidence(
    const pbns_attestation_challenge *challenge,
    const pbns_attestation_submission *submission, pbns_view inventory,
    pbns_view quote, pbns_view quote_signature,
    const uint8_t report_digest[32], pbns_buffer output, size_t *written) {
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  encode_common(&encoder, challenge);
  QCBOREncode_AddEncodedToMapN(
      &encoder, 20, (UsefulBufC){inventory.ptr, inventory.len});
  QCBOREncode_AddBytesToMapN(&encoder, 21,
                             (UsefulBufC){quote.ptr, quote.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 22,
      (UsefulBufC){quote_signature.ptr, quote_signature.len});
  QCBOREncode_OpenArrayInMapN(&encoder, 23);
  for (size_t index = 0U; index < submission->measured_boot->pcr_count;
       ++index) {
    const pbns_measured_boot_pcr_value *pcr =
        &submission->measured_boot->pcrs[index];
    QCBOREncode_OpenMap(&encoder);
    QCBOREncode_AddUInt64ToMapN(&encoder, 1,
                                pcr->selection.hash_algorithm);
    QCBOREncode_AddUInt64ToMapN(&encoder, 2, pcr->selection.pcr_index);
    QCBOREncode_AddBytesToMapN(
        &encoder, 3, (UsefulBufC){pcr->digest, pcr->digest_size});
    QCBOREncode_CloseMap(&encoder);
  }
  QCBOREncode_CloseArray(&encoder);
  QCBOREncode_AddBytesToMapN(
      &encoder, 24,
      (UsefulBufC){submission->measured_boot->event_log.ptr,
                   submission->measured_boot->event_log.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 25,
      (UsefulBufC){submission->ak_name.ptr, submission->ak_name.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 26,
      (UsefulBufC){submission->ak_reference.ptr,
                   submission->ak_reference.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 27,
      (UsefulBufC){report_digest, PBNS_ATTESTATION_DIGEST_SIZE});
  QCBOREncode_AddBytesToMapN(
      &encoder, 28,
      (UsefulBufC){submission->measured_boot->selection_digest,
                   PBNS_ATTESTATION_DIGEST_SIZE});
  QCBOREncode_AddBytesToMapN(
      &encoder, 29,
      (UsefulBufC){submission->measured_boot->event_log_digest,
                   PBNS_ATTESTATION_DIGEST_SIZE});
  QCBOREncode_CloseMap(&encoder);
  return finish_encode(&encoder, written);
}

#define PBNS_ATTESTATION_WORKSPACE_COUNT 8U
#define PBNS_ATTESTATION_INPUT_VIEW_COUNT 16U

static void workspace_buffers(const pbns_attestation_workspace *workspace,
                              pbns_buffer buffers[8]) {
  buffers[0] = workspace->inventory;
  buffers[1] = workspace->selection;
  buffers[2] = workspace->quote;
  buffers[3] = workspace->quote_signature;
  buffers[4] = workspace->evidence;
  buffers[5] = workspace->signed_evidence;
  buffers[6] = workspace->ciphertext;
  buffers[7] = workspace->aad;
}

static void submission_input_views(
    const pbns_attestation_challenge *challenge,
    const pbns_attestation_submission *submission,
    const pbns_attestation_workspace *workspace,
    pbns_view inputs[PBNS_ATTESTATION_INPUT_VIEW_COUNT]) {
  inputs[0] = (pbns_view){(const uint8_t *)challenge, sizeof(*challenge)};
  inputs[1] = (pbns_view){(const uint8_t *)submission, sizeof(*submission)};
  inputs[2] = (pbns_view){(const uint8_t *)submission->inventory_report,
                          sizeof(*submission->inventory_report)};
  inputs[3] = (pbns_view){(const uint8_t *)submission->measured_boot,
                          sizeof(*submission->measured_boot)};
  inputs[4] = submission->measured_boot->event_log;
  inputs[5] = submission->ak_name;
  inputs[6] = submission->ak_reference;
  inputs[7] = (pbns_view){(const uint8_t *)submission->host_signer,
                          sizeof(*submission->host_signer)};
  inputs[8] = (pbns_view){(const uint8_t *)submission->recipient_encrypter,
                          sizeof(*submission->recipient_encrypter)};
  inputs[9] = (pbns_view){(const uint8_t *)workspace, sizeof(*workspace)};
  inputs[10] = submission->host_signer_context_region;
  inputs[11] = submission->recipient_encrypter_context_region;
  inputs[12] = submission->sha256_context_region;
  inputs[13] = submission->quote_context_region;
  inputs[14] = submission->consume_context_region;
  inputs[15] = submission->send_context_region;
}

static bool workspace_layout_valid(
    const pbns_attestation_challenge *challenge,
    const pbns_attestation_submission *submission,
    const pbns_attestation_workspace *workspace) {
  pbns_buffer buffers[PBNS_ATTESTATION_WORKSPACE_COUNT] = {0};
  workspace_buffers(workspace, buffers);
  const size_t capacities[PBNS_ATTESTATION_WORKSPACE_COUNT] = {
      PBNS_INVENTORY_ENCODED_MAX_SIZE,
      PBNS_ATTESTATION_SELECTION_WORKSPACE_SIZE,
      PBNS_ATTESTATION_QUOTE_MAX_SIZE,
      PBNS_ATTESTATION_QUOTE_SIGNATURE_MAX_SIZE,
      PBNS_ATTESTATION_EVIDENCE_MAX_SIZE,
      PBNS_ATTESTATION_SIGNED_MAX_SIZE,
      PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE,
      PBNS_ATTESTATION_AAD_MAX_SIZE,
  };
  for (size_t index = 0U; index < PBNS_ATTESTATION_WORKSPACE_COUNT; ++index) {
    if (!buffer_valid(buffers[index]) ||
        buffers[index].cap != capacities[index]) {
      return false;
    }
    for (size_t other = 0U; other < index; ++other) {
      if (ranges_overlap(buffer_range(buffers[index]),
                         buffer_range(buffers[other]))) {
        return false;
      }
    }
  }
  pbns_view inputs[PBNS_ATTESTATION_INPUT_VIEW_COUNT] = {0};
  submission_input_views(challenge, submission, workspace, inputs);
  const pbns_view digest_output = buffer_range(submission->evidence_digest);
  for (size_t buffer = 0U; buffer < PBNS_ATTESTATION_WORKSPACE_COUNT;
       ++buffer) {
    for (size_t input = 0U; input < PBNS_ATTESTATION_INPUT_VIEW_COUNT;
         ++input) {
      if (ranges_overlap(buffer_range(buffers[buffer]), inputs[input])) {
        return false;
      }
    }
    if (ranges_overlap(buffer_range(buffers[buffer]), digest_output)) {
      return false;
    }
  }
  for (size_t input = 0U; input < PBNS_ATTESTATION_INPUT_VIEW_COUNT; ++input) {
    if (ranges_overlap(digest_output, inputs[input])) {
      return false;
    }
  }
  return true;
}

static bool context_region_valid(const void *context, pbns_view region) {
  if (!view_valid(region)) {
    return false;
  }
  if (context == NULL) {
    return region.ptr == NULL && region.len == 0U;
  }
  return region.ptr == (const uint8_t *)context && region.len > 0U;
}

static bool submission_arguments_valid(
    const pbns_attestation_challenge *challenge,
    const pbns_attestation_submission *submission,
    const pbns_attestation_workspace *workspace) {
  if (challenge == NULL || submission == NULL || workspace == NULL ||
      submission->inventory_report == NULL ||
      submission->measured_boot == NULL || submission->host_signer == NULL ||
      submission->recipient_encrypter == NULL || submission->sha256 == NULL ||
      submission->quote == NULL || submission->consume == NULL ||
      submission->send_data == NULL ||
      !context_region_valid(submission->host_signer->context,
                            submission->host_signer_context_region) ||
      !context_region_valid(submission->recipient_encrypter->context,
                            submission->recipient_encrypter_context_region) ||
      !context_region_valid(submission->sha256_context,
                            submission->sha256_context_region) ||
      !context_region_valid(submission->quote_context,
                            submission->quote_context_region) ||
      !context_region_valid(submission->consume_context,
                            submission->consume_context_region) ||
      !context_region_valid(submission->send_context,
                            submission->send_context_region) ||
      !view_valid(submission->ak_name) ||
      submission->ak_name.len == 0U ||
      submission->ak_name.len > PBNS_ATTESTATION_AK_NAME_MAX_SIZE ||
      !view_valid(submission->ak_reference) ||
      submission->ak_reference.len == 0U ||
      submission->ak_reference.len > PBNS_ATTESTATION_AK_REFERENCE_MAX_SIZE ||
      !selection_valid(challenge->selection_items,
                       challenge->selection_count) ||
      !view_valid(submission->measured_boot->event_log) ||
      submission->measured_boot->event_log.len == 0U ||
      submission->measured_boot->event_log.len >
          PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE ||
      submission->measured_boot->pcr_count != challenge->selection_count ||
      !buffer_valid(submission->evidence_digest) ||
      submission->evidence_digest.cap != PBNS_ATTESTATION_DIGEST_SIZE) {
    return false;
  }
  return workspace_layout_valid(challenge, submission, workspace);
}

static void wipe_workspace(pbns_attestation_workspace *workspace) {
  if (workspace == NULL) {
    return;
  }
  wipe_buffer(workspace->inventory);
  wipe_buffer(workspace->selection);
  wipe_buffer(workspace->quote);
  wipe_buffer(workspace->quote_signature);
  wipe_buffer(workspace->evidence);
  wipe_buffer(workspace->signed_evidence);
  wipe_buffer(workspace->ciphertext);
  wipe_buffer(workspace->aad);
}

static pbns_status verify_measured_binding(
    const pbns_attestation_challenge *challenge,
    const pbns_attestation_submission *submission,
    pbns_attestation_workspace *workspace, size_t *selection_size) {
  for (size_t index = 0U; index < challenge->selection_count; ++index) {
    const pbns_measured_boot_pcr_value *pcr =
        &submission->measured_boot->pcrs[index];
    if (pcr->selection.hash_algorithm !=
            challenge->selection_items[index].hash_algorithm ||
        pcr->selection.pcr_index !=
            challenge->selection_items[index].pcr_index ||
        pcr->digest_size != PBNS_MEASURED_BOOT_DIGEST_SIZE) {
      return PBNS_ERR_AUTHENTICATION;
    }
  }
  pbns_status status = pbns_measured_boot_encode_canonical_selection(
      (pbns_measured_boot_selection){challenge->selection_items,
                                     challenge->selection_count},
      workspace->selection, selection_size);
  if (status != PBNS_OK) {
    return status;
  }
  uint8_t digest[PBNS_ATTESTATION_DIGEST_SIZE] = {0};
  status = submission->sha256(
      submission->sha256_context,
      (pbns_view){workspace->selection.ptr, *selection_size}, digest);
  if (status == PBNS_OK &&
      !bytes_equal(digest, submission->measured_boot->selection_digest,
                   sizeof(digest))) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  if (status == PBNS_OK) {
    pbns_measured_boot_summary summary = {0};
    status = pbns_measured_boot_validate_event_log(
        submission->measured_boot->event_log, &summary);
  }
  if (status == PBNS_OK) {
    status = submission->sha256(submission->sha256_context,
                                submission->measured_boot->event_log,
                                digest);
  }
  if (status == PBNS_OK &&
      !bytes_equal(digest, submission->measured_boot->event_log_digest,
                   sizeof(digest))) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  wipe_bytes(digest, sizeof(digest));
  return status;
}

pbns_status pbns_attestation_submit(
    pbns_attestation_challenge *challenge,
    const pbns_attestation_submission *submission,
    pbns_attestation_workspace *workspace) {
  if (!submission_arguments_valid(challenge, submission, workspace)) {
    return PBNS_ERR_ARGUMENT;
  }
  wipe_buffer(submission->evidence_digest);
  if (challenge->consumed) {
    wipe_workspace(workspace);
    return PBNS_ERR_ARGUMENT;
  }
  challenge->consumed = true;
  pbns_status status = submission->consume(
      submission->consume_context, &challenge->request_id,
      challenge->verifier_nonce);
  size_t inventory_size = 0U;
  size_t selection_size = 0U;
  size_t quote_size = 0U;
  size_t quote_signature_size = 0U;
  size_t evidence_size = 0U;
  size_t aad_size = 0U;
  size_t signed_size = 0U;
  size_t ciphertext_size = 0U;
  uint8_t report_digest[PBNS_ATTESTATION_DIGEST_SIZE] = {0};
  uint8_t qualifying_data[PBNS_ATTESTATION_DIGEST_SIZE] = {0};
  if (status == PBNS_OK &&
      !bytes_equal(submission->inventory_report->host_fingerprint,
                   challenge->host_fingerprint,
                   sizeof(challenge->host_fingerprint))) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  if (status == PBNS_OK) {
    status = pbns_inventory_encode(submission->inventory_report,
                                   workspace->inventory, &inventory_size);
  }
  if (status == PBNS_OK) {
    status = submission->sha256(
        submission->sha256_context,
        (pbns_view){workspace->inventory.ptr, inventory_size}, report_digest);
  }
  if (status == PBNS_OK) {
    status = verify_measured_binding(challenge, submission, workspace,
                                     &selection_size);
  }
  if (status == PBNS_OK) {
    status = pbns_attestation_qualifying_data(
        submission->sha256, submission->sha256_context,
        &challenge->request_id, challenge->verifier_nonce, report_digest,
        submission->measured_boot->selection_digest,
        submission->measured_boot->event_log_digest, workspace->aad,
        qualifying_data);
  }
  if (status == PBNS_OK) {
    status = submission->quote(
        submission->quote_context,
        (pbns_measured_boot_selection){challenge->selection_items,
                                       challenge->selection_count},
        qualifying_data, workspace->quote, &quote_size,
        workspace->quote_signature, &quote_signature_size);
    if (status == PBNS_OK &&
        (quote_size == 0U || quote_size > workspace->quote.cap ||
         quote_signature_size == 0U ||
         quote_signature_size > workspace->quote_signature.cap)) {
      status = PBNS_ERR_LIMIT;
    }
  }
  if (status == PBNS_OK) {
    status = encode_evidence(
        challenge, submission,
        (pbns_view){workspace->inventory.ptr, inventory_size},
        (pbns_view){workspace->quote.ptr, quote_size},
        (pbns_view){workspace->quote_signature.ptr, quote_signature_size},
        report_digest, workspace->evidence, &evidence_size);
  }
  if (status == PBNS_OK) {
    status = pbns_attestation_sign_aad(challenge, submission->ak_name,
                                       workspace->aad, &aad_size);
  }
  if (status == PBNS_OK) {
    status = pbns_sign1_sign(
        submission->host_signer,
        (pbns_view){workspace->evidence.ptr, evidence_size},
        (pbns_view){workspace->aad.ptr, aad_size},
        workspace->signed_evidence, &signed_size);
    if (status == PBNS_OK &&
        (signed_size == 0U || signed_size > workspace->signed_evidence.cap)) {
      status = PBNS_ERR_LIMIT;
    }
  }
  if (status == PBNS_OK) {
    status = submission->sha256(
        submission->sha256_context,
        (pbns_view){workspace->signed_evidence.ptr, signed_size},
        submission->evidence_digest.ptr);
  }
  if (status == PBNS_OK) {
    wipe_buffer(workspace->aad);
    status = pbns_attestation_encrypt_aad(challenge, workspace->aad,
                                          &aad_size);
  }
  if (status == PBNS_OK) {
    status = pbns_attestation_encrypt_message(
        submission->recipient_encrypter,
        (pbns_view){challenge->recipient_kid,
                    challenge->recipient_kid_len},
        (pbns_view){workspace->signed_evidence.ptr, signed_size},
        (pbns_view){workspace->aad.ptr, aad_size}, workspace->ciphertext,
        &ciphertext_size);
    if (status == PBNS_OK &&
        (ciphertext_size == 0U ||
         ciphertext_size > workspace->ciphertext.cap)) {
      status = PBNS_ERR_LIMIT;
    }
  }
  uint32_t sequence = 0U;
  for (size_t offset = 0U; status == PBNS_OK && offset < ciphertext_size;) {
    const size_t remaining = ciphertext_size - offset;
    const size_t chunk_size = remaining > PBNS_FRAME_V1_DATA_PAYLOAD_MAX
                                  ? PBNS_FRAME_V1_DATA_PAYLOAD_MAX
                                  : remaining;
    const bool final_record = chunk_size == remaining;
    status = submission->send_data(
        submission->send_context, &challenge->request_id, sequence,
        (pbns_view){&workspace->ciphertext.ptr[offset], chunk_size},
        final_record);
    offset += chunk_size;
    if (status == PBNS_OK && !final_record) {
      if (sequence == UINT32_MAX) {
        status = PBNS_ERR_LIMIT;
      } else {
        ++sequence;
      }
    }
  }
  if (status != PBNS_OK) {
    wipe_buffer(submission->evidence_digest);
  }
  wipe_bytes(report_digest, sizeof(report_digest));
  wipe_bytes(qualifying_data, sizeof(qualifying_data));
  wipe_workspace(workspace);
  return status;
}

void pbns_attestation_challenge_reset(pbns_attestation_challenge *challenge) {
  if (challenge != NULL) {
    wipe_bytes((uint8_t *)challenge, sizeof(*challenge));
  }
}
