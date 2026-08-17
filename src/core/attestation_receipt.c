#include "pbns/attestation_receipt.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "qcbor/qcbor.h"

#define PBNS_COSE_SIGN1_TAG UINT64_C(18)
#define PBNS_COSE_ES256 (-7)

typedef struct decoded_receipt {
  pbns_view domain;
  uint64_t version;
  uint64_t service;
  uint8_t request_id[PBNS_ATTESTATION_RECEIPT_REQUEST_ID_SIZE];
  uint8_t verifier_nonce[PBNS_ATTESTATION_RECEIPT_DIGEST_SIZE];
  uint8_t host_fingerprint[PBNS_ATTESTATION_RECEIPT_DIGEST_SIZE];
  uint8_t evidence_digest[PBNS_ATTESTATION_RECEIPT_DIGEST_SIZE];
  uint8_t baseline_id[PBNS_ATTESTATION_RECEIPT_DIGEST_SIZE];
  uint64_t verdict;
  uint64_t reasons[PBNS_ATTESTATION_RECEIPT_MAX_REASONS];
  size_t reason_count;
  pbns_view key_id;
} decoded_receipt;

static bool view_valid(pbns_view view) {
  return view.ptr != NULL || view.len == 0U;
}

static bool buffer_valid(pbns_buffer buffer) {
  return buffer.len == 0U && (buffer.ptr != NULL || buffer.cap == 0U);
}

static bool ranges_overlap(pbns_view input, pbns_buffer output) {
  if (input.len == 0U || output.cap == 0U) { return false; }
  const uintptr_t input_start = (uintptr_t)input.ptr;
  const uintptr_t output_start = (uintptr_t)output.ptr;
  if (input.len > UINTPTR_MAX - input_start || output.cap > UINTPTR_MAX - output_start) { return true; }
  return input_start < output_start + output.cap && output_start < input_start + input.len;
}

static bool workspaces_overlap(const pbns_attestation_receipt_workspace *workspace) {
  const pbns_view payload = {workspace->canonical_payload.ptr, workspace->canonical_payload.cap};
  const pbns_view cose = {workspace->canonical_cose.ptr, workspace->canonical_cose.cap};
  return ranges_overlap(payload, workspace->canonical_cose) ||
         ranges_overlap(payload, workspace->aad) || ranges_overlap(cose, workspace->aad);
}

static bool nonzero(const uint8_t *bytes, size_t length) {
  uint8_t aggregate = 0U;
  for (size_t index = 0U; index < length; ++index) {
    aggregate |= bytes[index];
  }
  return aggregate != 0U;
}

static bool constant_equal(const uint8_t *left, const uint8_t *right,
                           size_t length) {
  uint8_t difference = 0U;
  for (size_t index = 0U; index < length; ++index) {
    difference |= (uint8_t)(left[index] ^ right[index]);
  }
  return difference == 0U;
}

static bool expectation_valid(
    const pbns_attestation_receipt_expectation *expectation) {
  return expectation != NULL &&
         nonzero(expectation->request_id, sizeof(expectation->request_id)) &&
         nonzero(expectation->verifier_nonce,
                 sizeof(expectation->verifier_nonce)) &&
         nonzero(expectation->host_fingerprint,
                 sizeof(expectation->host_fingerprint)) &&
         nonzero(expectation->evidence_digest,
                 sizeof(expectation->evidence_digest)) &&
         nonzero(expectation->baseline_id, sizeof(expectation->baseline_id)) &&
         view_valid(expectation->key_id) && expectation->key_id.len > 0U &&
         expectation->key_id.len <= PBNS_ATTESTATION_RECEIPT_MAX_KEY_ID_SIZE;
}

static pbns_status next_labeled(QCBORDecodeContext *decoder, int64_t label,
                                QCBORItem *item) {
  if (QCBORDecode_GetNext(decoder, item) != QCBOR_SUCCESS ||
      item->uNestingLevel != 1U || item->uLabelType != QCBOR_TYPE_INT64 ||
      item->label.int64 != label) {
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

static bool decode_fixed(QCBORDecodeContext *decoder, int64_t label,
                         uint8_t *output, size_t length) {
  QCBORItem item = {0};
  if (next_labeled(decoder, label, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      item.val.string.len != length) {
    return false;
  }
  const uint8_t *input = item.val.string.ptr;
  for (size_t index = 0U; index < length; ++index) { output[index] = input[index]; }
  return true;
}

static bool reasons_valid(const decoded_receipt *receipt) {
  for (size_t index = 0U; index < receipt->reason_count; ++index) {
    if (receipt->reasons[index] < 1U || receipt->reasons[index] > 16U ||
        (index > 0U &&
         receipt->reasons[index] <= receipt->reasons[index - 1U])) {
      return false;
    }
  }
  if (receipt->verdict == PBNS_ATTESTATION_RECEIPT_FULL) {
    return receipt->reason_count == 0U;
  }
  if (receipt->verdict == PBNS_ATTESTATION_RECEIPT_REDUCED) {
    return receipt->reason_count == 1U && receipt->reasons[0] == 1U;
  }
  return receipt->verdict == PBNS_ATTESTATION_RECEIPT_FAILURE &&
         receipt->reason_count > 0U;
}

static bool decoded_shape_valid(const decoded_receipt *receipt) {
  static const uint8_t domain[] = PBNS_ATTESTATION_RECEIPT_DOMAIN;
  return receipt->domain.ptr != NULL &&
         receipt->domain.len == sizeof(domain) - 1U &&
         memcmp(receipt->domain.ptr, domain, sizeof(domain) - 1U) == 0 &&
         receipt->version == PBNS_ATTESTATION_RECEIPT_VERSION &&
         receipt->service == PBNS_ATTESTATION_RECEIPT_SERVICE &&
         nonzero(receipt->request_id, sizeof(receipt->request_id)) &&
         nonzero(receipt->verifier_nonce, sizeof(receipt->verifier_nonce)) &&
         nonzero(receipt->host_fingerprint,
                 sizeof(receipt->host_fingerprint)) &&
         nonzero(receipt->evidence_digest,
                 sizeof(receipt->evidence_digest)) &&
         nonzero(receipt->baseline_id, sizeof(receipt->baseline_id)) &&
         receipt->key_id.ptr != NULL && receipt->key_id.len > 0U &&
         receipt->key_id.len <= PBNS_ATTESTATION_RECEIPT_MAX_KEY_ID_SIZE &&
         reasons_valid(receipt);
}

static pbns_status decode_payload(pbns_view payload, decoded_receipt *receipt) {
  QCBORDecodeContext decoder = {0};
  QCBORItem item = {0};
  QCBORDecode_Init(&decoder, (UsefulBufC){payload.ptr, payload.len},
                   QCBOR_DECODE_MODE_NORMAL);
  if (QCBORDecode_GetNext(&decoder, &item) != QCBOR_SUCCESS ||
      item.uDataType != QCBOR_TYPE_MAP || item.uLabelType != QCBOR_TYPE_NONE ||
      item.val.uCount != 11U || next_labeled(&decoder, 1, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_TEXT_STRING) {
    return PBNS_ERR_FORMAT;
  }
  receipt->domain = (pbns_view){item.val.string.ptr, item.val.string.len};
  if (next_labeled(&decoder, 2, &item) != PBNS_OK ||
      !item_uint(&item, &receipt->version) ||
      next_labeled(&decoder, 3, &item) != PBNS_OK ||
      !item_uint(&item, &receipt->service) ||
      !decode_fixed(&decoder, 4, receipt->request_id,
                    sizeof(receipt->request_id)) ||
      !decode_fixed(&decoder, 5, receipt->verifier_nonce,
                    sizeof(receipt->verifier_nonce)) ||
      !decode_fixed(&decoder, 6, receipt->host_fingerprint,
                    sizeof(receipt->host_fingerprint)) ||
      !decode_fixed(&decoder, 7, receipt->evidence_digest,
                    sizeof(receipt->evidence_digest)) ||
      !decode_fixed(&decoder, 8, receipt->baseline_id,
                    sizeof(receipt->baseline_id)) ||
      next_labeled(&decoder, 9, &item) != PBNS_OK ||
      !item_uint(&item, &receipt->verdict) ||
      next_labeled(&decoder, 10, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_ARRAY ||
      item.val.uCount > PBNS_ATTESTATION_RECEIPT_MAX_REASONS) {
    return PBNS_ERR_FORMAT;
  }
  receipt->reason_count = item.val.uCount;
  for (size_t index = 0U; index < receipt->reason_count; ++index) {
    if (QCBORDecode_GetNext(&decoder, &item) != QCBOR_SUCCESS ||
        item.uNestingLevel != 2U || item.uLabelType != QCBOR_TYPE_NONE ||
        !item_uint(&item, &receipt->reasons[index])) {
      return PBNS_ERR_FORMAT;
    }
  }
  if (next_labeled(&decoder, 11, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS) {
    return PBNS_ERR_FORMAT;
  }
  receipt->key_id = (pbns_view){item.val.string.ptr, item.val.string.len};
  return decoded_shape_valid(receipt) ? PBNS_OK : PBNS_ERR_FORMAT;
}

static pbns_status encode_payload(const decoded_receipt *receipt,
                                  pbns_buffer output, size_t *written) {
  QCBOREncodeContext encoder = {0};
  UsefulBufC encoded = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddTextToMapN(
      &encoder, 1,
      (UsefulBufC){receipt->domain.ptr, receipt->domain.len});
  QCBOREncode_AddUInt64ToMapN(&encoder, 2, receipt->version);
  QCBOREncode_AddUInt64ToMapN(&encoder, 3, receipt->service);
  QCBOREncode_AddBytesToMapN(
      &encoder, 4,
      (UsefulBufC){receipt->request_id, sizeof(receipt->request_id)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 5,
      (UsefulBufC){receipt->verifier_nonce, sizeof(receipt->verifier_nonce)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 6, (UsefulBufC){receipt->host_fingerprint,
                                sizeof(receipt->host_fingerprint)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 7,
      (UsefulBufC){receipt->evidence_digest, sizeof(receipt->evidence_digest)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 8,
      (UsefulBufC){receipt->baseline_id, sizeof(receipt->baseline_id)});
  QCBOREncode_AddUInt64ToMapN(&encoder, 9, receipt->verdict);
  QCBOREncode_OpenArrayInMapN(&encoder, 10);
  for (size_t index = 0U; index < receipt->reason_count; ++index) {
    QCBOREncode_AddUInt64(&encoder, receipt->reasons[index]);
  }
  QCBOREncode_CloseArray(&encoder);
  QCBOREncode_AddBytesToMapN(
      &encoder, 11,
      (UsefulBufC){receipt->key_id.ptr, receipt->key_id.len});
  QCBOREncode_CloseMap(&encoder);
  const QCBORError error = QCBOREncode_Finish(&encoder, &encoded);
  if (error == QCBOR_ERR_BUFFER_TOO_SMALL) {
    return PBNS_ERR_LIMIT;
  }
  if (error != QCBOR_SUCCESS) {
    return PBNS_ERR_FORMAT;
  }
  *written = encoded.len;
  return PBNS_OK;
}

static bool cose_profile_valid(pbns_view signed_receipt, pbns_view expected_kid,
                               pbns_buffer canonical_cose) {
  QCBORDecodeContext decoder = {0};
  QCBORItem item = {0};
  UsefulBufC protected_headers = {0};
  UsefulBufC payload = {0};
  UsefulBufC signature = {0};
  QCBORDecode_Init(&decoder,
                   (UsefulBufC){signed_receipt.ptr, signed_receipt.len},
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
      QCBORDecode_GetNext(&headers, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uLabelType != QCBOR_TYPE_INT64 ||
      item.label.int64 != 1 || item.uDataType != QCBOR_TYPE_INT64 ||
      item.val.int64 != PBNS_COSE_ES256 ||
      QCBORDecode_GetNext(&headers, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uLabelType != QCBOR_TYPE_INT64 ||
      item.label.int64 != 4 || item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      item.val.string.len != expected_kid.len ||
      !constant_equal(item.val.string.ptr, expected_kid.ptr,
                      expected_kid.len) ||
      QCBORDecode_Finish(&headers) != QCBOR_SUCCESS) {
    return false;
  }

  uint8_t canonical_headers[96] = {0};
  QCBOREncodeContext encoder = {0};
  UsefulBufC encoded_headers = {0};
  QCBOREncode_Init(&encoder,
                   (UsefulBuf){canonical_headers, sizeof(canonical_headers)});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddInt64ToMapN(&encoder, 1, PBNS_COSE_ES256);
  QCBOREncode_AddBytesToMapN(
      &encoder, 4, (UsefulBufC){expected_kid.ptr, expected_kid.len});
  QCBOREncode_CloseMap(&encoder);
  if (QCBOREncode_Finish(&encoder, &encoded_headers) != QCBOR_SUCCESS ||
      encoded_headers.len != protected_headers.len ||
      memcmp(encoded_headers.ptr, protected_headers.ptr,
             encoded_headers.len) != 0) {
    return false;
  }

  UsefulBufC canonical = {0};
  QCBOREncode_Init(&encoder,
                   (UsefulBuf){canonical_cose.ptr, canonical_cose.cap});
  QCBOREncode_AddTag(&encoder, PBNS_COSE_SIGN1_TAG);
  QCBOREncode_OpenArray(&encoder);
  QCBOREncode_AddBytes(&encoder, protected_headers);
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_CloseMap(&encoder);
  QCBOREncode_AddBytes(&encoder, payload);
  QCBOREncode_AddBytes(&encoder, signature);
  QCBOREncode_CloseArray(&encoder);
  return QCBOREncode_Finish(&encoder, &canonical) == QCBOR_SUCCESS &&
         canonical.len == signed_receipt.len &&
         memcmp(canonical.ptr, signed_receipt.ptr, canonical.len) == 0;
}

static pbns_status make_aad(
    const pbns_attestation_receipt_expectation *expectation,
    pbns_buffer output, size_t *written) {
  QCBOREncodeContext encoder = {0};
  UsefulBufC encoded = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenArray(&encoder);
  QCBOREncode_AddSZString(&encoder, PBNS_ATTESTATION_RECEIPT_AAD_DOMAIN);
  QCBOREncode_AddUInt64(&encoder, PBNS_ATTESTATION_RECEIPT_VERSION);
  QCBOREncode_AddUInt64(&encoder, PBNS_ATTESTATION_RECEIPT_SERVICE);
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){expectation->request_id, sizeof(expectation->request_id)});
  QCBOREncode_AddBytes(
      &encoder, (UsefulBufC){expectation->verifier_nonce,
                             sizeof(expectation->verifier_nonce)});
  QCBOREncode_AddBytes(
      &encoder, (UsefulBufC){expectation->host_fingerprint,
                             sizeof(expectation->host_fingerprint)});
  QCBOREncode_AddBytes(
      &encoder, (UsefulBufC){expectation->evidence_digest,
                             sizeof(expectation->evidence_digest)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){expectation->baseline_id, sizeof(expectation->baseline_id)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){expectation->key_id.ptr, expectation->key_id.len});
  QCBOREncode_CloseArray(&encoder);
  const QCBORError error = QCBOREncode_Finish(&encoder, &encoded);
  if (error == QCBOR_ERR_BUFFER_TOO_SMALL) {
    return PBNS_ERR_LIMIT;
  }
  if (error != QCBOR_SUCCESS) {
    return PBNS_ERR_FORMAT;
  }
  *written = encoded.len;
  return PBNS_OK;
}

static bool bindings_match(
    const decoded_receipt *receipt,
    const pbns_attestation_receipt_expectation *expectation) {
  return constant_equal(receipt->request_id, expectation->request_id,
                        sizeof(receipt->request_id)) &&
         constant_equal(receipt->verifier_nonce, expectation->verifier_nonce,
                        sizeof(receipt->verifier_nonce)) &&
         constant_equal(receipt->host_fingerprint,
                        expectation->host_fingerprint,
                        sizeof(receipt->host_fingerprint)) &&
         constant_equal(receipt->evidence_digest, expectation->evidence_digest,
                        sizeof(receipt->evidence_digest)) &&
         constant_equal(receipt->baseline_id, expectation->baseline_id,
                        sizeof(receipt->baseline_id)) &&
         receipt->key_id.len == expectation->key_id.len &&
         constant_equal(receipt->key_id.ptr, expectation->key_id.ptr,
                        expectation->key_id.len);
}

pbns_status pbns_attestation_receipt_verify(
    const pbns_crypto *verifier, pbns_view signed_receipt,
    const pbns_attestation_receipt_expectation *expectation,
    pbns_attestation_receipt_workspace *workspace,
    pbns_attestation_receipt_result *result) {
  if (result != NULL) {
    *result = (pbns_attestation_receipt_result){
        .verdict = PBNS_ATTESTATION_RECEIPT_FAILURE,
        .display_state = PBNS_ATTESTATION_DISPLAY_FAILURE};
  }
  if (verifier == NULL || !view_valid(signed_receipt) ||
      signed_receipt.len == 0U ||
      signed_receipt.len > PBNS_ATTESTATION_RECEIPT_MAX_SIGNED_SIZE ||
      !expectation_valid(expectation) || workspace == NULL ||
      !buffer_valid(workspace->canonical_payload) ||
      !buffer_valid(workspace->canonical_cose) ||
      !buffer_valid(workspace->aad) || result == NULL ||
      ranges_overlap(signed_receipt, workspace->canonical_payload) ||
      ranges_overlap(signed_receipt, workspace->canonical_cose) ||
      ranges_overlap(signed_receipt, workspace->aad) ||
      workspaces_overlap(workspace)) {
    return PBNS_ERR_ARGUMENT;
  }
  if (workspace->canonical_payload.cap <
          PBNS_ATTESTATION_RECEIPT_MAX_PAYLOAD_SIZE ||
      workspace->canonical_cose.cap < signed_receipt.len ||
      workspace->aad.cap < PBNS_ATTESTATION_RECEIPT_MAX_AAD_SIZE) {
    return PBNS_ERR_LIMIT;
  }
  if (!cose_profile_valid(signed_receipt, expectation->key_id,
                          workspace->canonical_cose)) {
    return PBNS_ERR_AUTHENTICATION;
  }
  size_t aad_size = 0U;
  pbns_status status = make_aad(expectation, workspace->aad, &aad_size);
  if (status != PBNS_OK) {
    return status;
  }
  pbns_view payload = {0};
  status = pbns_sign1_verify(verifier, signed_receipt,
                             (pbns_view){workspace->aad.ptr, aad_size},
                             &payload);
  if (status != PBNS_OK) {
    return PBNS_ERR_AUTHENTICATION;
  }
  decoded_receipt decoded = {0};
  status = decode_payload(payload, &decoded);
  if (status != PBNS_OK) {
    return status;
  }
  size_t canonical_size = 0U;
  status = encode_payload(&decoded, workspace->canonical_payload,
                          &canonical_size);
  if (status != PBNS_OK || canonical_size != payload.len ||
      memcmp(workspace->canonical_payload.ptr, payload.ptr, payload.len) != 0) {
    return PBNS_ERR_FORMAT;
  }
  if (!bindings_match(&decoded, expectation)) {
    return PBNS_ERR_AUTHENTICATION;
  }
  result->verdict = (pbns_attestation_receipt_verdict)decoded.verdict;
  result->reason_count = decoded.reason_count;
  for (size_t index = 0U; index < decoded.reason_count; ++index) {
    result->reasons[index] = decoded.reasons[index];
  }
  result->display_state = decoded.verdict == PBNS_ATTESTATION_RECEIPT_FULL
                              ? PBNS_ATTESTATION_DISPLAY_FULL
                              : decoded.verdict == PBNS_ATTESTATION_RECEIPT_REDUCED
                                    ? PBNS_ATTESTATION_DISPLAY_REDUCED
                                    : PBNS_ATTESTATION_DISPLAY_FAILURE;
  return PBNS_OK;
}
