#include "pbns/recovery_request.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"

#define PBNS_RECOVERY_REQUEST_FIELD_COUNT 8U

static bool output_valid(pbns_buffer output) {
  return output.len == 0U && (output.ptr != NULL || output.cap == 0U);
}

static bool view_valid(pbns_view input) {
  return input.ptr != NULL || input.len == 0U;
}

static bool any_nonzero(const uint8_t *value, size_t size) {
  uint8_t combined = 0U;
  for (size_t index = 0U; index < size; ++index) {
    combined |= value[index];
  }
  return combined != 0U;
}

static bool request_valid(const pbns_recovery_request *request) {
  if (request == NULL ||
      !any_nonzero(request->request_id, sizeof(request->request_id)) ||
      !any_nonzero(request->host_fingerprint,
                   sizeof(request->host_fingerprint)) ||
      !any_nonzero(request->nonce, sizeof(request->nonce))) {
    return false;
  }
  const bool digest_nonzero = any_nonzero(request->artifact_digest,
                                          sizeof(request->artifact_digest));
  return (request->operation == PBNS_RECOVERY_OPERATION_MANIFEST &&
          !digest_nonzero) ||
         (request->operation == PBNS_RECOVERY_OPERATION_ARTIFACT &&
          digest_nonzero);
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

static pbns_status encode_unchecked(const pbns_recovery_request *request,
                                    pbns_buffer output, size_t *written) {
  QCBOREncodeContext encoder = {0};
  UsefulBufC encoded = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddSZStringToMapN(&encoder, 1,
                                PBNS_RECOVERY_REQUEST_DOMAIN);
  QCBOREncode_AddUInt64ToMapN(&encoder, 2,
                              PBNS_RECOVERY_REQUEST_VERSION);
  QCBOREncode_AddUInt64ToMapN(&encoder, 3,
                              PBNS_RECOVERY_REQUEST_SERVICE);
  QCBOREncode_AddUInt64ToMapN(&encoder, 4, (uint64_t)request->operation);
  QCBOREncode_AddBytesToMapN(
      &encoder, 5,
      (UsefulBufC){request->request_id, sizeof(request->request_id)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 6,
      (UsefulBufC){request->host_fingerprint,
                   sizeof(request->host_fingerprint)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 7, (UsefulBufC){request->nonce, sizeof(request->nonce)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 8,
      (UsefulBufC){request->artifact_digest,
                   sizeof(request->artifact_digest)});
  QCBOREncode_CloseMap(&encoder);
  const QCBORError error = QCBOREncode_Finish(&encoder, &encoded);
  if (error == QCBOR_ERR_BUFFER_TOO_SMALL) {
    return PBNS_ERR_LIMIT;
  }
  if (error != QCBOR_SUCCESS || encoded.len == 0U ||
      encoded.len > PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  *written = encoded.len;
  return PBNS_OK;
}

pbns_status pbns_recovery_request_encode(const pbns_recovery_request *request,
                                         pbns_buffer output,
                                         size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  if (request == NULL || !output_valid(output) || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!request_valid(request)) {
    return PBNS_ERR_ARGUMENT;
  }
  if (output.cap > PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE) {
    output.cap = PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE;
  }
  return encode_unchecked(request, output, written);
}

static pbns_status next_item(QCBORDecodeContext *decoder, int64_t label,
                             QCBORItem *item) {
  if (QCBORDecode_GetNext(decoder, item) != QCBOR_SUCCESS ||
      item->uNestingLevel != 1U || item->uLabelType != QCBOR_TYPE_INT64 ||
      item->label.int64 != label) {
    return PBNS_ERR_FORMAT;
  }
  return PBNS_OK;
}

static bool item_uint64(const QCBORItem *item, uint64_t *value) {
  if (item->uDataType == QCBOR_TYPE_UINT64) {
    *value = item->val.uint64;
    return true;
  }
  if (item->uDataType == QCBOR_TYPE_INT64 && item->val.int64 >= 0) {
    *value = (uint64_t)item->val.int64;
    return true;
  }
  return false;
}

static bool item_bytes(const QCBORItem *item, uint8_t *output,
                       size_t expected_size) {
  if (item->uDataType != QCBOR_TYPE_BYTE_STRING ||
      item->val.string.len != expected_size) {
    return false;
  }
  memcpy(output, item->val.string.ptr, expected_size);
  return true;
}

static pbns_status decode_unchecked(pbns_view encoded,
                                    pbns_recovery_request *request) {
  QCBORDecodeContext decoder = {0};
  QCBORItem item = {0};
  QCBORDecode_Init(&decoder, (UsefulBufC){encoded.ptr, encoded.len},
                   QCBOR_DECODE_MODE_NORMAL);
  if (QCBORDecode_GetNext(&decoder, &item) != QCBOR_SUCCESS ||
      item.uDataType != QCBOR_TYPE_MAP || item.uLabelType != QCBOR_TYPE_NONE ||
      item.val.uCount != PBNS_RECOVERY_REQUEST_FIELD_COUNT) {
    return PBNS_ERR_FORMAT;
  }
  if (next_item(&decoder, 1, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_TEXT_STRING) {
    return PBNS_ERR_FORMAT;
  }
  static const uint8_t domain[] = PBNS_RECOVERY_REQUEST_DOMAIN;
  if (item.val.string.len != sizeof(domain) - 1U ||
      memcmp(item.val.string.ptr, domain, sizeof(domain) - 1U) != 0) {
    return PBNS_ERR_FORMAT;
  }
  uint64_t value = 0U;
  if (next_item(&decoder, 2, &item) != PBNS_OK ||
      !item_uint64(&item, &value) ||
      value != PBNS_RECOVERY_REQUEST_VERSION ||
      next_item(&decoder, 3, &item) != PBNS_OK ||
      !item_uint64(&item, &value) ||
      value != PBNS_RECOVERY_REQUEST_SERVICE ||
      next_item(&decoder, 4, &item) != PBNS_OK ||
      !item_uint64(&item, &value) || value > UINT32_MAX) {
    return PBNS_ERR_FORMAT;
  }
  request->operation = (pbns_recovery_operation)value;
  if (next_item(&decoder, 5, &item) != PBNS_OK ||
      !item_bytes(&item, request->request_id, sizeof(request->request_id)) ||
      next_item(&decoder, 6, &item) != PBNS_OK ||
      !item_bytes(&item, request->host_fingerprint,
                  sizeof(request->host_fingerprint)) ||
      next_item(&decoder, 7, &item) != PBNS_OK ||
      !item_bytes(&item, request->nonce, sizeof(request->nonce)) ||
      next_item(&decoder, 8, &item) != PBNS_OK ||
      !item_bytes(&item, request->artifact_digest,
                  sizeof(request->artifact_digest)) ||
      QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS ||
      !request_valid(request)) {
    return PBNS_ERR_FORMAT;
  }
  return PBNS_OK;
}

pbns_status pbns_recovery_request_decode(pbns_view encoded,
                                         pbns_buffer canonical_scratch,
                                         pbns_recovery_request *request) {
  if (request != NULL) {
    *request = (pbns_recovery_request){0};
  }
  if (!view_valid(encoded) || encoded.len == 0U ||
      encoded.len > PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE ||
      !output_valid(canonical_scratch) || request == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (canonical_scratch.cap < encoded.len) {
    return PBNS_ERR_LIMIT;
  }
  if (ranges_overlap(encoded, canonical_scratch)) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_recovery_request decoded = {0};
  pbns_status status = decode_unchecked(encoded, &decoded);
  if (status != PBNS_OK) {
    return status;
  }
  size_t canonical_size = 0U;
  status = encode_unchecked(&decoded, canonical_scratch, &canonical_size);
  if (status != PBNS_OK) {
    return status;
  }
  if (canonical_size != encoded.len ||
      memcmp(canonical_scratch.ptr, encoded.ptr, encoded.len) != 0) {
    return PBNS_ERR_FORMAT;
  }
  *request = decoded;
  return PBNS_OK;
}
