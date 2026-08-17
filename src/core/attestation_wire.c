#include "pbns/attestation_wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "qcbor/qcbor.h"

#define PBNS_ATTESTATION_WIRE_REQUEST_FIELDS 3U
#define PBNS_ATTESTATION_WIRE_RESPONSE_FIELDS 7U

static bool buffer_valid(pbns_buffer buffer) {
  return buffer.ptr != NULL && buffer.len == 0U && buffer.cap > 0U &&
         buffer.cap <= PBNS_ATTESTATION_WIRE_MAX_SIZE;
}

static bool view_valid(pbns_view view) {
  return view.ptr != NULL || view.len == 0U;
}

static bool nonzero(const uint8_t *bytes, size_t length) {
  uint8_t aggregate = 0U;
  for (size_t index = 0U; index < length; ++index) {
    aggregate |= bytes[index];
  }
  return aggregate != 0U;
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

static pbns_status encode_request(uint64_t operation, pbns_view host,
                                  pbns_view challenge_request_id,
                                  pbns_buffer output, size_t *written) {
  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (!buffer_valid(output) || !view_valid(host) ||
      !view_valid(challenge_request_id) || host.len != 32U ||
      challenge_request_id.len != sizeof(((pbns_request_id *)0)->bytes)) {
    return PBNS_ERR_ARGUMENT;
  }
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddUInt64ToMapN(&encoder, 1, operation);
  QCBOREncode_AddBytesToMapN(
      &encoder, 2, (UsefulBufC){host.ptr, host.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 3,
      (UsefulBufC){challenge_request_id.ptr, challenge_request_id.len});
  QCBOREncode_CloseMap(&encoder);
  return finish_encode(&encoder, written);
}

pbns_status pbns_attestation_wire_encode_issue_request(
    const uint8_t host_fingerprint[32], pbns_buffer output, size_t *written) {
  static const uint8_t empty_request_id[16] = {0};
  if (host_fingerprint == NULL ||
      !nonzero(host_fingerprint, sizeof(empty_request_id) * 2U)) {
    if (written != NULL) {
      *written = 0U;
    }
    return PBNS_ERR_ARGUMENT;
  }
  return encode_request(
      PBNS_ATTESTATION_WIRE_ISSUE,
      (pbns_view){host_fingerprint, sizeof(empty_request_id) * 2U},
      (pbns_view){empty_request_id, sizeof(empty_request_id)}, output, written);
}

pbns_status pbns_attestation_wire_encode_submit_request(
    pbns_view challenge_request_id, pbns_buffer output, size_t *written) {
  static const uint8_t empty_host[32] = {0};
  if (!view_valid(challenge_request_id) ||
      challenge_request_id.len != sizeof(((pbns_request_id *)0)->bytes) ||
      !nonzero(challenge_request_id.ptr, challenge_request_id.len)) {
    if (written != NULL) {
      *written = 0U;
    }
    return PBNS_ERR_ARGUMENT;
  }
  return encode_request(PBNS_ATTESTATION_WIRE_SUBMIT,
                        (pbns_view){empty_host, sizeof(empty_host)},
                        challenge_request_id, output, written);
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

static pbns_status decode_fixed(QCBORDecodeContext *decoder, int64_t label,
                                uint8_t *output, size_t length) {
  QCBORItem item = {0};
  if (next_labeled(decoder, label, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      item.val.string.len != length) {
    return PBNS_ERR_FORMAT;
  }
  memcpy(output, item.val.string.ptr, length);
  return PBNS_OK;
}

static pbns_status decode_view(QCBORDecodeContext *decoder, int64_t label,
                               pbns_view *output) {
  QCBORItem item = {0};
  if (next_labeled(decoder, label, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING) {
    return PBNS_ERR_FORMAT;
  }
  *output = (pbns_view){item.val.string.ptr, item.val.string.len};
  return PBNS_OK;
}

static pbns_status encode_response(
    const pbns_attestation_wire_response *response, pbns_buffer output,
    size_t *written) {
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddUInt64ToMapN(&encoder, 1, response->operation);
  QCBOREncode_AddBytesToMapN(
      &encoder, 2,
      (UsefulBufC){response->challenge_request_id.bytes,
                   sizeof(response->challenge_request_id.bytes)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 3,
      (UsefulBufC){response->verifier_nonce,
                   sizeof(response->verifier_nonce)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 4,
      (UsefulBufC){response->recipient_kid.ptr, response->recipient_kid.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 5, (UsefulBufC){response->object.ptr, response->object.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 6,
      (UsefulBufC){response->evidence_digest,
                   sizeof(response->evidence_digest)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 7,
      (UsefulBufC){response->baseline_id, sizeof(response->baseline_id)});
  QCBOREncode_CloseMap(&encoder);
  return finish_encode(&encoder, written);
}

static pbns_status decode_response(pbns_view encoded, uint64_t operation,
                                   pbns_buffer canonical,
                                   pbns_attestation_wire_response *response) {
  if (!view_valid(encoded) || encoded.len == 0U ||
      encoded.len > PBNS_ATTESTATION_WIRE_MAX_SIZE ||
      !buffer_valid(canonical) || canonical.cap < encoded.len ||
      response == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *response = (pbns_attestation_wire_response){0};
  QCBORDecodeContext decoder = {0};
  QCBORItem item = {0};
  QCBORDecode_Init(&decoder, (UsefulBufC){encoded.ptr, encoded.len},
                   QCBOR_DECODE_MODE_NORMAL);
  if (QCBORDecode_GetNext(&decoder, &item) != QCBOR_SUCCESS ||
      item.uDataType != QCBOR_TYPE_MAP || item.uLabelType != QCBOR_TYPE_NONE ||
      item.val.uCount != PBNS_ATTESTATION_WIRE_RESPONSE_FIELDS ||
      next_labeled(&decoder, 1, &item) != PBNS_OK ||
      !item_uint(&item, &response->operation) ||
      response->operation != operation ||
      decode_fixed(&decoder, 2, response->challenge_request_id.bytes,
                   sizeof(response->challenge_request_id.bytes)) != PBNS_OK ||
      decode_fixed(&decoder, 3, response->verifier_nonce,
                   sizeof(response->verifier_nonce)) != PBNS_OK ||
      decode_view(&decoder, 4, &response->recipient_kid) != PBNS_OK ||
      decode_view(&decoder, 5, &response->object) != PBNS_OK ||
      decode_fixed(&decoder, 6, response->evidence_digest,
                   sizeof(response->evidence_digest)) != PBNS_OK ||
      decode_fixed(&decoder, 7, response->baseline_id,
                   sizeof(response->baseline_id)) != PBNS_OK ||
      QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS) {
    *response = (pbns_attestation_wire_response){0};
    return PBNS_ERR_FORMAT;
  }
  size_t canonical_size = 0U;
  const pbns_status status =
      encode_response(response, canonical, &canonical_size);
  if (status != PBNS_OK || canonical_size != encoded.len ||
      memcmp(canonical.ptr, encoded.ptr, encoded.len) != 0) {
    *response = (pbns_attestation_wire_response){0};
    return status == PBNS_OK ? PBNS_ERR_FORMAT : status;
  }
  return PBNS_OK;
}

pbns_status pbns_attestation_wire_decode_issue_response(
    pbns_view encoded, pbns_buffer canonical,
    pbns_attestation_wire_response *response) {
  const pbns_status status = decode_response(
      encoded, PBNS_ATTESTATION_WIRE_ISSUE, canonical, response);
  if (status != PBNS_OK) {
    return status;
  }
  if (!nonzero(response->challenge_request_id.bytes,
               sizeof(response->challenge_request_id.bytes)) ||
      !nonzero(response->verifier_nonce, sizeof(response->verifier_nonce)) ||
      response->recipient_kid.len == 0U ||
      response->recipient_kid.len > 64U || response->object.len == 0U ||
      nonzero(response->evidence_digest, sizeof(response->evidence_digest)) ||
      nonzero(response->baseline_id, sizeof(response->baseline_id))) {
    *response = (pbns_attestation_wire_response){0};
    return PBNS_ERR_FORMAT;
  }
  return PBNS_OK;
}

pbns_status pbns_attestation_wire_decode_submit_response(
    pbns_view encoded, pbns_view expected_challenge_request_id,
    pbns_buffer canonical, pbns_attestation_wire_response *response) {
  if (!view_valid(expected_challenge_request_id) ||
      expected_challenge_request_id.len !=
          sizeof(((pbns_request_id *)0)->bytes) ||
      !nonzero(expected_challenge_request_id.ptr,
               expected_challenge_request_id.len)) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status status = decode_response(
      encoded, PBNS_ATTESTATION_WIRE_SUBMIT, canonical, response);
  if (status != PBNS_OK) {
    return status;
  }
  if (memcmp(response->challenge_request_id.bytes,
             expected_challenge_request_id.ptr,
             expected_challenge_request_id.len) != 0) {
    *response = (pbns_attestation_wire_response){0};
    return PBNS_ERR_AUTHENTICATION;
  }
  if (nonzero(response->verifier_nonce, sizeof(response->verifier_nonce)) ||
      response->recipient_kid.len != 0U || response->object.len == 0U ||
      !nonzero(response->evidence_digest,
               sizeof(response->evidence_digest)) ||
      !nonzero(response->baseline_id, sizeof(response->baseline_id))) {
    *response = (pbns_attestation_wire_response){0};
    return PBNS_ERR_FORMAT;
  }
  return PBNS_OK;
}
