#include "pbns/trusted_time.h"

#include <limits.h>
#include <stddef.h>
#include <string.h>

#include "qcbor/qcbor.h"

#define PBNS_NANOSECONDS_PER_SECOND ((int64_t)1000000000)
#define PBNS_NANOSECONDS_PER_MILLISECOND UINT64_C(1000000)

static void secure_zero(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  while (length > 0U) {
    *bytes = 0U;
    ++bytes;
    --length;
  }
}

static bool bytes_equal(const uint8_t *left, const uint8_t *right,
                        size_t length) {
  uint8_t difference = 0U;
  for (size_t index = 0U; index < length; ++index) {
    difference |= (uint8_t)(left[index] ^ right[index]);
  }
  return difference == 0U;
}

static bool domain_is_valid(pbns_view domain) {
  static const uint8_t expected[] = PBNS_TIME_DOMAIN;
  return domain.ptr != NULL && domain.len == sizeof(expected) - 1U &&
         memcmp(domain.ptr, expected, sizeof(expected) - 1U) == 0;
}

static bool view_is_valid(pbns_view view) {
  return view.ptr != NULL || view.len == 0U;
}

static bool output_is_valid(pbns_buffer output) {
  return output.len == 0U && (output.ptr != NULL || output.cap == 0U);
}

static bool nonzero(const uint8_t *value, size_t length) {
  uint8_t aggregate = 0U;
  for (size_t index = 0U; index < length; ++index) {
    aggregate |= value[index];
  }
  return aggregate != 0U;
}

static bool request_is_valid(const pbns_trusted_time_request *request) {
  return request != NULL &&
         nonzero(request->request_id, sizeof(request->request_id)) &&
         nonzero(request->host_fingerprint,
                 sizeof(request->host_fingerprint)) &&
         nonzero(request->nonce, sizeof(request->nonce)) &&
         request->max_age_ms > 0U &&
         request->max_age_ms <= PBNS_TIME_MAX_AGE_MS;
}

static bool
assertion_shape_is_valid(const pbns_trusted_time_assertion *assertion) {
  return assertion != NULL && view_is_valid(assertion->domain) &&
         assertion->unix_seconds >= 0 &&
         assertion->nanoseconds < (uint32_t)PBNS_NANOSECONDS_PER_SECOND &&
         view_is_valid(assertion->quality) && assertion->quality.len > 0U &&
         assertion->quality.len <= PBNS_TIME_QUALITY_MAX_SIZE &&
         view_is_valid(assertion->key_id) && assertion->key_id.len > 0U &&
         assertion->key_id.len <= PBNS_TIME_KEY_ID_MAX_SIZE &&
         nonzero(assertion->request_id, sizeof(assertion->request_id)) &&
         nonzero(assertion->host_fingerprint,
                 sizeof(assertion->host_fingerprint)) &&
         nonzero(assertion->nonce, sizeof(assertion->nonce)) &&
         assertion->max_age_ms > 0U &&
         assertion->max_age_ms <= PBNS_TIME_MAX_AGE_MS;
}

static pbns_status finish_encoding(QCBOREncodeContext *encoder,
                                   size_t *written) {
  UsefulBufC encoded = {0};
  const QCBORError error = QCBOREncode_Finish(encoder, &encoded);
  if (error == QCBOR_ERR_BUFFER_TOO_SMALL) {
    return PBNS_ERR_LIMIT;
  }
  if (error != QCBOR_SUCCESS || encoded.len == 0U ||
      encoded.len > PBNS_TIME_ENCODED_MAX_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  *written = encoded.len;
  return PBNS_OK;
}

pbns_status
pbns_trusted_time_request_encode(const pbns_trusted_time_request *request,
                                 pbns_buffer output, size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  if (request == NULL || !output_is_valid(output) || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!request_is_valid(request)) {
    return PBNS_ERR_FORMAT;
  }
  if (output.cap > PBNS_TIME_ENCODED_MAX_SIZE) {
    output.cap = PBNS_TIME_ENCODED_MAX_SIZE;
  }
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddSZStringToMapN(&encoder, 1, PBNS_TIME_DOMAIN);
  QCBOREncode_AddUInt64ToMapN(&encoder, 2, PBNS_TIME_VERSION);
  QCBOREncode_AddUInt64ToMapN(&encoder, 3, PBNS_TIME_SERVICE);
  QCBOREncode_AddBytesToMapN(
      &encoder, 4,
      (UsefulBufC){request->request_id, sizeof(request->request_id)});
  QCBOREncode_AddBytesToMapN(&encoder, 5,
                             (UsefulBufC){request->host_fingerprint,
                                          sizeof(request->host_fingerprint)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 6, (UsefulBufC){request->nonce, sizeof(request->nonce)});
  QCBOREncode_AddUInt64ToMapN(&encoder, 7, request->max_age_ms);
  QCBOREncode_CloseMap(&encoder);
  return finish_encoding(&encoder, written);
}

static pbns_status
assertion_encode_unchecked(const pbns_trusted_time_assertion *assertion,
                           pbns_buffer output, size_t *written) {
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddTextToMapN(
      &encoder, 1, (UsefulBufC){assertion->domain.ptr, assertion->domain.len});
  QCBOREncode_AddUInt64ToMapN(&encoder, 2, assertion->version);
  QCBOREncode_AddUInt64ToMapN(&encoder, 3, assertion->service);
  QCBOREncode_AddBytesToMapN(
      &encoder, 4,
      (UsefulBufC){assertion->request_id, sizeof(assertion->request_id)});
  QCBOREncode_AddBytesToMapN(&encoder, 5,
                             (UsefulBufC){assertion->host_fingerprint,
                                          sizeof(assertion->host_fingerprint)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 6, (UsefulBufC){assertion->nonce, sizeof(assertion->nonce)});
  QCBOREncode_AddInt64ToMapN(&encoder, 7, assertion->unix_seconds);
  QCBOREncode_AddUInt64ToMapN(&encoder, 8, assertion->nanoseconds);
  QCBOREncode_AddUInt64ToMapN(&encoder, 9, assertion->uncertainty_ns);
  QCBOREncode_AddTextToMapN(
      &encoder, 10,
      (UsefulBufC){assertion->quality.ptr, assertion->quality.len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 11, (UsefulBufC){assertion->key_id.ptr, assertion->key_id.len});
  QCBOREncode_AddUInt64ToMapN(&encoder, 12, assertion->max_age_ms);
  QCBOREncode_CloseMap(&encoder);
  return finish_encoding(&encoder, written);
}

pbns_status
pbns_trusted_time_assertion_encode(const pbns_trusted_time_assertion *assertion,
                                   pbns_buffer output, size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  if (assertion == NULL || !output_is_valid(output) || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!assertion_shape_is_valid(assertion) ||
      !domain_is_valid(assertion->domain) ||
      assertion->version != PBNS_TIME_VERSION ||
      assertion->service != PBNS_TIME_SERVICE) {
    return PBNS_ERR_FORMAT;
  }
  if (output.cap > PBNS_TIME_ENCODED_MAX_SIZE) {
    output.cap = PBNS_TIME_ENCODED_MAX_SIZE;
  }
  return assertion_encode_unchecked(assertion, output, written);
}

static pbns_status next_item(QCBORDecodeContext *decoder,
                             int64_t expected_label, QCBORItem *item) {
  if (QCBORDecode_GetNext(decoder, item) != QCBOR_SUCCESS ||
      item->uNestingLevel != 1U || item->uLabelType != QCBOR_TYPE_INT64 ||
      item->label.int64 != expected_label) {
    return PBNS_ERR_FORMAT;
  }
  return PBNS_OK;
}

static bool item_to_u64(const QCBORItem *item, uint64_t *value) {
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

static bool decode_bytes(QCBORDecodeContext *decoder, int64_t label,
                         uint8_t *output, size_t expected_size) {
  QCBORItem item = {0};
  if (next_item(decoder, label, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      item.val.string.len != expected_size) {
    return false;
  }
  memcpy(output, item.val.string.ptr, expected_size);
  return true;
}

static pbns_status decode_assertion(pbns_view encoded,
                                    pbns_trusted_time_assertion *assertion) {
  QCBORDecodeContext decoder = {0};
  QCBORItem item = {0};
  QCBORDecode_Init(&decoder, (UsefulBufC){encoded.ptr, encoded.len},
                   QCBOR_DECODE_MODE_NORMAL);
  if (QCBORDecode_GetNext(&decoder, &item) != QCBOR_SUCCESS ||
      item.uDataType != QCBOR_TYPE_MAP || item.uLabelType != QCBOR_TYPE_NONE ||
      item.val.uCount != 12U) {
    return PBNS_ERR_FORMAT;
  }
  if (next_item(&decoder, 1, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_TEXT_STRING) {
    return PBNS_ERR_FORMAT;
  }
  assertion->domain = (pbns_view){item.val.string.ptr, item.val.string.len};
  if (next_item(&decoder, 2, &item) != PBNS_OK ||
      !item_to_u64(&item, &assertion->version) ||
      next_item(&decoder, 3, &item) != PBNS_OK ||
      !item_to_u64(&item, &assertion->service) ||
      !decode_bytes(&decoder, 4, assertion->request_id,
                    sizeof(assertion->request_id)) ||
      !decode_bytes(&decoder, 5, assertion->host_fingerprint,
                    sizeof(assertion->host_fingerprint)) ||
      !decode_bytes(&decoder, 6, assertion->nonce, sizeof(assertion->nonce))) {
    return PBNS_ERR_FORMAT;
  }
  if (next_item(&decoder, 7, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_INT64 || item.val.int64 < 0) {
    return PBNS_ERR_FORMAT;
  }
  assertion->unix_seconds = item.val.int64;
  uint64_t value = 0U;
  if (next_item(&decoder, 8, &item) != PBNS_OK || !item_to_u64(&item, &value) ||
      value > UINT32_MAX) {
    return PBNS_ERR_FORMAT;
  }
  assertion->nanoseconds = (uint32_t)value;
  if (next_item(&decoder, 9, &item) != PBNS_OK ||
      !item_to_u64(&item, &assertion->uncertainty_ns) ||
      next_item(&decoder, 10, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_TEXT_STRING) {
    return PBNS_ERR_FORMAT;
  }
  assertion->quality = (pbns_view){item.val.string.ptr, item.val.string.len};
  if (next_item(&decoder, 11, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING) {
    return PBNS_ERR_FORMAT;
  }
  assertion->key_id = (pbns_view){item.val.string.ptr, item.val.string.len};
  if (next_item(&decoder, 12, &item) != PBNS_OK ||
      !item_to_u64(&item, &value) || value > UINT32_MAX) {
    return PBNS_ERR_FORMAT;
  }
  assertion->max_age_ms = (uint32_t)value;
  if (QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS ||
      !assertion_shape_is_valid(assertion)) {
    return PBNS_ERR_FORMAT;
  }
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

pbns_status pbns_trusted_time_decode_verified_assertion(
    pbns_view verified_payload, pbns_view expected_key_id,
    pbns_buffer canonical_scratch, pbns_trusted_time_assertion *assertion) {
  if (assertion != NULL) {
    *assertion = (pbns_trusted_time_assertion){0};
  }
  if (!view_is_valid(verified_payload) || verified_payload.len == 0U ||
      verified_payload.len > PBNS_TIME_ENCODED_MAX_SIZE ||
      !view_is_valid(expected_key_id) || expected_key_id.len == 0U ||
      expected_key_id.len > PBNS_TIME_KEY_ID_MAX_SIZE ||
      !output_is_valid(canonical_scratch) || assertion == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (canonical_scratch.cap < verified_payload.len) {
    return PBNS_ERR_LIMIT;
  }
  if (buffers_overlap(verified_payload, canonical_scratch)) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_trusted_time_assertion decoded = {0};
  pbns_status status = decode_assertion(verified_payload, &decoded);
  if (status != PBNS_OK) {
    return status;
  }
  size_t canonical_size = 0U;
  status =
      assertion_encode_unchecked(&decoded, canonical_scratch, &canonical_size);
  if (status != PBNS_OK || canonical_size != verified_payload.len ||
      memcmp(canonical_scratch.ptr, verified_payload.ptr, canonical_size) !=
          0) {
    return PBNS_ERR_FORMAT;
  }
  if (!domain_is_valid(decoded.domain)) {
    return PBNS_ERR_AUTHENTICATION;
  }
  if (decoded.key_id.len != expected_key_id.len ||
      !bytes_equal(decoded.key_id.ptr, expected_key_id.ptr,
                   expected_key_id.len)) {
    return PBNS_ERR_AUTHENTICATION;
  }
  if (decoded.version != PBNS_TIME_VERSION) {
    return PBNS_ERR_VERSION;
  }
  if (decoded.service != PBNS_TIME_SERVICE) {
    return PBNS_ERR_SERVICE;
  }
  *assertion = decoded;
  return PBNS_OK;
}

pbns_status pbns_trusted_time_assertion_aad(
    const uint8_t request_id[PBNS_TIME_REQUEST_ID_SIZE],
    const uint8_t host_fingerprint[PBNS_TIME_FINGERPRINT_SIZE],
    const uint8_t nonce[PBNS_TIME_NONCE_SIZE], pbns_view key_id,
    pbns_buffer output, size_t *written) {
  static const uint8_t prefix[] = PBNS_TIME_ASSERTION_AAD;
  if (written != NULL) {
    *written = 0U;
  }
  if (request_id == NULL || host_fingerprint == NULL || nonce == NULL ||
      !view_is_valid(key_id) || key_id.len == 0U ||
      key_id.len > PBNS_TIME_KEY_ID_MAX_SIZE || !output_is_valid(output) ||
      written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  const size_t required = sizeof(prefix) - 1U + PBNS_TIME_REQUEST_ID_SIZE +
                          PBNS_TIME_FINGERPRINT_SIZE + PBNS_TIME_NONCE_SIZE +
                          key_id.len;
  if (output.cap < required) {
    return PBNS_ERR_LIMIT;
  }
  size_t offset = 0U;
  memcpy(output.ptr + offset, prefix, sizeof(prefix) - 1U);
  offset += sizeof(prefix) - 1U;
  memcpy(output.ptr + offset, request_id, PBNS_TIME_REQUEST_ID_SIZE);
  offset += PBNS_TIME_REQUEST_ID_SIZE;
  memcpy(output.ptr + offset, host_fingerprint, PBNS_TIME_FINGERPRINT_SIZE);
  offset += PBNS_TIME_FINGERPRINT_SIZE;
  memcpy(output.ptr + offset, nonce, PBNS_TIME_NONCE_SIZE);
  offset += PBNS_TIME_NONCE_SIZE;
  memcpy(output.ptr + offset, key_id.ptr, key_id.len);
  *written = required;
  return PBNS_OK;
}

static bool workspace_is_valid(const pbns_trusted_time_workspace *workspace) {
  if (workspace == NULL || !output_is_valid(workspace->request_payload) ||
      !output_is_valid(workspace->signed_request) ||
      !output_is_valid(workspace->signed_response) ||
      !output_is_valid(workspace->canonical_scratch) ||
      !output_is_valid(workspace->aad) ||
      workspace->request_payload.cap != PBNS_TIME_ENCODED_MAX_SIZE ||
      workspace->signed_request.cap == 0U ||
      workspace->signed_request.cap > PBNS_TIME_SIGNED_MAX_SIZE ||
      workspace->signed_response.cap == 0U ||
      workspace->signed_response.cap > PBNS_TIME_SIGNED_MAX_SIZE ||
      workspace->canonical_scratch.cap != PBNS_TIME_ENCODED_MAX_SIZE ||
      workspace->aad.cap > PBNS_TIME_AAD_MAX_SIZE ||
      workspace->aad.cap <
          sizeof(PBNS_TIME_ASSERTION_AAD) - 1U + PBNS_TIME_REQUEST_ID_SIZE +
              PBNS_TIME_FINGERPRINT_SIZE + PBNS_TIME_NONCE_SIZE +
              PBNS_TIME_KEY_ID_MAX_SIZE) {
    return false;
  }
  const pbns_buffer buffers[] = {
      workspace->request_payload,
      workspace->signed_request,
      workspace->signed_response,
      workspace->canonical_scratch,
      workspace->aad,
  };
  for (size_t left = 0U; left < sizeof(buffers) / sizeof(buffers[0]); ++left) {
    for (size_t right = left + 1U; right < sizeof(buffers) / sizeof(buffers[0]);
         ++right) {
      if (buffers_overlap((pbns_view){buffers[left].ptr, buffers[left].cap},
                          buffers[right])) {
        return false;
      }
    }
  }
  return true;
}

static bool client_is_valid(const pbns_trusted_time_client *client) {
  return client != NULL && client->random_fill != NULL &&
         client->sign_request != NULL && client->exchange != NULL &&
         client->verify_assertion != NULL && client->monotonic_ms != NULL &&
         view_is_valid(client->time_key_id) && client->time_key_id.len > 0U &&
         client->time_key_id.len <= PBNS_TIME_KEY_ID_MAX_SIZE &&
         client->maximum_round_trip_ms > 0U &&
         client->maximum_round_trip_ms <= PBNS_TIME_MAX_AGE_MS;
}

static pbns_status query_finish(pbns_trusted_time_workspace *workspace,
                                pbns_trusted_time_request *request,
                                pbns_status status) {
  secure_zero(request, sizeof(*request));
  secure_zero(workspace->request_payload.ptr, workspace->request_payload.cap);
  secure_zero(workspace->signed_request.ptr, workspace->signed_request.cap);
  secure_zero(workspace->signed_response.ptr, workspace->signed_response.cap);
  secure_zero(workspace->canonical_scratch.ptr,
              workspace->canonical_scratch.cap);
  secure_zero(workspace->aad.ptr, workspace->aad.cap);
  return status;
}

pbns_status pbns_trusted_time_query(
    const pbns_trusted_time_client *client,
    const uint8_t host_fingerprint[PBNS_TIME_FINGERPRINT_SIZE],
    const pbns_time_interval *previous_interval,
    pbns_trusted_time_workspace *workspace, pbns_time_interval *interval) {
  if (interval != NULL) {
    *interval = (pbns_time_interval){0};
  }
  if (!client_is_valid(client) || host_fingerprint == NULL ||
      !nonzero(host_fingerprint, PBNS_TIME_FINGERPRINT_SIZE) ||
      !workspace_is_valid(workspace) || interval == NULL) {
    return PBNS_ERR_ARGUMENT;
  }

  uint8_t random[PBNS_TIME_REQUEST_ID_SIZE + PBNS_TIME_NONCE_SIZE] = {0};
  pbns_trusted_time_request request = {0};
  pbns_status status = client->random_fill(
      client->random_context, (pbns_buffer){random, 0U, sizeof(random)});
  if (status != PBNS_OK) {
    secure_zero(random, sizeof(random));
    return query_finish(workspace, &request, status);
  }
  memcpy(request.request_id, random, sizeof(request.request_id));
  memcpy(request.nonce, random + sizeof(request.request_id),
         sizeof(request.nonce));
  memcpy(request.host_fingerprint, host_fingerprint,
         sizeof(request.host_fingerprint));
  request.max_age_ms = (uint32_t)client->maximum_round_trip_ms;
  secure_zero(random, sizeof(random));

  size_t request_payload_size = 0U;
  status = pbns_trusted_time_request_encode(
      &request, workspace->request_payload, &request_payload_size);
  if (status != PBNS_OK) {
    return query_finish(workspace, &request, status);
  }
  static const uint8_t request_aad[] = PBNS_TIME_REQUEST_AAD;
  size_t signed_request_size = 0U;
  status = client->sign_request(
      client->sign_context,
      (pbns_view){workspace->request_payload.ptr, request_payload_size},
      (pbns_view){request_aad, sizeof(request_aad) - 1U},
      workspace->signed_request, &signed_request_size);
  if (status != PBNS_OK || signed_request_size == 0U ||
      signed_request_size > workspace->signed_request.cap) {
    status = status == PBNS_OK ? PBNS_ERR_IO : status;
    return query_finish(workspace, &request, status);
  }

  uint64_t started_ms = 0U;
  status = client->monotonic_ms(client->clock_context, &started_ms);
  if (status != PBNS_OK) {
    return query_finish(workspace, &request, status);
  }
  size_t signed_response_size = 0U;
  const pbns_status exchange_status = client->exchange(
      client->exchange_context,
      (pbns_view){workspace->signed_request.ptr, signed_request_size},
      workspace->signed_response, &signed_response_size);
  uint64_t finished_ms = 0U;
  status = client->monotonic_ms(client->clock_context, &finished_ms);
  if (status != PBNS_OK) {
    return query_finish(workspace, &request, status);
  }
  if (exchange_status != PBNS_OK) {
    return query_finish(workspace, &request, exchange_status);
  }
  if (signed_response_size == 0U ||
      signed_response_size > workspace->signed_response.cap) {
    return query_finish(workspace, &request, PBNS_ERR_IO);
  }
  if (finished_ms < started_ms) {
    return query_finish(workspace, &request, PBNS_ERR_STATE);
  }
  const uint64_t round_trip_ms = finished_ms - started_ms;
  if (round_trip_ms > client->maximum_round_trip_ms) {
    return query_finish(workspace, &request, PBNS_ERR_TIMEOUT);
  }

  size_t aad_size = 0U;
  status = pbns_trusted_time_assertion_aad(
      request.request_id, request.host_fingerprint, request.nonce,
      client->time_key_id, workspace->aad, &aad_size);
  if (status != PBNS_OK) {
    return query_finish(workspace, &request, status);
  }
  pbns_view verified_payload = {0};
  status = client->verify_assertion(
      client->verify_context,
      (pbns_view){workspace->signed_response.ptr, signed_response_size},
      (pbns_view){workspace->aad.ptr, aad_size}, &verified_payload);
  if (status != PBNS_OK) {
    return query_finish(workspace, &request, status);
  }
  pbns_trusted_time_assertion assertion = {0};
  status = pbns_trusted_time_decode_verified_assertion(
      verified_payload, client->time_key_id, workspace->canonical_scratch,
      &assertion);
  if (status == PBNS_OK && assertion.max_age_ms != request.max_age_ms) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  if (status == PBNS_OK) {
    status = pbns_trusted_time_accept_verified_assertion(
        &assertion, request.request_id, request.host_fingerprint, request.nonce,
        round_trip_ms, client->maximum_round_trip_ms, previous_interval,
        interval);
  }
  return query_finish(workspace, &request, status);
}

pbns_status
pbns_time_interval_from_assertion(const pbns_trusted_time_assertion *assertion,
                                  uint64_t round_trip_ns,
                                  pbns_time_interval *interval) {
  if (assertion == NULL || interval == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *interval = (pbns_time_interval){0};
  if (assertion->unix_seconds < 0 ||
      assertion->nanoseconds >= (uint32_t)PBNS_NANOSECONDS_PER_SECOND) {
    return PBNS_ERR_FORMAT;
  }
  if (assertion->unix_seconds > (INT64_MAX - (int64_t)assertion->nanoseconds) /
                                    PBNS_NANOSECONDS_PER_SECOND) {
    return PBNS_ERR_LIMIT;
  }
  const int64_t asserted_ns =
      assertion->unix_seconds * PBNS_NANOSECONDS_PER_SECOND +
      (int64_t)assertion->nanoseconds;
  if (assertion->uncertainty_ns > (uint64_t)INT64_MAX ||
      assertion->uncertainty_ns > (uint64_t)asserted_ns) {
    return PBNS_ERR_LIMIT;
  }
  if (round_trip_ns > (uint64_t)INT64_MAX ||
      round_trip_ns > (uint64_t)(INT64_MAX - asserted_ns)) {
    return PBNS_ERR_LIMIT;
  }
  const int64_t latest_without_uncertainty =
      asserted_ns + (int64_t)round_trip_ns;
  if (assertion->uncertainty_ns >
      (uint64_t)(INT64_MAX - latest_without_uncertainty)) {
    return PBNS_ERR_LIMIT;
  }
  interval->earliest_ns = asserted_ns - (int64_t)assertion->uncertainty_ns;
  interval->latest_ns =
      latest_without_uncertainty + (int64_t)assertion->uncertainty_ns;
  return PBNS_OK;
}

bool pbns_time_interval_within(const pbns_time_interval *interval,
                               int64_t not_before_ns, int64_t not_after_ns) {
  return interval != NULL && interval->earliest_ns <= interval->latest_ns &&
         not_before_ns <= not_after_ns &&
         interval->earliest_ns >= not_before_ns &&
         interval->latest_ns <= not_after_ns;
}

pbns_status pbns_trusted_time_accept_verified_assertion(
    const pbns_trusted_time_assertion *assertion,
    const uint8_t expected_request_id[PBNS_TIME_REQUEST_ID_SIZE],
    const uint8_t expected_host_fingerprint[PBNS_TIME_FINGERPRINT_SIZE],
    const uint8_t expected_nonce[PBNS_TIME_NONCE_SIZE], uint64_t round_trip_ms,
    uint64_t maximum_round_trip_ms, const pbns_time_interval *previous_interval,
    pbns_time_interval *interval) {
  if (assertion == NULL || expected_request_id == NULL ||
      expected_host_fingerprint == NULL || expected_nonce == NULL ||
      interval == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *interval = (pbns_time_interval){0};
  if (assertion->version != PBNS_TIME_VERSION ||
      assertion->service != PBNS_TIME_SERVICE ||
      !view_is_valid(assertion->quality) || assertion->quality.len == 0U ||
      assertion->quality.len > PBNS_TIME_QUALITY_MAX_SIZE ||
      !view_is_valid(assertion->key_id) || assertion->key_id.len == 0U ||
      assertion->key_id.len > PBNS_TIME_KEY_ID_MAX_SIZE ||
      assertion->max_age_ms == 0U ||
      assertion->max_age_ms > PBNS_TIME_MAX_AGE_MS) {
    return PBNS_ERR_FORMAT;
  }
  if (previous_interval != NULL &&
      previous_interval->earliest_ns > previous_interval->latest_ns) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!domain_is_valid(assertion->domain) ||
      !bytes_equal(assertion->request_id, expected_request_id,
                   PBNS_TIME_REQUEST_ID_SIZE) ||
      !bytes_equal(assertion->host_fingerprint, expected_host_fingerprint,
                   PBNS_TIME_FINGERPRINT_SIZE) ||
      !bytes_equal(assertion->nonce, expected_nonce, PBNS_TIME_NONCE_SIZE)) {
    return PBNS_ERR_AUTHENTICATION;
  }
  if (round_trip_ms > maximum_round_trip_ms ||
      round_trip_ms > assertion->max_age_ms) {
    return PBNS_ERR_TIMEOUT;
  }
  if (round_trip_ms > UINT64_MAX / PBNS_NANOSECONDS_PER_MILLISECOND) {
    return PBNS_ERR_LIMIT;
  }
  const uint64_t round_trip_ns =
      round_trip_ms * PBNS_NANOSECONDS_PER_MILLISECOND;
  pbns_status status =
      pbns_time_interval_from_assertion(assertion, round_trip_ns, interval);
  if (status != PBNS_OK) {
    return status;
  }
  if (previous_interval != NULL &&
      interval->earliest_ns <= previous_interval->earliest_ns) {
    *interval = (pbns_time_interval){0};
    return PBNS_ERR_REPLAY;
  }
  return PBNS_OK;
}
