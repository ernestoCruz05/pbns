#include "pbns/attestation_run.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include "qcbor/qcbor.h"

#define ARRAY_COUNT(value) (sizeof(value) / sizeof((value)[0]))
#define TEST_EVENT_DATA_SIZE ((size_t)PBNS_FRAME_V1_DATA_PAYLOAD_MAX + 1024U)
#define ATTEMPT_MAX 32U
#define EVENT_MAX 32U
#define WORKSPACE_DESCRIPTOR_COUNT 20U

typedef enum run_event {
  EVENT_QUOTE,
  EVENT_SIGN_COMPLETE,
  EVENT_ENCRYPT_COMPLETE,
  EVENT_SUBMIT_REQUEST,
  EVENT_DATA,
  EVENT_COMPLETE,
  EVENT_RECEIPT_VERIFY,
  EVENT_UPLOAD_FINISH_CLOSE,
  EVENT_CLEANUP_OBSERVED,
  EVENT_DISPLAY
} run_event;

typedef enum measured_view_mode {
  MEASURED_VIEW_ARENA,
  MEASURED_VIEW_EMPTY,
  MEASURED_VIEW_BEFORE_ARENA,
  MEASURED_VIEW_AT_END,
  MEASURED_VIEW_INTEGER_WRAP,
  MEASURED_VIEW_EXTENDS_PAST_END,
  MEASURED_VIEW_BOUNDED_SUBVIEW
} measured_view_mode;

typedef enum failure_point {
  FAIL_NONE,
  FAIL_CHALLENGE_SIGNATURE,
  FAIL_CHALLENGE_EXPIRED,
  FAIL_CHALLENGE_MALFORMED,
  FAIL_CHALLENGE_REQUEST_BINDING,
  FAIL_CHALLENGE_NONCE_BINDING,
  FAIL_CHALLENGE_HOST_BINDING,
  FAIL_CHALLENGE_KID_BINDING,
  FAIL_INVENTORY,
  FAIL_INVENTORY_HOST,
  FAIL_MEASURED,
  FAIL_MEASURED_MISMATCH,
  FAIL_QUOTE,
  FAIL_QUOTE_ZERO,
  FAIL_QUOTE_OVERSIZE,
  FAIL_SIGNATURE_ZERO,
  FAIL_SIGNATURE_OVERSIZE,
  FAIL_SIGN,
  FAIL_SIGN_ZERO,
  FAIL_SIGN_OVERSIZE,
  FAIL_DIGEST,
  FAIL_ENCRYPT,
  FAIL_ENCRYPT_ZERO,
  FAIL_ENCRYPT_OVERSIZE,
  FAIL_RECEIPT,
  FAIL_RECEIPT_MALFORMED,
  FAIL_RECEIPT_UNBOUND,
  FAIL_MALFORMED_SUBMIT,
  FAIL_CORRELATION,
  FAIL_EVIDENCE_BINDING,
  FAIL_CIPHERTEXT_DIGEST,
  FAIL_CONFIGURED_SIGNED_HASH
} failure_point;

typedef struct fixture fixture;

typedef struct transport_state {
  fixture *owner;
  uint8_t response[PBNS_FRAME_V1_WIRE_MAX];
  size_t response_size;
  size_t response_offset;
  pbns_message_type attempts[ATTEMPT_MAX];
  size_t attempt_count;
  size_t open_calls;
  size_t limits_calls;
  size_t send_calls;
  size_t receive_calls;
  size_t close_calls;
  size_t cancel_calls;
  size_t upload_request_count;
  bool fail_issue_close;
  bool fail_upload_close;
} transport_state;

struct fixture {
  pbns_broker broker;
  transport_state transport;
  uint8_t *broker_storage;
  uint8_t challenge_payload[PBNS_ATTESTATION_CHALLENGE_MAX_SIZE];
  size_t challenge_payload_size;
  uint8_t challenge_cose[PBNS_ATTESTATION_CHALLENGE_MAX_SIZE];
  size_t challenge_cose_size;
  uint8_t receipt_payload[PBNS_ATTESTATION_RECEIPT_MAX_PAYLOAD_SIZE];
  size_t receipt_payload_size;
  uint8_t receipt_cose[PBNS_ATTESTATION_RECEIPT_MAX_SIGNED_SIZE];
  size_t receipt_cose_size;
  uint8_t *signed_evidence;
  size_t signed_evidence_size;
  uint8_t *ciphertext;
  size_t ciphertext_size;
  uint8_t *uploaded;
  size_t uploaded_size;
  uint8_t issue_recipient[8];
  uint8_t recipient_kid[8];
  uint8_t challenge_kid[8];
  uint8_t receipt_kid[8];
  uint8_t ak_name[4];
  uint8_t ak_reference[8];
  pbns_crypto challenge_verifier;
  pbns_crypto receipt_verifier;
  pbns_crypto signer;
  pbns_crypto encrypter;
  failure_point failure;
  measured_view_mode measured_view;
  pbns_attestation_receipt_verdict verdict;
  uint64_t now_ms;
  size_t monotonic_calls;
  size_t timeout_at_monotonic_call;
  size_t jump_at_monotonic_call;
  uint64_t jump_to_ms;
  pbns_status monotonic_status;
  pbns_status cancellation_status;
  size_t cancellation_error_at;
  pbns_status display_status;
  uint64_t challenge_expiry_ns;
  size_t trusted_time_calls;
  bool issue_response_received;
  bool trusted_time_after_issue_response;
  size_t random_calls;
  size_t broker_clock_calls;
  size_t cancel_checks;
  size_t cancel_at;
  size_t capture_inventory_calls;
  size_t capture_measured_calls;
  size_t quote_calls;
  size_t sign_calls;
  size_t encrypt_calls;
  size_t display_calls;
  bool display_saw_wipe;
  run_event events[EVENT_MAX];
  size_t event_count;
  pbns_attestation_run_config config;
  pbns_attestation_run_workspace workspace;
  pbns_attestation_run_result result;
};

static void store_u16(uint8_t *output, uint16_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8U);
}

static void store_u32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8U);
  output[2] = (uint8_t)(value >> 16U);
  output[3] = (uint8_t)(value >> 24U);
}

static size_t make_event_log(uint8_t *output, size_t capacity) {
  static const uint8_t signature[16] = "Spec ID Event03";
  const size_t required = 119U + TEST_EVENT_DATA_SIZE;
  assert(capacity >= required && TEST_EVENT_DATA_SIZE <= UINT32_MAX);
  size_t offset = 0U;
  store_u32(output + offset, 0U); offset += 4U;
  store_u32(output + offset, 3U); offset += 4U;
  memset(output + offset, 0, 20U); offset += 20U;
  store_u32(output + offset, 37U); offset += 4U;
  memcpy(output + offset, signature, sizeof(signature)); offset += sizeof(signature);
  store_u32(output + offset, 0U); offset += 4U;
  output[offset++] = 0U; output[offset++] = 2U;
  output[offset++] = 0U; output[offset++] = 2U;
  store_u32(output + offset, 2U); offset += 4U;
  store_u16(output + offset, UINT16_C(0x0004));
  store_u16(output + offset + 2U, 20U); offset += 4U;
  store_u16(output + offset, PBNS_TPM_ALG_SHA256);
  store_u16(output + offset + 2U, 32U); offset += 4U;
  output[offset++] = 0U;
  store_u32(output + offset, 7U); offset += 4U;
  store_u32(output + offset, UINT32_C(0x80000001)); offset += 4U;
  store_u32(output + offset, 1U); offset += 4U;
  store_u16(output + offset, PBNS_TPM_ALG_SHA256); offset += 2U;
  memset(output + offset, 0x5a, 32U); offset += 32U;
  store_u32(output + offset, (uint32_t)TEST_EVENT_DATA_SIZE); offset += 4U;
  memset(output + offset, 0x65, TEST_EVENT_DATA_SIZE); offset += TEST_EVENT_DATA_SIZE;
  assert(offset == required);
  return offset;
}

static pbns_status independent_sha256(pbns_view input, uint8_t digest[32]) {
  unsigned int written = 0U;
  return EVP_Digest(input.ptr, input.len, digest, &written, EVP_sha256(), NULL) ==
                     1 &&
                 written == 32U
             ? PBNS_OK
             : PBNS_ERR_CRYPTO;
}

static pbns_status hash_bytes(void *context, pbns_view input,
                              uint8_t digest[32]) {
  fixture *value = context;
  if (value->failure == FAIL_DIGEST && value->sign_calls > 0U) {
    return PBNS_ERR_CRYPTO;
  }
  const pbns_status status = independent_sha256(input, digest);
  if (status == PBNS_OK && value->failure == FAIL_CONFIGURED_SIGNED_HASH &&
      input.ptr == value->workspace.attestation.signed_evidence.ptr &&
      input.len == value->signed_evidence_size) {
    digest[0] ^= UINT8_C(0x80);
  }
  return status;
}

static size_t finish_encode(QCBOREncodeContext *encoder) {
  UsefulBufC encoded = {0};
  assert(QCBOREncode_Finish(encoder, &encoded) == QCBOR_SUCCESS);
  return encoded.len;
}

static void record_event(fixture *value, run_event event) {
  assert(value->event_count < EVENT_MAX);
  value->events[value->event_count++] = event;
}

static void assert_exact_view(pbns_view actual, const uint8_t *expected,
                              size_t expected_size) {
  assert(actual.ptr != NULL && actual.len == expected_size);
  assert(memcmp(actual.ptr, expected, expected_size) == 0);
}

static pbns_view borrowed_cose_payload(pbns_view cose) {
  QCBORDecodeContext decoder = {0};
  QCBORItem item = {0};
  QCBORDecode_Init(&decoder, (UsefulBufC){cose.ptr, cose.len},
                   QCBOR_DECODE_MODE_NORMAL);
  assert(QCBORDecode_GetNext(&decoder, &item) == QCBOR_SUCCESS);
  assert(item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 4U);
  assert(QCBORDecode_GetNext(&decoder, &item) == QCBOR_SUCCESS);
  assert(item.uDataType == QCBOR_TYPE_BYTE_STRING);
  assert(QCBORDecode_GetNext(&decoder, &item) == QCBOR_SUCCESS);
  assert(item.uDataType == QCBOR_TYPE_MAP && item.val.uCount == 0U);
  assert(QCBORDecode_GetNext(&decoder, &item) == QCBOR_SUCCESS);
  assert(item.uDataType == QCBOR_TYPE_BYTE_STRING && item.val.string.len > 0U);
  const pbns_view payload = {item.val.string.ptr, item.val.string.len};
  const uintptr_t cose_start = (uintptr_t)cose.ptr;
  const uintptr_t payload_start = (uintptr_t)payload.ptr;
  assert(payload_start >= cose_start && payload.len <= cose.len &&
         payload_start - cose_start <= cose.len - payload.len);
  return payload;
}

static size_t encode_challenge_aad_independent(const fixture *value,
                                                uint8_t *output,
                                                size_t capacity) {
  static const uint8_t domain[] =
      "PBNS-ATTESTATION-CHALLENGE-SIGN-v1";
  uint8_t request[16] = {0};
  uint8_t nonce[32] = {0};
  memset(request, 0x22, sizeof(request));
  memset(nonce, 0x33, sizeof(nonce));
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output, capacity});
  QCBOREncode_OpenArray(&encoder);
  QCBOREncode_AddText(&encoder,
                      (UsefulBufC){domain, sizeof(domain) - 1U});
  QCBOREncode_AddUInt64(&encoder, 1U);
  QCBOREncode_AddUInt64(&encoder, 3U);
  QCBOREncode_AddBytes(&encoder, (UsefulBufC){request, sizeof(request)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){value->config.host_fingerprint,
                   sizeof(value->config.host_fingerprint)});
  QCBOREncode_AddBytes(&encoder, (UsefulBufC){nonce, sizeof(nonce)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){value->recipient_kid, sizeof(value->recipient_kid)});
  QCBOREncode_CloseArray(&encoder);
  return finish_encode(&encoder);
}

static size_t encode_sign_aad_independent(const fixture *value,
                                           uint8_t *output,
                                           size_t capacity) {
  static const uint8_t domain[] = "PBNS-ATTESTATION-SIGN-v1";
  uint8_t request[16] = {0};
  uint8_t nonce[32] = {0};
  memset(request, 0x22, sizeof(request));
  memset(nonce, 0x33, sizeof(nonce));
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output, capacity});
  QCBOREncode_OpenArray(&encoder);
  QCBOREncode_AddText(&encoder,
                      (UsefulBufC){domain, sizeof(domain) - 1U});
  QCBOREncode_AddUInt64(&encoder, 1U);
  QCBOREncode_AddBytes(&encoder, (UsefulBufC){request, sizeof(request)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){value->config.host_fingerprint,
                   sizeof(value->config.host_fingerprint)});
  QCBOREncode_AddBytes(&encoder, (UsefulBufC){nonce, sizeof(nonce)});
  QCBOREncode_AddBytes(
      &encoder, (UsefulBufC){value->ak_name, sizeof(value->ak_name)});
  QCBOREncode_CloseArray(&encoder);
  return finish_encode(&encoder);
}

static size_t encode_encrypt_aad_independent(const fixture *value,
                                              uint8_t *output,
                                              size_t capacity) {
  static const uint8_t domain[] = "PBNS-ATTESTATION-ENCRYPT-v1";
  uint8_t request[16] = {0};
  uint8_t nonce[32] = {0};
  memset(request, 0x22, sizeof(request));
  memset(nonce, 0x33, sizeof(nonce));
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output, capacity});
  QCBOREncode_OpenArray(&encoder);
  QCBOREncode_AddText(&encoder,
                      (UsefulBufC){domain, sizeof(domain) - 1U});
  QCBOREncode_AddUInt64(&encoder, 1U);
  QCBOREncode_AddUInt64(&encoder, 3U);
  QCBOREncode_AddBytes(&encoder, (UsefulBufC){request, sizeof(request)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){value->config.host_fingerprint,
                   sizeof(value->config.host_fingerprint)});
  QCBOREncode_AddBytes(&encoder, (UsefulBufC){nonce, sizeof(nonce)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){value->recipient_kid, sizeof(value->recipient_kid)});
  QCBOREncode_CloseArray(&encoder);
  return finish_encode(&encoder);
}

static size_t encode_receipt_aad_independent(const fixture *value,
                                              uint8_t *output,
                                              size_t capacity) {
  static const uint8_t domain[] =
      "PBNS-ATTESTATION-RECEIPT-SIGN-v1";
  uint8_t request[16] = {0};
  uint8_t nonce[32] = {0};
  uint8_t digest[32] = {0};
  uint8_t baseline[32] = {0};
  unsigned int digest_size = 0U;
  memset(request, 0x22, sizeof(request));
  memset(nonce, 0x33, sizeof(nonce));
  memset(baseline, 0x66, sizeof(baseline));
  assert(EVP_Digest(value->signed_evidence, value->signed_evidence_size,
                    digest, &digest_size, EVP_sha256(), NULL) == 1);
  assert(digest_size == sizeof(digest));
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output, capacity});
  QCBOREncode_OpenArray(&encoder);
  QCBOREncode_AddText(&encoder,
                      (UsefulBufC){domain, sizeof(domain) - 1U});
  QCBOREncode_AddUInt64(&encoder, 1U);
  QCBOREncode_AddUInt64(&encoder, 3U);
  QCBOREncode_AddBytes(&encoder, (UsefulBufC){request, sizeof(request)});
  QCBOREncode_AddBytes(&encoder, (UsefulBufC){nonce, sizeof(nonce)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){value->config.host_fingerprint,
                   sizeof(value->config.host_fingerprint)});
  QCBOREncode_AddBytes(&encoder, (UsefulBufC){digest, sizeof(digest)});
  QCBOREncode_AddBytes(&encoder,
                       (UsefulBufC){baseline, sizeof(baseline)});
  QCBOREncode_AddBytes(
      &encoder,
      (UsefulBufC){value->receipt_kid, sizeof(value->receipt_kid)});
  QCBOREncode_CloseArray(&encoder);
  return finish_encode(&encoder);
}

static size_t wrap_cose(pbns_view payload, pbns_view kid, uint8_t *output,
                        size_t capacity) {
  uint8_t protected_headers[96] = {0};
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){protected_headers, sizeof(protected_headers)});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddInt64ToMapN(&encoder, 1, -7);
  QCBOREncode_AddBytesToMapN(&encoder, 4, (UsefulBufC){kid.ptr, kid.len});
  QCBOREncode_CloseMap(&encoder);
  const size_t protected_size = finish_encode(&encoder);
  uint8_t signature[64] = {0};
  memset(signature, 0x7a, sizeof(signature));
  QCBOREncode_Init(&encoder, (UsefulBuf){output, capacity});
  QCBOREncode_AddTag(&encoder, 18U);
  QCBOREncode_OpenArray(&encoder);
  QCBOREncode_AddBytes(&encoder, (UsefulBufC){protected_headers, protected_size});
  QCBOREncode_OpenMap(&encoder); QCBOREncode_CloseMap(&encoder);
  QCBOREncode_AddBytes(&encoder, (UsefulBufC){payload.ptr, payload.len});
  QCBOREncode_AddBytes(&encoder, (UsefulBufC){signature, sizeof(signature)});
  QCBOREncode_CloseArray(&encoder);
  return finish_encode(&encoder);
}

static size_t encode_wire_response(
    const pbns_attestation_wire_response *response, uint8_t *output,
    size_t capacity) {
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output, capacity});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddUInt64ToMapN(&encoder, 1, response->operation);
  QCBOREncode_AddBytesToMapN(&encoder, 2,
      (UsefulBufC){response->challenge_request_id.bytes, 16U});
  QCBOREncode_AddBytesToMapN(&encoder, 3,
      (UsefulBufC){response->verifier_nonce, 32U});
  QCBOREncode_AddBytesToMapN(&encoder, 4,
      (UsefulBufC){response->recipient_kid.ptr, response->recipient_kid.len});
  QCBOREncode_AddBytesToMapN(&encoder, 5,
      (UsefulBufC){response->object.ptr, response->object.len});
  QCBOREncode_AddBytesToMapN(&encoder, 6,
      (UsefulBufC){response->evidence_digest, 32U});
  QCBOREncode_AddBytesToMapN(&encoder, 7,
      (UsefulBufC){response->baseline_id, 32U});
  QCBOREncode_CloseMap(&encoder);
  return finish_encode(&encoder);
}

static void frame_response(fixture *value, const pbns_request_id *request,
                           pbns_view payload) {
  uint8_t raw[PBNS_FRAME_V1_RAW_MAX] = {0};
  const pbns_frame frame = {
      .service = PBNS_SERVICE_PLATFORM_ATTESTATION,
      .type = PBNS_MESSAGE_RESPONSE,
      .request_id = *request,
      .sequence = 0U,
  };
  assert(pbns_frame_encode(&frame, payload,
      (pbns_buffer){raw, 0U, sizeof(raw)},
      (pbns_buffer){value->transport.response, 0U,
                    sizeof(value->transport.response)},
      &value->transport.response_size) == PBNS_OK);
  value->transport.response_offset = 0U;
}

static void make_receipt_payload(fixture *value, const uint8_t digest[32],
                                 uint8_t baseline[32]) {
  static const uint8_t domain[] = PBNS_ATTESTATION_RECEIPT_DOMAIN;
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder,
      (UsefulBuf){value->receipt_payload, sizeof(value->receipt_payload)});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddTextToMapN(&encoder, 1,
      (UsefulBufC){domain, sizeof(domain) - 1U});
  QCBOREncode_AddUInt64ToMapN(&encoder, 2, 1U);
  QCBOREncode_AddUInt64ToMapN(&encoder, 3, 3U);
  uint8_t request[16] = {0}; memset(request, 0x22, sizeof(request));
  uint8_t nonce[32] = {0}; memset(nonce, 0x33, sizeof(nonce));
  QCBOREncode_AddBytesToMapN(&encoder, 4, (UsefulBufC){request, sizeof(request)});
  QCBOREncode_AddBytesToMapN(&encoder, 5, (UsefulBufC){nonce, sizeof(nonce)});
  QCBOREncode_AddBytesToMapN(&encoder, 6,
      (UsefulBufC){value->config.host_fingerprint, 32U});
  uint8_t receipt_digest[32] = {0};
  memcpy(receipt_digest, digest, sizeof(receipt_digest));
  if (value->failure == FAIL_RECEIPT_UNBOUND) {
    receipt_digest[0] ^= 1U;
  }
  QCBOREncode_AddBytesToMapN(&encoder, 7,
      (UsefulBufC){receipt_digest, sizeof(receipt_digest)});
  QCBOREncode_AddBytesToMapN(&encoder, 8, (UsefulBufC){baseline, 32U});
  QCBOREncode_AddUInt64ToMapN(&encoder, 9, (uint64_t)value->verdict);
  QCBOREncode_OpenArrayInMapN(&encoder, 10);
  if (value->verdict == PBNS_ATTESTATION_RECEIPT_REDUCED) {
    QCBOREncode_AddUInt64(&encoder, 1U);
  } else if (value->verdict == PBNS_ATTESTATION_RECEIPT_FAILURE) {
    QCBOREncode_AddUInt64(&encoder, 2U);
  }
  QCBOREncode_CloseArray(&encoder);
  QCBOREncode_AddBytesToMapN(&encoder, 11,
      (UsefulBufC){value->receipt_kid, sizeof(value->receipt_kid)});
  QCBOREncode_CloseMap(&encoder);
  value->receipt_payload_size = finish_encode(&encoder);
}

static void make_submit_response(fixture *value, const pbns_request_id *request) {
  uint8_t digest[32] = {0};
  pbns_view digest_input = {
      value->signed_evidence, value->signed_evidence_size};
  if (value->failure == FAIL_CIPHERTEXT_DIGEST) {
    digest_input = (pbns_view){value->ciphertext, value->ciphertext_size};
  }
  assert(independent_sha256(digest_input, digest) == PBNS_OK);
  if (value->failure == FAIL_EVIDENCE_BINDING) {
    digest[0] ^= 1U;
  }
  uint8_t baseline[32] = {0}; memset(baseline, 0x66, sizeof(baseline));
  make_receipt_payload(value, digest, baseline);
  value->receipt_cose_size = wrap_cose(
      (pbns_view){value->receipt_payload, value->receipt_payload_size},
      (pbns_view){value->receipt_kid, sizeof(value->receipt_kid)},
      value->receipt_cose, sizeof(value->receipt_cose));
  if (value->failure == FAIL_RECEIPT_MALFORMED) {
    value->receipt_cose[0] = 0xffU;
  }
  pbns_attestation_wire_response response = {
      .operation = PBNS_ATTESTATION_WIRE_SUBMIT,
      .object = {value->receipt_cose, value->receipt_cose_size},
  };
  memset(response.challenge_request_id.bytes, 0x22,
         sizeof(response.challenge_request_id.bytes));
  memcpy(response.evidence_digest, digest, sizeof(digest));
  memcpy(response.baseline_id, baseline, sizeof(baseline));
  if (value->failure == FAIL_CORRELATION) {
    response.challenge_request_id.bytes[0] ^= 1U;
  }
  uint8_t application[PBNS_ATTESTATION_WIRE_MAX_SIZE] = {0};
  size_t application_size = encode_wire_response(&response, application,
                                                  sizeof(application));
  if (value->failure == FAIL_MALFORMED_SUBMIT) {
    application[0] = 0xffU;
  }
  frame_response(value, request, (pbns_view){application, application_size});
}

static pbns_status transport_open(void *context) {
  transport_state *state = context;
  ++state->open_calls;
  return PBNS_OK;
}

static pbns_status transport_close(void *context) {
  transport_state *state = context;
  ++state->close_calls;
  if (state->close_calls == 2U) {
    record_event(state->owner, EVENT_UPLOAD_FINISH_CLOSE);
  }
  return ((state->fail_issue_close && state->close_calls == 1U) ||
          (state->fail_upload_close && state->close_calls == 2U))
             ? PBNS_ERR_TRANSPORT
             : PBNS_OK;
}

static pbns_status transport_send(void *context, pbns_view encoded,
                                  uint32_t timeout_ms) {
  transport_state *state = context;
  ++state->send_calls;
  fixture *value = state->owner;
  assert(timeout_ms > 0U && encoded.len > 1U);
  uint8_t raw[PBNS_FRAME_V1_RAW_MAX] = {0};
  pbns_frame frame = {0};
  pbns_view payload = {0};
  const pbns_frame_limits limits = {
      PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX,
      PBNS_FRAME_V1_DATA_PAYLOAD_MAX,
      PBNS_FRAME_V1_WIRE_MAX,
  };
  assert(pbns_frame_decode((pbns_view){encoded.ptr, encoded.len - 1U}, limits,
      (pbns_buffer){raw, 0U, sizeof(raw)}, &frame, &payload) == PBNS_OK);
  assert(state->attempt_count < ATTEMPT_MAX);
  state->attempts[state->attempt_count++] = frame.type;
  if (frame.type == PBNS_MESSAGE_REQUEST && state->open_calls == 2U) {
    ++state->upload_request_count;
    assert(value->signed_evidence_size > 0U && value->ciphertext_size >
           PBNS_FRAME_V1_DATA_PAYLOAD_MAX);
    assert(value->signed_evidence_size == value->ciphertext_size);
    assert(memcmp(value->signed_evidence, value->ciphertext,
                  value->ciphertext_size) != 0);
    QCBORDecodeContext decoder = {0};
    QCBORItem item = {0};
    QCBORDecode_Init(&decoder, (UsefulBufC){payload.ptr, payload.len},
                     QCBOR_DECODE_MODE_NORMAL);
    assert(QCBORDecode_GetNext(&decoder, &item) == QCBOR_SUCCESS);
    assert(item.uDataType == QCBOR_TYPE_MAP && item.val.uCount == 3U);
    assert(QCBORDecode_GetNext(&decoder, &item) == QCBOR_SUCCESS);
    assert(item.uLabelType == QCBOR_TYPE_INT64 && item.label.int64 == 1);
    assert(((item.uDataType == QCBOR_TYPE_INT64 && item.val.int64 == 2) ||
            (item.uDataType == QCBOR_TYPE_UINT64 && item.val.uint64 == 2U)));
    record_event(value, EVENT_SUBMIT_REQUEST);
  } else if (frame.type == PBNS_MESSAGE_DATA) {
    assert(payload.len <= PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE -
                              value->uploaded_size);
    memcpy(value->uploaded + value->uploaded_size, payload.ptr, payload.len);
    value->uploaded_size += payload.len;
    record_event(value, EVENT_DATA);
  } else if (frame.type == PBNS_MESSAGE_COMPLETE) {
    assert(value->uploaded_size == value->ciphertext_size);
    assert(memcmp(value->uploaded, value->ciphertext,
                  value->ciphertext_size) == 0);
    record_event(value, EVENT_COMPLETE);
    make_submit_response(value, &frame.request_id);
  }
  return PBNS_OK;
}

static pbns_status transport_receive(void *context, pbns_buffer output,
                                     uint32_t timeout_ms, size_t *received) {
  transport_state *state = context;
  ++state->receive_calls;
  assert(timeout_ms > 0U);
  const size_t remaining = state->response_size - state->response_offset;
  assert(remaining > 0U);
  const size_t amount = remaining < output.cap ? remaining : output.cap;
  memcpy(output.ptr, state->response + state->response_offset, amount);
  state->response_offset += amount;
  if (state->open_calls == 1U &&
      state->response_offset == state->response_size) {
    state->owner->issue_response_received = true;
  }
  *received = amount;
  return PBNS_OK;
}

static pbns_status transport_cancel(void *context,
                                    const pbns_request_id *request_id) {
  transport_state *state = context;
  assert(request_id != NULL);
  ++state->cancel_calls;
  return PBNS_OK;
}

static pbns_status transport_limits(void *context, pbns_frame_limits *limits) {
  transport_state *state = context;
  ++state->limits_calls;
  *limits = (pbns_frame_limits){PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX,
                                PBNS_FRAME_V1_DATA_PAYLOAD_MAX,
                                PBNS_FRAME_V1_WIRE_MAX};
  return PBNS_OK;
}

static pbns_status random_fill(void *context, pbns_buffer output) {
  transport_state *state = context;
  ++state->owner->random_calls;
  memset(output.ptr, 0x11, output.cap);
  return PBNS_OK;
}

static pbns_status broker_clock(void *context, uint64_t *now_ms) {
  transport_state *state = context;
  ++state->owner->broker_clock_calls;
  *now_ms = state->owner->now_ms;
  return PBNS_OK;
}

static const pbns_transport_ops transport_ops = {
    transport_open, transport_close, transport_send, transport_receive,
    transport_cancel, transport_limits};
static const pbns_broker_platform_ops broker_ops = {random_fill, broker_clock};

static pbns_status verify_challenge(void *context, pbns_view cose,
                                    pbns_view aad, pbns_view kid,
                                    pbns_view *payload) {
  fixture *value = context;
  assert_exact_view(cose, value->challenge_cose,
                    value->challenge_cose_size);
  uint8_t expected_aad[PBNS_ATTESTATION_AAD_MAX_SIZE] = {0};
  const size_t expected_aad_size = encode_challenge_aad_independent(
      value, expected_aad, sizeof(expected_aad));
  assert_exact_view(aad, expected_aad, expected_aad_size);
  assert_exact_view(kid, value->challenge_kid,
                    sizeof(value->challenge_kid));
  *payload = borrowed_cose_payload(cose);
  assert_exact_view(*payload, value->challenge_payload,
                    value->challenge_payload_size);
  if (value->failure == FAIL_CHALLENGE_SIGNATURE) {
    return PBNS_ERR_CRYPTO;
  }
  return PBNS_OK;
}

static pbns_status verify_receipt(void *context, pbns_view cose,
                                  pbns_view aad, pbns_view *payload) {
  fixture *value = context;
  assert_exact_view(cose, value->receipt_cose, value->receipt_cose_size);
  uint8_t expected_aad[PBNS_ATTESTATION_RECEIPT_MAX_AAD_SIZE] = {0};
  const size_t expected_aad_size = encode_receipt_aad_independent(
      value, expected_aad, sizeof(expected_aad));
  assert_exact_view(aad, expected_aad, expected_aad_size);
  *payload = borrowed_cose_payload(cose);
  assert_exact_view(*payload, value->receipt_payload,
                    value->receipt_payload_size);
  record_event(value, EVENT_RECEIPT_VERIFY);
  if (value->failure == FAIL_RECEIPT) {
    return PBNS_ERR_CRYPTO;
  }
  return PBNS_OK;
}

static pbns_status sign_evidence(void *context, pbns_view payload,
                                 pbns_view aad, pbns_buffer output,
                                 size_t *written) {
  fixture *value = context;
  uint8_t expected_aad[PBNS_ATTESTATION_AAD_MAX_SIZE] = {0};
  const size_t expected_aad_size = encode_sign_aad_independent(
      value, expected_aad, sizeof(expected_aad));
  assert_exact_view(aad, expected_aad, expected_aad_size);
  ++value->sign_calls;
  if (value->failure == FAIL_SIGN) {
    return PBNS_ERR_CRYPTO;
  }
  if (value->failure == FAIL_SIGN_ZERO ||
      value->failure == FAIL_SIGN_OVERSIZE) {
    output.ptr[0] = 0x5aU;
    *written = value->failure == FAIL_SIGN_ZERO ? 0U : output.cap + 1U;
    return PBNS_OK;
  }
  assert(payload.len <= output.cap &&
         payload.len <= PBNS_ATTESTATION_SIGNED_MAX_SIZE);
  for (size_t index = 0U; index < payload.len; ++index) {
    output.ptr[index] = (uint8_t)(payload.ptr[index] ^ UINT8_C(0x3c));
  }
  memcpy(value->signed_evidence, output.ptr, payload.len);
  value->signed_evidence_size = payload.len;
  assert(memcmp(payload.ptr, value->signed_evidence, payload.len) != 0);
  *written = payload.len;
  record_event(value, EVENT_SIGN_COMPLETE);
  return PBNS_OK;
}

static pbns_status encrypt_evidence(void *context, pbns_view kid,
                                    pbns_view plaintext, pbns_view aad,
                                    pbns_buffer output, size_t *written) {
  fixture *value = context;
  assert_exact_view(kid, value->recipient_kid,
                    sizeof(value->recipient_kid));
  uint8_t expected_aad[PBNS_ATTESTATION_AAD_MAX_SIZE] = {0};
  const size_t expected_aad_size = encode_encrypt_aad_independent(
      value, expected_aad, sizeof(expected_aad));
  assert_exact_view(aad, expected_aad, expected_aad_size);
  assert_exact_view(plaintext, value->signed_evidence,
                    value->signed_evidence_size);
  ++value->encrypt_calls;
  if (value->failure == FAIL_ENCRYPT) {
    return PBNS_ERR_CRYPTO;
  }
  if (value->failure == FAIL_ENCRYPT_ZERO ||
      value->failure == FAIL_ENCRYPT_OVERSIZE) {
    output.ptr[0] = 0x5aU;
    *written = value->failure == FAIL_ENCRYPT_ZERO ? 0U : SIZE_MAX;
    return PBNS_OK;
  }
  assert(plaintext.len <= output.cap &&
         plaintext.len <= PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE);
  for (size_t index = 0U; index < plaintext.len; ++index) {
    output.ptr[index] =
        (uint8_t)(plaintext.ptr[index] ^ UINT8_C(0xa5));
  }
  memcpy(value->ciphertext, output.ptr, plaintext.len);
  value->ciphertext_size = plaintext.len;
  assert(memcmp(value->ciphertext, plaintext.ptr, plaintext.len) != 0);
  *written = plaintext.len;
  record_event(value, EVENT_ENCRYPT_COMPLETE);
  return PBNS_OK;
}

static pbns_status quote_evidence(void *context,
                                  pbns_measured_boot_selection selection,
                                  const uint8_t qualifying[32],
                                  pbns_buffer quote, size_t *quote_size,
                                  pbns_buffer signature,
                                  size_t *signature_size) {
  fixture *value = context;
  (void)selection; (void)qualifying;
  ++value->quote_calls;
  if (value->failure == FAIL_QUOTE) {
    return PBNS_ERR_CRYPTO;
  }
  if (value->failure == FAIL_QUOTE_ZERO ||
      value->failure == FAIL_QUOTE_OVERSIZE ||
      value->failure == FAIL_SIGNATURE_ZERO ||
      value->failure == FAIL_SIGNATURE_OVERSIZE) {
    quote.ptr[0] = 0x5aU;
    signature.ptr[0] = 0x5aU;
    *quote_size = value->failure == FAIL_QUOTE_ZERO
                      ? 0U
                      : value->failure == FAIL_QUOTE_OVERSIZE
                            ? quote.cap + 1U
                            : 1U;
    *signature_size = value->failure == FAIL_SIGNATURE_ZERO
                          ? 0U
                          : value->failure == FAIL_SIGNATURE_OVERSIZE
                                ? signature.cap + 1U
                                : 1U;
    return PBNS_OK;
  }
  static const uint8_t quote_bytes[] = "TPM2B_ATTEST-QUOTE";
  static const uint8_t signature_bytes[] = "TPMT_SIGNATURE";
  memcpy(quote.ptr, quote_bytes, sizeof(quote_bytes));
  memcpy(signature.ptr, signature_bytes, sizeof(signature_bytes));
  *quote_size = sizeof(quote_bytes);
  *signature_size = sizeof(signature_bytes);
  record_event(value, EVENT_QUOTE);
  return PBNS_OK;
}

static pbns_status trusted_time(void *context, pbns_time_interval *interval) {
  fixture *value = context;
  ++value->trusted_time_calls;
  value->trusted_time_after_issue_response = value->issue_response_received;
  if (value->issue_response_received) {
    memset(value->broker_storage + 3U * PBNS_FRAME_V1_WIRE_MAX, 0xa5,
           PBNS_FRAME_V1_WIRE_MAX);
  }
  const int64_t instant = value->failure == FAIL_CHALLENGE_EXPIRED
                              ? INT64_C(101000000000)
                              : INT64_C(1000000000);
  *interval = (pbns_time_interval){instant, instant};
  return PBNS_OK;
}

static pbns_status monotonic_time(void *context, uint64_t *now_ms) {
  fixture *value = context;
  ++value->monotonic_calls;
  if (value->monotonic_status != PBNS_OK) {
    return value->monotonic_status;
  }
  if (value->timeout_at_monotonic_call != 0U &&
      value->monotonic_calls >= value->timeout_at_monotonic_call) {
    value->now_ms += value->config.timeout_ms;
    value->timeout_at_monotonic_call = 0U;
  }
  if (value->jump_at_monotonic_call != 0U &&
      value->monotonic_calls >= value->jump_at_monotonic_call) {
    value->now_ms = value->jump_to_ms;
    value->jump_at_monotonic_call = 0U;
  }
  *now_ms = value->now_ms;
  return PBNS_OK;
}

static pbns_status cancel_requested(void *context, bool *requested) {
  fixture *value = context;
  ++value->cancel_checks;
  if (value->cancellation_status != PBNS_OK &&
      (value->cancellation_error_at == 0U ||
       value->cancel_checks >= value->cancellation_error_at)) {
    return value->cancellation_status;
  }
  *requested = value->cancel_at != 0U && value->cancel_checks >= value->cancel_at;
  return PBNS_OK;
}

static pbns_status capture_inventory(void *context, pbns_buffer scratch,
                                     pbns_inventory_report *report) {
  fixture *value = context;
  assert(scratch.cap == PBNS_INVENTORY_VARIABLE_MAX_SIZE);
  ++value->capture_inventory_calls;
  if (value->failure == FAIL_INVENTORY) {
    return PBNS_ERR_IO;
  }
  memcpy(report->host_fingerprint, value->config.host_fingerprint, 32U);
  if (value->failure == FAIL_INVENTORY_HOST) {
    report->host_fingerprint[0] ^= 1U;
  }
  memset(report->board_model_digest, 0xb2, 32U);
  report->tpm_present = true;
  report->tpm_active_banks[0] = PBNS_TPM_ALG_SHA256;
  report->tpm_active_bank_count = 1U;
  return PBNS_OK;
}

static pbns_status capture_measured(void *context,
                                    pbns_measured_boot_selection selection,
                                    pbns_buffer arena,
                                    pbns_measured_boot_evidence *evidence) {
  fixture *value = context;
  ++value->capture_measured_calls;
  if (value->failure == FAIL_MEASURED) {
    return PBNS_ERR_IO;
  }
  uint8_t *event_start = arena.ptr;
  size_t event_capacity = arena.cap;
  if (value->measured_view == MEASURED_VIEW_BOUNDED_SUBVIEW) {
    ++event_start;
    --event_capacity;
  }
  const size_t event_size = make_event_log(event_start, event_capacity);
  evidence->event_log = (pbns_view){event_start, event_size};
  evidence->pcr_count = selection.count;
  for (size_t index = 0U; index < selection.count; ++index) {
    evidence->pcrs[index].selection = selection.items[index];
    if (value->failure == FAIL_MEASURED_MISMATCH && index == 0U) {
      evidence->pcrs[index].selection.pcr_index ^= 1U;
    }
    memset(evidence->pcrs[index].digest, (int)(0x70U + index), 32U);
    evidence->pcrs[index].digest_size = 32U;
  }
  static const uint8_t sha256_pcr7_selection[] = {0x00U, 0x0bU, 0x07U};
  assert(selection.count == 1U &&
         selection.items[0].hash_algorithm == PBNS_TPM_ALG_SHA256 &&
         selection.items[0].pcr_index == 7U);
  assert(independent_sha256(
             (pbns_view){sha256_pcr7_selection,
                         sizeof(sha256_pcr7_selection)},
             evidence->selection_digest) == PBNS_OK);
  assert(independent_sha256(evidence->event_log,
                            evidence->event_log_digest) == PBNS_OK);
  if (value->measured_view == MEASURED_VIEW_EMPTY) {
    evidence->event_log = (pbns_view){arena.ptr, 0U};
  } else if (value->measured_view == MEASURED_VIEW_BEFORE_ARENA) {
    evidence->event_log.ptr =
        (const uint8_t *)((uintptr_t)arena.ptr - (uintptr_t)1U);
  } else if (value->measured_view == MEASURED_VIEW_AT_END) {
    evidence->event_log = (pbns_view){arena.ptr + arena.cap, 1U};
  } else if (value->measured_view == MEASURED_VIEW_INTEGER_WRAP) {
    evidence->event_log =
        (pbns_view){(const uint8_t *)(UINTPTR_MAX - (uintptr_t)3U), 8U};
  } else if (value->measured_view == MEASURED_VIEW_EXTENDS_PAST_END) {
    evidence->event_log.len = arena.cap + 1U;
  }
  return PBNS_OK;
}

static bool all_zero(pbns_buffer buffer) {
  for (size_t index = 0U; index < buffer.cap; ++index) {
    if (buffer.ptr[index] != 0U) return false;
  }
  return true;
}

static void collect_workspace_descriptors(
    pbns_attestation_run_workspace *workspace,
    pbns_buffer *descriptors[WORKSPACE_DESCRIPTOR_COUNT]) {
  descriptors[0] = &workspace->issue_wire;
  descriptors[1] = &workspace->issue_canonical;
  descriptors[2] = &workspace->submit_wire;
  descriptors[3] = &workspace->submit_canonical;
  descriptors[4] = &workspace->challenge.canonical;
  descriptors[5] = &workspace->challenge.aad;
  descriptors[6] = &workspace->inventory_variable_scratch;
  descriptors[7] = &workspace->event_log_arena;
  descriptors[8] = &workspace->attestation.inventory;
  descriptors[9] = &workspace->attestation.selection;
  descriptors[10] = &workspace->attestation.quote;
  descriptors[11] = &workspace->attestation.quote_signature;
  descriptors[12] = &workspace->attestation.evidence;
  descriptors[13] = &workspace->attestation.signed_evidence;
  descriptors[14] = &workspace->attestation.ciphertext;
  descriptors[15] = &workspace->attestation.aad;
  descriptors[16] = &workspace->receipt.canonical_payload;
  descriptors[17] = &workspace->receipt.canonical_cose;
  descriptors[18] = &workspace->receipt.aad;
  descriptors[19] = &workspace->evidence_digest;
}

static bool broker_storage_all_value(const fixture *value, uint8_t expected) {
  const pbns_buffer buffers[] = {
      value->broker.storage.encoded, value->broker.storage.raw_scratch,
      value->broker.storage.receive, value->broker.storage.decoded};
  for (size_t buffer_index = 0U; buffer_index < ARRAY_COUNT(buffers);
       ++buffer_index) {
    for (size_t byte_index = 0U; byte_index < buffers[buffer_index].cap;
         ++byte_index) {
      if (buffers[buffer_index].ptr[byte_index] != expected) {
        return false;
      }
    }
  }
  return true;
}

static bool workspace_all_value(const fixture *value, uint8_t expected) {
  const pbns_buffer buffers[] = {
      value->workspace.issue_wire, value->workspace.issue_canonical,
      value->workspace.submit_wire, value->workspace.submit_canonical,
      value->workspace.challenge.canonical, value->workspace.challenge.aad,
      value->workspace.inventory_variable_scratch, value->workspace.event_log_arena,
      value->workspace.attestation.inventory, value->workspace.attestation.selection,
      value->workspace.attestation.quote, value->workspace.attestation.quote_signature,
      value->workspace.attestation.evidence, value->workspace.attestation.signed_evidence,
      value->workspace.attestation.ciphertext, value->workspace.attestation.aad,
      value->workspace.receipt.canonical_payload, value->workspace.receipt.canonical_cose,
      value->workspace.receipt.aad, value->workspace.evidence_digest};
  for (size_t buffer_index = 0U; buffer_index < ARRAY_COUNT(buffers);
       ++buffer_index) {
    for (size_t byte_index = 0U; byte_index < buffers[buffer_index].cap;
         ++byte_index) {
      if (buffers[buffer_index].ptr[byte_index] != expected) {
        return false;
      }
    }
  }
  return true;
}

static bool workspace_all_zero(const fixture *value) {
  return workspace_all_value(value, 0U);
}

static pbns_status display_result(void *context,
                                  const pbns_attestation_run_result *result) {
  fixture *value = context;
  ++value->display_calls;
  value->display_saw_wipe = workspace_all_zero(value) &&
                            all_zero(value->broker.storage.decoded);
  assert(value->display_saw_wipe);
  record_event(value, EVENT_CLEANUP_OBSERVED);
  assert(result->verdict == value->verdict);
  record_event(value, EVENT_DISPLAY);
  return value->display_status;
}

static pbns_buffer allocate_buffer(size_t capacity) {
  uint8_t *bytes = malloc(capacity);
  assert(bytes != NULL);
  memset(bytes, 0xa5, capacity);
  return (pbns_buffer){bytes, 0U, capacity};
}

static void allocate_workspace(pbns_attestation_run_workspace *workspace) {
  *workspace = (pbns_attestation_run_workspace){
      .issue_wire = allocate_buffer(PBNS_ATTESTATION_WIRE_MAX_SIZE),
      .issue_canonical = allocate_buffer(PBNS_ATTESTATION_WIRE_MAX_SIZE),
      .submit_wire = allocate_buffer(PBNS_ATTESTATION_WIRE_MAX_SIZE),
      .submit_canonical = allocate_buffer(PBNS_ATTESTATION_WIRE_MAX_SIZE),
      .challenge = {allocate_buffer(PBNS_ATTESTATION_CHALLENGE_MAX_SIZE),
                    allocate_buffer(PBNS_ATTESTATION_AAD_MAX_SIZE)},
      .inventory_variable_scratch = allocate_buffer(PBNS_INVENTORY_VARIABLE_MAX_SIZE),
      .event_log_arena = allocate_buffer(PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE),
      .attestation = {
          allocate_buffer(PBNS_INVENTORY_ENCODED_MAX_SIZE),
          allocate_buffer(PBNS_ATTESTATION_SELECTION_WORKSPACE_SIZE),
          allocate_buffer(PBNS_ATTESTATION_QUOTE_MAX_SIZE),
          allocate_buffer(PBNS_ATTESTATION_QUOTE_SIGNATURE_MAX_SIZE),
          allocate_buffer(PBNS_ATTESTATION_EVIDENCE_MAX_SIZE),
          allocate_buffer(PBNS_ATTESTATION_SIGNED_MAX_SIZE),
          allocate_buffer(PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE),
          allocate_buffer(PBNS_ATTESTATION_AAD_MAX_SIZE)},
      .receipt = {allocate_buffer(PBNS_ATTESTATION_RECEIPT_MAX_PAYLOAD_SIZE),
                  allocate_buffer(PBNS_ATTESTATION_RECEIPT_MAX_SIGNED_SIZE),
                  allocate_buffer(PBNS_ATTESTATION_RECEIPT_MAX_AAD_SIZE)},
      .evidence_digest = allocate_buffer(PBNS_ATTESTATION_DIGEST_SIZE)};
}

static void free_workspace(pbns_attestation_run_workspace *workspace) {
  pbns_buffer buffers[] = {
      workspace->issue_wire, workspace->issue_canonical, workspace->submit_wire,
      workspace->submit_canonical, workspace->challenge.canonical,
      workspace->challenge.aad, workspace->inventory_variable_scratch,
      workspace->event_log_arena, workspace->attestation.inventory,
      workspace->attestation.selection, workspace->attestation.quote,
      workspace->attestation.quote_signature, workspace->attestation.evidence,
      workspace->attestation.signed_evidence, workspace->attestation.ciphertext,
      workspace->attestation.aad, workspace->receipt.canonical_payload,
      workspace->receipt.canonical_cose, workspace->receipt.aad,
      workspace->evidence_digest};
  for (size_t index = 0U; index < ARRAY_COUNT(buffers); ++index) free(buffers[index].ptr);
  *workspace = (pbns_attestation_run_workspace){0};
}

static void prepare_issue_response(fixture *value) {
  pbns_attestation_challenge challenge = {0};
  memset(challenge.request_id.bytes, 0x22, sizeof(challenge.request_id.bytes));
  memset(challenge.host_fingerprint, 0x44, sizeof(challenge.host_fingerprint));
  memset(challenge.verifier_nonce, 0x33, sizeof(challenge.verifier_nonce));
  challenge.selection_items[0] =
      (pbns_measured_boot_selection_item){PBNS_TPM_ALG_SHA256, 7U};
  challenge.selection_count = 1U;
  memcpy(challenge.recipient_kid, value->recipient_kid, sizeof(value->recipient_kid));
  challenge.recipient_kid_len = sizeof(value->recipient_kid);
  challenge.issued_at_ns = UINT64_C(500000000);
  challenge.expiry_ns = value->challenge_expiry_ns;
  if (value->failure == FAIL_CHALLENGE_REQUEST_BINDING) {
    challenge.request_id.bytes[0] ^= 1U;
  } else if (value->failure == FAIL_CHALLENGE_NONCE_BINDING) {
    challenge.verifier_nonce[0] ^= 1U;
  } else if (value->failure == FAIL_CHALLENGE_HOST_BINDING) {
    challenge.host_fingerprint[0] ^= 1U;
  } else if (value->failure == FAIL_CHALLENGE_KID_BINDING) {
    challenge.recipient_kid[0] ^= 1U;
  }
  assert(pbns_attestation_challenge_encode(
      &challenge,
      (pbns_buffer){value->challenge_payload, 0U, sizeof(value->challenge_payload)},
      &value->challenge_payload_size) == PBNS_OK);
  if (value->failure == FAIL_CHALLENGE_MALFORMED) {
    value->challenge_payload[0] = 0xffU;
  }
  value->challenge_cose_size = wrap_cose(
      (pbns_view){value->challenge_payload, value->challenge_payload_size},
      (pbns_view){value->challenge_kid, sizeof(value->challenge_kid)},
      value->challenge_cose, sizeof(value->challenge_cose));
  pbns_attestation_wire_response response = {
      .operation = PBNS_ATTESTATION_WIRE_ISSUE,
      .recipient_kid = {value->issue_recipient, sizeof(value->issue_recipient)},
      .object = {value->challenge_cose, value->challenge_cose_size},
  };
  memset(response.challenge_request_id.bytes, 0x22, 16U);
  memset(response.verifier_nonce, 0x33, 32U);
  uint8_t application[PBNS_ATTESTATION_WIRE_MAX_SIZE] = {0};
  const size_t application_size = encode_wire_response(
      &response, application, sizeof(application));
  pbns_request_id outer = {0}; memset(outer.bytes, 0x11, 16U);
  frame_response(value, &outer, (pbns_view){application, application_size});
}

static void fixture_init(fixture *value) {
  *value = (fixture){0};
  value->transport.owner = value;
  value->verdict = PBNS_ATTESTATION_RECEIPT_FULL;
  value->now_ms = 100U;
  value->challenge_expiry_ns = UINT64_C(100000000000);
  memset(value->recipient_kid, 0x51, sizeof(value->recipient_kid));
  memcpy(value->issue_recipient, value->recipient_kid, sizeof(value->recipient_kid));
  memset(value->challenge_kid, 0x52, sizeof(value->challenge_kid));
  memset(value->receipt_kid, 0x53, sizeof(value->receipt_kid));
  memset(value->ak_name, 0x54, sizeof(value->ak_name));
  memset(value->ak_reference, 0x55, sizeof(value->ak_reference));
  static const pbns_crypto_ops challenge_ops = {.sign1_verify_profile = verify_challenge};
  static const pbns_crypto_ops receipt_ops = {.sign1_verify = verify_receipt};
  static const pbns_crypto_ops signer_ops = {.sign1_sign = sign_evidence};
  static const pbns_crypto_ops encrypt_ops = {.encrypt_for_recipient = encrypt_evidence};
  value->challenge_verifier = (pbns_crypto){&challenge_ops, value};
  value->receipt_verifier = (pbns_crypto){&receipt_ops, value};
  value->signer = (pbns_crypto){&signer_ops, value};
  value->encrypter = (pbns_crypto){&encrypt_ops, value};
  value->broker_storage = malloc(4U * PBNS_FRAME_V1_WIRE_MAX);
  value->signed_evidence = malloc(PBNS_ATTESTATION_SIGNED_MAX_SIZE);
  value->ciphertext = malloc(PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE);
  value->uploaded = malloc(PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE);
  assert(value->broker_storage != NULL && value->signed_evidence != NULL &&
         value->ciphertext != NULL && value->uploaded != NULL);
  memset(value->broker_storage, 0xa5, 4U * PBNS_FRAME_V1_WIRE_MAX);
  assert(pbns_broker_init(&value->broker,
      (pbns_transport){&transport_ops, &value->transport},
      (pbns_broker_platform){&broker_ops, &value->transport},
      (pbns_broker_storage){
          {value->broker_storage, 0U, PBNS_FRAME_V1_WIRE_MAX},
          {value->broker_storage + PBNS_FRAME_V1_WIRE_MAX, 0U, PBNS_FRAME_V1_WIRE_MAX},
          {value->broker_storage + 2U * PBNS_FRAME_V1_WIRE_MAX, 0U, PBNS_FRAME_V1_WIRE_MAX},
          {value->broker_storage + 3U * PBNS_FRAME_V1_WIRE_MAX, 0U, PBNS_FRAME_V1_WIRE_MAX}}) == PBNS_OK);
  allocate_workspace(&value->workspace);
  value->config = (pbns_attestation_run_config){
      .broker = &value->broker,
      .broker_transport_context_region = {
          (const uint8_t *)&value->transport, sizeof(value->transport)},
      .broker_platform_context_region = {
          (const uint8_t *)&value->transport, sizeof(value->transport)},
      .identity_assurance = PBNS_IDENTITY_TPM_UNVERIFIED_EK,
      .recipient_kid = {value->recipient_kid, sizeof(value->recipient_kid)},
      .challenge_kid = {value->challenge_kid, sizeof(value->challenge_kid)},
      .receipt_kid = {value->receipt_kid, sizeof(value->receipt_kid)},
      .ak_name = {value->ak_name, sizeof(value->ak_name)},
      .ak_reference = {value->ak_reference, sizeof(value->ak_reference)},
      .challenge_verifier = &value->challenge_verifier,
      .receipt_verifier = &value->receipt_verifier,
      .challenge_verifier_context_region = {
          (const uint8_t *)value, offsetof(fixture, config)},
      .receipt_verifier_context_region = {
          (const uint8_t *)value, offsetof(fixture, config)},
      .submission_template = {
          .host_signer = &value->signer,
          .recipient_encrypter = &value->encrypter,
          .sha256 = hash_bytes,
          .quote = quote_evidence,
          .sha256_context = value,
          .quote_context = value,
          .host_signer_context_region = {
              (const uint8_t *)value, offsetof(fixture, config)},
          .recipient_encrypter_context_region = {
              (const uint8_t *)value, offsetof(fixture, config)},
          .sha256_context_region = {
              (const uint8_t *)value, offsetof(fixture, config)},
          .quote_context_region = {
              (const uint8_t *)value, offsetof(fixture, config)}},
      .ops = {trusted_time, monotonic_time, cancel_requested,
              capture_inventory, capture_measured, display_result},
      .context = value,
      .context_region = {
          (const uint8_t *)value, offsetof(fixture, config)},
      .timeout_ms = 5000U};
  memset(value->config.host_fingerprint, 0x44, 32U);
  prepare_issue_response(value);
}

static void fixture_destroy(fixture *value) {
  pbns_broker_reset(&value->broker);
  free(value->broker_storage);
  free(value->signed_evidence);
  free(value->ciphertext);
  free(value->uploaded);
  free_workspace(&value->workspace);
}

static pbns_status populated_consume(
    void *context, const pbns_request_id *request_id,
    const uint8_t verifier_nonce[PBNS_ATTESTATION_NONCE_SIZE]) {
  (void)context;
  (void)request_id;
  (void)verifier_nonce;
  return PBNS_OK;
}

static pbns_status populated_send(
    void *context, const pbns_request_id *request_id, uint32_t sequence,
    pbns_view payload, bool final_record) {
  (void)context;
  (void)request_id;
  (void)sequence;
  (void)payload;
  (void)final_record;
  return PBNS_OK;
}

typedef enum structural_case {
  STRUCT_BROKER_NULL,
  STRUCT_BROKER_UNINITIALIZED,
  STRUCT_BROKER_ACTIVE,
  STRUCT_BROKER_OPENED,
  STRUCT_TRANSPORT_OPS,
  STRUCT_PLATFORM_OPS,
  STRUCT_TRANSPORT_CONTEXT,
  STRUCT_PLATFORM_CONTEXT,
  STRUCT_TRANSPORT_OPEN,
  STRUCT_TRANSPORT_CLOSE,
  STRUCT_TRANSPORT_SEND,
  STRUCT_TRANSPORT_RECEIVE,
  STRUCT_TRANSPORT_CANCEL,
  STRUCT_TRANSPORT_LIMITS,
  STRUCT_BROKER_RANDOM,
  STRUCT_BROKER_MONOTONIC,
  STRUCT_ZERO_FINGERPRINT,
  STRUCT_RECIPIENT_EMPTY,
  STRUCT_RECIPIENT_OVERSIZE,
  STRUCT_CHALLENGE_EMPTY,
  STRUCT_CHALLENGE_OVERSIZE,
  STRUCT_RECEIPT_EMPTY,
  STRUCT_RECEIPT_OVERSIZE,
  STRUCT_AK_NAME_EMPTY,
  STRUCT_AK_NAME_OVERSIZE,
  STRUCT_AK_REFERENCE_EMPTY,
  STRUCT_AK_REFERENCE_OVERSIZE,
  STRUCT_TRUSTED_TIME,
  STRUCT_MONOTONIC,
  STRUCT_CANCEL,
  STRUCT_INVENTORY,
  STRUCT_MEASURED,
  STRUCT_DISPLAY,
  STRUCT_CHALLENGE_VERIFIER,
  STRUCT_CHALLENGE_OPS,
  STRUCT_CHALLENGE_CONTEXT,
  STRUCT_CHALLENGE_VERIFY,
  STRUCT_CHALLENGE_REGION,
  STRUCT_RECEIPT_VERIFIER,
  STRUCT_RECEIPT_OPS,
  STRUCT_RECEIPT_CONTEXT,
  STRUCT_RECEIPT_VERIFY,
  STRUCT_RECEIPT_REGION,
  STRUCT_SIGNER,
  STRUCT_SIGNER_OPS,
  STRUCT_SIGNER_CONTEXT,
  STRUCT_SIGN_OPERATION,
  STRUCT_SIGNER_REGION,
  STRUCT_ENCRYPTER,
  STRUCT_ENCRYPTER_OPS,
  STRUCT_ENCRYPTER_CONTEXT,
  STRUCT_ENCRYPT_OPERATION,
  STRUCT_ENCRYPTER_REGION,
  STRUCT_SHA_OPERATION,
  STRUCT_SHA_CONTEXT,
  STRUCT_SHA_REGION,
  STRUCT_QUOTE_OPERATION,
  STRUCT_QUOTE_CONTEXT,
  STRUCT_QUOTE_REGION,
  STRUCT_TRANSPORT_CONTEXT_REGION,
  STRUCT_PLATFORM_CONTEXT_REGION,
  STRUCT_TIMEOUT,
  STRUCT_TEMPLATE_INVENTORY,
  STRUCT_TEMPLATE_MEASURED,
  STRUCT_TEMPLATE_AK_NAME,
  STRUCT_TEMPLATE_AK_REFERENCE,
  STRUCT_TEMPLATE_CONSUME,
  STRUCT_TEMPLATE_SEND,
  STRUCT_TEMPLATE_CONSUME_CONTEXT,
  STRUCT_TEMPLATE_SEND_CONTEXT,
  STRUCT_TEMPLATE_CONSUME_REGION,
  STRUCT_TEMPLATE_SEND_REGION,
  STRUCT_TEMPLATE_DIGEST,
  STRUCT_BUFFER_NULL,
  STRUCT_BUFFER_LEN,
  STRUCT_BUFFER_CAP,
  STRUCT_ASSURANCE,
  STRUCT_COUNT
} structural_case;

static void assert_no_structural_callbacks(const fixture *value) {
  assert(value->monotonic_calls == 0U && value->trusted_time_calls == 0U &&
         value->random_calls == 0U && value->broker_clock_calls == 0U &&
         value->cancel_checks == 0U && value->transport.open_calls == 0U &&
         value->transport.limits_calls == 0U &&
         value->transport.send_calls == 0U &&
         value->transport.receive_calls == 0U &&
         value->transport.close_calls == 0U &&
         value->transport.cancel_calls == 0U &&
         value->capture_inventory_calls == 0U &&
         value->capture_measured_calls == 0U && value->quote_calls == 0U &&
         value->sign_calls == 0U && value->encrypt_calls == 0U &&
         value->display_calls == 0U);
}

static void call_structural_rejection(fixture *value) {
  uint8_t result_before[sizeof(value->result)] = {0};
  memset(&value->result, 0xa5, sizeof(value->result));
  memcpy(result_before, &value->result, sizeof(result_before));
  assert(pbns_attestation_run(&value->config, &value->workspace,
                              &value->result) == PBNS_ERR_ARGUMENT);
  assert(memcmp(result_before, &value->result, sizeof(result_before)) == 0);
  assert_no_structural_callbacks(value);
}

static void assert_structural_canaries(const fixture *value) {
  assert(workspace_all_value(value, UINT8_C(0xa5)));
  assert(broker_storage_all_value(value, UINT8_C(0xa5)));
}

static void assert_structural_rejection(fixture *value) {
  call_structural_rejection(value);
  assert_structural_canaries(value);
}

/* Quebras detectadas: toda a forma estrutural tem de falhar sem callbacks. */
static void test_complete_structural_matrix(void) {
  assert(pbns_attestation_run(NULL, NULL, NULL) == PBNS_ERR_ARGUMENT);
  fixture nulls = {0};
  fixture_init(&nulls);
  const pbns_attestation_run_result null_result_before = nulls.result;
  assert(pbns_attestation_run(NULL, &nulls.workspace, &nulls.result) ==
         PBNS_ERR_ARGUMENT);
  assert(workspace_all_value(&nulls, UINT8_C(0xa5)) &&
         broker_storage_all_value(&nulls, UINT8_C(0xa5)));
  assert(pbns_attestation_run(&nulls.config, NULL, &nulls.result) ==
         PBNS_ERR_ARGUMENT);
  assert(workspace_all_value(&nulls, UINT8_C(0xa5)) &&
         broker_storage_all_value(&nulls, UINT8_C(0xa5)));
  assert(pbns_attestation_run(&nulls.config, &nulls.workspace, NULL) ==
         PBNS_ERR_ARGUMENT);
  assert(memcmp(&nulls.result, &null_result_before,
                sizeof(null_result_before)) == 0 &&
         workspace_all_value(&nulls, UINT8_C(0xa5)) &&
         broker_storage_all_value(&nulls, UINT8_C(0xa5)));
  assert_no_structural_callbacks(&nulls);
  fixture_destroy(&nulls);
  for (size_t case_index = 0U; case_index < (size_t)STRUCT_COUNT;
       ++case_index) {
    fixture value = {0};
    fixture_init(&value);
    pbns_transport_ops mutable_transport = *value.broker.transport.ops;
    pbns_broker_platform_ops mutable_platform = *value.broker.platform.ops;
    pbns_crypto_ops mutable_crypto = {0};
    const pbns_buffer saved_issue = value.workspace.issue_wire;
    switch ((structural_case)case_index) {
      case STRUCT_BROKER_NULL: value.config.broker = NULL; break;
      case STRUCT_BROKER_UNINITIALIZED: value.broker.initialized = false; break;
      case STRUCT_BROKER_ACTIVE: value.broker.active = true; break;
      case STRUCT_BROKER_OPENED: value.broker.opened = true; break;
      case STRUCT_TRANSPORT_OPS: value.broker.transport.ops = NULL; break;
      case STRUCT_PLATFORM_OPS: value.broker.platform.ops = NULL; break;
      case STRUCT_TRANSPORT_CONTEXT: value.broker.transport.context = NULL; break;
      case STRUCT_PLATFORM_CONTEXT: value.broker.platform.context = NULL; break;
      case STRUCT_TRANSPORT_OPEN: mutable_transport.open = NULL; value.broker.transport.ops = &mutable_transport; break;
      case STRUCT_TRANSPORT_CLOSE: mutable_transport.close = NULL; value.broker.transport.ops = &mutable_transport; break;
      case STRUCT_TRANSPORT_SEND: mutable_transport.send = NULL; value.broker.transport.ops = &mutable_transport; break;
      case STRUCT_TRANSPORT_RECEIVE: mutable_transport.receive = NULL; value.broker.transport.ops = &mutable_transport; break;
      case STRUCT_TRANSPORT_CANCEL: mutable_transport.cancel = NULL; value.broker.transport.ops = &mutable_transport; break;
      case STRUCT_TRANSPORT_LIMITS: mutable_transport.limits = NULL; value.broker.transport.ops = &mutable_transport; break;
      case STRUCT_BROKER_RANDOM: mutable_platform.random = NULL; value.broker.platform.ops = &mutable_platform; break;
      case STRUCT_BROKER_MONOTONIC: mutable_platform.monotonic_ms = NULL; value.broker.platform.ops = &mutable_platform; break;
      case STRUCT_ZERO_FINGERPRINT: memset(value.config.host_fingerprint, 0, sizeof(value.config.host_fingerprint)); break;
      case STRUCT_RECIPIENT_EMPTY: value.config.recipient_kid = (pbns_view){0}; break;
      case STRUCT_RECIPIENT_OVERSIZE: value.config.recipient_kid.len = 65U; break;
      case STRUCT_CHALLENGE_EMPTY: value.config.challenge_kid = (pbns_view){0}; break;
      case STRUCT_CHALLENGE_OVERSIZE: value.config.challenge_kid.len = 65U; break;
      case STRUCT_RECEIPT_EMPTY: value.config.receipt_kid = (pbns_view){0}; break;
      case STRUCT_RECEIPT_OVERSIZE: value.config.receipt_kid.len = 65U; break;
      case STRUCT_AK_NAME_EMPTY: value.config.ak_name = (pbns_view){0}; break;
      case STRUCT_AK_NAME_OVERSIZE: value.config.ak_name.len = PBNS_ATTESTATION_AK_NAME_MAX_SIZE + 1U; break;
      case STRUCT_AK_REFERENCE_EMPTY: value.config.ak_reference = (pbns_view){0}; break;
      case STRUCT_AK_REFERENCE_OVERSIZE: value.config.ak_reference.len = PBNS_ATTESTATION_AK_REFERENCE_MAX_SIZE + 1U; break;
      case STRUCT_TRUSTED_TIME: value.config.ops.trusted_time = NULL; break;
      case STRUCT_MONOTONIC: value.config.ops.monotonic_ms = NULL; break;
      case STRUCT_CANCEL: value.config.ops.cancel_requested = NULL; break;
      case STRUCT_INVENTORY: value.config.ops.capture_inventory = NULL; break;
      case STRUCT_MEASURED: value.config.ops.capture_measured = NULL; break;
      case STRUCT_DISPLAY: value.config.ops.display_authenticated = NULL; break;
      case STRUCT_CHALLENGE_VERIFIER: value.config.challenge_verifier = NULL; break;
      case STRUCT_CHALLENGE_OPS: value.challenge_verifier.ops = NULL; break;
      case STRUCT_CHALLENGE_CONTEXT: value.challenge_verifier.context = NULL; break;
      case STRUCT_CHALLENGE_VERIFY: mutable_crypto = *value.challenge_verifier.ops; mutable_crypto.sign1_verify_profile = NULL; value.challenge_verifier.ops = &mutable_crypto; break;
      case STRUCT_CHALLENGE_REGION: value.config.challenge_verifier_context_region = (pbns_view){0}; break;
      case STRUCT_RECEIPT_VERIFIER: value.config.receipt_verifier = NULL; break;
      case STRUCT_RECEIPT_OPS: value.receipt_verifier.ops = NULL; break;
      case STRUCT_RECEIPT_CONTEXT: value.receipt_verifier.context = NULL; break;
      case STRUCT_RECEIPT_VERIFY: mutable_crypto = *value.receipt_verifier.ops; mutable_crypto.sign1_verify = NULL; value.receipt_verifier.ops = &mutable_crypto; break;
      case STRUCT_RECEIPT_REGION: value.config.receipt_verifier_context_region = (pbns_view){0}; break;
      case STRUCT_SIGNER: value.config.submission_template.host_signer = NULL; break;
      case STRUCT_SIGNER_OPS: value.signer.ops = NULL; break;
      case STRUCT_SIGNER_CONTEXT: value.signer.context = NULL; break;
      case STRUCT_SIGN_OPERATION: mutable_crypto = *value.signer.ops; mutable_crypto.sign1_sign = NULL; value.signer.ops = &mutable_crypto; break;
      case STRUCT_SIGNER_REGION: value.config.submission_template.host_signer_context_region = (pbns_view){0}; break;
      case STRUCT_ENCRYPTER: value.config.submission_template.recipient_encrypter = NULL; break;
      case STRUCT_ENCRYPTER_OPS: value.encrypter.ops = NULL; break;
      case STRUCT_ENCRYPTER_CONTEXT: value.encrypter.context = NULL; break;
      case STRUCT_ENCRYPT_OPERATION: mutable_crypto = *value.encrypter.ops; mutable_crypto.encrypt_for_recipient = NULL; value.encrypter.ops = &mutable_crypto; break;
      case STRUCT_ENCRYPTER_REGION: value.config.submission_template.recipient_encrypter_context_region = (pbns_view){0}; break;
      case STRUCT_SHA_OPERATION: value.config.submission_template.sha256 = NULL; break;
      case STRUCT_SHA_CONTEXT: value.config.submission_template.sha256_context = NULL; break;
      case STRUCT_SHA_REGION: value.config.submission_template.sha256_context_region = (pbns_view){0}; break;
      case STRUCT_QUOTE_OPERATION: value.config.submission_template.quote = NULL; break;
      case STRUCT_QUOTE_CONTEXT: value.config.submission_template.quote_context = NULL; break;
      case STRUCT_QUOTE_REGION: value.config.submission_template.quote_context_region = (pbns_view){0}; break;
      case STRUCT_TRANSPORT_CONTEXT_REGION: value.config.broker_transport_context_region = (pbns_view){0}; break;
      case STRUCT_PLATFORM_CONTEXT_REGION: value.config.broker_platform_context_region = (pbns_view){0}; break;
      case STRUCT_TIMEOUT: value.config.timeout_ms = 0U; break;
      case STRUCT_TEMPLATE_INVENTORY: value.config.submission_template.inventory_report = (const pbns_inventory_report *)&value.result; break;
      case STRUCT_TEMPLATE_MEASURED: value.config.submission_template.measured_boot = (const pbns_measured_boot_evidence *)&value.result; break;
      case STRUCT_TEMPLATE_AK_NAME: value.config.submission_template.ak_name = (pbns_view){value.ak_name, 1U}; break;
      case STRUCT_TEMPLATE_AK_REFERENCE: value.config.submission_template.ak_reference = (pbns_view){value.ak_reference, 1U}; break;
      case STRUCT_TEMPLATE_CONSUME: value.config.submission_template.consume = populated_consume; break;
      case STRUCT_TEMPLATE_SEND: value.config.submission_template.send_data = populated_send; break;
      case STRUCT_TEMPLATE_CONSUME_CONTEXT: value.config.submission_template.consume_context = &value; break;
      case STRUCT_TEMPLATE_SEND_CONTEXT: value.config.submission_template.send_context = &value; break;
      case STRUCT_TEMPLATE_CONSUME_REGION: value.config.submission_template.consume_context_region = (pbns_view){(const uint8_t *)&value, 1U}; break;
      case STRUCT_TEMPLATE_SEND_REGION: value.config.submission_template.send_context_region = (pbns_view){(const uint8_t *)&value, 1U}; break;
      case STRUCT_TEMPLATE_DIGEST: value.config.submission_template.evidence_digest = value.workspace.evidence_digest; break;
      case STRUCT_BUFFER_NULL: value.workspace.issue_wire.ptr = NULL; break;
      case STRUCT_BUFFER_LEN: value.workspace.issue_wire.len = 1U; break;
      case STRUCT_BUFFER_CAP: --value.workspace.issue_wire.cap; break;
      case STRUCT_ASSURANCE: value.config.identity_assurance = PBNS_IDENTITY_TPM_VERIFIED; break;
      case STRUCT_COUNT: assert(false); break;
    }
    if (case_index >= (size_t)STRUCT_BUFFER_NULL &&
        case_index <= (size_t)STRUCT_BUFFER_CAP) {
      uint8_t result_before[sizeof(value.result)] = {0};
      memset(&value.result, 0xa5, sizeof(value.result));
      memcpy(result_before, &value.result, sizeof(result_before));
      assert(pbns_attestation_run(&value.config, &value.workspace,
                                  &value.result) == PBNS_ERR_ARGUMENT);
      value.workspace.issue_wire = saved_issue;
      assert(memcmp(result_before, &value.result, sizeof(result_before)) == 0);
      assert(workspace_all_value(&value, UINT8_C(0xa5)));
      assert(broker_storage_all_value(&value, UINT8_C(0xa5)));
      assert_no_structural_callbacks(&value);
    } else {
      assert_structural_rejection(&value);
    }
    value.config.broker = &value.broker;
    value.broker.initialized = true;
    value.broker.active = false;
    value.broker.opened = false;
    value.broker.transport.ops = &transport_ops;
    value.broker.platform.ops = &broker_ops;
    value.broker.transport.context = &value.transport;
    value.broker.platform.context = &value.transport;
    value.workspace.issue_wire = saved_issue;
    fixture_destroy(&value);
  }
}

/* Quebras detectadas: cada uma das 20 formas é validada sem tocar no ponteiro
 * NULL intencional e é restaurada antes de libertar a fixture. */
static void test_all_workspace_descriptor_shapes(void) {
  for (size_t descriptor_index = 0U;
       descriptor_index < WORKSPACE_DESCRIPTOR_COUNT; ++descriptor_index) {
    for (size_t shape_index = 0U; shape_index < 3U; ++shape_index) {
      fixture value = {0};
      fixture_init(&value);
      pbns_buffer *descriptors[WORKSPACE_DESCRIPTOR_COUNT] = {0};
      collect_workspace_descriptors(&value.workspace, descriptors);
      const pbns_buffer saved = *descriptors[descriptor_index];
      if (shape_index == 0U) {
        descriptors[descriptor_index]->ptr = NULL;
      } else if (shape_index == 1U) {
        descriptors[descriptor_index]->len = 1U;
      } else {
        assert(descriptors[descriptor_index]->cap > 0U);
        --descriptors[descriptor_index]->cap;
      }
      call_structural_rejection(&value);
      *descriptors[descriptor_index] = saved;
      assert_structural_canaries(&value);
      fixture_destroy(&value);
    }
  }
}

/* Quebra detectada: remover a comparação par-a-par deixa uma classe passar. */
static void test_every_workspace_predecessor_alias(void) {
  fixture value = {0};
  fixture_init(&value);
  pbns_buffer *descriptors[WORKSPACE_DESCRIPTOR_COUNT] = {0};
  collect_workspace_descriptors(&value.workspace, descriptors);
  for (size_t descriptor_index = 1U;
       descriptor_index < WORKSPACE_DESCRIPTOR_COUNT; ++descriptor_index) {
    const pbns_buffer saved = *descriptors[descriptor_index];
    descriptors[descriptor_index]->ptr = descriptors[descriptor_index - 1U]->ptr;
    call_structural_rejection(&value);
    *descriptors[descriptor_index] = saved;
    assert_structural_canaries(&value);
  }
  fixture_destroy(&value);
}

static void test_each_workspace_aliases_result_config_and_run_context(void) {
  for (size_t input_index = 0U; input_index < 3U; ++input_index) {
    fixture value = {0};
    fixture_init(&value);
    pbns_buffer *descriptors[WORKSPACE_DESCRIPTOR_COUNT] = {0};
    collect_workspace_descriptors(&value.workspace, descriptors);
    for (size_t descriptor_index = 0U;
         descriptor_index < WORKSPACE_DESCRIPTOR_COUNT; ++descriptor_index) {
      const pbns_buffer saved = *descriptors[descriptor_index];
      const pbns_attestation_run_config config_before = value.config;
      descriptors[descriptor_index]->ptr =
          input_index == 0U
              ? (uint8_t *)&value.result
              : input_index == 1U ? (uint8_t *)&value.config
                                  : (uint8_t *)&value;
      call_structural_rejection(&value);
      *descriptors[descriptor_index] = saved;
      assert(memcmp(&config_before, &value.config, sizeof(config_before)) == 0);
      assert_structural_canaries(&value);
    }
    fixture_destroy(&value);
  }
}

static void test_every_view_aliases_each_workspace_class(void) {
  fixture value = {0};
  fixture_init(&value);
  pbns_buffer *descriptors[WORKSPACE_DESCRIPTOR_COUNT] = {0};
  pbns_view *views[] = {&value.config.recipient_kid, &value.config.challenge_kid,
                        &value.config.receipt_kid, &value.config.ak_name,
                        &value.config.ak_reference};
  collect_workspace_descriptors(&value.workspace, descriptors);
  for (size_t view_index = 0U; view_index < ARRAY_COUNT(views); ++view_index) {
    const pbns_view saved_view = *views[view_index];
    for (size_t descriptor_index = 0U;
         descriptor_index < WORKSPACE_DESCRIPTOR_COUNT; ++descriptor_index) {
      views[view_index]->ptr = descriptors[descriptor_index]->ptr;
      call_structural_rejection(&value);
      *views[view_index] = saved_view;
      assert_structural_canaries(&value);
    }
  }
  fixture_destroy(&value);
}

static void test_crypto_descriptors_and_contexts_alias_each_workspace_class(void) {
  /* Each configured descriptor is outside the aggregate fixture context, so
   * only its own workspace-overlap entry can reject the alias. */
  for (size_t crypto_index = 0U; crypto_index < 4U; ++crypto_index) {
    for (size_t descriptor_offset = 0U;
         descriptor_offset < WORKSPACE_DESCRIPTOR_COUNT; ++descriptor_offset) {
      /* canonical_payload is consumed only after all four crypto descriptors,
       * giving descriptor-entry mutations an exact status/canary failure
       * before any earlier workspace use could corrupt an indirect call. */
      const size_t descriptor_index =
          (16U + descriptor_offset) % WORKSPACE_DESCRIPTOR_COUNT;
      fixture value = {0};
      fixture_init(&value);
      pbns_buffer *descriptors[WORKSPACE_DESCRIPTOR_COUNT] = {0};
      collect_workspace_descriptors(&value.workspace, descriptors);
      const pbns_crypto **configured_crypto =
          crypto_index == 0U
              ? &value.config.challenge_verifier
              : crypto_index == 1U
                    ? &value.config.receipt_verifier
                    : crypto_index == 2U
                          ? &value.config.submission_template.host_signer
                          : &value.config.submission_template.recipient_encrypter;
      const pbns_crypto *const saved_crypto = *configured_crypto;
      const pbns_buffer saved_descriptor = *descriptors[descriptor_index];
      const size_t block_size =
          saved_descriptor.cap > sizeof(pbns_crypto)
              ? saved_descriptor.cap
              : sizeof(pbns_crypto);
      uint8_t *const block = malloc(block_size);
      uint8_t *const snapshot = malloc(block_size);
      assert(block != NULL && snapshot != NULL);
      memset(block, 0xa5, block_size);
      pbns_crypto *const aliased_crypto = (pbns_crypto *)block;
      *aliased_crypto = *saved_crypto;
      memcpy(snapshot, block, block_size);

      *configured_crypto = aliased_crypto;
      descriptors[descriptor_index]->ptr = block;
      call_structural_rejection(&value);
      assert(memcmp(snapshot, block, block_size) == 0);

      *descriptors[descriptor_index] = saved_descriptor;
      *configured_crypto = saved_crypto;
      assert_structural_canaries(&value);
      free(snapshot);
      free(block);
      fixture_destroy(&value);
    }
  }

  fixture value = {0};
  fixture_init(&value);
  pbns_buffer *descriptors[WORKSPACE_DESCRIPTOR_COUNT] = {0};
  collect_workspace_descriptors(&value.workspace, descriptors);
  void **contexts[] = {&value.challenge_verifier.context,
                       &value.receipt_verifier.context,
                       &value.signer.context,
                       &value.encrypter.context,
                       &value.config.submission_template.sha256_context,
                       &value.config.submission_template.quote_context};
  pbns_view *regions[] = {
      &value.config.challenge_verifier_context_region,
      &value.config.receipt_verifier_context_region,
      &value.config.submission_template.host_signer_context_region,
      &value.config.submission_template.recipient_encrypter_context_region,
      &value.config.submission_template.sha256_context_region,
      &value.config.submission_template.quote_context_region};
  for (size_t context_index = 0U; context_index < ARRAY_COUNT(contexts);
       ++context_index) {
    void *const saved_context = *contexts[context_index];
    const pbns_view saved_region = *regions[context_index];
    for (size_t descriptor_index = 0U;
         descriptor_index < WORKSPACE_DESCRIPTOR_COUNT; ++descriptor_index) {
      *contexts[context_index] = descriptors[descriptor_index]->ptr;
      *regions[context_index] =
          (pbns_view){descriptors[descriptor_index]->ptr, 1U};
      call_structural_rejection(&value);
      *contexts[context_index] = saved_context;
      *regions[context_index] = saved_region;
      assert_structural_canaries(&value);
    }
  }
  fixture_destroy(&value);
}

static void test_every_broker_storage_aliases_each_workspace_class(void) {
  fixture value = {0};
  fixture_init(&value);
  pbns_buffer *descriptors[WORKSPACE_DESCRIPTOR_COUNT] = {0};
  pbns_buffer *storage[] = {&value.broker.storage.encoded,
                            &value.broker.storage.raw_scratch,
                            &value.broker.storage.receive,
                            &value.broker.storage.decoded};
  collect_workspace_descriptors(&value.workspace, descriptors);
  for (size_t storage_index = 0U; storage_index < ARRAY_COUNT(storage);
       ++storage_index) {
    for (size_t descriptor_index = 0U;
         descriptor_index < WORKSPACE_DESCRIPTOR_COUNT; ++descriptor_index) {
      const pbns_buffer saved = *descriptors[descriptor_index];
      descriptors[descriptor_index]->ptr = storage[storage_index]->ptr;
      call_structural_rejection(&value);
      *descriptors[descriptor_index] = saved;
      assert_structural_canaries(&value);
    }
  }
  fixture_destroy(&value);
}

/* Quebra detectada: contextos obrigatórios aceitam NULL com região vazia. */
static void test_mandatory_contexts_are_nonnull(void) {
  fixture sha = {0};
  fixture_init(&sha);
  sha.config.submission_template.sha256_context = NULL;
  sha.config.submission_template.sha256_context_region = (pbns_view){0};
  assert_structural_rejection(&sha);
  fixture_destroy(&sha);

  fixture quote = {0};
  fixture_init(&quote);
  quote.config.submission_template.quote_context = NULL;
  quote.config.submission_template.quote_context_region = (pbns_view){0};
  assert_structural_rejection(&quote);
  fixture_destroy(&quote);

  fixture run = {0};
  fixture_init(&run);
  run.config.context = NULL;
  run.config.context_region = (pbns_view){0};
  assert_structural_rejection(&run);
  fixture_destroy(&run);
}

/* Quebra detectada: uma região não começa no contexto exacto. */
static void test_context_regions_require_exact_start(void) {
  for (size_t region_index = 0U; region_index < 9U; ++region_index) {
    fixture value = {0};
    fixture_init(&value);
    pbns_view *region = region_index == 0U
                            ? &value.config.challenge_verifier_context_region
                            : region_index == 1U
                                  ? &value.config.receipt_verifier_context_region
                                  : region_index == 2U
                                        ? &value.config.submission_template.host_signer_context_region
                                        : region_index == 3U
                                              ? &value.config.submission_template.recipient_encrypter_context_region
                                              : region_index == 4U
                                                    ? &value.config.submission_template.sha256_context_region
                                                    : region_index == 5U
                                                          ? &value.config.submission_template.quote_context_region
                                                          : region_index == 6U
                                                                ? &value.config.context_region
                                                                : region_index == 7U
                                                                      ? &value.config.broker_transport_context_region
                                                                      : &value.config.broker_platform_context_region;
    region->ptr = region->ptr + 1U;
    assert_structural_rejection(&value);
    fixture_destroy(&value);
  }
}

/* Quebras detectadas: aliases de resultado/config/contexto/armazenamento. */
static void test_complete_descriptor_alias_matrix(void) {
  fixture result_value = {0};
  fixture_init(&result_value);
  pbns_attestation_run_result *aliased_result =
      (pbns_attestation_run_result *)result_value.workspace.submit_wire.ptr;
  uint8_t result_snapshot[sizeof(*aliased_result)] = {0};
  memcpy(result_snapshot, aliased_result, sizeof(result_snapshot));
  assert(pbns_attestation_run(&result_value.config, &result_value.workspace,
                              aliased_result) == PBNS_ERR_ARGUMENT);
  assert(memcmp(result_snapshot, aliased_result,
                sizeof(result_snapshot)) == 0);
  assert_no_structural_callbacks(&result_value);
  fixture_destroy(&result_value);

  fixture config_value = {0};
  fixture_init(&config_value);
  pbns_attestation_run_config *aliased_config =
      (pbns_attestation_run_config *)config_value.workspace.submit_wire.ptr;
  *aliased_config = config_value.config;
  uint8_t config_snapshot[sizeof(*aliased_config)] = {0};
  memcpy(config_snapshot, aliased_config, sizeof(config_snapshot));
  assert(pbns_attestation_run(aliased_config, &config_value.workspace,
                              &config_value.result) == PBNS_ERR_ARGUMENT);
  assert(memcmp(config_snapshot, aliased_config,
                sizeof(config_snapshot)) == 0);
  assert_no_structural_callbacks(&config_value);
  fixture_destroy(&config_value);

  fixture context_value = {0};
  fixture_init(&context_value);
  context_value.config.context = context_value.workspace.submit_wire.ptr;
  context_value.config.context_region =
      (pbns_view){context_value.workspace.submit_wire.ptr, 1U};
  assert_structural_rejection(&context_value);
  fixture_destroy(&context_value);

  fixture crypto_context_value = {0};
  fixture_init(&crypto_context_value);
  crypto_context_value.challenge_verifier.context =
      crypto_context_value.workspace.submit_wire.ptr;
  crypto_context_value.config.challenge_verifier_context_region =
      (pbns_view){crypto_context_value.workspace.submit_wire.ptr, 1U};
  assert_structural_rejection(&crypto_context_value);
  fixture_destroy(&crypto_context_value);

  fixture broker_storage_value = {0};
  fixture_init(&broker_storage_value);
  const pbns_buffer saved_submit = broker_storage_value.workspace.submit_wire;
  broker_storage_value.workspace.submit_wire = (pbns_buffer){
      broker_storage_value.broker.storage.encoded.ptr, 0U,
      PBNS_ATTESTATION_WIRE_MAX_SIZE};
  assert(pbns_attestation_run(&broker_storage_value.config,
                              &broker_storage_value.workspace,
                              &broker_storage_value.result) ==
         PBNS_ERR_ARGUMENT);
  assert(broker_storage_all_value(&broker_storage_value, UINT8_C(0xa5)));
  assert_no_structural_callbacks(&broker_storage_value);
  broker_storage_value.workspace.submit_wire = saved_submit;
  assert_structural_canaries(&broker_storage_value);
  fixture_destroy(&broker_storage_value);
}

/* Quebra detectada: limpar a arena antes de rejeitar uma tabela crypto nela. */
static void test_crypto_ops_alias_is_rejected_before_callbacks(void) {
  for (size_t crypto_index = 0U; crypto_index < 4U; ++crypto_index) {
    fixture value = {0};
    fixture_init(&value);
    pbns_crypto_ops *aliased =
        (pbns_crypto_ops *)value.workspace.submit_wire.ptr;
    const pbns_crypto_ops *source = crypto_index == 0U
                                        ? value.challenge_verifier.ops
                                        : crypto_index == 1U
                                              ? value.receipt_verifier.ops
                                              : crypto_index == 2U
                                                    ? value.signer.ops
                                                    : value.encrypter.ops;
    *aliased = *source;
    if (crypto_index == 0U) {
      value.challenge_verifier.ops = aliased;
    } else if (crypto_index == 1U) {
      value.receipt_verifier.ops = aliased;
    } else if (crypto_index == 2U) {
      value.signer.ops = aliased;
    } else {
      value.encrypter.ops = aliased;
    }
    uint8_t *snapshot = malloc(value.workspace.submit_wire.cap);
    assert(snapshot != NULL);
    memcpy(snapshot, value.workspace.submit_wire.ptr,
           value.workspace.submit_wire.cap);
    assert(pbns_attestation_run(&value.config, &value.workspace,
                                &value.result) == PBNS_ERR_ARGUMENT);
    assert(memcmp(snapshot, value.workspace.submit_wire.ptr,
                  value.workspace.submit_wire.cap) == 0);
    assert_no_structural_callbacks(&value);
    free(snapshot);
    fixture_destroy(&value);
  }
}

/* Quebras detectadas: tabelas/contextos do broker sobrepostos são usados. */
static void test_broker_ops_and_context_aliases_precede_callbacks(void) {
  for (size_t ops_index = 0U; ops_index < 2U; ++ops_index) {
    fixture value = {0};
    fixture_init(&value);
    if (ops_index == 0U) {
      pbns_transport_ops *aliased =
          (pbns_transport_ops *)value.workspace.submit_wire.ptr;
      *aliased = *value.broker.transport.ops;
      value.broker.transport.ops = aliased;
    } else {
      pbns_broker_platform_ops *aliased =
          (pbns_broker_platform_ops *)value.workspace.submit_wire.ptr;
      *aliased = *value.broker.platform.ops;
      value.broker.platform.ops = aliased;
    }
    uint8_t *snapshot = malloc(value.workspace.submit_wire.cap);
    assert(snapshot != NULL);
    memcpy(snapshot, value.workspace.submit_wire.ptr,
           value.workspace.submit_wire.cap);
    assert(pbns_attestation_run(&value.config, &value.workspace,
                                &value.result) == PBNS_ERR_ARGUMENT);
    assert(memcmp(snapshot, value.workspace.submit_wire.ptr,
                  value.workspace.submit_wire.cap) == 0);
    assert_no_structural_callbacks(&value);
    value.broker.transport.ops = &transport_ops;
    value.broker.platform.ops = &broker_ops;
    free(snapshot);
    fixture_destroy(&value);
  }

  for (size_t context_index = 0U; context_index < 2U; ++context_index) {
    fixture value = {0};
    fixture_init(&value);
    uint8_t *aliased = value.workspace.submit_wire.ptr;
    *aliased = 0x7bU;
    if (context_index == 0U) {
      value.broker.transport.context = aliased;
      value.config.broker_transport_context_region =
          (pbns_view){aliased, 1U};
    } else {
      value.broker.platform.context = aliased;
      value.config.broker_platform_context_region =
          (pbns_view){aliased, 1U};
    }
    uint8_t *snapshot = malloc(value.workspace.submit_wire.cap);
    assert(snapshot != NULL);
    memcpy(snapshot, value.workspace.submit_wire.ptr,
           value.workspace.submit_wire.cap);
    assert(pbns_attestation_run(&value.config, &value.workspace,
                                &value.result) == PBNS_ERR_ARGUMENT);
    assert(memcmp(snapshot, value.workspace.submit_wire.ptr,
                  value.workspace.submit_wire.cap) == 0);
    assert_no_structural_callbacks(&value);
    value.broker.transport.context = &value.transport;
    value.broker.platform.context = &value.transport;
    free(snapshot);
    fixture_destroy(&value);
  }
}

/* Quebra detectada: close do ISSUE mascara erro primário de protocolo. */
static void test_issue_protocol_error_survives_close_failure(void) {
  fixture value = {0};
  fixture_init(&value);
  assert(value.transport.response_size > PBNS_FRAME_V1_HEADER_SIZE + 1U);
  value.transport.response[PBNS_FRAME_V1_HEADER_SIZE + 1U] ^= UINT8_C(0x80);
  value.transport.fail_issue_close = true;
  assert(pbns_attestation_run(&value.config, &value.workspace,
                              &value.result) == PBNS_ERR_CRC);
  assert(value.transport.open_calls == 1U &&
         value.transport.close_calls == 1U &&
         value.transport.cancel_calls == 0U &&
         value.capture_inventory_calls == 0U && value.display_calls == 0U &&
         workspace_all_zero(&value) &&
         all_zero(value.broker.storage.decoded));
  const pbns_attestation_run_result cleared = {0};
  assert(memcmp(&value.result, &cleared, sizeof(cleared)) == 0);
  fixture_destroy(&value);
}

/* Quebra detectada: capturar inventário antes de ligar o KID da implantação. */
static void test_recipient_mismatch_precedes_capture(void) {
  fixture value = {0}; fixture_init(&value);
  value.issue_recipient[0] ^= 1U; prepare_issue_response(&value);
  assert(pbns_attestation_run(&value.config, &value.workspace, &value.result) == PBNS_ERR_AUTHENTICATION);
  assert(value.capture_inventory_calls == 0U && value.transport.open_calls == 1U);
  fixture_destroy(&value);
}

/* Quebra detectada: desafio inválido captura ou aceita uma ligação errada. */
static void test_exact_challenge_failure_matrix(void) {
  typedef struct challenge_case {
    failure_point failure;
    pbns_status expected;
  } challenge_case;
  const challenge_case cases[] = {
      {FAIL_CHALLENGE_MALFORMED, PBNS_ERR_FORMAT},
      {FAIL_CHALLENGE_SIGNATURE, PBNS_ERR_CRYPTO},
      {FAIL_CHALLENGE_EXPIRED, PBNS_ERR_TIMEOUT},
      {FAIL_CHALLENGE_REQUEST_BINDING, PBNS_ERR_AUTHENTICATION},
      {FAIL_CHALLENGE_NONCE_BINDING, PBNS_ERR_AUTHENTICATION},
      {FAIL_CHALLENGE_HOST_BINDING, PBNS_ERR_AUTHENTICATION},
      {FAIL_CHALLENGE_KID_BINDING, PBNS_ERR_AUTHENTICATION}};
  for (size_t index = 0U; index < ARRAY_COUNT(cases); ++index) {
    fixture value = {0};
    fixture_init(&value);
    value.failure = cases[index].failure;
    if (value.failure != FAIL_CHALLENGE_SIGNATURE &&
        value.failure != FAIL_CHALLENGE_EXPIRED) {
      prepare_issue_response(&value);
    }
    assert(pbns_attestation_run(&value.config, &value.workspace,
                                &value.result) == cases[index].expected);
    assert(value.capture_inventory_calls == 0U &&
           value.capture_measured_calls == 0U && value.quote_calls == 0U &&
           value.sign_calls == 0U && value.encrypt_calls == 0U &&
           value.transport.open_calls == 1U &&
           value.transport.close_calls == 1U &&
           value.transport.upload_request_count == 0U &&
           value.transport.cancel_calls == 0U && value.display_calls == 0U);
    assert(workspace_all_zero(&value));
    const pbns_attestation_run_result cleared = {0};
    assert(memcmp(&value.result, &cleared, sizeof(cleared)) == 0);
    fixture_destroy(&value);
  }
}

/* Quebra detectada: uma vista medida fora da arena chega ao parser. */
static void test_measured_event_log_must_be_contained_in_arena(void) {
  const measured_view_mode invalid[] = {
      MEASURED_VIEW_EMPTY, MEASURED_VIEW_BEFORE_ARENA, MEASURED_VIEW_AT_END,
      MEASURED_VIEW_INTEGER_WRAP, MEASURED_VIEW_EXTENDS_PAST_END};
  for (size_t index = 0U; index < ARRAY_COUNT(invalid); ++index) {
    fixture value = {0};
    fixture_init(&value);
    value.measured_view = invalid[index];
    assert(pbns_attestation_run(&value.config, &value.workspace,
                                &value.result) == PBNS_ERR_ARGUMENT);
    assert(value.capture_inventory_calls == 1U &&
           value.capture_measured_calls == 1U && value.quote_calls == 0U &&
           value.sign_calls == 0U && value.encrypt_calls == 0U &&
           value.transport.upload_request_count == 0U &&
           value.transport.cancel_calls == 0U &&
           value.transport.open_calls == 1U &&
           value.transport.close_calls == 1U && value.display_calls == 0U);
    assert(workspace_all_zero(&value));
    assert(value.result.reason_count == 0U && value.result.verdict == 0U);
    fixture_destroy(&value);
  }
  fixture bounded = {0};
  fixture_init(&bounded);
  bounded.measured_view = MEASURED_VIEW_BOUNDED_SUBVIEW;
  assert(pbns_attestation_run(&bounded.config, &bounded.workspace,
                              &bounded.result) == PBNS_OK);
  fixture_destroy(&bounded);
}

/* Quebras detectadas: cada falha pré-upload tem estado e fronteira exactos. */
static void test_exact_pre_upload_failure_matrix(void) {
  typedef struct pre_upload_case {
    failure_point failure;
    pbns_status expected;
    size_t inventory_calls;
    size_t measured_calls;
    size_t quote_calls;
    size_t sign_calls;
    size_t encrypt_calls;
  } pre_upload_case;
  const pre_upload_case cases[] = {
      {FAIL_INVENTORY, PBNS_ERR_IO, 1U, 0U, 0U, 0U, 0U},
      {FAIL_INVENTORY_HOST, PBNS_ERR_AUTHENTICATION, 1U, 1U, 0U, 0U, 0U},
      {FAIL_MEASURED, PBNS_ERR_IO, 1U, 1U, 0U, 0U, 0U},
      {FAIL_MEASURED_MISMATCH, PBNS_ERR_AUTHENTICATION, 1U, 1U, 0U, 0U, 0U},
      {FAIL_QUOTE, PBNS_ERR_CRYPTO, 1U, 1U, 1U, 0U, 0U},
      {FAIL_QUOTE_ZERO, PBNS_ERR_LIMIT, 1U, 1U, 1U, 0U, 0U},
      {FAIL_QUOTE_OVERSIZE, PBNS_ERR_LIMIT, 1U, 1U, 1U, 0U, 0U},
      {FAIL_SIGNATURE_ZERO, PBNS_ERR_LIMIT, 1U, 1U, 1U, 0U, 0U},
      {FAIL_SIGNATURE_OVERSIZE, PBNS_ERR_LIMIT, 1U, 1U, 1U, 0U, 0U},
      {FAIL_SIGN, PBNS_ERR_CRYPTO, 1U, 1U, 1U, 1U, 0U},
      {FAIL_SIGN_ZERO, PBNS_ERR_LIMIT, 1U, 1U, 1U, 1U, 0U},
      {FAIL_SIGN_OVERSIZE, PBNS_ERR_LIMIT, 1U, 1U, 1U, 1U, 0U},
      {FAIL_DIGEST, PBNS_ERR_CRYPTO, 1U, 1U, 1U, 1U, 0U},
      {FAIL_ENCRYPT, PBNS_ERR_CRYPTO, 1U, 1U, 1U, 1U, 1U},
      {FAIL_ENCRYPT_ZERO, PBNS_ERR_LIMIT, 1U, 1U, 1U, 1U, 1U},
      {FAIL_ENCRYPT_OVERSIZE, PBNS_ERR_LIMIT, 1U, 1U, 1U, 1U, 1U}};
  for (size_t index = 0U; index < ARRAY_COUNT(cases); ++index) {
    fixture value = {0};
    fixture_init(&value);
    value.failure = cases[index].failure;
    assert(pbns_attestation_run(&value.config, &value.workspace,
                                &value.result) == cases[index].expected);
    assert(value.capture_inventory_calls == cases[index].inventory_calls &&
           value.capture_measured_calls == cases[index].measured_calls &&
           value.quote_calls == cases[index].quote_calls &&
           value.sign_calls == cases[index].sign_calls &&
           value.encrypt_calls == cases[index].encrypt_calls);
    assert(value.transport.upload_request_count == 0U &&
           value.transport.cancel_calls == 0U &&
           value.transport.open_calls == 1U &&
           value.transport.close_calls == 1U && value.display_calls == 0U);
    assert(workspace_all_zero(&value));
    const pbns_attestation_run_result cleared = {0};
    assert(memcmp(&value.result, &cleared, sizeof(cleared)) == 0);
    fixture_destroy(&value);
  }
}

/* Quebras detectadas: REQUEST antecipado, DATA divergente, finish/display fora de ordem. */
static void test_golden_multirecord_full_and_wipe_before_display(void) {
  fixture value = {0}; fixture_init(&value);
  assert(pbns_attestation_run(&value.config, &value.workspace, &value.result) == PBNS_OK);
  assert(value.transport.upload_request_count == 1U);
  const pbns_message_type expected[] = {
      PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_DATA,
      PBNS_MESSAGE_DATA, PBNS_MESSAGE_COMPLETE};
  assert(value.transport.attempt_count == ARRAY_COUNT(expected));
  assert(memcmp(value.transport.attempts, expected, sizeof(expected)) == 0);
  assert(value.ciphertext_size > PBNS_FRAME_V1_DATA_PAYLOAD_MAX);
  assert(value.uploaded_size == value.ciphertext_size);
  assert(memcmp(value.uploaded, value.ciphertext, value.ciphertext_size) == 0);
  assert(value.transport.cancel_calls == 0U && value.transport.close_calls == 2U);
  assert(value.trusted_time_calls == 1U &&
         value.trusted_time_after_issue_response);
  assert(value.display_calls == 1U && value.display_saw_wipe);
  assert(value.result.verdict == PBNS_ATTESTATION_RECEIPT_FULL &&
         value.result.reason_count == 0U &&
         value.result.display_state == PBNS_ATTESTATION_DISPLAY_FULL);
  const run_event expected_events[] = {
      EVENT_QUOTE, EVENT_SIGN_COMPLETE, EVENT_ENCRYPT_COMPLETE,
      EVENT_SUBMIT_REQUEST, EVENT_DATA, EVENT_DATA, EVENT_COMPLETE,
      EVENT_RECEIPT_VERIFY, EVENT_UPLOAD_FINISH_CLOSE,
      EVENT_CLEANUP_OBSERVED, EVENT_DISPLAY};
  assert(value.event_count == ARRAY_COUNT(expected_events));
  assert(memcmp(value.events, expected_events, sizeof(expected_events)) == 0);
  fixture_destroy(&value);
}

/* Quebra detectada: mapear veredictos autenticados sem a política terminal. */
static void test_reduced_and_failure_mapping(void) {
  fixture reduced = {0}; fixture_init(&reduced);
  reduced.verdict = PBNS_ATTESTATION_RECEIPT_REDUCED;
  assert(pbns_attestation_run(&reduced.config, &reduced.workspace, &reduced.result) == PBNS_OK);
  assert(reduced.result.verdict == PBNS_ATTESTATION_RECEIPT_REDUCED &&
         reduced.result.reason_count == 1U && reduced.result.reasons[0] == 1U &&
         reduced.result.display_state == PBNS_ATTESTATION_DISPLAY_REDUCED &&
         reduced.display_calls == 1U);
  fixture_destroy(&reduced);
  fixture failed = {0}; fixture_init(&failed);
  failed.verdict = PBNS_ATTESTATION_RECEIPT_FAILURE;
  assert(pbns_attestation_run(&failed.config, &failed.workspace, &failed.result) == PBNS_ERR_AUTHENTICATION);
  assert(failed.result.verdict == PBNS_ATTESTATION_RECEIPT_FAILURE &&
         failed.result.reason_count == 1U && failed.result.reasons[0] == 2U &&
         failed.result.display_state == PBNS_ATTESTATION_DISPLAY_FAILURE &&
         failed.display_calls == 1U);
  fixture_destroy(&failed);
}

/* Quebra detectada: erro de display apaga um resultado já autenticado. */
static void test_display_failure_keeps_authenticated_result(void) {
  fixture value = {0};
  fixture_init(&value);
  value.display_status = PBNS_ERR_IO;
  assert(pbns_attestation_run(&value.config, &value.workspace,
                              &value.result) == PBNS_ERR_IO);
  assert(value.result.verdict == PBNS_ATTESTATION_RECEIPT_FULL &&
         value.result.reason_count == 0U &&
         value.result.display_state == PBNS_ATTESTATION_DISPLAY_FULL);
  assert(value.display_calls == 1U && value.display_saw_wipe &&
         value.transport.cancel_calls == 0U &&
         value.transport.close_calls == 2U);
  assert(value.event_count >= 2U &&
         value.events[value.event_count - 2U] == EVENT_CLEANUP_OBSERVED &&
         value.events[value.event_count - 1U] == EVENT_DISPLAY);
  fixture_destroy(&value);
}

/* Quebra detectada: PBNS_ERR_AUTHENTICATION mascara o erro de apresentação de
 * um veredicto FAILURE já autenticado. */
static void test_failure_display_error_has_precedence(void) {
  fixture value = {0};
  fixture_init(&value);
  value.verdict = PBNS_ATTESTATION_RECEIPT_FAILURE;
  value.display_status = PBNS_ERR_IO;
  assert(pbns_attestation_run(&value.config, &value.workspace,
                              &value.result) == PBNS_ERR_IO);
  assert(value.result.verdict == PBNS_ATTESTATION_RECEIPT_FAILURE &&
         value.result.reason_count == 1U && value.result.reasons[0] == 2U &&
         value.result.display_state == PBNS_ATTESTATION_DISPLAY_FAILURE);
  const pbns_message_type successful_prefix[] = {
      PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_DATA,
      PBNS_MESSAGE_DATA, PBNS_MESSAGE_COMPLETE};
  assert(value.transport.attempt_count == ARRAY_COUNT(successful_prefix));
  assert(memcmp(value.transport.attempts, successful_prefix,
                sizeof(successful_prefix)) == 0);
  assert(value.display_calls == 1U && value.display_saw_wipe &&
         value.transport.cancel_calls == 0U &&
         value.transport.close_calls == 2U);
  assert(value.event_count >= 2U &&
         value.events[value.event_count - 2U] == EVENT_CLEANUP_OBSERVED &&
         value.events[value.event_count - 1U] == EVENT_DISPLAY);
  fixture_destroy(&value);
}

/* Quebra detectada: resposta/recibo não autenticado tem prefixo impreciso. */
static void test_exact_post_begin_authentication_failure_matrix(void) {
  typedef struct post_begin_case {
    failure_point failure;
    pbns_status expected;
  } post_begin_case;
  const post_begin_case cases[] = {
      {FAIL_MALFORMED_SUBMIT, PBNS_ERR_FORMAT},
      {FAIL_CORRELATION, PBNS_ERR_AUTHENTICATION},
      {FAIL_EVIDENCE_BINDING, PBNS_ERR_AUTHENTICATION},
      {FAIL_CIPHERTEXT_DIGEST, PBNS_ERR_AUTHENTICATION},
      {FAIL_CONFIGURED_SIGNED_HASH, PBNS_ERR_AUTHENTICATION},
      {FAIL_RECEIPT, PBNS_ERR_AUTHENTICATION},
      {FAIL_RECEIPT_MALFORMED, PBNS_ERR_AUTHENTICATION},
      {FAIL_RECEIPT_UNBOUND, PBNS_ERR_AUTHENTICATION}};
  const pbns_message_type expected_prefix[] = {
      PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_DATA,
      PBNS_MESSAGE_DATA, PBNS_MESSAGE_COMPLETE, PBNS_MESSAGE_CANCEL};
  for (size_t index = 0U; index < ARRAY_COUNT(cases); ++index) {
    fixture value = {0};
    fixture_init(&value);
    value.failure = cases[index].failure;
    assert(pbns_attestation_run(&value.config, &value.workspace,
                                &value.result) == cases[index].expected);
    assert(value.transport.attempt_count == ARRAY_COUNT(expected_prefix));
    assert(memcmp(value.transport.attempts, expected_prefix,
                  sizeof(expected_prefix)) == 0);
    assert(value.transport.cancel_calls == 1U &&
           value.transport.close_calls == 2U &&
           value.transport.upload_request_count == 1U &&
           value.quote_calls == 1U && value.sign_calls == 1U &&
           value.encrypt_calls == 1U && value.display_calls == 0U);
    assert(workspace_all_zero(&value) &&
           all_zero(value.broker.storage.decoded));
    const pbns_attestation_run_result cleared = {0};
    assert(memcmp(&value.result, &cleared, sizeof(cleared)) == 0);
    fixture_destroy(&value);
  }
}

/* Quebras detectadas: selecção/saturação de deadline e erros de callbacks. */
static void test_complete_deadline_matrix(void) {
  fixture early = {0};
  fixture_init(&early);
  early.timeout_at_monotonic_call = 2U;
  assert(pbns_attestation_run(&early.config, &early.workspace,
                              &early.result) == PBNS_ERR_TIMEOUT);
  assert(early.transport.attempt_count == 0U &&
         early.transport.open_calls == 0U &&
         early.transport.cancel_calls == 0U && early.display_calls == 0U);
  fixture_destroy(&early);

  fixture challenge = {0};
  fixture_init(&challenge);
  challenge.challenge_expiry_ns = UINT64_C(1002000000);
  challenge.jump_at_monotonic_call = 4U;
  challenge.jump_to_ms = 102U;
  prepare_issue_response(&challenge);
  assert(pbns_attestation_run(&challenge.config, &challenge.workspace,
                              &challenge.result) == PBNS_ERR_TIMEOUT);
  assert(challenge.transport.attempt_count == 1U &&
         challenge.transport.attempts[0] == PBNS_MESSAGE_REQUEST &&
         challenge.capture_inventory_calls == 0U &&
         challenge.transport.cancel_calls == 0U &&
         challenge.transport.close_calls == 1U);
  fixture_destroy(&challenge);

  fixture saturated = {0};
  fixture_init(&saturated);
  saturated.now_ms = UINT64_MAX - UINT64_C(50);
  saturated.config.timeout_ms = UINT64_C(100);
  assert(pbns_attestation_run(&saturated.config, &saturated.workspace,
                              &saturated.result) == PBNS_OK);
  assert(saturated.display_calls == 1U &&
         saturated.transport.cancel_calls == 0U);
  fixture_destroy(&saturated);

  fixture clock_error = {0};
  fixture_init(&clock_error);
  clock_error.monotonic_status = PBNS_ERR_IO;
  assert(pbns_attestation_run(&clock_error.config, &clock_error.workspace,
                              &clock_error.result) == PBNS_ERR_IO);
  assert(clock_error.monotonic_calls == 1U &&
         clock_error.cancel_checks == 0U &&
         clock_error.transport.attempt_count == 0U);
  fixture_destroy(&clock_error);

  fixture cancel_error = {0};
  fixture_init(&cancel_error);
  cancel_error.cancellation_status = PBNS_ERR_IO;
  assert(pbns_attestation_run(&cancel_error.config, &cancel_error.workspace,
                              &cancel_error.result) == PBNS_ERR_IO);
  assert(cancel_error.cancel_checks == 1U &&
         cancel_error.transport.attempt_count == 0U &&
         cancel_error.transport.cancel_calls == 0U);
  fixture_destroy(&cancel_error);

  const pbns_message_type late_prefix[] = {
      PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_DATA,
      PBNS_MESSAGE_CANCEL};
  fixture late = {0};
  fixture_init(&late);
  late.timeout_at_monotonic_call = 9U;
  assert(pbns_attestation_run(&late.config, &late.workspace,
                              &late.result) == PBNS_ERR_TIMEOUT);
  assert(late.transport.attempt_count == ARRAY_COUNT(late_prefix));
  assert(memcmp(late.transport.attempts, late_prefix,
                sizeof(late_prefix)) == 0);
  assert(late.transport.cancel_calls == 1U &&
         late.transport.close_calls == 2U && late.display_calls == 0U);
  fixture_destroy(&late);
}

/* Quebras detectadas: cancel antes/depois do begin e finish são imprecisos. */
static void test_complete_cancellation_and_finish_matrix(void) {
  fixture before_upload = {0};
  fixture_init(&before_upload);
  before_upload.cancel_at = 7U;
  assert(pbns_attestation_run(&before_upload.config,
                              &before_upload.workspace,
                              &before_upload.result) == PBNS_ERR_STATE);
  assert(before_upload.transport.attempt_count == 1U &&
         before_upload.transport.attempts[0] == PBNS_MESSAGE_REQUEST &&
         before_upload.transport.upload_request_count == 0U &&
         before_upload.transport.cancel_calls == 0U &&
         before_upload.transport.close_calls == 1U);
  fixture_destroy(&before_upload);

  const pbns_message_type late_prefix[] = {
      PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_DATA,
      PBNS_MESSAGE_CANCEL};
  fixture late = {0};
  fixture_init(&late);
  late.cancel_at = 8U;
  assert(pbns_attestation_run(&late.config, &late.workspace,
                              &late.result) == PBNS_ERR_STATE);
  assert(late.transport.attempt_count == ARRAY_COUNT(late_prefix));
  assert(memcmp(late.transport.attempts, late_prefix,
                sizeof(late_prefix)) == 0);
  assert(late.transport.cancel_calls == 1U &&
         late.transport.close_calls == 2U && late.display_calls == 0U);
  fixture_destroy(&late);

  fixture callback_error = {0};
  fixture_init(&callback_error);
  callback_error.cancellation_status = PBNS_ERR_IO;
  callback_error.cancellation_error_at = 8U;
  assert(pbns_attestation_run(&callback_error.config,
                              &callback_error.workspace,
                              &callback_error.result) == PBNS_ERR_IO);
  assert(callback_error.transport.attempt_count ==
         ARRAY_COUNT(late_prefix));
  assert(memcmp(callback_error.transport.attempts, late_prefix,
                sizeof(late_prefix)) == 0);
  assert(callback_error.transport.cancel_calls == 1U &&
         callback_error.transport.close_calls == 2U);
  fixture_destroy(&callback_error);

  fixture closed = {0};
  fixture_init(&closed);
  closed.transport.fail_upload_close = true;
  assert(pbns_attestation_run(&closed.config, &closed.workspace,
                              &closed.result) == PBNS_ERR_TRANSPORT);
  const pbns_message_type success_prefix[] = {
      PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_DATA,
      PBNS_MESSAGE_DATA, PBNS_MESSAGE_COMPLETE};
  assert(closed.transport.attempt_count == ARRAY_COUNT(success_prefix));
  assert(memcmp(closed.transport.attempts, success_prefix,
                sizeof(success_prefix)) == 0);
  assert(closed.transport.cancel_calls == 0U &&
         closed.transport.close_calls == 2U && closed.display_calls == 0U &&
         !closed.broker.active && !closed.broker.opened &&
         all_zero(closed.broker.storage.decoded) &&
         workspace_all_zero(&closed));
  const pbns_attestation_run_result cleared = {0};
  assert(memcmp(&closed.result, &cleared, sizeof(cleared)) == 0);
  fixture_destroy(&closed);
}

int main(void) {
  test_complete_structural_matrix();
  test_all_workspace_descriptor_shapes();
  test_every_workspace_predecessor_alias();
  test_each_workspace_aliases_result_config_and_run_context();
  test_every_view_aliases_each_workspace_class();
  test_crypto_descriptors_and_contexts_alias_each_workspace_class();
  test_every_broker_storage_aliases_each_workspace_class();
  test_mandatory_contexts_are_nonnull();
  test_context_regions_require_exact_start();
  test_complete_descriptor_alias_matrix();
  test_crypto_ops_alias_is_rejected_before_callbacks();
  test_broker_ops_and_context_aliases_precede_callbacks();
  test_issue_protocol_error_survives_close_failure();
  test_recipient_mismatch_precedes_capture();
  test_exact_challenge_failure_matrix();
  test_measured_event_log_must_be_contained_in_arena();
  test_exact_pre_upload_failure_matrix();
  test_golden_multirecord_full_and_wipe_before_display();
  test_reduced_and_failure_mapping();
  test_display_failure_keeps_authenticated_result();
  test_failure_display_error_has_precedence();
  test_exact_post_begin_authentication_failure_matrix();
  test_complete_deadline_matrix();
  test_complete_cancellation_and_finish_matrix();
  puts("attestation run tests passed");
  return EXIT_SUCCESS;
}
