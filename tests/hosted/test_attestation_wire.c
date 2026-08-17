#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pbns/attestation_wire.h"
#include "qcbor/qcbor_encode.h"

static void fill(uint8_t *bytes, size_t length, uint8_t value) {
  memset(bytes, value, length);
}

static size_t encode_response(const pbns_attestation_wire_response *response,
                              uint8_t *output, size_t capacity) {
  QCBOREncodeContext encoder = {0};
  UsefulBufC encoded = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output, capacity});
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
  assert(QCBOREncode_Finish(&encoder, &encoded) == QCBOR_SUCCESS);
  return encoded.len;
}

static void test_issue_request_and_response_bindings(void) {
  uint8_t host[32] = {0};
  uint8_t request_id[16] = {0};
  uint8_t nonce[32] = {0};
  uint8_t encoded[1024] = {0};
  uint8_t canonical[1024] = {0};
  static const uint8_t kid[] = "attestation-recipient-1";
  static const uint8_t object[] = {0xd2U, 0x84U, 0x40U, 0xa0U, 0x41U, 0x01U,
                                   0x58U, 0x40U};
  fill(host, sizeof(host), 0x11U);
  fill(request_id, sizeof(request_id), 0x22U);
  fill(nonce, sizeof(nonce), 0x33U);

  size_t written = 0U;
  assert(pbns_attestation_wire_encode_issue_request(
             host, (pbns_buffer){encoded, 0U, sizeof(encoded)}, &written) ==
         PBNS_OK);
  assert(written == 56U);
  assert(encoded[0] == 0xa3U && encoded[1] == 0x01U && encoded[2] == 0x01U);

  const pbns_attestation_wire_response response = {
      .operation = PBNS_ATTESTATION_WIRE_ISSUE,
      .challenge_request_id = {.bytes = {0}},
      .verifier_nonce = {0},
      .recipient_kid = {kid, sizeof(kid) - 1U},
      .object = {object, sizeof(object)},
  };
  pbns_attestation_wire_response mutable_response = response;
  memcpy(mutable_response.challenge_request_id.bytes, request_id,
         sizeof(request_id));
  memcpy(mutable_response.verifier_nonce, nonce, sizeof(nonce));
  written = encode_response(&mutable_response, encoded, sizeof(encoded));
  pbns_attestation_wire_response decoded = {0};
  assert(pbns_attestation_wire_decode_issue_response(
             (pbns_view){encoded, written},
             (pbns_buffer){canonical, 0U, sizeof(canonical)}, &decoded) ==
         PBNS_OK);
  assert(memcmp(decoded.challenge_request_id.bytes, request_id,
                sizeof(request_id)) == 0);
  assert(memcmp(decoded.verifier_nonce, nonce, sizeof(nonce)) == 0);
  assert(decoded.recipient_kid.len == sizeof(kid) - 1U);

  encoded[2] = 0x02U;
  assert(pbns_attestation_wire_decode_issue_response(
             (pbns_view){encoded, written},
             (pbns_buffer){canonical, 0U, sizeof(canonical)}, &decoded) !=
         PBNS_OK);
}

static void test_submit_response_rejects_wrong_request_and_malformed(void) {
  uint8_t request_id[16] = {0};
  uint8_t wrong_id[16] = {0};
  uint8_t evidence[32] = {0};
  uint8_t baseline[32] = {0};
  uint8_t encoded[1024] = {0};
  uint8_t canonical[1024] = {0};
  static const uint8_t receipt[] = {0xd2U, 0x84U, 0x40U, 0xa0U, 0x41U, 0x01U,
                                    0x58U, 0x40U};
  fill(request_id, sizeof(request_id), 0x44U);
  fill(wrong_id, sizeof(wrong_id), 0x45U);
  fill(evidence, sizeof(evidence), 0x55U);
  fill(baseline, sizeof(baseline), 0x66U);
  pbns_attestation_wire_response response = {
      .operation = PBNS_ATTESTATION_WIRE_SUBMIT,
      .object = {receipt, sizeof(receipt)},
  };
  memcpy(response.challenge_request_id.bytes, request_id, sizeof(request_id));
  memcpy(response.evidence_digest, evidence, sizeof(evidence));
  memcpy(response.baseline_id, baseline, sizeof(baseline));
  size_t written = encode_response(&response, encoded, sizeof(encoded));
  pbns_attestation_wire_response decoded = {0};
  assert(pbns_attestation_wire_decode_submit_response(
             (pbns_view){encoded, written},
             (pbns_view){request_id, sizeof(request_id)},
             (pbns_buffer){canonical, 0U, sizeof(canonical)}, &decoded) ==
         PBNS_OK);
  assert(pbns_attestation_wire_decode_submit_response(
             (pbns_view){encoded, written},
             (pbns_view){wrong_id, sizeof(wrong_id)},
             (pbns_buffer){canonical, 0U, sizeof(canonical)}, &decoded) ==
         PBNS_ERR_AUTHENTICATION);
  encoded[0] = 0xa6U;
  assert(pbns_attestation_wire_decode_submit_response(
             (pbns_view){encoded, written},
             (pbns_view){request_id, sizeof(request_id)},
             (pbns_buffer){canonical, 0U, sizeof(canonical)}, &decoded) ==
         PBNS_ERR_FORMAT);
}

static void test_submit_request_has_service_operation_and_exact_id(void) {
  uint8_t request_id[16] = {0};
  uint8_t encoded[128] = {0};
  fill(request_id, sizeof(request_id), 0x77U);
  size_t written = 0U;
  assert(pbns_attestation_wire_encode_submit_request(
             (pbns_view){request_id, sizeof(request_id)},
             (pbns_buffer){encoded, 0U, sizeof(encoded)}, &written) == PBNS_OK);
  assert(written == 56U);
  assert(encoded[0] == 0xa3U && encoded[1] == 0x01U && encoded[2] == 0x02U);
  assert(pbns_attestation_wire_encode_submit_request(
             (pbns_view){request_id, sizeof(request_id) - 1U},
             (pbns_buffer){encoded, 0U, sizeof(encoded)}, &written) ==
         PBNS_ERR_ARGUMENT);
}

int main(void) {
  test_issue_request_and_response_bindings();
  test_submit_response_rejects_wrong_request_and_malformed();
  test_submit_request_has_service_operation_and_exact_id();
  puts("attestation wire tests passed");
  return 0;
}
