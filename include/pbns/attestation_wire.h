#ifndef PBNS_ATTESTATION_WIRE_H
#define PBNS_ATTESTATION_WIRE_H

#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/frame.h"
#include "pbns/status.h"

#define PBNS_ATTESTATION_WIRE_ISSUE UINT64_C(1)
#define PBNS_ATTESTATION_WIRE_SUBMIT UINT64_C(2)
#define PBNS_ATTESTATION_WIRE_MAX_SIZE 16384U

typedef struct pbns_attestation_wire_response {
  uint64_t operation;
  pbns_request_id challenge_request_id;
  uint8_t verifier_nonce[32];
  pbns_view recipient_kid;
  pbns_view object;
  uint8_t evidence_digest[32];
  uint8_t baseline_id[32];
} pbns_attestation_wire_response;

pbns_status pbns_attestation_wire_encode_issue_request(
    const uint8_t host_fingerprint[32], pbns_buffer output, size_t *written);
pbns_status pbns_attestation_wire_encode_submit_request(
    pbns_view challenge_request_id, pbns_buffer output, size_t *written);
pbns_status pbns_attestation_wire_decode_issue_response(
    pbns_view encoded, pbns_buffer canonical,
    pbns_attestation_wire_response *response);
pbns_status pbns_attestation_wire_decode_submit_response(
    pbns_view encoded, pbns_view expected_challenge_request_id,
    pbns_buffer canonical, pbns_attestation_wire_response *response);

#endif
