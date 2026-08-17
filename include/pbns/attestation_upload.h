#ifndef PBNS_ATTESTATION_UPLOAD_H
#define PBNS_ATTESTATION_UPLOAD_H

#include <stdbool.h>
#include <stdint.h>

#include "pbns/attestation.h"
#include "pbns/broker.h"

typedef struct pbns_attestation_upload {
  pbns_broker *broker;
  pbns_request_id request_id;
  pbns_view encoded_request;
  /* Borrowed from broker decoded storage through response decode/authentication;
   * invalidated by finish, cancel, broker reset, or the next broker operation. */
  pbns_view response_payload;
  uint32_t timeout_ms;
  uint32_t next_sequence;
  bool started;
  bool response_received;
  /* Terminal after finish is attempted, including a local close failure. */
  bool finished;
  bool cancelled;
} pbns_attestation_upload;

pbns_status pbns_attestation_upload_send(
    void *context, const pbns_request_id *request_id, uint32_t sequence,
    pbns_view payload, bool final_record);
pbns_status pbns_attestation_upload_finish(pbns_attestation_upload *upload);
pbns_status pbns_attestation_upload_cancel(pbns_attestation_upload *upload);
void pbns_attestation_upload_reset(pbns_attestation_upload *upload);

#endif
