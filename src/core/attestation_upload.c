#include "pbns/attestation_upload.h"

#include <stddef.h>
#include <string.h>

static bool same_request(const pbns_request_id *left,
                         const pbns_request_id *right) {
  return left != NULL && right != NULL &&
         memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

static pbns_status abort_upload(pbns_attestation_upload *upload,
                                pbns_status primary) {
  if (upload != NULL && upload->started && !upload->finished &&
      !upload->cancelled) {
    upload->cancelled = true;
    upload->response_payload = (pbns_view){0};
    (void)pbns_broker_cancel(upload->broker);
  }
  return primary;
}

pbns_status pbns_attestation_upload_send(
    void *context, const pbns_request_id *request_id, uint32_t sequence,
    pbns_view payload, bool final_record) {
  pbns_attestation_upload *upload = context;
  if (upload == NULL || upload->broker == NULL || request_id == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (upload->finished || upload->cancelled || upload->response_received ||
      sequence != upload->next_sequence ||
      !same_request(request_id, &upload->request_id)) {
    return abort_upload(upload, PBNS_ERR_STATE);
  }
  if (upload->next_sequence == UINT32_MAX) {
    return abort_upload(upload, PBNS_ERR_LIMIT);
  }
  if (!upload->started) {
    const pbns_status begin = pbns_broker_upload_begin(
        upload->broker, PBNS_SERVICE_PLATFORM_ATTESTATION, request_id,
        upload->encoded_request, upload->timeout_ms);
    if (begin != PBNS_OK) {
      return begin;
    }
    upload->started = true;
  }
  pbns_broker_response response = {0};
  const pbns_status status = pbns_broker_upload_send(
      upload->broker, payload, final_record, &response);
  if (status != PBNS_OK) {
    return abort_upload(upload, status);
  }
  if (!final_record) {
    ++upload->next_sequence;
    return PBNS_OK;
  }
  if (response.frame.service != PBNS_SERVICE_PLATFORM_ATTESTATION ||
      response.frame.type != PBNS_MESSAGE_RESPONSE ||
      response.frame.sequence != 0U ||
      !same_request(&response.frame.request_id, request_id) ||
      response.payload.len == 0U) {
    return abort_upload(upload, PBNS_ERR_FORMAT);
  }
  /* Borrowed from broker decoded storage. It remains valid until finish,
   * cancel, broker reset, or the next broker operation. */
  upload->response_payload = response.payload;
  upload->response_received = true;
  return PBNS_OK;
}

pbns_status pbns_attestation_upload_finish(pbns_attestation_upload *upload) {
  if (upload == NULL || upload->broker == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!upload->started || !upload->response_received || upload->finished ||
      upload->cancelled) {
    return PBNS_ERR_STATE;
  }
  const pbns_status status = pbns_broker_upload_finish(upload->broker);
  upload->response_payload = (pbns_view){0};
  upload->finished = true;
  return status;
}

pbns_status pbns_attestation_upload_cancel(pbns_attestation_upload *upload) {
  if (upload == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!upload->started || upload->finished || upload->cancelled) {
    return PBNS_OK;
  }
  upload->cancelled = true;
  return pbns_broker_cancel(upload->broker);
}

void pbns_attestation_upload_reset(pbns_attestation_upload *upload) {
  if (upload != NULL) {
    memset(upload, 0, sizeof(*upload));
  }
}
