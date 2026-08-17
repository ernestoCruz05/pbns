#include "pbns/attestation_run.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PBNS_RUN_BUFFER_COUNT 18U
#define PBNS_NS_PER_MS UINT64_C(1000000)

typedef struct run_consume_context {
  const pbns_request_id *request_id;
  const uint8_t *nonce;
  bool consumed;
} run_consume_context;

typedef struct run_send_context {
  const pbns_attestation_run_config *config;
  pbns_attestation_upload *upload;
  uint64_t deadline_ms;
} run_send_context;

static bool view_valid(pbns_view view) {
  return view.ptr != NULL || view.len == 0U;
}

static bool buffer_valid(pbns_buffer buffer) {
  return buffer.len == 0U && (buffer.ptr != NULL || buffer.cap == 0U);
}

static pbns_view buffer_view(pbns_buffer buffer) {
  return (pbns_view){buffer.ptr, buffer.cap};
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

static bool view_contained_in_buffer(pbns_view view, pbns_buffer buffer) {
  if (view.ptr == NULL || view.len == 0U || buffer.ptr == NULL ||
      buffer.cap == 0U) {
    return false;
  }
  const uintptr_t view_start = (uintptr_t)view.ptr;
  const uintptr_t buffer_start = (uintptr_t)buffer.ptr;
  if (view_start < buffer_start || view.len > UINTPTR_MAX - view_start ||
      buffer.cap > UINTPTR_MAX - buffer_start) {
    return false;
  }
  return view_start + view.len <= buffer_start + buffer.cap;
}

static bool nonzero(const uint8_t *bytes, size_t length) {
  uint8_t combined = 0U;
  for (size_t index = 0U; index < length; ++index) {
    combined |= bytes[index];
  }
  return combined != 0U;
}

static bool constant_equal(const uint8_t *left, const uint8_t *right,
                           size_t length) {
  uint8_t difference = 0U;
  for (size_t index = 0U; index < length; ++index) {
    difference |= (uint8_t)(left[index] ^ right[index]);
  }
  return difference == 0U;
}

static void wipe_bytes(void *storage, size_t length) {
  if (storage == NULL) {
    return;
  }
  volatile uint8_t *bytes = storage;
  for (size_t index = 0U; index < length; ++index) {
    bytes[index] = 0U;
  }
}

static void wipe_buffer(pbns_buffer buffer) {
  wipe_bytes(buffer.ptr, buffer.cap);
}

static void copy_bytes(uint8_t *destination, const uint8_t *source,
                       size_t length) {
  for (size_t index = 0U; index < length; ++index) {
    destination[index] = source[index];
  }
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

static bool kid_valid(pbns_view kid) {
  return view_valid(kid) && kid.len > 0U &&
         kid.len <= PBNS_ATTESTATION_RUN_KID_MAX_SIZE;
}

static bool clean_template(const pbns_attestation_submission *submission) {
  return submission->inventory_report == NULL &&
         submission->measured_boot == NULL && submission->ak_name.ptr == NULL &&
         submission->ak_name.len == 0U &&
         submission->ak_reference.ptr == NULL &&
         submission->ak_reference.len == 0U && submission->consume == NULL &&
         submission->send_data == NULL && submission->consume_context == NULL &&
         submission->send_context == NULL &&
         submission->consume_context_region.ptr == NULL &&
         submission->consume_context_region.len == 0U &&
         submission->send_context_region.ptr == NULL &&
         submission->send_context_region.len == 0U &&
         submission->evidence_digest.ptr == NULL &&
         submission->evidence_digest.len == 0U &&
         submission->evidence_digest.cap == 0U;
}

static bool crypto_valid(const pbns_crypto *crypto, pbns_view region,
                         bool profile) {
  return crypto != NULL && crypto->ops != NULL && crypto->context != NULL &&
         (profile ? crypto->ops->sign1_verify_profile != NULL
                  : crypto->ops->sign1_verify != NULL) &&
         context_region_valid(crypto->context, region);
}

static bool broker_valid(const pbns_attestation_run_config *config) {
  const pbns_broker *broker = config->broker;
  return broker != NULL && broker->initialized && !broker->active &&
         !broker->opened && broker->transport.ops != NULL &&
         broker->transport.ops->open != NULL &&
         broker->transport.ops->close != NULL &&
         broker->transport.ops->send != NULL &&
         broker->transport.ops->receive != NULL &&
         broker->transport.ops->cancel != NULL &&
         broker->transport.ops->limits != NULL &&
         broker->platform.ops != NULL && broker->platform.ops->random != NULL &&
         broker->platform.ops->monotonic_ms != NULL &&
         broker->transport.context != NULL && broker->platform.context != NULL &&
         context_region_valid(broker->transport.context,
                              config->broker_transport_context_region) &&
         context_region_valid(broker->platform.context,
                              config->broker_platform_context_region);
}

static void collect_buffers(const pbns_attestation_run_workspace *workspace,
                            pbns_buffer buffers[PBNS_RUN_BUFFER_COUNT]) {
  buffers[0] = workspace->issue_wire;
  buffers[1] = workspace->issue_canonical;
  buffers[2] = workspace->submit_wire;
  buffers[3] = workspace->submit_canonical;
  buffers[4] = workspace->challenge.canonical;
  buffers[5] = workspace->challenge.aad;
  buffers[6] = workspace->inventory_variable_scratch;
  buffers[7] = workspace->event_log_arena;
  buffers[8] = workspace->attestation.inventory;
  buffers[9] = workspace->attestation.selection;
  buffers[10] = workspace->attestation.quote;
  buffers[11] = workspace->attestation.quote_signature;
  buffers[12] = workspace->attestation.evidence;
  buffers[13] = workspace->attestation.signed_evidence;
  buffers[14] = workspace->attestation.ciphertext;
  buffers[15] = workspace->attestation.aad;
  buffers[16] = workspace->receipt.canonical_payload;
  buffers[17] = workspace->receipt.canonical_cose;
}

static bool capacities_valid(
    const pbns_attestation_run_workspace *workspace) {
  const pbns_buffer exact[] = {
      workspace->issue_wire,
      workspace->issue_canonical,
      workspace->submit_wire,
      workspace->submit_canonical,
      workspace->challenge.canonical,
      workspace->challenge.aad,
      workspace->inventory_variable_scratch,
      workspace->event_log_arena,
      workspace->attestation.inventory,
      workspace->attestation.selection,
      workspace->attestation.quote,
      workspace->attestation.quote_signature,
      workspace->attestation.evidence,
      workspace->attestation.signed_evidence,
      workspace->attestation.ciphertext,
      workspace->attestation.aad,
      workspace->receipt.canonical_payload,
      workspace->receipt.canonical_cose,
      workspace->receipt.aad,
      workspace->evidence_digest,
  };
  const size_t capacities[] = {
      PBNS_ATTESTATION_WIRE_MAX_SIZE,
      PBNS_ATTESTATION_WIRE_MAX_SIZE,
      PBNS_ATTESTATION_WIRE_MAX_SIZE,
      PBNS_ATTESTATION_WIRE_MAX_SIZE,
      PBNS_ATTESTATION_CHALLENGE_MAX_SIZE,
      PBNS_ATTESTATION_AAD_MAX_SIZE,
      PBNS_INVENTORY_VARIABLE_MAX_SIZE,
      PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE,
      PBNS_INVENTORY_ENCODED_MAX_SIZE,
      PBNS_ATTESTATION_SELECTION_WORKSPACE_SIZE,
      PBNS_ATTESTATION_QUOTE_MAX_SIZE,
      PBNS_ATTESTATION_QUOTE_SIGNATURE_MAX_SIZE,
      PBNS_ATTESTATION_EVIDENCE_MAX_SIZE,
      PBNS_ATTESTATION_SIGNED_MAX_SIZE,
      PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE,
      PBNS_ATTESTATION_AAD_MAX_SIZE,
      PBNS_ATTESTATION_RECEIPT_MAX_PAYLOAD_SIZE,
      PBNS_ATTESTATION_RECEIPT_MAX_SIGNED_SIZE,
      PBNS_ATTESTATION_RECEIPT_MAX_AAD_SIZE,
      PBNS_ATTESTATION_DIGEST_SIZE,
  };
  for (size_t index = 0U; index < sizeof(exact) / sizeof(exact[0]); ++index) {
    if (!buffer_valid(exact[index]) || exact[index].cap != capacities[index]) {
      return false;
    }
  }
  return true;
}

static bool workspace_layout_valid(
    const pbns_attestation_run_config *config,
    const pbns_attestation_run_workspace *workspace,
    const pbns_attestation_run_result *result) {
  pbns_buffer buffers[PBNS_RUN_BUFFER_COUNT] = {0};
  collect_buffers(workspace, buffers);
  const pbns_buffer extra[] = {workspace->receipt.aad,
                               workspace->evidence_digest};
  const pbns_view inputs[] = {
      {(const uint8_t *)config, sizeof(*config)},
      {(const uint8_t *)workspace, sizeof(*workspace)},
      {(const uint8_t *)result, sizeof(*result)},
      {(const uint8_t *)config->broker, sizeof(*config->broker)},
      {(const uint8_t *)config->broker->transport.ops,
       sizeof(*config->broker->transport.ops)},
      {(const uint8_t *)config->broker->platform.ops,
       sizeof(*config->broker->platform.ops)},
      config->broker_transport_context_region,
      config->broker_platform_context_region,
      config->recipient_kid,
      config->challenge_kid,
      config->receipt_kid,
      config->ak_name,
      config->ak_reference,
      {(const uint8_t *)config->challenge_verifier,
       sizeof(*config->challenge_verifier)},
      {(const uint8_t *)config->receipt_verifier,
       sizeof(*config->receipt_verifier)},
      {(const uint8_t *)config->challenge_verifier->ops,
       sizeof(*config->challenge_verifier->ops)},
      {(const uint8_t *)config->receipt_verifier->ops,
       sizeof(*config->receipt_verifier->ops)},
      {(const uint8_t *)config->submission_template.host_signer,
       sizeof(*config->submission_template.host_signer)},
      {(const uint8_t *)config->submission_template.host_signer->ops,
       sizeof(*config->submission_template.host_signer->ops)},
      {(const uint8_t *)config->submission_template.recipient_encrypter,
       sizeof(*config->submission_template.recipient_encrypter)},
      {(const uint8_t *)config->submission_template.recipient_encrypter->ops,
       sizeof(*config->submission_template.recipient_encrypter->ops)},
      config->challenge_verifier_context_region,
      config->receipt_verifier_context_region,
      config->context_region,
      config->submission_template.host_signer_context_region,
      config->submission_template.recipient_encrypter_context_region,
      config->submission_template.sha256_context_region,
      config->submission_template.quote_context_region,
      buffer_view(config->broker->storage.encoded),
      buffer_view(config->broker->storage.raw_scratch),
      buffer_view(config->broker->storage.receive),
      buffer_view(config->broker->storage.decoded),
  };
  const pbns_view result_range = {(const uint8_t *)result, sizeof(*result)};
  for (size_t input = 0U; input < sizeof(inputs) / sizeof(inputs[0]); ++input) {
    if (input != 2U && ranges_overlap(result_range, inputs[input])) {
      return false;
    }
  }
  for (size_t index = 0U; index < PBNS_RUN_BUFFER_COUNT; ++index) {
    if (ranges_overlap(result_range, buffer_view(buffers[index]))) {
      return false;
    }
    for (size_t other = 0U; other < index; ++other) {
      if (ranges_overlap(buffer_view(buffers[index]),
                         buffer_view(buffers[other]))) {
        return false;
      }
    }
    for (size_t input = 0U; input < sizeof(inputs) / sizeof(inputs[0]);
         ++input) {
      if (ranges_overlap(buffer_view(buffers[index]), inputs[input])) {
        return false;
      }
    }
    for (size_t other = 0U; other < sizeof(extra) / sizeof(extra[0]); ++other) {
      if (ranges_overlap(buffer_view(buffers[index]),
                         buffer_view(extra[other]))) {
        return false;
      }
    }
  }
  if (ranges_overlap(buffer_view(extra[0]), buffer_view(extra[1])) ||
      ranges_overlap(result_range, buffer_view(extra[0])) ||
      ranges_overlap(result_range, buffer_view(extra[1]))) {
    return false;
  }
  for (size_t index = 0U; index < sizeof(extra) / sizeof(extra[0]); ++index) {
    for (size_t input = 0U; input < sizeof(inputs) / sizeof(inputs[0]);
         ++input) {
      if (ranges_overlap(buffer_view(extra[index]), inputs[input])) {
        return false;
      }
    }
  }
  return true;
}

static bool config_valid(const pbns_attestation_run_config *config) {
  if (!broker_valid(config) ||
      config->identity_assurance != PBNS_IDENTITY_TPM_UNVERIFIED_EK ||
      !nonzero(config->host_fingerprint, sizeof(config->host_fingerprint)) ||
      !kid_valid(config->recipient_kid) || !kid_valid(config->challenge_kid) ||
      !kid_valid(config->receipt_kid) || !view_valid(config->ak_name) ||
      config->ak_name.len == 0U ||
      config->ak_name.len > PBNS_ATTESTATION_AK_NAME_MAX_SIZE ||
      !view_valid(config->ak_reference) || config->ak_reference.len == 0U ||
      config->ak_reference.len > PBNS_ATTESTATION_AK_REFERENCE_MAX_SIZE ||
      !crypto_valid(config->challenge_verifier,
                    config->challenge_verifier_context_region, true) ||
      !crypto_valid(config->receipt_verifier,
                    config->receipt_verifier_context_region, false) ||
      config->submission_template.host_signer == NULL ||
      config->submission_template.host_signer->ops == NULL ||
      config->submission_template.host_signer->context == NULL ||
      config->submission_template.host_signer->ops->sign1_sign == NULL ||
      config->submission_template.recipient_encrypter == NULL ||
      config->submission_template.recipient_encrypter->ops == NULL ||
      config->submission_template.recipient_encrypter->context == NULL ||
      config->submission_template.recipient_encrypter->ops
              ->encrypt_for_recipient == NULL ||
      config->submission_template.sha256 == NULL ||
      config->submission_template.sha256_context == NULL ||
      config->submission_template.quote == NULL ||
      config->submission_template.quote_context == NULL ||
      !context_region_valid(
          config->submission_template.host_signer->context,
          config->submission_template.host_signer_context_region) ||
      !context_region_valid(
          config->submission_template.recipient_encrypter->context,
          config->submission_template.recipient_encrypter_context_region) ||
      !context_region_valid(config->submission_template.sha256_context,
                            config->submission_template.sha256_context_region) ||
      !context_region_valid(config->submission_template.quote_context,
                            config->submission_template.quote_context_region) ||
      !clean_template(&config->submission_template) ||
      config->ops.trusted_time == NULL || config->ops.monotonic_ms == NULL ||
      config->ops.cancel_requested == NULL ||
      config->ops.capture_inventory == NULL ||
      config->ops.capture_measured == NULL ||
      config->ops.display_authenticated == NULL || config->context == NULL ||
      !context_region_valid(config->context, config->context_region) ||
      config->timeout_ms == 0U) {
    return false;
  }
  return true;
}

static bool arguments_valid(const pbns_attestation_run_config *config,
                            const pbns_attestation_run_workspace *workspace,
                            const pbns_attestation_run_result *result) {
  return config != NULL && workspace != NULL && result != NULL &&
         config_valid(config) && capacities_valid(workspace) &&
         workspace_layout_valid(config, workspace, result);
}

static void wipe_workspace(pbns_attestation_run_workspace *workspace) {
  pbns_buffer buffers[PBNS_RUN_BUFFER_COUNT] = {0};
  collect_buffers(workspace, buffers);
  for (size_t index = 0U; index < PBNS_RUN_BUFFER_COUNT; ++index) {
    wipe_buffer(buffers[index]);
  }
  wipe_buffer(workspace->receipt.aad);
  wipe_buffer(workspace->evidence_digest);
}

static uint64_t saturating_add(uint64_t left, uint64_t right) {
  return right > UINT64_MAX - left ? UINT64_MAX : left + right;
}

static pbns_status remaining_ms(const pbns_attestation_run_config *config,
                                uint64_t deadline_ms, uint32_t *remaining) {
  uint64_t now = 0U;
  pbns_status status = config->ops.monotonic_ms(config->context, &now);
  if (status != PBNS_OK) {
    return status;
  }
  if (now >= deadline_ms) {
    return PBNS_ERR_TIMEOUT;
  }
  const uint64_t amount = deadline_ms - now;
  *remaining = amount > (uint64_t)UINT32_MAX ? UINT32_MAX : (uint32_t)amount;
  return PBNS_OK;
}

static pbns_status gate(const pbns_attestation_run_config *config,
                        uint64_t deadline_ms, uint32_t *remaining) {
  bool cancelled = false;
  pbns_status status =
      config->ops.cancel_requested(config->context, &cancelled);
  if (status != PBNS_OK) {
    return status;
  }
  if (cancelled) {
    return PBNS_ERR_STATE;
  }
  return remaining_ms(config, deadline_ms, remaining);
}

static pbns_status consume_once(
    void *context, const pbns_request_id *request_id,
    const uint8_t verifier_nonce[PBNS_ATTESTATION_NONCE_SIZE]) {
  run_consume_context *consume = context;
  if (consume == NULL || request_id == NULL || verifier_nonce == NULL ||
      consume->consumed ||
      !constant_equal(request_id->bytes, consume->request_id->bytes,
                      sizeof(request_id->bytes)) ||
      !constant_equal(verifier_nonce, consume->nonce,
                      PBNS_ATTESTATION_NONCE_SIZE)) {
    return PBNS_ERR_STATE;
  }
  consume->consumed = true;
  return PBNS_OK;
}

static pbns_status send_with_gate(void *context,
                                  const pbns_request_id *request_id,
                                  uint32_t sequence, pbns_view payload,
                                  bool final_record) {
  run_send_context *send = context;
  uint32_t remaining = 0U;
  const pbns_status status =
      gate(send->config, send->deadline_ms, &remaining);
  if (status != PBNS_OK) {
    return status;
  }
  if (!send->upload->started) {
    send->upload->timeout_ms = remaining;
  }
  return pbns_attestation_upload_send(send->upload, request_id, sequence,
                                      payload, final_record);
}

static uint64_t challenge_deadline(uint64_t start_ms,
                                   const pbns_time_interval *trusted_time,
                                   const pbns_attestation_challenge *challenge,
                                   uint64_t global_deadline) {
  const uint64_t latest = (uint64_t)trusted_time->latest_ns;
  const uint64_t delta_ns = challenge->expiry_ns - latest;
  const uint64_t expiry_deadline =
      saturating_add(start_ms, delta_ns / PBNS_NS_PER_MS);
  return expiry_deadline < global_deadline ? expiry_deadline : global_deadline;
}

static void copy_result(pbns_attestation_run_result *destination,
                        const pbns_attestation_receipt_result *source) {
  destination->verdict = source->verdict;
  destination->reason_count = source->reason_count;
  for (size_t index = 0U; index < source->reason_count; ++index) {
    destination->reasons[index] = source->reasons[index];
  }
  destination->display_state = source->display_state;
}

pbns_status pbns_attestation_run(const pbns_attestation_run_config *config,
                                 pbns_attestation_run_workspace *workspace,
                                 pbns_attestation_run_result *result) {
  if (!arguments_valid(config, workspace, result)) {
    return PBNS_ERR_ARGUMENT;
  }

  wipe_bytes(result, sizeof(*result));
  wipe_workspace(workspace);
  pbns_status status = PBNS_OK;
  uint64_t start_ms = 0U;
  uint64_t deadline_ms = 0U;
  uint32_t timeout = 0U;
  pbns_time_interval trusted_time = {0};
  pbns_broker_response issue_broker_response = {0};
  pbns_attestation_wire_response issue_response = {0};
  pbns_attestation_challenge_expected challenge_expected = {0};
  pbns_attestation_challenge challenge = {0};
  pbns_inventory_report inventory = {0};
  pbns_measured_boot_evidence measured = {0};
  pbns_attestation_upload upload = {0};
  pbns_attestation_wire_response submit_response = {0};
  pbns_attestation_receipt_expectation expectation = {0};
  pbns_attestation_receipt_result receipt_result = {
      .verdict = PBNS_ATTESTATION_RECEIPT_FAILURE,
      .display_state = PBNS_ATTESTATION_DISPLAY_FAILURE};
  pbns_attestation_run_result staged = {
      .verdict = PBNS_ATTESTATION_RECEIPT_FAILURE,
      .display_state = PBNS_ATTESTATION_DISPLAY_FAILURE};
  run_consume_context consume = {0};
  run_send_context send = {0};
  pbns_attestation_submission submission = {0};
  size_t written = 0U;
  bool authenticated = false;

  status = config->ops.monotonic_ms(config->context, &start_ms);
  if (status == PBNS_OK) {
    deadline_ms = saturating_add(start_ms, config->timeout_ms);
    status = gate(config, deadline_ms, &timeout);
  }
  if (status == PBNS_OK) {
    status = pbns_attestation_wire_encode_issue_request(
        config->host_fingerprint, workspace->issue_wire, &written);
  }
  if (status == PBNS_OK) {
    status = pbns_broker_request(
        config->broker, PBNS_SERVICE_PLATFORM_ATTESTATION,
        (pbns_view){workspace->issue_wire.ptr, written}, timeout,
        &issue_broker_response);
  }
  if (status == PBNS_OK) {
    if (issue_broker_response.payload.len > workspace->issue_wire.cap) {
      status = PBNS_ERR_LIMIT;
    } else {
      copy_bytes(workspace->issue_wire.ptr, issue_broker_response.payload.ptr,
                 issue_broker_response.payload.len);
    }
  }
  if (status == PBNS_OK) {
    status = pbns_attestation_wire_decode_issue_response(
        (pbns_view){workspace->issue_wire.ptr,
                    issue_broker_response.payload.len},
        workspace->issue_canonical, &issue_response);
  }
  if (status == PBNS_OK &&
      (issue_response.recipient_kid.len != config->recipient_kid.len ||
       !constant_equal(issue_response.recipient_kid.ptr,
                       config->recipient_kid.ptr,
                       config->recipient_kid.len))) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  if (status == PBNS_OK) {
    status = config->ops.trusted_time(config->context, &trusted_time);
  }
  if (status == PBNS_OK &&
      (trusted_time.earliest_ns < 0 || trusted_time.latest_ns < 0 ||
       trusted_time.earliest_ns > trusted_time.latest_ns)) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  if (status == PBNS_OK) {
    status = gate(config, deadline_ms, &timeout);
  }
  challenge_expected.request_id = issue_response.challenge_request_id;
  challenge_expected.recipient_kid = config->recipient_kid;
  challenge_expected.challenge_kid = config->challenge_kid;
  copy_bytes(challenge_expected.host_fingerprint, config->host_fingerprint,
             sizeof(challenge_expected.host_fingerprint));
  copy_bytes(challenge_expected.verifier_nonce, issue_response.verifier_nonce,
             sizeof(challenge_expected.verifier_nonce));
  if (status == PBNS_OK) {
    status = pbns_attestation_accept_challenge(
        config->challenge_verifier, issue_response.object, &challenge_expected,
        &trusted_time, &workspace->challenge, &challenge);
  }
  if (status == PBNS_OK) {
    deadline_ms =
        challenge_deadline(start_ms, &trusted_time, &challenge, deadline_ms);
    status = gate(config, deadline_ms, &timeout);
  }
  if (status == PBNS_OK) {
    status = config->ops.capture_inventory(
        config->context, workspace->inventory_variable_scratch, &inventory);
  }
  if (status == PBNS_OK) {
    status = gate(config, deadline_ms, &timeout);
  }
  if (status == PBNS_OK) {
    status = gate(config, deadline_ms, &timeout);
  }
  if (status == PBNS_OK) {
    status = config->ops.capture_measured(
        config->context,
        (pbns_measured_boot_selection){challenge.selection_items,
                                       challenge.selection_count},
        workspace->event_log_arena, &measured);
  }
  if (status == PBNS_OK &&
      !view_contained_in_buffer(measured.event_log,
                                workspace->event_log_arena)) {
    status = PBNS_ERR_ARGUMENT;
  }
  if (status == PBNS_OK) {
    status = gate(config, deadline_ms, &timeout);
  }
  if (status == PBNS_OK) {
    status = pbns_attestation_wire_encode_submit_request(
        (pbns_view){challenge.request_id.bytes,
                    sizeof(challenge.request_id.bytes)},
        workspace->submit_wire, &written);
  }
  if (status == PBNS_OK) {
    upload = (pbns_attestation_upload){
        .broker = config->broker,
        .request_id = challenge.request_id,
        .encoded_request = {workspace->submit_wire.ptr, written},
        .timeout_ms = timeout,
    };
    consume = (run_consume_context){
        .request_id = &challenge.request_id,
        .nonce = challenge.verifier_nonce,
    };
    send = (run_send_context){
        .config = config,
        .upload = &upload,
        .deadline_ms = deadline_ms,
    };
    submission = config->submission_template;
    submission.inventory_report = &inventory;
    submission.measured_boot = &measured;
    submission.ak_name = config->ak_name;
    submission.ak_reference = config->ak_reference;
    submission.consume = consume_once;
    submission.send_data = send_with_gate;
    submission.evidence_digest = workspace->evidence_digest;
    submission.consume_context = &consume;
    submission.send_context = &send;
    submission.consume_context_region =
        (pbns_view){(const uint8_t *)&consume, sizeof(consume)};
    submission.send_context_region =
        (pbns_view){(const uint8_t *)&send, sizeof(send)};
    status = pbns_attestation_submit(&challenge, &submission,
                                     &workspace->attestation);
  }
  if (status == PBNS_OK && (!consume.consumed || !upload.response_received)) {
    status = PBNS_ERR_STATE;
  }
  if (status == PBNS_OK) {
    status = pbns_attestation_wire_decode_submit_response(
        upload.response_payload,
        (pbns_view){challenge.request_id.bytes,
                    sizeof(challenge.request_id.bytes)},
        workspace->submit_canonical, &submit_response);
  }
  if (status == PBNS_OK &&
      !constant_equal(submit_response.evidence_digest,
                      workspace->evidence_digest.ptr,
                      PBNS_ATTESTATION_DIGEST_SIZE)) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  if (status == PBNS_OK) {
    copy_bytes(expectation.request_id, challenge.request_id.bytes,
               sizeof(expectation.request_id));
    copy_bytes(expectation.verifier_nonce, challenge.verifier_nonce,
               sizeof(expectation.verifier_nonce));
    copy_bytes(expectation.host_fingerprint, config->host_fingerprint,
               sizeof(expectation.host_fingerprint));
    copy_bytes(expectation.evidence_digest, workspace->evidence_digest.ptr,
               sizeof(expectation.evidence_digest));
    copy_bytes(expectation.baseline_id, submit_response.baseline_id,
               sizeof(expectation.baseline_id));
    expectation.key_id = config->receipt_kid;
    status = pbns_attestation_receipt_verify(
        config->receipt_verifier, submit_response.object, &expectation,
        &workspace->receipt, &receipt_result);
  }
  if (status == PBNS_OK) {
    status = gate(config, deadline_ms, &timeout);
  }
  if (status == PBNS_OK) {
    copy_result(&staged, &receipt_result);
    authenticated = true;
    status = pbns_attestation_upload_finish(&upload);
  }

  if (status != PBNS_OK && upload.started && !upload.finished &&
      !upload.cancelled) {
    (void)pbns_attestation_upload_cancel(&upload);
  }
  pbns_attestation_challenge_reset(&challenge);
  pbns_attestation_upload_reset(&upload);
  wipe_bytes(&issue_broker_response, sizeof(issue_broker_response));
  wipe_bytes(&issue_response, sizeof(issue_response));
  wipe_bytes(&submit_response, sizeof(submit_response));
  wipe_bytes(&challenge_expected, sizeof(challenge_expected));
  wipe_bytes(&expectation, sizeof(expectation));
  wipe_bytes(&receipt_result, sizeof(receipt_result));
  wipe_bytes(&inventory, sizeof(inventory));
  wipe_bytes(&measured, sizeof(measured));
  wipe_bytes(&submission, sizeof(submission));
  wipe_bytes(&consume, sizeof(consume));
  wipe_bytes(&send, sizeof(send));
  wipe_bytes(&trusted_time, sizeof(trusted_time));
  wipe_buffer(config->broker->storage.decoded);
  config->broker->storage.decoded.len = 0U;
  wipe_workspace(workspace);

  if (status == PBNS_OK && authenticated) {
    *result = staged;
    const pbns_status display_status =
        config->ops.display_authenticated(config->context, &staged);
    if (display_status != PBNS_OK) {
      status = display_status;
    } else if (staged.verdict == PBNS_ATTESTATION_RECEIPT_FAILURE) {
      status = PBNS_ERR_AUTHENTICATION;
    }
  } else {
    wipe_bytes(result, sizeof(*result));
  }
  wipe_bytes(&staged, sizeof(staged));
  return status;
}
