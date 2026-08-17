#include "pbns/attestation_upload.h"
#include "pbns/attestation_wire.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARRAY_COUNT(value) (sizeof(value) / sizeof((value)[0]))
#define MAX_ATTEMPTS 16U

typedef struct transport_state {
  uint8_t response[PBNS_FRAME_V1_WIRE_MAX];
  size_t response_size;
  size_t read_offset;
  pbns_message_type attempts[MAX_ATTEMPTS];
  size_t attempt_count;
  size_t open_calls;
  size_t close_calls;
  size_t cancel_calls;
  size_t receive_calls;
  pbns_status open_status;
  pbns_status close_status;
  pbns_status cancel_status;
  pbns_status limits_status;
  pbns_status receive_status;
  pbns_status send_status[PBNS_MESSAGE_COMPLETE + 1U];
  uint64_t now;
} transport_state;

typedef struct fixture {
  uint8_t storage[PBNS_FRAME_V1_WIRE_MAX * 4U];
  transport_state transport;
  pbns_broker broker;
  pbns_attestation_upload upload;
  pbns_request_id request;
} fixture;

static pbns_status open_transport(void *context) {
  transport_state *state = context;
  ++state->open_calls;
  return state->open_status;
}

static pbns_status close_transport(void *context) {
  transport_state *state = context;
  ++state->close_calls;
  return state->close_status;
}

static pbns_status send_transport(void *context, pbns_view data,
                                  uint32_t timeout_ms) {
  transport_state *state = context;
  assert(timeout_ms > 0U && data.len > 1U && data.ptr[data.len - 1U] == 0U);
  uint8_t raw[PBNS_FRAME_V1_RAW_MAX] = {0};
  pbns_frame frame = {0};
  pbns_view payload = {0};
  const pbns_frame_limits limits = {
      .control_payload_max = PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX,
      .data_payload_max = PBNS_FRAME_V1_DATA_PAYLOAD_MAX,
      .encoded_record_max = PBNS_FRAME_V1_WIRE_MAX,
  };
  assert(pbns_frame_decode((pbns_view){data.ptr, data.len - 1U}, limits,
                           (pbns_buffer){raw, 0U, sizeof(raw)}, &frame,
                           &payload) == PBNS_OK);
  assert(state->attempt_count < ARRAY_COUNT(state->attempts));
  state->attempts[state->attempt_count++] = frame.type;
  assert((size_t)frame.type < ARRAY_COUNT(state->send_status));
  return state->send_status[frame.type];
}

static pbns_status receive_transport(void *context, pbns_buffer output,
                                     uint32_t timeout_ms, size_t *read) {
  transport_state *state = context;
  assert(timeout_ms > 0U);
  ++state->receive_calls;
  *read = 0U;
  if (state->receive_status != PBNS_OK) {
    return state->receive_status;
  }
  if (state->read_offset == state->response_size) {
    return PBNS_ERR_TIMEOUT;
  }
  const size_t remaining = state->response_size - state->read_offset;
  const size_t amount = remaining < output.cap ? remaining : output.cap;
  memcpy(output.ptr, state->response + state->read_offset, amount);
  state->read_offset += amount;
  *read = amount;
  return PBNS_OK;
}

static pbns_status cancel_transport(void *context,
                                    const pbns_request_id *request_id) {
  transport_state *state = context;
  assert(request_id != NULL);
  ++state->cancel_calls;
  return state->cancel_status;
}

static pbns_status limits_transport(void *context, pbns_frame_limits *limits) {
  transport_state *state = context;
  if (state->limits_status != PBNS_OK) {
    return state->limits_status;
  }
  *limits = (pbns_frame_limits){
      .control_payload_max = PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX,
      .data_payload_max = PBNS_FRAME_V1_DATA_PAYLOAD_MAX,
      .encoded_record_max = PBNS_FRAME_V1_WIRE_MAX,
  };
  return PBNS_OK;
}

static pbns_status random_bytes(void *context, pbns_buffer output) {
  (void)context;
  memset(output.ptr, 0x11, output.cap);
  return PBNS_OK;
}

static pbns_status monotonic(void *context, uint64_t *now) {
  transport_state *state = context;
  *now = ++state->now;
  return PBNS_OK;
}

static const pbns_transport_ops transport_ops = {
    .open = open_transport,
    .close = close_transport,
    .send = send_transport,
    .receive = receive_transport,
    .cancel = cancel_transport,
    .limits = limits_transport,
};

static const pbns_broker_platform_ops platform_ops = {
    .random = random_bytes,
    .monotonic_ms = monotonic,
};

static void fixture_init(fixture *value) {
  *value = (fixture){0};
  value->request.bytes[0] = 1U;
  assert(pbns_broker_init(
             &value->broker,
             (pbns_transport){&transport_ops, &value->transport},
             (pbns_broker_platform){&platform_ops, &value->transport},
             (pbns_broker_storage){
                 {value->storage, 0U, PBNS_FRAME_V1_WIRE_MAX},
                 {value->storage + PBNS_FRAME_V1_WIRE_MAX, 0U,
                  PBNS_FRAME_V1_WIRE_MAX},
                 {value->storage + PBNS_FRAME_V1_WIRE_MAX * 2U, 0U,
                  PBNS_FRAME_V1_WIRE_MAX},
                 {value->storage + PBNS_FRAME_V1_WIRE_MAX * 3U, 0U,
                  PBNS_FRAME_V1_WIRE_MAX},
             }) == PBNS_OK);
  static const uint8_t control[] = {0xa1U, 0x01U, 0x02U};
  value->upload = (pbns_attestation_upload){
      .broker = &value->broker,
      .request_id = value->request,
      .encoded_request = {control, sizeof(control)},
      .timeout_ms = 100U,
  };
}

static void encode_response(fixture *value, pbns_service_id service,
                            pbns_message_type type,
                            const pbns_request_id *request, uint32_t sequence,
                            pbns_view payload) {
  uint8_t raw[PBNS_FRAME_V1_RAW_MAX] = {0};
  const pbns_frame frame = {
      .service = service,
      .type = type,
      .request_id = *request,
      .sequence = sequence,
  };
  assert(pbns_frame_encode(
             &frame, payload, (pbns_buffer){raw, 0U, sizeof(raw)},
             (pbns_buffer){value->transport.response, 0U,
                           sizeof(value->transport.response)},
             &value->transport.response_size) == PBNS_OK);
}

static size_t attempt_count(const fixture *value, pbns_message_type type) {
  size_t count = 0U;
  for (size_t index = 0U; index < value->transport.attempt_count; ++index) {
    if (value->transport.attempts[index] == type) {
      ++count;
    }
  }
  return count;
}

static pbns_status send_record(fixture *value, uint32_t sequence,
                               bool final_record) {
  static const uint8_t ciphertext[] = {1U, 2U, 3U};
  return pbns_attestation_upload_send(
      &value->upload, &value->request, sequence,
      (pbns_view){ciphertext, sizeof(ciphertext)}, final_record);
}

static void assert_attempts(const fixture *value,
                            const pbns_message_type *expected,
                            size_t expected_count) {
  assert(value->transport.attempt_count == expected_count);
  if (expected_count > 0U) {
    assert(expected != NULL);
    assert(memcmp(value->transport.attempts, expected,
                  expected_count * sizeof(expected[0])) == 0);
  }
}

static void assert_upload_reset_no_transport(fixture *value) {
  const size_t attempts = value->transport.attempt_count;
  const size_t opens = value->transport.open_calls;
  const size_t receives = value->transport.receive_calls;
  const size_t cancels = value->transport.cancel_calls;
  const size_t closes = value->transport.close_calls;
  const uint64_t now = value->transport.now;
  pbns_attestation_upload_reset(&value->upload);
  const uint8_t zero[sizeof(value->upload)] = {0};
  assert(memcmp(&value->upload, zero, sizeof(value->upload)) == 0);
  assert(value->transport.attempt_count == attempts &&
         value->transport.open_calls == opens &&
         value->transport.receive_calls == receives &&
         value->transport.cancel_calls == cancels &&
         value->transport.close_calls == closes &&
         value->transport.now == now);
}

static void assert_no_more_cleanup(fixture *value) {
  const size_t attempts = value->transport.attempt_count;
  const size_t cancels = value->transport.cancel_calls;
  const size_t closes = value->transport.close_calls;
  assert(pbns_attestation_upload_cancel(&value->upload) == PBNS_OK);
  (void)pbns_attestation_upload_finish(&value->upload);
  assert(value->transport.attempt_count == attempts &&
         value->transport.cancel_calls == cancels &&
         value->transport.close_calls == closes);
  assert_upload_reset_no_transport(value);
  pbns_broker_reset(&value->broker);
  assert(value->transport.attempt_count == attempts &&
         value->transport.cancel_calls == cancels &&
         value->transport.close_calls == closes);
}

static void assert_aborted(fixture *value, const char *case_name,
                           pbns_status actual, pbns_status expected,
                           const pbns_message_type *expected_attempts,
                           size_t expected_attempt_count) {
  if (actual != expected) {
    fprintf(stderr,
            "%s: abort status actual=%d expected=%d attempts=%zu\n",
            case_name, (int)actual, (int)expected,
            value->transport.attempt_count);
  }
  assert(actual == expected);
  assert_attempts(value, expected_attempts, expected_attempt_count);
  assert(attempt_count(value, PBNS_MESSAGE_CANCEL) == 1U);
  assert(value->transport.cancel_calls == 1U);
  assert(value->transport.close_calls == 1U);
  assert_no_more_cleanup(value);
}

#define ASSERT_ABORTED(value, expression, expected, attempts)                  \
  assert_aborted((value), #expression, (expression), (expected), (attempts),   \
                 ARRAY_COUNT(attempts))

static void test_success_and_terminal_close(void) {
  static const uint8_t receipt[] = {0xa1U, 0x01U, 0x01U};
  fixture value = {0};
  fixture_init(&value);
  encode_response(&value, PBNS_SERVICE_PLATFORM_ATTESTATION,
                  PBNS_MESSAGE_RESPONSE, &value.request, 0U,
                  (pbns_view){receipt, sizeof(receipt)});
  assert(send_record(&value, 0U, false) == PBNS_OK);
  assert(send_record(&value, 1U, true) == PBNS_OK);
  const pbns_message_type expected[] = {
      PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_DATA, PBNS_MESSAGE_DATA,
      PBNS_MESSAGE_COMPLETE,
  };
  assert(value.transport.attempt_count == ARRAY_COUNT(expected) &&
         memcmp(value.transport.attempts, expected, sizeof(expected)) == 0);
  assert(value.upload.response_received && value.upload.response_payload.len ==
                                               sizeof(receipt));
  assert(value.transport.cancel_calls == 0U &&
         attempt_count(&value, PBNS_MESSAGE_CANCEL) == 0U &&
         value.transport.close_calls == 0U);
  assert(pbns_attestation_upload_finish(&value.upload) == PBNS_OK);
  assert(value.upload.finished && value.upload.response_payload.ptr == NULL &&
         value.upload.response_payload.len == 0U &&
         value.transport.close_calls == 1U);
  assert_no_more_cleanup(&value);

  fixture_init(&value);
  encode_response(&value, PBNS_SERVICE_PLATFORM_ATTESTATION,
                  PBNS_MESSAGE_RESPONSE, &value.request, 0U,
                  (pbns_view){receipt, sizeof(receipt)});
  assert(send_record(&value, 0U, true) == PBNS_OK);
  const pbns_message_type finish_close_attempts[] = {
      PBNS_MESSAGE_REQUEST,
      PBNS_MESSAGE_DATA,
      PBNS_MESSAGE_COMPLETE,
  };
  assert_attempts(&value, finish_close_attempts,
                  ARRAY_COUNT(finish_close_attempts));
  value.transport.close_status = PBNS_ERR_TRANSPORT;
  assert(pbns_attestation_upload_finish(&value.upload) == PBNS_ERR_TRANSPORT);
  assert(value.upload.finished && value.upload.response_payload.ptr == NULL &&
         value.upload.response_payload.len == 0U);
  assert(attempt_count(&value, PBNS_MESSAGE_CANCEL) == 0U &&
         value.transport.cancel_calls == 0U &&
         value.transport.close_calls == 1U);
  assert_no_more_cleanup(&value);
}

static void test_pre_begin_and_send_failures(void) {
  static const pbns_message_type failure_attempts[][4] = {
      {PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_CANCEL},
      {PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_DATA, PBNS_MESSAGE_CANCEL},
      {PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_DATA, PBNS_MESSAGE_COMPLETE,
       PBNS_MESSAGE_CANCEL},
  };
  static const size_t failure_attempt_counts[] = {2U, 3U, 4U};
  fixture value = {0};
  fixture_init(&value);
  pbns_request_id wrong = value.request;
  wrong.bytes[0] ^= 1U;
  static const uint8_t data[] = {1U};
  assert(pbns_attestation_upload_send(
             &value.upload, &wrong, 0U, (pbns_view){data, sizeof(data)},
             true) == PBNS_ERR_STATE);
  assert(value.transport.attempt_count == 0U &&
         value.transport.open_calls == 0U && value.transport.cancel_calls == 0U &&
         value.transport.close_calls == 0U && value.transport.now == 0U);
  assert_upload_reset_no_transport(&value);
  pbns_broker_reset(&value.broker);

  fixture_init(&value);
  value.transport.open_status = PBNS_ERR_TRANSPORT;
  assert(send_record(&value, 0U, true) == PBNS_ERR_TRANSPORT);
  assert(value.transport.attempt_count == 0U &&
         value.transport.cancel_calls == 0U && value.transport.close_calls == 0U);
  assert_upload_reset_no_transport(&value);
  pbns_broker_reset(&value.broker);

  fixture_init(&value);
  value.transport.limits_status = PBNS_ERR_TRANSPORT;
  assert(send_record(&value, 0U, true) == PBNS_ERR_TRANSPORT);
  assert(value.transport.attempt_count == 0U &&
         value.transport.cancel_calls == 0U && value.transport.close_calls == 1U);
  assert_upload_reset_no_transport(&value);
  pbns_broker_reset(&value.broker);

  const pbns_message_type failed_types[] = {
      PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_DATA, PBNS_MESSAGE_COMPLETE,
  };
  for (size_t index = 0U; index < ARRAY_COUNT(failed_types); ++index) {
    fixture_init(&value);
    static const uint8_t receipt[] = {0xa1U};
    encode_response(&value, PBNS_SERVICE_PLATFORM_ATTESTATION,
                    PBNS_MESSAGE_RESPONSE, &value.request, 0U,
                    (pbns_view){receipt, sizeof(receipt)});
    value.transport.send_status[failed_types[index]] = PBNS_ERR_TRANSPORT;
    assert_aborted(&value, "frame send failure",
                   send_record(&value, 0U, true), PBNS_ERR_TRANSPORT,
                   failure_attempts[index], failure_attempt_counts[index]);
  }
}

typedef struct response_case {
  const char *name;
  pbns_service_id service;
  pbns_message_type type;
  bool wrong_request;
  uint32_t sequence;
  pbns_view payload;
  pbns_status expected;
} response_case;

static void test_receive_and_response_failures(void) {
  static const pbns_message_type attempts[] = {
      PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_DATA, PBNS_MESSAGE_COMPLETE,
      PBNS_MESSAGE_CANCEL,
  };
  static const uint8_t valid_payload[] = {0xa1U, 0x01U, 0x01U};
  static const uint8_t empty_marker[] = {0U};
  const response_case cases[] = {
      {"wrong service", PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_RESPONSE,
       false, 0U, {valid_payload, sizeof(valid_payload)}, PBNS_ERR_SERVICE},
      {"wrong request", PBNS_SERVICE_PLATFORM_ATTESTATION,
       PBNS_MESSAGE_RESPONSE, true, 0U,
       {valid_payload, sizeof(valid_payload)}, PBNS_ERR_STATE},
      {"wrong sequence", PBNS_SERVICE_PLATFORM_ATTESTATION,
       PBNS_MESSAGE_RESPONSE, false, 1U,
       {valid_payload, sizeof(valid_payload)}, PBNS_ERR_SEQUENCE},
      {"wrong type", PBNS_SERVICE_PLATFORM_ATTESTATION, PBNS_MESSAGE_DATA,
       false, 0U, {valid_payload, sizeof(valid_payload)},
       PBNS_ERR_MESSAGE_TYPE},
      {"empty application payload", PBNS_SERVICE_PLATFORM_ATTESTATION,
       PBNS_MESSAGE_RESPONSE, false, 0U, {empty_marker, 0U}, PBNS_ERR_FORMAT},
  };
  for (size_t index = 0U; index < ARRAY_COUNT(cases); ++index) {
    (void)cases[index].name;
    fixture value = {0};
    fixture_init(&value);
    pbns_request_id response_request = value.request;
    if (cases[index].wrong_request) {
      response_request.bytes[0] ^= 1U;
    }
    encode_response(&value, cases[index].service, cases[index].type,
                    &response_request, cases[index].sequence,
                    cases[index].payload);
    assert_aborted(&value, cases[index].name,
                   send_record(&value, 0U, true), cases[index].expected,
                   attempts, ARRAY_COUNT(attempts));
  }

  fixture value = {0};
  fixture_init(&value);
  value.transport.receive_status = PBNS_ERR_TIMEOUT;
  ASSERT_ABORTED(&value, send_record(&value, 0U, true), PBNS_ERR_TIMEOUT,
                 attempts);

  fixture_init(&value);
  value.transport.response[0] = 0xffU;
  value.transport.response[1] = 0U;
  value.transport.response_size = 2U;
  ASSERT_ABORTED(&value, send_record(&value, 0U, true), PBNS_ERR_FORMAT,
                 attempts);

  fixture_init(&value);
  encode_response(&value, PBNS_SERVICE_PLATFORM_ATTESTATION,
                  PBNS_MESSAGE_RESPONSE, &value.request, 0U,
                  (pbns_view){valid_payload, sizeof(valid_payload)});
  value.transport.response[1] ^= 1U;
  ASSERT_ABORTED(&value, send_record(&value, 0U, true), PBNS_ERR_FORMAT,
                 attempts);
}

static void test_sequence_failures(void) {
  static const pbns_message_type attempts[] = {
      PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_DATA, PBNS_MESSAGE_CANCEL,
  };
  fixture value = {0};
  fixture_init(&value);
  assert(send_record(&value, 0U, false) == PBNS_OK);
  ASSERT_ABORTED(&value, send_record(&value, 2U, false), PBNS_ERR_STATE,
                 attempts);

  fixture_init(&value);
  assert(send_record(&value, 0U, false) == PBNS_OK);
  value.upload.next_sequence = UINT32_MAX;
  value.broker.upload_next_sequence = UINT32_MAX - 1U;
  ASSERT_ABORTED(&value, send_record(&value, UINT32_MAX, false),
                 PBNS_ERR_LIMIT, attempts);

  fixture_init(&value);
  assert(send_record(&value, 0U, false) == PBNS_OK);
  value.upload.next_sequence = UINT32_MAX - 1U;
  value.broker.upload_next_sequence = UINT32_MAX;
  ASSERT_ABORTED(&value, send_record(&value, UINT32_MAX - 1U, false),
                 PBNS_ERR_LIMIT, attempts);
}

static void test_malformed_application_response_cancels(void) {
  static const pbns_message_type before_cancel[] = {
      PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_DATA, PBNS_MESSAGE_COMPLETE,
  };
  static const pbns_message_type after_cancel[] = {
      PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_DATA, PBNS_MESSAGE_COMPLETE,
      PBNS_MESSAGE_CANCEL,
  };
  static const uint8_t malformed[] = {0xffU};
  fixture value = {0};
  fixture_init(&value);
  encode_response(&value, PBNS_SERVICE_PLATFORM_ATTESTATION,
                  PBNS_MESSAGE_RESPONSE, &value.request, 0U,
                  (pbns_view){malformed, sizeof(malformed)});
  assert(send_record(&value, 0U, true) == PBNS_OK);
  assert(value.upload.response_received &&
         value.upload.response_payload.len == sizeof(malformed));
  assert_attempts(&value, before_cancel, ARRAY_COUNT(before_cancel));

  uint8_t canonical[PBNS_ATTESTATION_WIRE_MAX_SIZE] = {0};
  pbns_attestation_wire_response response = {0};
  assert(pbns_attestation_wire_decode_submit_response(
             value.upload.response_payload,
             (pbns_view){value.request.bytes, sizeof(value.request.bytes)},
             (pbns_buffer){canonical, 0U, sizeof(canonical)}, &response) ==
         PBNS_ERR_FORMAT);
  assert(pbns_attestation_upload_cancel(&value.upload) == PBNS_OK);
  assert_attempts(&value, after_cancel, ARRAY_COUNT(after_cancel));
  assert(attempt_count(&value, PBNS_MESSAGE_CANCEL) == 1U &&
         value.transport.cancel_calls == 1U &&
         value.transport.close_calls == 1U && !value.upload.finished);
  assert_no_more_cleanup(&value);
}

static void test_abort_secondary_failures_preserve_primary(void) {
  static const pbns_message_type attempts[] = {
      PBNS_MESSAGE_REQUEST, PBNS_MESSAGE_DATA, PBNS_MESSAGE_COMPLETE,
      PBNS_MESSAGE_CANCEL,
  };
  static const uint8_t payload[] = {0xa1U};
  for (size_t injection = 0U; injection < 3U; ++injection) {
    fixture value = {0};
    fixture_init(&value);
    encode_response(&value, PBNS_SERVICE_PLATFORM_ATTESTATION,
                    PBNS_MESSAGE_RESPONSE, &value.request, 1U,
                    (pbns_view){payload, sizeof(payload)});
    if (injection == 0U) {
      value.transport.send_status[PBNS_MESSAGE_CANCEL] = PBNS_ERR_TRANSPORT;
    } else if (injection == 1U) {
      value.transport.cancel_status = PBNS_ERR_IO;
    } else {
      value.transport.close_status = PBNS_ERR_RESOURCE;
    }
    ASSERT_ABORTED(&value, send_record(&value, 0U, true), PBNS_ERR_SEQUENCE,
                   attempts);
  }
}

int main(void) {
  test_success_and_terminal_close();
  test_pre_begin_and_send_failures();
  test_receive_and_response_failures();
  test_sequence_failures();
  test_malformed_application_response_cancels();
  test_abort_secondary_failures_preserve_primary();
  return EXIT_SUCCESS;
}
