#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pbns/broker.h"
#include "pbns/cobs.h"
#include "pbns/crc32c.h"
#include "pbns/frame.h"
#include "pbns/status.h"
#include "pbns/transport.h"
#include "qcbor/qcbor.h"

#define TEST_BUFFER_CAP 1024U
#define FAKE_WIRE_CAP 2048U
#define FAKE_SEND_MAX 16U
#define BULK_WINDOW 8U
#define BULK_EXACT_SIZE 8U
#define BULK_DATA_RECORDS 8U
#define ACK_PAYLOAD_SIZE 8U

static const uint8_t bulk_body[] = {UINT8_C(0xa0)};
static const uint8_t bulk_data[] = {UINT8_C(1), UINT8_C(2), UINT8_C(3), UINT8_C(4),
                                    UINT8_C(5), UINT8_C(6), UINT8_C(7), UINT8_C(8)};

typedef struct fake_record {
    uint8_t bytes[FAKE_WIRE_CAP];
    size_t len;
} fake_record;

typedef struct fake_environment {
    pbns_status random_status;
    pbns_status clock_status;
    pbns_status open_status;
    pbns_status send_status;
    pbns_status send_failure_status;
    pbns_status receive_status;
    pbns_status cancel_status;
    pbns_status close_status;
    pbns_frame_limits limits;
    pbns_status limits_status;
    uint8_t random_seed;
    bool random_all_zero;
    bool limits_require_open;
    uint64_t now_ms;
    uint64_t clock_step_ms;
    uint8_t incoming[FAKE_WIRE_CAP];
    size_t incoming_len;
    size_t incoming_offset;
    size_t fragment_size;
    fake_record sent[FAKE_SEND_MAX];
    size_t send_count;
    size_t send_calls;
    size_t send_failure_call;
    size_t random_calls;
    size_t clock_calls;
    size_t open_calls;
    size_t receive_calls;
    size_t cancel_calls;
    size_t close_calls;
    size_t live_resources;
    char order[512];
    size_t order_len;
} fake_environment;

typedef struct broker_fixture {
    fake_environment fake;
    pbns_broker broker;
    uint8_t encoded[TEST_BUFFER_CAP];
    uint8_t raw[TEST_BUFFER_CAP];
    uint8_t receive[128];
    uint8_t decoded[TEST_BUFFER_CAP];
} broker_fixture;

typedef struct bulk_data_range {
    uint32_t first_sequence;
    uint32_t count;
} bulk_data_range;

typedef struct frame_mutation {
    pbns_message_type type;
    uint8_t flags;
} frame_mutation;

static void append_order(fake_environment *fake, char operation) {
    assert(fake->order_len + 1U < sizeof(fake->order));
    fake->order[fake->order_len] = operation;
    ++fake->order_len;
    fake->order[fake->order_len] = '\0';
}

static pbns_request_id request_id_for_seed(uint8_t seed) {
    pbns_request_id request_id = {0};
    for (size_t index = 0U; index < sizeof(request_id.bytes); ++index) {
        request_id.bytes[index] = (uint8_t)(seed + (uint8_t)index);
    }
    return request_id;
}

static pbns_status fake_random(void *context, pbns_buffer output) {
    fake_environment *const fake = context;
    ++fake->random_calls;
    if (fake->random_status != PBNS_OK) {
        return fake->random_status;
    }
    assert(output.ptr != NULL);
    assert(output.cap == PBNS_REQUEST_ID_SIZE);
    const pbns_request_id request_id = fake->random_all_zero
                                           ? (pbns_request_id){0}
                                           : request_id_for_seed(fake->random_seed);
    memcpy(output.ptr, request_id.bytes, sizeof(request_id.bytes));
    fake->random_seed = (uint8_t)(fake->random_seed + UINT8_C(0x20));
    return PBNS_OK;
}

static pbns_status fake_monotonic_ms(void *context, uint64_t *now_ms) {
    fake_environment *const fake = context;
    ++fake->clock_calls;
    if (now_ms == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    *now_ms = 0U;
    if (fake->clock_status != PBNS_OK) {
        return fake->clock_status;
    }
    *now_ms = fake->now_ms;
    fake->now_ms += fake->clock_step_ms;
    return PBNS_OK;
}

static pbns_status fake_open(void *context) {
    fake_environment *const fake = context;
    ++fake->open_calls;
    append_order(fake, 'O');
    if (fake->open_status == PBNS_OK) {
        ++fake->live_resources;
    }
    return fake->open_status;
}

static pbns_status fake_close(void *context) {
    fake_environment *const fake = context;
    ++fake->close_calls;
    append_order(fake, 'C');
    if (fake->live_resources > 0U) {
        --fake->live_resources;
    }
    return fake->close_status;
}

static pbns_status fake_send(void *context, pbns_view bytes, uint32_t timeout_ms) {
    fake_environment *const fake = context;
    append_order(fake, 'S');
    assert(timeout_ms > 0U);
    ++fake->send_calls;
    if (fake->send_status != PBNS_OK) {
        return fake->send_status;
    }
    if (fake->send_failure_call == fake->send_calls) {
        return fake->send_failure_status;
    }
    assert(fake->send_count < FAKE_SEND_MAX);
    assert(bytes.len <= sizeof(fake->sent[0].bytes));
    fake_record *const record = &fake->sent[fake->send_count];
    memcpy(record->bytes, bytes.ptr, bytes.len);
    record->len = bytes.len;
    ++fake->send_count;
    return PBNS_OK;
}

static pbns_status fake_receive(void *context, pbns_buffer buffer, uint32_t timeout_ms,
                                size_t *received) {
    fake_environment *const fake = context;
    ++fake->receive_calls;
    append_order(fake, 'R');
    assert(received != NULL);
    assert(timeout_ms > 0U);
    *received = 0U;
    if (fake->receive_status != PBNS_OK) {
        return fake->receive_status;
    }
    if (fake->incoming_offset >= fake->incoming_len) {
        return PBNS_ERR_TIMEOUT;
    }
    size_t amount = fake->incoming_len - fake->incoming_offset;
    if (fake->fragment_size > 0U && amount > fake->fragment_size) {
        amount = fake->fragment_size;
    }
    if (amount > buffer.cap) {
        amount = buffer.cap;
    }
    memcpy(buffer.ptr, fake->incoming + fake->incoming_offset, amount);
    fake->incoming_offset += amount;
    *received = amount;
    return PBNS_OK;
}

static pbns_status fake_cancel(void *context, const pbns_request_id *request_id) {
    fake_environment *const fake = context;
    assert(request_id != NULL);
    ++fake->cancel_calls;
    append_order(fake, 'K');
    return fake->cancel_status;
}

static pbns_status fake_limits(void *context, pbns_frame_limits *limits) {
    fake_environment *const fake = context;
    assert(limits != NULL);
    append_order(fake, 'L');
    if (fake->limits_require_open && fake->live_resources == 0U) {
        return PBNS_ERR_STATE;
    }
    if (fake->limits_status != PBNS_OK) {
        return fake->limits_status;
    }
    *limits = fake->limits;
    return PBNS_OK;
}

static const pbns_transport_ops fake_transport_ops = {
    .open = fake_open,
    .close = fake_close,
    .send = fake_send,
    .receive = fake_receive,
    .cancel = fake_cancel,
    .limits = fake_limits,
};

static const pbns_broker_platform_ops fake_platform_ops = {
    .random = fake_random,
    .monotonic_ms = fake_monotonic_ms,
};

static pbns_broker_storage fixture_storage(broker_fixture *fixture) {
    return (pbns_broker_storage){
        .encoded = {fixture->encoded, 0U, sizeof(fixture->encoded)},
        .raw_scratch = {fixture->raw, 0U, sizeof(fixture->raw)},
        .receive = {fixture->receive, 0U, sizeof(fixture->receive)},
        .decoded = {fixture->decoded, 0U, sizeof(fixture->decoded)},
    };
}

static void fixture_init(broker_fixture *fixture) {
    *fixture = (broker_fixture){0};
    fixture->fake.random_status = PBNS_OK;
    fixture->fake.clock_status = PBNS_OK;
    fixture->fake.open_status = PBNS_OK;
    fixture->fake.send_status = PBNS_OK;
    fixture->fake.send_failure_status = PBNS_ERR_TRANSPORT;
    fixture->fake.receive_status = PBNS_OK;
    fixture->fake.cancel_status = PBNS_OK;
    fixture->fake.close_status = PBNS_OK;
    fixture->fake.limits_status = PBNS_OK;
    fixture->fake.limits = (pbns_frame_limits){
        .control_payload_max = PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX,
        .data_payload_max = PBNS_FRAME_V1_DATA_PAYLOAD_MAX,
        .encoded_record_max = PBNS_FRAME_V1_WIRE_MAX,
    };
    fixture->fake.random_seed = UINT8_C(0x10);
    fixture->fake.now_ms = UINT64_C(1000);
    assert(pbns_broker_init(&fixture->broker, (pbns_transport){&fake_transport_ops, &fixture->fake},
                            (pbns_broker_platform){&fake_platform_ops, &fixture->fake},
                            fixture_storage(fixture)) == PBNS_OK);
}

static size_t encode_error_payload(uint64_t code, pbns_service_id service, const char *detail,
                                   uint8_t *output, size_t capacity) {
    QCBOREncodeContext encoder = {0};
    UsefulBufC encoded = {0};
    QCBOREncode_Init(&encoder, (UsefulBuf){output, capacity});
    QCBOREncode_OpenMap(&encoder);
    QCBOREncode_AddUInt64ToMapN(&encoder, 1, code);
    QCBOREncode_AddUInt64ToMapN(&encoder, 2, (uint64_t)service);
    QCBOREncode_AddTextToMapN(&encoder, 3, (UsefulBufC){detail, strlen(detail)});
    QCBOREncode_CloseMap(&encoder);
    assert(QCBOREncode_Finish(&encoder, &encoded) == QCBOR_SUCCESS);
    assert(encoded.ptr == output);
    return encoded.len;
}

static void append_incoming(fake_environment *fake, pbns_service_id service,
                            pbns_message_type type, pbns_request_id request_id,
                            uint32_t sequence, pbns_view payload) {
    uint8_t raw[FAKE_WIRE_CAP] = {0};
    size_t written = 0U;
    const pbns_frame frame = {
        .service = service,
        .type = type,
        .flags = 0U,
        .request_id = request_id,
        .sequence = sequence,
    };
    assert(fake->incoming_len <= sizeof(fake->incoming));
    assert(pbns_frame_encode(&frame, payload, (pbns_buffer){raw, 0U, sizeof(raw)},
                             (pbns_buffer){fake->incoming + fake->incoming_len, 0U,
                                            sizeof(fake->incoming) - fake->incoming_len},
                             &written) == PBNS_OK);
    fake->incoming_len += written;
}

static void prepare_incoming(fake_environment *fake, pbns_service_id service,
                             pbns_message_type type, pbns_request_id request_id,
                             pbns_view payload) {
    fake->incoming_len = 0U;
    fake->incoming_offset = 0U;
    append_incoming(fake, service, type, request_id, 0U, payload);
}

static void write_u32_be(uint8_t *destination, uint32_t value) {
    destination[0] = (uint8_t)(value >> 24U);
    destination[1] = (uint8_t)(value >> 16U);
    destination[2] = (uint8_t)(value >> 8U);
    destination[3] = (uint8_t)value;
}

static void append_mutated_incoming(fake_environment *fake, pbns_service_id service,
                                    pbns_request_id request_id, uint32_t sequence,
                                    pbns_view payload, frame_mutation mutation) {
    uint8_t raw[FAKE_WIRE_CAP] = {0};
    uint8_t wire[FAKE_WIRE_CAP] = {0};
    size_t wire_len = 0U;
    const pbns_frame frame = {
        .service = service,
        .type = PBNS_MESSAGE_DATA,
        .flags = 0U,
        .request_id = request_id,
        .sequence = sequence,
    };
    assert(pbns_frame_encode(&frame, payload, (pbns_buffer){raw, 0U, sizeof(raw)},
                             (pbns_buffer){wire, 0U, sizeof(wire)}, &wire_len) == PBNS_OK);
    size_t raw_len = 0U;
    assert(pbns_cobs_decode((pbns_view){wire, wire_len - 1U},
                            (pbns_buffer){raw, 0U, sizeof(raw)}, &raw_len) == PBNS_OK);
    raw[6] = (uint8_t)mutation.type;
    raw[7] = mutation.flags;
    write_u32_be(raw + 32U, pbns_crc32c((pbns_view){raw, 32U}));
    write_u32_be(raw + raw_len - PBNS_FRAME_V1_TRAILER_SIZE,
                 pbns_crc32c((pbns_view){raw, raw_len - PBNS_FRAME_V1_TRAILER_SIZE}));
    size_t encoded_len = 0U;
    assert(pbns_cobs_encode((pbns_view){raw, raw_len},
                            (pbns_buffer){fake->incoming + fake->incoming_len, 0U,
                                           sizeof(fake->incoming) - fake->incoming_len - 1U},
                            &encoded_len) == PBNS_OK);
    fake->incoming_len += encoded_len;
    fake->incoming[fake->incoming_len] = 0U;
    ++fake->incoming_len;
}

static void prepare_error(fake_environment *fake, pbns_service_id frame_service,
                          pbns_request_id request_id, uint64_t code,
                          pbns_service_id payload_service) {
    uint8_t payload[128] = {0};
    const size_t payload_len = encode_error_payload(
        code, payload_service, "service not implemented", payload, sizeof(payload));
    prepare_incoming(fake, frame_service, PBNS_MESSAGE_ERROR, request_id,
                     (pbns_view){payload, payload_len});
}

static pbns_frame decode_sent_with_payload(const fake_record *record, uint8_t *raw,
                                           size_t raw_capacity, pbns_view *payload) {
    assert(record->len > 1U);
    assert(record->bytes[record->len - 1U] == UINT8_C(0));
    pbns_frame frame = {0};
    pbns_view decoded_payload = {0};
    const pbns_frame_limits limits = {
        .control_payload_max = PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX,
        .data_payload_max = PBNS_FRAME_V1_DATA_PAYLOAD_MAX,
        .encoded_record_max = PBNS_FRAME_V1_WIRE_MAX,
    };
    assert(pbns_frame_decode((pbns_view){record->bytes, record->len - 1U}, limits,
                             (pbns_buffer){raw, 0U, raw_capacity}, &frame,
                             &decoded_payload) == PBNS_OK);
    if (payload != NULL) {
        *payload = decoded_payload;
    }
    return frame;
}

static pbns_frame decode_sent(const fake_record *record, uint8_t *raw, size_t raw_capacity) {
    return decode_sent_with_payload(record, raw, raw_capacity, NULL);
}

static bool request_ids_equal(pbns_request_id left, pbns_request_id right) {
    return memcmp(left.bytes, right.bytes, sizeof(left.bytes)) == 0;
}

static pbns_status make_request(broker_fixture *fixture, pbns_broker_response *response) {
    static const uint8_t body[] = {UINT8_C(0xa0)};
    return pbns_broker_request(&fixture->broker, PBNS_SERVICE_TRUSTED_TIME,
                               (pbns_view){body, sizeof(body)}, UINT32_C(5000), response);
}

static pbns_status make_request_with_id(broker_fixture *fixture,
                                        const pbns_request_id *request_id,
                                        pbns_broker_response *response) {
    static const uint8_t body[] = {UINT8_C(0xa0)};
    return pbns_broker_request_with_id(&fixture->broker, PBNS_SERVICE_TRUSTED_TIME, request_id,
                                       (pbns_view){body, sizeof(body)}, UINT32_C(5000), response);
}

static void test_caller_supplied_id_is_encoded_and_correlates_response(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    const pbns_request_id request_id = request_id_for_seed(UINT8_C(0x80));
    static const uint8_t payload[] = {UINT8_C(0xde), UINT8_C(0xad)};
    prepare_incoming(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, PBNS_MESSAGE_RESPONSE, request_id,
                     (pbns_view){payload, sizeof(payload)});

    pbns_broker_response response = {0};
    assert(make_request_with_id(&fixture, &request_id, &response) == PBNS_OK);
    uint8_t raw[FAKE_WIRE_CAP] = {0};
    const pbns_frame sent = decode_sent(&fixture.fake.sent[0], raw, sizeof(raw));
    assert(request_ids_equal(sent.request_id, request_id));
    assert(request_ids_equal(response.frame.request_id, request_id));
    assert(response.payload.len == sizeof(payload));
    assert(memcmp(response.payload.ptr, payload, sizeof(payload)) == 0);
    assert(fixture.fake.random_calls == 0U);
    assert(fixture.fake.open_calls == 1U);
    assert(fixture.fake.close_calls == 1U);
    pbns_broker_reset(&fixture.broker);
}

static void test_caller_supplied_id_snapshots_broker_request_id(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    const pbns_request_id request_id = request_id_for_seed(UINT8_C(0x80));
    fixture.broker.request_id = request_id;
    prepare_incoming(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, PBNS_MESSAGE_RESPONSE, request_id,
                     (pbns_view){NULL, 0U});

    pbns_broker_response response = {0};
    assert(make_request_with_id(&fixture, &fixture.broker.request_id, &response) == PBNS_OK);
    uint8_t raw[FAKE_WIRE_CAP] = {0};
    const pbns_frame sent = decode_sent(&fixture.fake.sent[0], raw, sizeof(raw));
    assert(request_ids_equal(sent.request_id, request_id));
    assert(request_ids_equal(response.frame.request_id, request_id));
    assert(fixture.fake.random_calls == 0U);
    pbns_broker_reset(&fixture.broker);
}

static void test_caller_supplied_id_snapshots_response_request_id(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    const pbns_request_id request_id = request_id_for_seed(UINT8_C(0x80));
    prepare_incoming(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, PBNS_MESSAGE_RESPONSE, request_id,
                     (pbns_view){NULL, 0U});

    pbns_broker_response response = {.frame = {.request_id = request_id}};
    assert(make_request_with_id(&fixture, &response.frame.request_id, &response) == PBNS_OK);
    uint8_t raw[FAKE_WIRE_CAP] = {0};
    const pbns_frame sent = decode_sent(&fixture.fake.sent[0], raw, sizeof(raw));
    assert(request_ids_equal(sent.request_id, request_id));
    assert(request_ids_equal(response.frame.request_id, request_id));
    assert(fixture.fake.random_calls == 0U);
    pbns_broker_reset(&fixture.broker);
}

static void test_caller_supplied_id_rejects_invalid_and_busy_requests(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    const pbns_request_id request_id = request_id_for_seed(UINT8_C(0x80));
    const pbns_request_id zero_request_id = {0};
    pbns_broker_response response = {.payload = {(const uint8_t *)"stale", 5U}};
    assert(make_request_with_id(&fixture, NULL, &response) == PBNS_ERR_ARGUMENT);
    assert(response.payload.ptr == NULL);
    assert(response.payload.len == 0U);
    assert(make_request_with_id(&fixture, &zero_request_id, &response) == PBNS_ERR_ARGUMENT);
    fixture.broker.active = true;
    assert(make_request_with_id(&fixture, &request_id, &response) == PBNS_ERR_BUSY);
    fixture.broker.active = false;
    assert(fixture.fake.random_calls == 0U);
    assert(fixture.fake.open_calls == 0U);
    assert(fixture.fake.send_count == 0U);
    pbns_broker_reset(&fixture.broker);
}

static void test_caller_supplied_id_rejects_replayed_response(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    const pbns_request_id first_request_id = request_id_for_seed(UINT8_C(0x80));
    const pbns_request_id second_request_id = request_id_for_seed(UINT8_C(0xa0));
    prepare_error(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, first_request_id, 17U,
                  PBNS_SERVICE_TRUSTED_TIME);

    pbns_broker_response response = {0};
    assert(make_request_with_id(&fixture, &first_request_id, &response) == PBNS_ERR_UNIMPLEMENTED);
    prepare_error(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, first_request_id, 17U,
                  PBNS_SERVICE_TRUSTED_TIME);
    assert(make_request_with_id(&fixture, &second_request_id, &response) == PBNS_ERR_STATE);
    assert(fixture.fake.random_calls == 0U);
    assert(fixture.fake.close_calls == 2U);
    assert(fixture.fake.live_resources == 0U);
    pbns_broker_reset(&fixture.broker);
}

static void test_legacy_request_rejects_all_zero_generated_id(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    fixture.fake.random_all_zero = true;
    pbns_broker_response response = {0};
    assert(make_request(&fixture, &response) == PBNS_ERR_ENTROPY);
    assert(fixture.fake.random_calls == 1U);
    assert(fixture.fake.open_calls == 0U);
    assert(fixture.fake.send_count == 0U);
    assert(request_ids_equal(fixture.broker.request_id, (pbns_request_id){0}));
    pbns_broker_reset(&fixture.broker);
}

static void test_open_precedes_limits_and_post_open_failures_close(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    fixture.fake.limits_require_open = true;
    fixture.fake.limits_status = PBNS_ERR_TRANSPORT;
    pbns_broker_response response = {0};
    assert(make_request(&fixture, &response) == PBNS_ERR_TRANSPORT);
    assert(strcmp(fixture.fake.order, "OLC") == 0);
    assert(fixture.fake.send_count == 0U && fixture.fake.live_resources == 0U);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    fixture.fake.limits_require_open = true;
    fixture.fake.limits.control_payload_max = 0U;
    assert(make_request(&fixture, &response) == PBNS_ERR_LIMIT);
    assert(strcmp(fixture.fake.order, "OLC") == 0);
    assert(fixture.fake.send_count == 0U && fixture.fake.live_resources == 0U);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    fixture.fake.limits_require_open = true;
    fixture.fake.limits.data_payload_max = 0U;
    const pbns_request_id request_id = request_id_for_seed(UINT8_C(0x80));
    assert(pbns_broker_bulk_begin(&fixture.broker, PBNS_SERVICE_RECOVERY_ARTIFACT,
                                  &request_id, (pbns_view){bulk_body, sizeof(bulk_body)},
                                  BULK_EXACT_SIZE, UINT32_C(5000)) == PBNS_ERR_LIMIT);
    assert(strcmp(fixture.fake.order, "OLC") == 0);
    assert(fixture.fake.send_count == 0U && fixture.fake.live_resources == 0U);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    uint8_t oversized_body[TEST_BUFFER_CAP] = {0};
    assert(pbns_broker_request(&fixture.broker, PBNS_SERVICE_TRUSTED_TIME,
                               (pbns_view){oversized_body, sizeof(oversized_body)},
                               UINT32_C(5000), &response) == PBNS_ERR_LIMIT);
    assert(strcmp(fixture.fake.order, "OLC") == 0);
    assert(fixture.fake.send_count == 0U && fixture.fake.live_resources == 0U);
    pbns_broker_reset(&fixture.broker);
}

static void test_correlated_unimplemented_lifecycle(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    prepare_error(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, request_id_for_seed(UINT8_C(0x10)), 17U,
                  PBNS_SERVICE_TRUSTED_TIME);

    pbns_broker_response response = {0};
    assert(make_request(&fixture, &response) == PBNS_ERR_UNIMPLEMENTED);
    assert(response.payload.ptr == NULL);
    assert(response.payload.len == 0U);
    assert(strcmp(fixture.fake.order, "OLSRC") == 0);
    assert(fixture.fake.random_calls == 1U);
    assert(fixture.fake.open_calls == 1U);
    assert(fixture.fake.close_calls == 1U);
    assert(fixture.fake.live_resources == 0U);
    assert(fixture.fake.send_count == 1U);
    pbns_broker_reset(&fixture.broker);
}

static void test_request_ids_are_fresh(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    prepare_error(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, request_id_for_seed(UINT8_C(0x10)), 17U,
                  PBNS_SERVICE_TRUSTED_TIME);
    pbns_broker_response response = {0};
    assert(make_request(&fixture, &response) == PBNS_ERR_UNIMPLEMENTED);

    prepare_error(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, request_id_for_seed(UINT8_C(0x30)), 17U,
                  PBNS_SERVICE_TRUSTED_TIME);
    assert(make_request(&fixture, &response) == PBNS_ERR_UNIMPLEMENTED);
    assert(fixture.fake.send_count == 2U);
    uint8_t first_raw[FAKE_WIRE_CAP] = {0};
    uint8_t second_raw[FAKE_WIRE_CAP] = {0};
    const pbns_frame first = decode_sent(&fixture.fake.sent[0], first_raw, sizeof(first_raw));
    const pbns_frame second = decode_sent(&fixture.fake.sent[1], second_raw, sizeof(second_raw));
    assert(!request_ids_equal(first.request_id, second.request_id));
    assert(fixture.fake.random_calls == 2U);
    pbns_broker_reset(&fixture.broker);
}

static void test_rng_and_clock_fail_before_open(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    fixture.fake.random_status = PBNS_ERR_ENTROPY;
    pbns_broker_response response = {0};
    assert(make_request(&fixture, &response) == PBNS_ERR_ENTROPY);
    assert(fixture.fake.open_calls == 0U);
    assert(fixture.fake.send_count == 0U);

    fixture.fake.random_status = PBNS_OK;
    fixture.fake.clock_status = PBNS_ERR_TRANSPORT;
    assert(make_request(&fixture, &response) == PBNS_ERR_TRANSPORT);
    assert(fixture.fake.open_calls == 0U);
    assert(fixture.fake.send_count == 0U);
    pbns_broker_reset(&fixture.broker);
}

static void test_rejects_wrong_request_and_service(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    pbns_request_id wrong_request = request_id_for_seed(UINT8_C(0x10));
    wrong_request.bytes[0] ^= UINT8_C(1);
    prepare_error(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, wrong_request, 17U,
                  PBNS_SERVICE_TRUSTED_TIME);
    pbns_broker_response response = {0};
    assert(make_request(&fixture, &response) == PBNS_ERR_STATE);
    assert(fixture.fake.close_calls == 1U);

    prepare_error(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, request_id_for_seed(UINT8_C(0x30)),
                  17U, PBNS_SERVICE_RECOVERY_ARTIFACT);
    assert(make_request(&fixture, &response) == PBNS_ERR_SERVICE);
    assert(fixture.fake.close_calls == 2U);
    assert(fixture.fake.live_resources == 0U);
    pbns_broker_reset(&fixture.broker);
}

static void test_fragmented_response_is_copied_to_owned_output(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    static const uint8_t payload[] = {UINT8_C(0xde), UINT8_C(0xad), UINT8_C(0xbe), UINT8_C(0xef)};
    prepare_incoming(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, PBNS_MESSAGE_RESPONSE,
                     request_id_for_seed(UINT8_C(0x10)), (pbns_view){payload, sizeof(payload)});
    fixture.fake.fragment_size = 1U;

    pbns_broker_response response = {0};
    assert(make_request(&fixture, &response) == PBNS_OK);
    assert(response.frame.type == PBNS_MESSAGE_RESPONSE);
    assert(response.payload.ptr == fixture.decoded);
    assert(response.payload.len == sizeof(payload));
    assert(memcmp(response.payload.ptr, payload, sizeof(payload)) == 0);
    assert(fixture.fake.receive_calls > 1U);
    assert(fixture.fake.live_resources == 0U);
    pbns_broker_reset(&fixture.broker);
}

static void test_absolute_deadline_cancels_fragmented_receive(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    static const uint8_t payload[] = {UINT8_C(1), UINT8_C(2), UINT8_C(3), UINT8_C(4)};
    prepare_incoming(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, PBNS_MESSAGE_RESPONSE,
                     request_id_for_seed(UINT8_C(0x10)), (pbns_view){payload, sizeof(payload)});
    fixture.fake.fragment_size = 1U;
    fixture.fake.clock_step_ms = 1U;

    pbns_broker_response response = {0};
    assert(pbns_broker_request(&fixture.broker, PBNS_SERVICE_TRUSTED_TIME, (pbns_view){NULL, 0U},
                               UINT32_C(4), &response) == PBNS_ERR_TIMEOUT);
    assert(fixture.fake.receive_calls > 0U);
    assert(fixture.fake.incoming_offset < fixture.fake.incoming_len);
    assert(fixture.fake.send_count == 2U);
    assert(fixture.fake.cancel_calls == 1U);
    assert(fixture.fake.close_calls == 1U);
    uint8_t raw[FAKE_WIRE_CAP] = {0};
    const pbns_frame cancel = decode_sent(&fixture.fake.sent[1], raw, sizeof(raw));
    assert(cancel.type == PBNS_MESSAGE_CANCEL);
    assert(cancel.sequence == UINT32_C(1));
    assert(request_ids_equal(cancel.request_id, request_id_for_seed(UINT8_C(0x10))));
    pbns_broker_reset(&fixture.broker);
}

static void test_transport_timeout_cancels_and_broker_is_reusable(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    fixture.fake.receive_status = PBNS_ERR_TIMEOUT;
    pbns_broker_response response = {0};
    assert(make_request(&fixture, &response) == PBNS_ERR_TIMEOUT);
    assert(fixture.fake.send_count == 2U);
    assert(fixture.fake.cancel_calls == 1U);
    assert(strcmp(fixture.fake.order, "OLSRSKC") == 0);
    assert(fixture.fake.live_resources == 0U);

    fixture.fake.receive_status = PBNS_OK;
    prepare_error(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, request_id_for_seed(UINT8_C(0x30)), 17U,
                  PBNS_SERVICE_TRUSTED_TIME);
    assert(make_request(&fixture, &response) == PBNS_ERR_UNIMPLEMENTED);
    assert(fixture.fake.close_calls == 2U);
    assert(fixture.fake.live_resources == 0U);
    pbns_broker_reset(&fixture.broker);
}

static void test_primary_protocol_status_survives_close_failure(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    static const uint8_t payload[] = {UINT8_C(0xa0)};
    prepare_incoming(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME,
                     PBNS_MESSAGE_RESPONSE,
                     request_id_for_seed(UINT8_C(0x10)),
                     (pbns_view){payload, sizeof(payload)});
    assert(fixture.fake.incoming_len > 4U);
    fixture.fake.incoming[fixture.fake.incoming_len / 2U] ^= UINT8_C(0x80);
    fixture.fake.close_status = PBNS_ERR_TRANSPORT;
    pbns_broker_response response = {0};
    assert(make_request(&fixture, &response) == PBNS_ERR_CRC);
    assert(response.payload.ptr == NULL && response.payload.len == 0U);
    for (size_t index = 0U; index < sizeof(fixture.decoded); ++index) {
        assert(fixture.decoded[index] == 0U);
    }
    assert(fixture.fake.close_calls == 1U && fixture.fake.live_resources == 0U);
    pbns_broker_reset(&fixture.broker);
}

static void test_primary_remote_status_survives_close_failure(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    prepare_error(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, request_id_for_seed(UINT8_C(0x10)), 17U,
                  PBNS_SERVICE_TRUSTED_TIME);
    fixture.fake.close_status = PBNS_ERR_TRANSPORT;
    pbns_broker_response response = {0};
    assert(make_request(&fixture, &response) == PBNS_ERR_UNIMPLEMENTED);
    assert(response.payload.ptr == NULL);
    assert(response.payload.len == 0U);
    assert(fixture.fake.close_calls == 1U);
    assert(fixture.fake.live_resources == 0U);
    pbns_broker_reset(&fixture.broker);
}

static void test_transport_loss_closes_without_retry(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    fixture.fake.receive_status = PBNS_ERR_TRANSPORT;
    pbns_broker_response response = {0};
    assert(make_request(&fixture, &response) == PBNS_ERR_TRANSPORT);
    assert(fixture.fake.open_calls == 1U);
    assert(fixture.fake.send_count == 1U);
    assert(fixture.fake.cancel_calls == 0U);
    assert(fixture.fake.close_calls == 1U);
    assert(fixture.fake.live_resources == 0U);
    pbns_broker_reset(&fixture.broker);
}

static void test_remote_error_validation_and_mapping(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    prepare_error(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, request_id_for_seed(UINT8_C(0x10)), 13U,
                  PBNS_SERVICE_TRUSTED_TIME);
    pbns_broker_response response = {0};
    assert(make_request(&fixture, &response) == PBNS_ERR_CRYPTO);

    prepare_error(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, request_id_for_seed(UINT8_C(0x30)), 17U,
                  PBNS_SERVICE_RECOVERY_ARTIFACT);
    assert(make_request(&fixture, &response) == PBNS_ERR_SERVICE);

    prepare_error(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, request_id_for_seed(UINT8_C(0x50)), 0U,
                  PBNS_SERVICE_TRUSTED_TIME);
    assert(make_request(&fixture, &response) == PBNS_ERR_FORMAT);
    pbns_broker_reset(&fixture.broker);
}

static void test_api_validation_and_repeated_reset(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    pbns_broker_response response = {.payload = {(const uint8_t *)"stale", 5U}};
    assert(pbns_broker_receive(&fixture.broker, &response) == PBNS_ERR_STATE);
    assert(response.payload.ptr == NULL);
    assert(response.payload.len == 0U);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_ERR_STATE);
    assert(pbns_broker_request(&fixture.broker, PBNS_SERVICE_INVALID, (pbns_view){NULL, 0U},
                               UINT32_C(1), &response) == PBNS_ERR_SERVICE);
    assert(pbns_broker_request(&fixture.broker, PBNS_SERVICE_TRUSTED_TIME, (pbns_view){NULL, 0U},
                               UINT32_C(0), &response) == PBNS_ERR_ARGUMENT);

    memset(fixture.encoded, 0xa5, sizeof(fixture.encoded));
    memset(fixture.raw, 0xa5, sizeof(fixture.raw));
    memset(fixture.receive, 0xa5, sizeof(fixture.receive));
    memset(fixture.decoded, 0xa5, sizeof(fixture.decoded));
    pbns_broker_reset(&fixture.broker);
    pbns_broker_reset(&fixture.broker);
    for (size_t index = 0U; index < sizeof(fixture.encoded); ++index) {
        assert(fixture.encoded[index] == 0U);
        assert(fixture.raw[index] == 0U);
        assert(fixture.decoded[index] == 0U);
    }
    for (size_t index = 0U; index < sizeof(fixture.receive); ++index) {
        assert(fixture.receive[index] == 0U);
    }

    pbns_broker broker = {0};
    pbns_broker_storage overlapping = fixture_storage(&fixture);
    overlapping.raw_scratch = overlapping.encoded;
    assert(pbns_broker_init(&broker, (pbns_transport){&fake_transport_ops, &fixture.fake},
                            (pbns_broker_platform){&fake_platform_ops, &fixture.fake},
                            overlapping) == PBNS_ERR_ARGUMENT);
    assert(pbns_broker_init(NULL, (pbns_transport){&fake_transport_ops, &fixture.fake},
                            (pbns_broker_platform){&fake_platform_ops, &fixture.fake},
                            fixture_storage(&fixture)) == PBNS_ERR_ARGUMENT);
}

static pbns_status bulk_begin(broker_fixture *fixture, const pbns_request_id *request_id,
                              uint64_t exact_size) {
    return pbns_broker_bulk_begin(&fixture->broker, PBNS_SERVICE_RECOVERY_ARTIFACT, request_id,
                                  (pbns_view){bulk_body, sizeof(bulk_body)}, exact_size,
                                  UINT32_C(5000));
}

static void append_bulk_data(fake_environment *fake, pbns_request_id request_id,
                             bulk_data_range range) {
    for (uint32_t offset = 0U; offset < range.count; ++offset) {
        const uint32_t sequence = range.first_sequence + offset;
        append_incoming(fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_DATA, request_id,
                        sequence, (pbns_view){bulk_data + sequence % BULK_DATA_RECORDS, 1U});
    }
}

static void receive_bulk_data(broker_fixture *fixture, uint32_t count) {
    pbns_broker_response response = {0};
    for (uint32_t index = 0U; index < count; ++index) {
        assert(pbns_broker_bulk_receive(&fixture->broker, &response) == PBNS_OK);
        assert(response.frame.type == PBNS_MESSAGE_DATA);
    }
}

static void assert_bulk_wiped(const broker_fixture *fixture) {
    assert(!fixture->broker.active && !fixture->broker.opened && !fixture->broker.bulk_mode &&
           !fixture->broker.bulk_failed && fixture->broker.bulk_exact_data_size == 0U &&
           fixture->broker.bulk_received_data_size == 0U &&
           fixture->broker.bulk_next_ack_sequence == 0U);
    for (size_t index = 0U; index < sizeof(fixture->broker.request_id.bytes); ++index) {
        assert(fixture->broker.request_id.bytes[index] == 0U);
    }
    for (size_t index = 0U; index < sizeof(fixture->encoded); ++index) {
        assert(fixture->encoded[index] == 0U && fixture->raw[index] == 0U &&
               fixture->decoded[index] == 0U);
    }
    for (size_t index = 0U; index < sizeof(fixture->receive); ++index) {
        assert(fixture->receive[index] == 0U);
    }
}

static void test_bulk_fragmented_session_ack_and_finish(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    fixture.fake.fragment_size = 3U;
    const pbns_request_id request_id = request_id_for_seed(UINT8_C(0x80));
    for (uint32_t sequence = 0U; sequence < BULK_DATA_RECORDS; ++sequence) {
        append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_DATA,
                        request_id, sequence, (pbns_view){bulk_data + sequence, 1U});
    }
    append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_COMPLETE,
                    request_id, BULK_DATA_RECORDS, (pbns_view){NULL, 0U});
    fixture.broker.request_id = request_id;
    assert(bulk_begin(&fixture, &fixture.broker.request_id, BULK_EXACT_SIZE) == PBNS_OK);
    assert(fixture.fake.random_calls == 0U);
    assert(fixture.fake.open_calls == 1U);
    uint8_t raw[FAKE_WIRE_CAP] = {0};
    const pbns_frame request = decode_sent(&fixture.fake.sent[0], raw, sizeof(raw));
    assert(request.type == PBNS_MESSAGE_REQUEST && request.sequence == 0U);
    assert(request_ids_equal(request.request_id, request_id));

    pbns_broker_response response = {0};
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_OK);
    assert(response.frame.type == PBNS_MESSAGE_DATA && response.frame.sequence == 0U);
    assert(response.payload.len == 1U && response.payload.ptr[0] == bulk_data[0]);
    assert(pbns_broker_bulk_ack(&fixture.broker, 0U, BULK_WINDOW) == PBNS_ERR_ARGUMENT);
    assert(pbns_broker_bulk_ack(&fixture.broker, 1U, BULK_WINDOW - 1U) == PBNS_ERR_ARGUMENT);
    assert(pbns_broker_bulk_ack(&fixture.broker, 1U, BULK_WINDOW) == PBNS_ERR_ARGUMENT);
    for (uint32_t sequence = 1U; sequence < BULK_DATA_RECORDS; ++sequence) {
        assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_OK);
        assert(response.frame.sequence == sequence && response.payload.len == 1U &&
               response.payload.ptr[0] == bulk_data[sequence]);
    }
    assert(pbns_broker_bulk_ack(&fixture.broker, BULK_DATA_RECORDS, BULK_WINDOW) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_OK);
    assert(response.frame.type == PBNS_MESSAGE_COMPLETE &&
           response.frame.sequence == BULK_DATA_RECORDS);
    assert(fixture.fake.close_calls == 0U);
    pbns_view ack_payload = {0};
    const pbns_frame ack0 =
        decode_sent_with_payload(&fixture.fake.sent[1], raw, sizeof(raw), &ack_payload);
    assert(ack0.type == PBNS_MESSAGE_ACK && ack0.sequence == 0U);
    assert(ack_payload.len == ACK_PAYLOAD_SIZE && ack_payload.ptr[0] == 0U &&
           ack_payload.ptr[3] == BULK_DATA_RECORDS && ack_payload.ptr[4] == 0U &&
           ack_payload.ptr[7] == BULK_WINDOW);
    assert(pbns_broker_bulk_ack(&fixture.broker, BULK_DATA_RECORDS + 1U, BULK_WINDOW) ==
           PBNS_ERR_STATE);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_STATE);
    assert(pbns_broker_bulk_finish(&fixture.broker) == PBNS_OK);
    assert(pbns_broker_bulk_ack(&fixture.broker, BULK_DATA_RECORDS + 1U, BULK_WINDOW) ==
           PBNS_ERR_STATE);
    assert(fixture.fake.close_calls == 1U && fixture.fake.live_resources == 0U);
    for (size_t index = 0U; index < sizeof(fixture.encoded); ++index) {
        assert(fixture.encoded[index] == 0U && fixture.raw[index] == 0U &&
               fixture.decoded[index] == 0U);
    }
    pbns_broker_reset(&fixture.broker);
}

static void test_bulk_ack_binds_each_window_once(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    const pbns_request_id request_id = request_id_for_seed(UINT8_C(0x80));
    const uint64_t exact_size = UINT64_C(16);
    for (uint32_t sequence = 0U; sequence < UINT32_C(16); ++sequence) {
        append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_DATA,
                        request_id, sequence,
                        (pbns_view){bulk_data + sequence % BULK_DATA_RECORDS, 1U});
    }
    append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_COMPLETE,
                    request_id, UINT32_C(16), (pbns_view){NULL, 0U});
    assert(bulk_begin(&fixture, &request_id, exact_size) == PBNS_OK);
    pbns_broker_response response = {0};
    for (uint32_t sequence = 0U; sequence < BULK_DATA_RECORDS; ++sequence) {
        assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_OK);
    }
    assert(pbns_broker_bulk_ack(&fixture.broker, BULK_DATA_RECORDS, BULK_WINDOW) == PBNS_OK);
    assert(pbns_broker_bulk_ack(&fixture.broker, BULK_DATA_RECORDS, BULK_WINDOW) ==
           PBNS_ERR_ARGUMENT);
    assert(pbns_broker_bulk_ack(&fixture.broker, UINT32_C(16), BULK_WINDOW) ==
           PBNS_ERR_ARGUMENT);
    for (uint32_t sequence = BULK_DATA_RECORDS; sequence < UINT32_C(16); ++sequence) {
        assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_OK);
    }
    assert(pbns_broker_bulk_ack(&fixture.broker, UINT32_C(16), BULK_WINDOW) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_OK);
    uint8_t raw[FAKE_WIRE_CAP] = {0};
    pbns_view payload = {0};
    const pbns_frame first_ack =
        decode_sent_with_payload(&fixture.fake.sent[1], raw, sizeof(raw), &payload);
    assert(first_ack.type == PBNS_MESSAGE_ACK && first_ack.sequence == 0U);
    assert(payload.len == ACK_PAYLOAD_SIZE && payload.ptr[3] == BULK_DATA_RECORDS);
    const pbns_frame second_ack =
        decode_sent_with_payload(&fixture.fake.sent[2], raw, sizeof(raw), &payload);
    assert(second_ack.type == PBNS_MESSAGE_ACK && second_ack.sequence == 1U);
    assert(payload.len == ACK_PAYLOAD_SIZE && payload.ptr[3] == UINT8_C(16));
    assert(pbns_broker_bulk_finish(&fixture.broker) == PBNS_OK);
    pbns_broker_reset(&fixture.broker);
}

static void test_bulk_rejects_invalid_begin_and_concurrent_request(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    const pbns_request_id request_id = request_id_for_seed(UINT8_C(0x80));
    const pbns_request_id zero_id = {0};
    pbns_broker_response response = {0};
    assert(bulk_begin(&fixture, NULL, BULK_EXACT_SIZE) == PBNS_ERR_ARGUMENT);
    assert(bulk_begin(&fixture, &zero_id, BULK_EXACT_SIZE) == PBNS_ERR_ARGUMENT);
    assert(bulk_begin(&fixture, &request_id, 0U) == PBNS_ERR_ARGUMENT);
    assert(pbns_broker_bulk_begin(&fixture.broker, PBNS_SERVICE_INVALID, &request_id,
                                  (pbns_view){bulk_body, sizeof(bulk_body)}, BULK_EXACT_SIZE,
                                  UINT32_C(1)) == PBNS_ERR_SERVICE);
    assert(pbns_broker_bulk_begin(&fixture.broker, PBNS_SERVICE_RECOVERY_ARTIFACT, &request_id,
                                  (pbns_view){NULL, 1U}, BULK_EXACT_SIZE,
                                  UINT32_C(1)) == PBNS_ERR_ARGUMENT);
    assert(fixture.fake.open_calls == 0U && fixture.fake.send_count == 0U);
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    assert(make_request(&fixture, &response) == PBNS_ERR_BUSY);
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_ERR_BUSY);
    assert(pbns_broker_bulk_finish(&fixture.broker) == PBNS_ERR_STATE);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    pbns_broker_reset(&fixture.broker);
}

static void test_bulk_rejects_bad_streams_and_requires_cancel(void) {
    const pbns_message_type invalid_types[] = {PBNS_MESSAGE_RESPONSE, PBNS_MESSAGE_REQUEST,
                                               PBNS_MESSAGE_ACK};
    const pbns_request_id request_id = request_id_for_seed(UINT8_C(0x80));
    for (size_t index = 0U; index < sizeof(invalid_types) / sizeof(invalid_types[0]); ++index) {
        broker_fixture fixture = {0};
        fixture_init(&fixture);
        const uint8_t ack_payload[ACK_PAYLOAD_SIZE] = {0U, 0U, 0U, 1U, 0U, 0U, 0U, 8U};
        const pbns_view payload = invalid_types[index] == PBNS_MESSAGE_ACK
                                      ? (pbns_view){ack_payload, sizeof(ack_payload)}
                                      : (pbns_view){NULL, 0U};
        prepare_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, invalid_types[index],
                         request_id, payload);
        assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
        pbns_broker_response response = {0};
        assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_MESSAGE_TYPE);
        assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_STATE);
        assert(pbns_broker_bulk_ack(&fixture.broker, 1U, BULK_WINDOW) == PBNS_ERR_STATE);
        assert(pbns_broker_bulk_finish(&fixture.broker) == PBNS_ERR_STATE);
        assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
        assert(fixture.fake.close_calls == 1U);
        pbns_broker_reset(&fixture.broker);
    }

    broker_fixture fixture = {0};
    fixture_init(&fixture);
    const pbns_request_id wrong_id = request_id_for_seed(UINT8_C(0xa0));
    append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_DATA, wrong_id,
                    0U, (pbns_view){bulk_data, 1U});
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    pbns_broker_response response = {0};
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_STATE);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    pbns_broker_reset(&fixture.broker);
}

static void test_bulk_rejects_sequence_and_exact_size_failures(void) {
    const pbns_request_id request_id = request_id_for_seed(UINT8_C(0x80));
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_DATA, request_id,
                    1U, (pbns_view){bulk_data, 1U});
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    pbns_broker_response response = {0};
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_SEQUENCE);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_DATA, request_id,
                    0U, (pbns_view){NULL, 0U});
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_FORMAT);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_COMPLETE,
                    request_id, 0U, (pbns_view){NULL, 0U});
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_LIMIT);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_DATA, request_id,
                    0U, (pbns_view){bulk_data, sizeof(bulk_data)});
    append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_DATA, request_id,
                    1U, (pbns_view){bulk_data, 1U});
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_LIMIT);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    pbns_broker_reset(&fixture.broker);
}

static void test_bulk_rejects_substitution_duplicate_and_receive_failure(void) {
    const pbns_request_id request_id = request_id_for_seed(UINT8_C(0x80));
    pbns_broker_response response = {0};
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    append_incoming(&fixture.fake, PBNS_SERVICE_TRUSTED_TIME, PBNS_MESSAGE_DATA, request_id, 0U,
                    (pbns_view){bulk_data, 1U});
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_SERVICE);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_DATA, request_id,
                    0U, (pbns_view){bulk_data, 1U});
    append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_DATA, request_id,
                    0U, (pbns_view){bulk_data, 1U});
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_SEQUENCE);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    static const uint8_t invalid_error[] = {UINT8_C(0xa0)};
    prepare_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_ERROR, request_id,
                     (pbns_view){invalid_error, sizeof(invalid_error)});
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_FORMAT);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    fixture.fake.receive_status = PBNS_ERR_TRANSPORT;
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_TRANSPORT);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    assert(fixture.fake.close_calls == 1U);
    pbns_broker_reset(&fixture.broker);
}

static void test_bulk_error_timeout_close_and_restart(void) {
    const pbns_request_id request_id = request_id_for_seed(UINT8_C(0x80));
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    prepare_error(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, request_id, 13U,
                  PBNS_SERVICE_RECOVERY_ARTIFACT);
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    pbns_broker_response response = {0};
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_CRYPTO);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    assert(fixture.fake.send_count == 2U && fixture.fake.cancel_calls == 1U);
    for (uint32_t sequence = 0U; sequence < BULK_DATA_RECORDS; ++sequence) {
        append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_DATA,
                        request_id, sequence, (pbns_view){bulk_data + sequence, 1U});
    }
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    uint8_t raw[FAKE_WIRE_CAP] = {0};
    assert(decode_sent(&fixture.fake.sent[2], raw, sizeof(raw)).sequence == 0U);
    for (uint32_t sequence = 0U; sequence < BULK_DATA_RECORDS; ++sequence) {
        assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_OK);
    }
    assert(pbns_broker_bulk_ack(&fixture.broker, BULK_DATA_RECORDS, BULK_WINDOW) == PBNS_OK);
    assert(decode_sent(&fixture.fake.sent[3], raw, sizeof(raw)).sequence == 0U);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    fixture.fake.now_ms = UINT64_C(1000);
    fixture.fake.clock_step_ms = UINT64_C(5000);
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_ERR_TIMEOUT);
    assert(fixture.fake.open_calls == 1U && fixture.fake.close_calls == 1U);
    fixture.fake.close_status = PBNS_ERR_TRANSPORT;
    fixture.fake.clock_step_ms = 0U;
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_ERR_TRANSPORT);
    pbns_broker_reset(&fixture.broker);
}

static void test_bulk_failed_active_deadline_and_ack_failures(void) {
    const pbns_request_id request_id = request_id_for_seed(UINT8_C(0x80));
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    fixture.fake.now_ms = fixture.broker.deadline_ms;
    pbns_broker_response response = {0};
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_TIMEOUT);
    assert(fixture.broker.active && fixture.broker.bulk_failed);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_STATE);
    assert(pbns_broker_bulk_ack(&fixture.broker, BULK_DATA_RECORDS, BULK_WINDOW) ==
           PBNS_ERR_STATE);
    assert(pbns_broker_bulk_finish(&fixture.broker) == PBNS_ERR_STATE);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    assert(fixture.fake.close_calls == 1U && fixture.fake.cancel_calls == 1U);
    assert_bulk_wiped(&fixture);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    append_bulk_data(&fixture.fake, request_id,
                     (bulk_data_range){.first_sequence = 0U, .count = BULK_DATA_RECORDS});
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    receive_bulk_data(&fixture, BULK_DATA_RECORDS);
    fixture.broker.storage.raw_scratch.cap = PBNS_FRAME_V1_HEADER_SIZE +
                                             PBNS_FRAME_V1_TRAILER_SIZE +
                                             PBNS_ACK_PAYLOAD_SIZE - 1U;
    assert(pbns_broker_bulk_ack(&fixture.broker, BULK_DATA_RECORDS, BULK_WINDOW) ==
           PBNS_ERR_LIMIT);
    assert(fixture.broker.active && fixture.broker.bulk_failed);
    fixture.broker.storage.raw_scratch.cap = sizeof(fixture.raw);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    assert(fixture.fake.cancel_calls == 1U && fixture.fake.close_calls == 1U);
    assert_bulk_wiped(&fixture);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    append_bulk_data(&fixture.fake, request_id,
                     (bulk_data_range){.first_sequence = 0U, .count = BULK_DATA_RECORDS});
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    receive_bulk_data(&fixture, BULK_DATA_RECORDS);
    fixture.fake.send_failure_call = 2U;
    assert(pbns_broker_bulk_ack(&fixture.broker, BULK_DATA_RECORDS, BULK_WINDOW) ==
           PBNS_ERR_TRANSPORT);
    assert(fixture.broker.active && fixture.broker.bulk_failed);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    assert(fixture.fake.send_calls == 3U && fixture.fake.cancel_calls == 1U &&
           fixture.fake.close_calls == 1U);
    assert_bulk_wiped(&fixture);
    pbns_broker_reset(&fixture.broker);
}

static void test_bulk_close_and_begin_failure_cleanup(void) {
    const pbns_request_id request_id = request_id_for_seed(UINT8_C(0x80));
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    append_bulk_data(&fixture.fake, request_id,
                     (bulk_data_range){.first_sequence = 0U, .count = BULK_DATA_RECORDS});
    append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_COMPLETE,
                    request_id, BULK_DATA_RECORDS, (pbns_view){NULL, 0U});
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    receive_bulk_data(&fixture, BULK_DATA_RECORDS);
    pbns_broker_response response = {0};
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_OK);
    fixture.fake.close_status = PBNS_ERR_TRANSPORT;
    assert(pbns_broker_bulk_finish(&fixture.broker) == PBNS_ERR_TRANSPORT);
    assert(fixture.fake.close_calls == 1U && fixture.fake.live_resources == 0U);
    assert_bulk_wiped(&fixture);
    fixture.fake.close_status = PBNS_OK;
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    uint8_t raw[FAKE_WIRE_CAP] = {0};
    assert(decode_sent(&fixture.fake.sent[1], raw, sizeof(raw)).sequence == 0U);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    append_bulk_data(&fixture.fake, request_id,
                     (bulk_data_range){.first_sequence = 0U, .count = BULK_DATA_RECORDS});
    append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_COMPLETE,
                    request_id, BULK_DATA_RECORDS, (pbns_view){NULL, 0U});
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    receive_bulk_data(&fixture, BULK_DATA_RECORDS);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_OK);
    assert(pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    assert(fixture.fake.send_count == 2U && fixture.fake.cancel_calls == 1U &&
           fixture.fake.close_calls == 1U);
    assert_bulk_wiped(&fixture);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    fixture.fake.open_status = PBNS_ERR_TRANSPORT;
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_ERR_TRANSPORT);
    assert(fixture.fake.open_calls == 1U && fixture.fake.close_calls == 0U &&
           fixture.fake.live_resources == 0U);
    assert_bulk_wiped(&fixture);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    fixture.fake.send_status = PBNS_ERR_TRANSPORT;
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_ERR_TRANSPORT);
    assert(fixture.fake.open_calls == 1U && fixture.fake.close_calls == 1U &&
           fixture.fake.live_resources == 0U);
    assert_bulk_wiped(&fixture);
    pbns_broker_reset(&fixture.broker);
}

static void test_bulk_protocol_boundaries_fail_active(void) {
    const pbns_request_id request_id = request_id_for_seed(UINT8_C(0x80));
    pbns_broker_response response = {0};
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    fixture.fake.limits.data_payload_max = 1U;
    append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_DATA, request_id,
                    0U, (pbns_view){bulk_data, 2U});
    assert(bulk_begin(&fixture, &request_id, 2U) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_LIMIT);
    assert(fixture.broker.bulk_failed && pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    assert_bulk_wiped(&fixture);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_DATA, request_id,
                    0U, (pbns_view){bulk_data, 1U});
    append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_COMPLETE,
                    request_id, 1U, (pbns_view){NULL, 0U});
    assert(bulk_begin(&fixture, &request_id, 2U) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_LIMIT);
    assert(fixture.broker.bulk_failed && pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    assert_bulk_wiped(&fixture);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    append_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_DATA, request_id,
                    0U, (pbns_view){bulk_data, 1U});
    --fixture.fake.incoming_len;
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_TIMEOUT);
    assert(fixture.broker.bulk_failed && pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    assert_bulk_wiped(&fixture);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    append_mutated_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, request_id, 0U,
                            (pbns_view){bulk_data, 1U},
                            (frame_mutation){.type = PBNS_MESSAGE_DATA, .flags = 1U});
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_FORMAT);
    assert(fixture.broker.bulk_failed && pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    assert_bulk_wiped(&fixture);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    append_mutated_incoming(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, request_id, 0U,
                            (pbns_view){bulk_data, 1U},
                            (frame_mutation){.type = PBNS_MESSAGE_COMPLETE, .flags = 0U});
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_FORMAT);
    assert(fixture.broker.bulk_failed && pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    assert_bulk_wiped(&fixture);
    pbns_broker_reset(&fixture.broker);

    fixture_init(&fixture);
    prepare_error(&fixture.fake, PBNS_SERVICE_RECOVERY_ARTIFACT, request_id, 13U,
                  PBNS_SERVICE_TRUSTED_TIME);
    assert(bulk_begin(&fixture, &request_id, BULK_EXACT_SIZE) == PBNS_OK);
    assert(pbns_broker_bulk_receive(&fixture.broker, &response) == PBNS_ERR_SERVICE);
    assert(fixture.broker.bulk_failed && pbns_broker_cancel(&fixture.broker) == PBNS_OK);
    assert_bulk_wiped(&fixture);
    pbns_broker_reset(&fixture.broker);
}

static void test_upload_streams_data_then_complete_and_receives_response(void) {
    broker_fixture fixture = {0};
    fixture_init(&fixture);
    const pbns_request_id request_id = request_id_for_seed(UINT8_C(0x90));
    static const uint8_t response_body[] = {UINT8_C(0xa1), UINT8_C(0x01), UINT8_C(0x02)};
    prepare_incoming(&fixture.fake, PBNS_SERVICE_PLATFORM_ATTESTATION,
                     PBNS_MESSAGE_RESPONSE, request_id,
                     (pbns_view){response_body, sizeof(response_body)});
    assert(pbns_broker_upload_begin(
               &fixture.broker, PBNS_SERVICE_PLATFORM_ATTESTATION, &request_id,
               (pbns_view){bulk_body, sizeof(bulk_body)}, UINT32_C(5000)) == PBNS_OK);
    pbns_broker_response response = {0};
    assert(pbns_broker_upload_send(
               &fixture.broker, (pbns_view){bulk_data, 3U}, false,
               &response) == PBNS_OK);
    assert(response.payload.ptr == NULL && fixture.fake.close_calls == 0U);
    assert(pbns_broker_upload_send(
               &fixture.broker, (pbns_view){bulk_data + 3U, 2U}, true,
               &response) == PBNS_OK);
    assert(response.frame.type == PBNS_MESSAGE_RESPONSE &&
           response.payload.len == sizeof(response_body) &&
           memcmp(response.payload.ptr, response_body, sizeof(response_body)) == 0);
    assert(fixture.fake.send_count == 4U && fixture.fake.close_calls == 0U);
    uint8_t raw[FAKE_WIRE_CAP] = {0};
    assert(decode_sent(&fixture.fake.sent[0], raw, sizeof(raw)).type ==
           PBNS_MESSAGE_REQUEST);
    const pbns_frame data0 = decode_sent(&fixture.fake.sent[1], raw, sizeof(raw));
    const pbns_frame data1 = decode_sent(&fixture.fake.sent[2], raw, sizeof(raw));
    const pbns_frame complete = decode_sent(&fixture.fake.sent[3], raw, sizeof(raw));
    assert(data0.type == PBNS_MESSAGE_DATA && data0.sequence == 0U &&
           data1.type == PBNS_MESSAGE_DATA && data1.sequence == 1U &&
           complete.type == PBNS_MESSAGE_COMPLETE && complete.sequence == 2U);
    assert(pbns_broker_upload_finish(&fixture.broker) == PBNS_OK);
    assert(fixture.fake.close_calls == 1U);
    pbns_broker_reset(&fixture.broker);
}

int main(void) {
    test_caller_supplied_id_is_encoded_and_correlates_response();
    test_caller_supplied_id_snapshots_broker_request_id();
    test_caller_supplied_id_snapshots_response_request_id();
    test_caller_supplied_id_rejects_invalid_and_busy_requests();
    test_caller_supplied_id_rejects_replayed_response();
    test_legacy_request_rejects_all_zero_generated_id();
    test_open_precedes_limits_and_post_open_failures_close();
    test_correlated_unimplemented_lifecycle();
    test_request_ids_are_fresh();
    test_rng_and_clock_fail_before_open();
    test_rejects_wrong_request_and_service();
    test_fragmented_response_is_copied_to_owned_output();
    test_absolute_deadline_cancels_fragmented_receive();
    test_transport_timeout_cancels_and_broker_is_reusable();
    test_primary_protocol_status_survives_close_failure();
    test_primary_remote_status_survives_close_failure();
    test_transport_loss_closes_without_retry();
    test_remote_error_validation_and_mapping();
    test_api_validation_and_repeated_reset();
    test_bulk_fragmented_session_ack_and_finish();
    test_bulk_ack_binds_each_window_once();
    test_bulk_rejects_invalid_begin_and_concurrent_request();
    test_bulk_rejects_bad_streams_and_requires_cancel();
    test_bulk_rejects_sequence_and_exact_size_failures();
    test_bulk_rejects_substitution_duplicate_and_receive_failure();
    test_bulk_error_timeout_close_and_restart();
    test_bulk_failed_active_deadline_and_ack_failures();
    test_bulk_close_and_begin_failure_cleanup();
    test_bulk_protocol_boundaries_fail_active();
    test_upload_streams_data_then_complete_and_receives_response();
    puts("broker tests passed");
    return 0;
}
