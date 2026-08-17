#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/stream.h"

static pbns_request_id request_id(uint8_t seed) {
    pbns_request_id request = {{0}};
    for (size_t index = 0U; index < sizeof(request.bytes); ++index) {
        request.bytes[index] = (uint8_t)(seed + (uint8_t)index);
    }
    return request;
}

static pbns_frame make_frame(pbns_service_id service,
                             pbns_message_type type,
                             pbns_request_id request,
                             uint32_t sequence) {
    return (pbns_frame){
        .service = service,
        .type = type,
        .flags = 0U,
        .request_id = request,
        .sequence = sequence,
    };
}

static void test_accepts_exact_progression_and_complete(void) {
    const pbns_request_id request = request_id(UINT8_C(0x10));
    pbns_stream_state state = {0};
    pbns_stream_init(&state, PBNS_SERVICE_RECOVERY_ARTIFACT, request, UINT64_C(5));
    static const uint8_t payload0[] = {0x01, 0x02, 0x03};
    static const uint8_t payload1[] = {0x04, 0x05};
    const pbns_frame data0 = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                        PBNS_MESSAGE_DATA,
                                        request,
                                        UINT32_C(0));
    const pbns_frame data1 = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                        PBNS_MESSAGE_DATA,
                                        request,
                                        UINT32_C(1));
    const pbns_frame complete = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                           PBNS_MESSAGE_COMPLETE,
                                           request,
                                           UINT32_C(2));

    assert(pbns_stream_accept(&state, &data0,
                              (pbns_view){payload0, sizeof(payload0)}) == PBNS_OK);
    assert(state.next_sequence == UINT32_C(1));
    assert(state.total_bytes == UINT64_C(3));
    assert(!state.complete);
    assert(!state.failed);

    assert(pbns_stream_accept(&state, &data1,
                              (pbns_view){payload1, sizeof(payload1)}) == PBNS_OK);
    assert(state.next_sequence == UINT32_C(2));
    assert(state.total_bytes == UINT64_C(5));
    assert(pbns_stream_accept(&state, &complete, (pbns_view){NULL, 0U}) == PBNS_OK);
    assert(state.next_sequence == UINT32_C(3));
    assert(state.total_bytes == UINT64_C(5));
    assert(state.complete);
    assert(!state.failed);
}

static void test_duplicate_sequence_fails_closed(void) {
    const pbns_request_id request = request_id(UINT8_C(0x20));
    pbns_stream_state state = {0};
    pbns_stream_init(&state, PBNS_SERVICE_RECOVERY_ARTIFACT,
                     request, UINT64_C(1048576));
    static const uint8_t payload[] = {0xaa};
    const pbns_frame data0 = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                        PBNS_MESSAGE_DATA,
                                        request,
                                        UINT32_C(0));
    const pbns_frame data1 = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                        PBNS_MESSAGE_DATA,
                                        request,
                                        UINT32_C(1));

    assert(pbns_stream_accept(&state, &data0,
                              (pbns_view){payload, sizeof(payload)}) == PBNS_OK);
    assert(pbns_stream_accept(&state, &data0,
                              (pbns_view){payload, sizeof(payload)})
           == PBNS_ERR_SEQUENCE);
    assert(state.failed);
    assert(pbns_stream_accept(&state, &data1,
                              (pbns_view){payload, sizeof(payload)}) == PBNS_ERR_STATE);
}

static void test_skipped_and_out_of_order_sequences_fail(void) {
    const pbns_request_id request = request_id(UINT8_C(0x30));
    static const uint8_t payload[] = {0xbb};
    const pbns_frame data0 = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                        PBNS_MESSAGE_DATA,
                                        request,
                                        UINT32_C(0));
    const pbns_frame data1 = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                        PBNS_MESSAGE_DATA,
                                        request,
                                        UINT32_C(1));
    const pbns_frame data2 = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                        PBNS_MESSAGE_DATA,
                                        request,
                                        UINT32_C(2));

    pbns_stream_state skipped = {0};
    pbns_stream_init(&skipped, PBNS_SERVICE_RECOVERY_ARTIFACT, request, UINT64_C(8));
    assert(pbns_stream_accept(&skipped, &data1,
                              (pbns_view){payload, sizeof(payload)})
           == PBNS_ERR_SEQUENCE);
    assert(skipped.failed);

    pbns_stream_state out_of_order = {0};
    pbns_stream_init(&out_of_order, PBNS_SERVICE_RECOVERY_ARTIFACT,
                     request, UINT64_C(8));
    assert(pbns_stream_accept(&out_of_order, &data0,
                              (pbns_view){payload, sizeof(payload)}) == PBNS_OK);
    assert(pbns_stream_accept(&out_of_order, &data2,
                              (pbns_view){payload, sizeof(payload)})
           == PBNS_ERR_SEQUENCE);
    assert(out_of_order.failed);
}

static void test_request_and_service_substitution_fail(void) {
    const pbns_request_id request = request_id(UINT8_C(0x40));
    const pbns_request_id substituted = request_id(UINT8_C(0x41));
    static const uint8_t payload[] = {0xcc};

    pbns_stream_state wrong_request = {0};
    pbns_stream_init(&wrong_request, PBNS_SERVICE_RECOVERY_ARTIFACT,
                     request, UINT64_C(8));
    const pbns_frame request_frame = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                                PBNS_MESSAGE_DATA,
                                                substituted,
                                                UINT32_C(0));
    assert(pbns_stream_accept(&wrong_request, &request_frame,
                              (pbns_view){payload, sizeof(payload)}) == PBNS_ERR_STATE);
    assert(wrong_request.failed);

    pbns_stream_state wrong_service = {0};
    pbns_stream_init(&wrong_service, PBNS_SERVICE_RECOVERY_ARTIFACT,
                     request, UINT64_C(8));
    const pbns_frame service_frame = make_frame(PBNS_SERVICE_TRUSTED_TIME,
                                                PBNS_MESSAGE_DATA,
                                                request,
                                                UINT32_C(0));
    assert(pbns_stream_accept(&wrong_service, &service_frame,
                              (pbns_view){payload, sizeof(payload)}) == PBNS_ERR_SERVICE);
    assert(wrong_service.failed);
}

static void test_byte_limit_and_total_overflow_fail_without_progress(void) {
    const pbns_request_id request = request_id(UINT8_C(0x50));
    static const uint8_t payload[] = {0x01, 0x02};
    const pbns_frame data0 = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                        PBNS_MESSAGE_DATA,
                                        request,
                                        UINT32_C(0));

    pbns_stream_state bounded = {0};
    pbns_stream_init(&bounded, PBNS_SERVICE_RECOVERY_ARTIFACT, request, UINT64_C(1));
    assert(pbns_stream_accept(&bounded, &data0,
                              (pbns_view){payload, sizeof(payload)}) == PBNS_ERR_LIMIT);
    assert(bounded.failed);
    assert(bounded.total_bytes == UINT64_C(0));
    assert(bounded.next_sequence == UINT32_C(0));

    pbns_stream_state overflowing = {0};
    pbns_stream_init(&overflowing, PBNS_SERVICE_RECOVERY_ARTIFACT,
                     request, UINT64_MAX);
    overflowing.total_bytes = UINT64_MAX - UINT64_C(1);
    assert(pbns_stream_accept(&overflowing, &data0,
                              (pbns_view){payload, sizeof(payload)}) == PBNS_ERR_LIMIT);
    assert(overflowing.failed);
    assert(overflowing.total_bytes == UINT64_MAX - UINT64_C(1));
    assert(overflowing.next_sequence == UINT32_C(0));
}

static void test_data_after_complete_fails_closed(void) {
    const pbns_request_id request = request_id(UINT8_C(0x60));
    static const uint8_t payload[] = {0xdd};
    pbns_stream_state state = {0};
    pbns_stream_init(&state, PBNS_SERVICE_RECOVERY_ARTIFACT, request, UINT64_C(8));
    const pbns_frame complete = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                           PBNS_MESSAGE_COMPLETE,
                                           request,
                                           UINT32_C(0));
    const pbns_frame data = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                       PBNS_MESSAGE_DATA,
                                       request,
                                       UINT32_C(1));
    assert(pbns_stream_accept(&state, &complete, (pbns_view){NULL, 0U}) == PBNS_OK);
    assert(state.complete);
    assert(pbns_stream_accept(&state, &data,
                              (pbns_view){payload, sizeof(payload)}) == PBNS_ERR_STATE);
    assert(state.failed);
}

static void test_ack_payload_validation(void) {
    const pbns_request_id request = request_id(UINT8_C(0x70));
    static const uint8_t valid_ack[PBNS_ACK_PAYLOAD_SIZE] = {
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08,
    };
    static const uint8_t zero_sequence[PBNS_ACK_PAYLOAD_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
    };
    static const uint8_t zero_window[PBNS_ACK_PAYLOAD_SIZE] = {
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    };
    const pbns_frame ack = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                      PBNS_MESSAGE_ACK,
                                      request,
                                      UINT32_C(0));

    pbns_stream_state valid = {0};
    pbns_stream_init(&valid, PBNS_SERVICE_RECOVERY_ARTIFACT,
                     request, PBNS_ACK_PAYLOAD_SIZE);
    assert(pbns_stream_accept(&valid, &ack,
                              (pbns_view){valid_ack, sizeof(valid_ack)}) == PBNS_OK);
    assert(valid.total_bytes == PBNS_ACK_PAYLOAD_SIZE);

    pbns_stream_state short_ack = {0};
    pbns_stream_init(&short_ack, PBNS_SERVICE_RECOVERY_ARTIFACT, request, UINT64_C(8));
    assert(pbns_stream_accept(&short_ack, &ack,
                              (pbns_view){valid_ack, sizeof(valid_ack) - 1U})
           == PBNS_ERR_FORMAT);
    assert(short_ack.failed);

    pbns_stream_state bad_sequence = {0};
    pbns_stream_init(&bad_sequence, PBNS_SERVICE_RECOVERY_ARTIFACT,
                     request, UINT64_C(8));
    assert(pbns_stream_accept(&bad_sequence, &ack,
                              (pbns_view){zero_sequence, sizeof(zero_sequence)})
           == PBNS_ERR_FORMAT);
    assert(bad_sequence.failed);

    pbns_stream_state bad_window = {0};
    pbns_stream_init(&bad_window, PBNS_SERVICE_RECOVERY_ARTIFACT,
                     request, UINT64_C(8));
    assert(pbns_stream_accept(&bad_window, &ack,
                              (pbns_view){zero_window, sizeof(zero_window)})
           == PBNS_ERR_FORMAT);
    assert(bad_window.failed);
}

static void test_terminal_payload_and_message_validation(void) {
    const pbns_request_id request = request_id(UINT8_C(0x80));
    static const uint8_t payload[] = {0xee};
    const pbns_frame bad_complete = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                               PBNS_MESSAGE_COMPLETE,
                                               request,
                                               UINT32_C(0));
    pbns_stream_state complete_state = {0};
    pbns_stream_init(&complete_state, PBNS_SERVICE_RECOVERY_ARTIFACT,
                     request, UINT64_C(8));
    assert(pbns_stream_accept(&complete_state, &bad_complete,
                              (pbns_view){payload, sizeof(payload)}) == PBNS_ERR_FORMAT);
    assert(complete_state.failed);

    const pbns_frame cancel = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                         PBNS_MESSAGE_CANCEL,
                                         request,
                                         UINT32_C(0));
    pbns_stream_state cancel_state = {0};
    pbns_stream_init(&cancel_state, PBNS_SERVICE_RECOVERY_ARTIFACT,
                     request, UINT64_C(8));
    assert(pbns_stream_accept(&cancel_state, &cancel,
                              (pbns_view){NULL, 0U}) == PBNS_OK);
    assert(cancel_state.complete);

    const pbns_frame error = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                        PBNS_MESSAGE_ERROR,
                                        request,
                                        UINT32_C(0));
    pbns_stream_state error_state = {0};
    pbns_stream_init(&error_state, PBNS_SERVICE_RECOVERY_ARTIFACT,
                     request, UINT64_C(8));
    assert(pbns_stream_accept(&error_state, &error,
                              (pbns_view){payload, sizeof(payload)}) == PBNS_OK);
    assert(error_state.complete);

    pbns_frame bad_type = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                     PBNS_MESSAGE_INVALID,
                                     request,
                                     UINT32_C(0));
    pbns_stream_state type_state = {0};
    pbns_stream_init(&type_state, PBNS_SERVICE_RECOVERY_ARTIFACT,
                     request, UINT64_C(8));
    assert(pbns_stream_accept(&type_state, &bad_type,
                              (pbns_view){NULL, 0U}) == PBNS_ERR_MESSAGE_TYPE);
    assert(type_state.failed);

    pbns_frame bad_flags = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                      PBNS_MESSAGE_DATA,
                                      request,
                                      UINT32_C(0));
    bad_flags.flags = UINT8_C(1);
    pbns_stream_state flags_state = {0};
    pbns_stream_init(&flags_state, PBNS_SERVICE_RECOVERY_ARTIFACT,
                     request, UINT64_C(8));
    assert(pbns_stream_accept(&flags_state, &bad_flags,
                              (pbns_view){payload, sizeof(payload)}) == PBNS_ERR_FORMAT);
    assert(flags_state.failed);
}

static void test_sequence_wrap_is_rejected(void) {
    const pbns_request_id request = request_id(UINT8_C(0x90));
    static const uint8_t payload[] = {0xff};
    pbns_stream_state state = {0};
    pbns_stream_init(&state, PBNS_SERVICE_RECOVERY_ARTIFACT, request, UINT64_C(8));
    state.next_sequence = UINT32_MAX;
    const pbns_frame frame = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                        PBNS_MESSAGE_DATA,
                                        request,
                                        UINT32_MAX);
    assert(pbns_stream_accept(&state, &frame,
                              (pbns_view){payload, sizeof(payload)})
           == PBNS_ERR_SEQUENCE);
    assert(state.failed);
    assert(state.next_sequence == UINT32_MAX);
}

static void test_reset_preserves_binding_and_policy(void) {
    const pbns_request_id request = request_id(UINT8_C(0xa0));
    static const uint8_t payload[] = {0x11};
    pbns_stream_state state = {0};
    pbns_stream_init(&state, PBNS_SERVICE_RECOVERY_ARTIFACT, request, UINT64_C(8));
    const pbns_frame skipped = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                          PBNS_MESSAGE_DATA,
                                          request,
                                          UINT32_C(1));
    const pbns_frame data0 = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                        PBNS_MESSAGE_DATA,
                                        request,
                                        UINT32_C(0));
    assert(pbns_stream_accept(&state, &skipped,
                              (pbns_view){payload, sizeof(payload)})
           == PBNS_ERR_SEQUENCE);
    pbns_stream_reset(&state);
    assert(state.initialized);
    assert(!state.failed);
    assert(!state.complete);
    assert(state.next_sequence == UINT32_C(0));
    assert(state.total_bytes == UINT64_C(0));
    assert(state.service == PBNS_SERVICE_RECOVERY_ARTIFACT);
    assert(state.byte_limit == UINT64_C(8));
    assert(memcmp(state.request_id.bytes, request.bytes, sizeof(request.bytes)) == 0);
    assert(pbns_stream_accept(&state, &data0,
                              (pbns_view){payload, sizeof(payload)}) == PBNS_OK);
}

static void test_invalid_arguments_and_initialization(void) {
    const pbns_request_id request = request_id(UINT8_C(0xb0));
    static const uint8_t payload[] = {0x22};
    const pbns_frame data0 = make_frame(PBNS_SERVICE_RECOVERY_ARTIFACT,
                                        PBNS_MESSAGE_DATA,
                                        request,
                                        UINT32_C(0));
    pbns_stream_state state = {0};

    pbns_stream_init(NULL, PBNS_SERVICE_RECOVERY_ARTIFACT, request, UINT64_C(8));
    pbns_stream_reset(NULL);
    pbns_stream_reset(&state);
    assert(pbns_stream_accept(&state, &data0,
                              (pbns_view){payload, sizeof(payload)}) == PBNS_ERR_STATE);

    pbns_stream_init(&state, PBNS_SERVICE_INVALID, request, UINT64_C(8));
    assert(!state.initialized);
    assert(pbns_stream_accept(&state, &data0,
                              (pbns_view){payload, sizeof(payload)}) == PBNS_ERR_STATE);

    pbns_stream_init(&state, PBNS_SERVICE_RECOVERY_ARTIFACT, request, UINT64_C(8));
    assert(pbns_stream_accept(NULL, &data0,
                              (pbns_view){payload, sizeof(payload)}) == PBNS_ERR_ARGUMENT);
    assert(pbns_stream_accept(&state, NULL,
                              (pbns_view){payload, sizeof(payload)}) == PBNS_ERR_ARGUMENT);
    assert(pbns_stream_accept(&state, &data0,
                              (pbns_view){NULL, 1U}) == PBNS_ERR_ARGUMENT);
    assert(!state.failed);
}

int main(void) {
    test_accepts_exact_progression_and_complete();
    test_duplicate_sequence_fails_closed();
    test_skipped_and_out_of_order_sequences_fail();
    test_request_and_service_substitution_fail();
    test_byte_limit_and_total_overflow_fail_without_progress();
    test_data_after_complete_fails_closed();
    test_ack_payload_validation();
    test_terminal_payload_and_message_validation();
    test_sequence_wrap_is_rejected();
    test_reset_preserves_binding_and_policy();
    test_invalid_arguments_and_initialization();
    return 0;
}
