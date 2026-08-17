#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/cobs.h"
#include "pbns/crc32c.h"
#include "pbns/frame.h"

static const uint8_t golden_empty_request[] = {
    0x08, 0x50, 0x42, 0x4e, 0x53, 0x01, 0x01, 0x01, 0x01, 0x10, 0x01, 0x02,
    0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x08, 0xfd,
    0xca, 0xa5, 0xd2, 0x03, 0xcd, 0x38, 0x01, 0x00,
};

static pbns_frame_limits default_limits(void) {
    return (pbns_frame_limits){
        .control_payload_max = PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX,
        .data_payload_max = PBNS_FRAME_V1_DATA_PAYLOAD_MAX,
        .encoded_record_max = PBNS_FRAME_V1_WIRE_MAX,
    };
}

static pbns_frame empty_request(void) {
    pbns_frame frame = {
        .service = PBNS_SERVICE_TRUSTED_TIME,
        .type = PBNS_MESSAGE_REQUEST,
        .flags = 0U,
        .request_id = {{0}},
        .sequence = 0U,
    };
    for (size_t index = 0U; index < sizeof(frame.request_id.bytes); ++index) {
        frame.request_id.bytes[index] = (uint8_t)index;
    }
    return frame;
}

static void write_u32_be(uint8_t *destination, uint32_t value) {
    destination[0] = (uint8_t)(value >> 24U);
    destination[1] = (uint8_t)(value >> 16U);
    destination[2] = (uint8_t)(value >> 8U);
    destination[3] = (uint8_t)value;
}

static void refresh_raw_crc(uint8_t *raw, size_t raw_len) {
    assert(raw_len >= PBNS_FRAME_V1_HEADER_SIZE + PBNS_FRAME_V1_TRAILER_SIZE);
    write_u32_be(raw + 32U, pbns_crc32c((pbns_view){raw, 32U}));
    write_u32_be(raw + raw_len - PBNS_FRAME_V1_TRAILER_SIZE,
                 pbns_crc32c((pbns_view){raw, raw_len - PBNS_FRAME_V1_TRAILER_SIZE}));
}

static size_t encode_empty(uint8_t *raw, size_t raw_cap, uint8_t *wire, size_t wire_cap) {
    const pbns_frame frame = empty_request();
    size_t written = 0U;
    assert(pbns_frame_encode(&frame,
                             (pbns_view){NULL, 0U},
                             (pbns_buffer){raw, 0U, raw_cap},
                             (pbns_buffer){wire, 0U, wire_cap},
                             &written) == PBNS_OK);
    return written;
}

static size_t unwrap_wire(const uint8_t *wire,
                          size_t wire_len,
                          uint8_t *raw,
                          size_t raw_cap) {
    assert(wire_len > 0U);
    assert(wire[wire_len - 1U] == UINT8_C(0));
    size_t written = 0U;
    assert(pbns_cobs_decode((pbns_view){wire, wire_len - 1U},
                            (pbns_buffer){raw, 0U, raw_cap},
                            &written) == PBNS_OK);
    return written;
}

static size_t wrap_raw(const uint8_t *raw,
                       size_t raw_len,
                       uint8_t *wire,
                       size_t wire_cap) {
    assert(wire_cap > 0U);
    size_t written = 0U;
    assert(pbns_cobs_encode((pbns_view){raw, raw_len},
                            (pbns_buffer){wire, 0U, wire_cap - 1U},
                            &written) == PBNS_OK);
    wire[written] = UINT8_C(0);
    return written + 1U;
}

static pbns_status decode_wire(const uint8_t *wire,
                               size_t wire_len,
                               pbns_frame_limits limits,
                               uint8_t *scratch,
                               size_t scratch_cap) {
    pbns_frame frame = {0};
    pbns_view payload = {0};
    assert(wire_len > 0U);
    return pbns_frame_decode((pbns_view){wire, wire_len - 1U},
                             limits,
                             (pbns_buffer){scratch, 0U, scratch_cap},
                             &frame,
                             &payload);
}

static void test_empty_request_matches_golden_vector(void) {
    uint8_t raw[PBNS_FRAME_V1_HEADER_SIZE + PBNS_FRAME_V1_TRAILER_SIZE] = {0};
    uint8_t wire[sizeof(golden_empty_request)] = {0};
    uint8_t decode_scratch[sizeof(raw)] = {0};
    const size_t written = encode_empty(raw, sizeof(raw), wire, sizeof(wire));

    assert(written == sizeof(golden_empty_request));
    assert(memcmp(wire, golden_empty_request, sizeof(wire)) == 0);

    pbns_frame decoded = {0};
    pbns_view payload = {0};
    assert(pbns_frame_decode((pbns_view){wire, written - 1U},
                             default_limits(),
                             (pbns_buffer){decode_scratch, 0U, sizeof(decode_scratch)},
                             &decoded,
                             &payload) == PBNS_OK);
    assert(decoded.service == PBNS_SERVICE_TRUSTED_TIME);
    assert(decoded.type == PBNS_MESSAGE_REQUEST);
    assert(decoded.sequence == 0U);
    assert(memcmp(decoded.request_id.bytes, empty_request().request_id.bytes,
                  sizeof(decoded.request_id.bytes)) == 0);
    assert(payload.len == 0U);
}

static void test_maximum_data_frame_round_trip(void) {
    static uint8_t payload[PBNS_FRAME_V1_DATA_PAYLOAD_MAX] = {0};
    static uint8_t raw[PBNS_FRAME_V1_HEADER_SIZE + PBNS_FRAME_V1_DATA_PAYLOAD_MAX
                       + PBNS_FRAME_V1_TRAILER_SIZE] = {0};
    static uint8_t wire[PBNS_FRAME_V1_WIRE_MAX] = {0};
    static uint8_t decode_scratch[sizeof(raw)] = {0};
    pbns_frame frame = empty_request();
    frame.service = PBNS_SERVICE_RECOVERY_ARTIFACT;
    frame.type = PBNS_MESSAGE_DATA;
    frame.sequence = 7U;
    size_t written = 0U;

    for (size_t index = 0U; index < sizeof(payload); ++index) {
        payload[index] = (uint8_t)index;
    }
    assert(pbns_frame_encode(&frame,
                             (pbns_view){payload, sizeof(payload)},
                             (pbns_buffer){raw, 0U, sizeof(raw)},
                             (pbns_buffer){wire, 0U, sizeof(wire)},
                             &written) == PBNS_OK);

    pbns_frame decoded = {0};
    pbns_view decoded_payload = {0};
    assert(pbns_frame_decode((pbns_view){wire, written - 1U},
                             default_limits(),
                             (pbns_buffer){decode_scratch, 0U, sizeof(decode_scratch)},
                             &decoded,
                             &decoded_payload) == PBNS_OK);
    assert(decoded.service == frame.service);
    assert(decoded.type == frame.type);
    assert(decoded.sequence == frame.sequence);
    assert(decoded_payload.len == sizeof(payload));
    assert(memcmp(decoded_payload.ptr, payload, sizeof(payload)) == 0);
}

static void test_rejects_invalid_encode_arguments_and_semantics(void) {
    uint8_t storage[PBNS_FRAME_V1_WIRE_MAX] = {0};
    pbns_frame frame = empty_request();
    size_t written = 99U;
    static const uint8_t one_byte[] = {0x42};
    static const uint8_t zero_window_ack[PBNS_ACK_PAYLOAD_SIZE] = {
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    };
    static const uint8_t zero_sequence_ack[PBNS_ACK_PAYLOAD_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };

    assert(pbns_frame_encode(NULL, (pbns_view){NULL, 0U},
                             (pbns_buffer){storage, 0U, sizeof(storage)},
                             (pbns_buffer){storage, 0U, sizeof(storage)},
                             &written) == PBNS_ERR_ARGUMENT);
    frame.type = PBNS_MESSAGE_CANCEL;
    assert(pbns_frame_encode(&frame, (pbns_view){one_byte, sizeof(one_byte)},
                             (pbns_buffer){storage, 0U, sizeof(storage)},
                             (pbns_buffer){storage + 128U, 0U, sizeof(storage) - 128U},
                             &written) == PBNS_ERR_FORMAT);
    frame.type = PBNS_MESSAGE_ACK;
    assert(pbns_frame_encode(&frame, (pbns_view){one_byte, sizeof(one_byte)},
                             (pbns_buffer){storage, 0U, sizeof(storage)},
                             (pbns_buffer){storage + 128U, 0U, sizeof(storage) - 128U},
                             &written) == PBNS_ERR_FORMAT);
    assert(pbns_frame_encode(&frame,
                             (pbns_view){zero_window_ack, sizeof(zero_window_ack)},
                             (pbns_buffer){storage, 0U, sizeof(storage)},
                             (pbns_buffer){storage + 128U, 0U, sizeof(storage) - 128U},
                             &written) == PBNS_ERR_FORMAT);
    assert(pbns_frame_encode(&frame,
                             (pbns_view){zero_sequence_ack, sizeof(zero_sequence_ack)},
                             (pbns_buffer){storage, 0U, sizeof(storage)},
                             (pbns_buffer){storage + 128U, 0U, sizeof(storage) - 128U},
                             &written) == PBNS_ERR_FORMAT);
    frame.type = PBNS_MESSAGE_DATA;
    assert(pbns_frame_encode(&frame,
                             (pbns_view){one_byte, PBNS_FRAME_V1_DATA_PAYLOAD_MAX + 1U},
                             (pbns_buffer){storage, 0U, sizeof(storage)},
                             (pbns_buffer){storage + 128U, 0U, sizeof(storage) - 128U},
                             &written) == PBNS_ERR_LIMIT);
}

static void test_rejects_short_and_overlapping_encode_buffers(void) {
    uint8_t raw[PBNS_FRAME_V1_HEADER_SIZE + PBNS_FRAME_V1_TRAILER_SIZE] = {0};
    uint8_t wire[sizeof(golden_empty_request) - 1U] = {0};
    uint8_t shared[128] = {0};
    uint8_t separate_output[128] = {0};
    pbns_frame frame = empty_request();
    size_t written = 99U;

    assert(pbns_frame_encode(&frame, (pbns_view){NULL, 0U},
                             (pbns_buffer){raw, 0U, sizeof(raw) - 1U},
                             (pbns_buffer){wire, 0U, sizeof(wire)},
                             &written) == PBNS_ERR_LIMIT);
    assert(written == 0U);
    assert(pbns_frame_encode(&frame, (pbns_view){NULL, 0U},
                             (pbns_buffer){raw, 0U, sizeof(raw)},
                             (pbns_buffer){wire, 0U, sizeof(wire)},
                             &written) == PBNS_ERR_LIMIT);
    assert(written == 0U);
    assert(pbns_frame_encode(&frame, (pbns_view){NULL, 0U},
                             (pbns_buffer){shared, 0U, sizeof(shared)},
                             (pbns_buffer){shared, 0U, sizeof(shared)},
                             &written) == PBNS_ERR_ARGUMENT);
    frame.type = PBNS_MESSAGE_REQUEST;
    assert(pbns_frame_encode(&frame, (pbns_view){shared + 10U, 1U},
                             (pbns_buffer){shared, 0U, sizeof(shared)},
                             (pbns_buffer){separate_output, 0U, sizeof(separate_output)},
                             &written) == PBNS_ERR_ARGUMENT);
}

static void test_rejects_header_field_errors_after_valid_crc(void) {
    uint8_t raw[64] = {0};
    uint8_t wire[128] = {0};
    uint8_t scratch[64] = {0};
    uint8_t encoded[128] = {0};
    const size_t wire_len = encode_empty(raw, 40U, wire, sizeof(wire));
    const size_t raw_len = unwrap_wire(wire, wire_len, raw, sizeof(raw));

    raw[0] = (uint8_t)'X';
    refresh_raw_crc(raw, raw_len);
    size_t encoded_len = wrap_raw(raw, raw_len, encoded, sizeof(encoded));
    assert(decode_wire(encoded, encoded_len, default_limits(), scratch, sizeof(scratch))
           == PBNS_ERR_FORMAT);

    unwrap_wire(wire, wire_len, raw, sizeof(raw));
    raw[4] = UINT8_C(2);
    refresh_raw_crc(raw, raw_len);
    encoded_len = wrap_raw(raw, raw_len, encoded, sizeof(encoded));
    assert(decode_wire(encoded, encoded_len, default_limits(), scratch, sizeof(scratch))
           == PBNS_ERR_VERSION);

    unwrap_wire(wire, wire_len, raw, sizeof(raw));
    raw[5] = UINT8_C(99);
    refresh_raw_crc(raw, raw_len);
    encoded_len = wrap_raw(raw, raw_len, encoded, sizeof(encoded));
    assert(decode_wire(encoded, encoded_len, default_limits(), scratch, sizeof(scratch))
           == PBNS_ERR_SERVICE);

    unwrap_wire(wire, wire_len, raw, sizeof(raw));
    raw[6] = UINT8_C(99);
    refresh_raw_crc(raw, raw_len);
    encoded_len = wrap_raw(raw, raw_len, encoded, sizeof(encoded));
    assert(decode_wire(encoded, encoded_len, default_limits(), scratch, sizeof(scratch))
           == PBNS_ERR_MESSAGE_TYPE);

    unwrap_wire(wire, wire_len, raw, sizeof(raw));
    raw[7] = UINT8_C(1);
    refresh_raw_crc(raw, raw_len);
    encoded_len = wrap_raw(raw, raw_len, encoded, sizeof(encoded));
    assert(decode_wire(encoded, encoded_len, default_limits(), scratch, sizeof(scratch))
           == PBNS_ERR_FORMAT);
}

static void test_header_crc_precedes_payload_length_use(void) {
    uint8_t raw[64] = {0};
    uint8_t wire[128] = {0};
    uint8_t scratch[64] = {0};
    uint8_t encoded[128] = {0};
    const size_t wire_len = encode_empty(raw, 40U, wire, sizeof(wire));
    const size_t raw_len = unwrap_wire(wire, wire_len, raw, sizeof(raw));

    raw[32] ^= UINT8_C(1);
    size_t encoded_len = wrap_raw(raw, raw_len, encoded, sizeof(encoded));
    assert(decode_wire(encoded, encoded_len, default_limits(), scratch, sizeof(scratch))
           == PBNS_ERR_CRC);

    unwrap_wire(wire, wire_len, raw, sizeof(raw));
    write_u32_be(raw + 28U, PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX + 1U);
    refresh_raw_crc(raw, raw_len);
    encoded_len = wrap_raw(raw, raw_len, encoded, sizeof(encoded));
    assert(decode_wire(encoded, encoded_len, default_limits(), scratch, sizeof(scratch))
           == PBNS_ERR_LIMIT);
}

static void test_rejects_size_record_crc_and_delimiter_errors(void) {
    uint8_t raw[64] = {0};
    uint8_t wire[128] = {0};
    uint8_t scratch[64] = {0};
    uint8_t encoded[128] = {0};
    const size_t wire_len = encode_empty(raw, 40U, wire, sizeof(wire));
    const size_t raw_len = unwrap_wire(wire, wire_len, raw, sizeof(raw));

    write_u32_be(raw + 28U, UINT32_C(1));
    refresh_raw_crc(raw, raw_len);
    size_t encoded_len = wrap_raw(raw, raw_len, encoded, sizeof(encoded));
    assert(decode_wire(encoded, encoded_len, default_limits(), scratch, sizeof(scratch))
           == PBNS_ERR_FORMAT);

    unwrap_wire(wire, wire_len, raw, sizeof(raw));
    raw[raw_len - 1U] ^= UINT8_C(1);
    encoded_len = wrap_raw(raw, raw_len, encoded, sizeof(encoded));
    assert(decode_wire(encoded, encoded_len, default_limits(), scratch, sizeof(scratch))
           == PBNS_ERR_CRC);

    unwrap_wire(wire, wire_len, raw, sizeof(raw));
    raw[raw_len] = UINT8_C(0xaa);
    encoded_len = wrap_raw(raw, raw_len + 1U, encoded, sizeof(encoded));
    assert(decode_wire(encoded, encoded_len, default_limits(), scratch, sizeof(scratch))
           == PBNS_ERR_FORMAT);

    pbns_frame decoded = {0};
    pbns_view payload = {0};
    assert(pbns_frame_decode((pbns_view){wire, wire_len}, default_limits(),
                             (pbns_buffer){scratch, 0U, sizeof(scratch)},
                             &decoded, &payload) == PBNS_ERR_FORMAT);
}

static void test_rejects_zero_ack_fields_on_decode(void) {
    uint8_t raw[64] = {0};
    uint8_t wire[128] = {0};
    uint8_t encoded[128] = {0};
    uint8_t scratch[64] = {0};
    static const uint8_t valid_ack[PBNS_ACK_PAYLOAD_SIZE] = {
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    };
    pbns_frame frame = empty_request();
    frame.type = PBNS_MESSAGE_ACK;
    size_t wire_len = 0U;

    assert(pbns_frame_encode(&frame,
                             (pbns_view){valid_ack, sizeof(valid_ack)},
                             (pbns_buffer){raw, 0U, sizeof(raw)},
                             (pbns_buffer){wire, 0U, sizeof(wire)},
                             &wire_len) == PBNS_OK);
    const size_t raw_len = unwrap_wire(wire, wire_len, raw, sizeof(raw));
    raw[PBNS_FRAME_V1_HEADER_SIZE + 4U] = UINT8_C(0);
    raw[PBNS_FRAME_V1_HEADER_SIZE + 5U] = UINT8_C(0);
    raw[PBNS_FRAME_V1_HEADER_SIZE + 6U] = UINT8_C(0);
    raw[PBNS_FRAME_V1_HEADER_SIZE + 7U] = UINT8_C(0);
    refresh_raw_crc(raw, raw_len);
    size_t encoded_len = wrap_raw(raw, raw_len, encoded, sizeof(encoded));
    assert(decode_wire(encoded, encoded_len, default_limits(), scratch, sizeof(scratch))
           == PBNS_ERR_FORMAT);

    raw[PBNS_FRAME_V1_HEADER_SIZE] = UINT8_C(0);
    raw[PBNS_FRAME_V1_HEADER_SIZE + 1U] = UINT8_C(0);
    raw[PBNS_FRAME_V1_HEADER_SIZE + 2U] = UINT8_C(0);
    raw[PBNS_FRAME_V1_HEADER_SIZE + 3U] = UINT8_C(0);
    raw[PBNS_FRAME_V1_HEADER_SIZE + 7U] = UINT8_C(1);
    refresh_raw_crc(raw, raw_len);
    encoded_len = wrap_raw(raw, raw_len, encoded, sizeof(encoded));
    assert(decode_wire(encoded, encoded_len, default_limits(), scratch, sizeof(scratch))
           == PBNS_ERR_FORMAT);
}

static void test_rejects_configured_limits_and_short_scratch(void) {
    uint8_t raw[40] = {0};
    uint8_t wire[sizeof(golden_empty_request)] = {0};
    uint8_t scratch[40] = {0};
    const size_t wire_len = encode_empty(raw, sizeof(raw), wire, sizeof(wire));
    pbns_frame_limits limits = default_limits();

    limits.encoded_record_max = wire_len - 1U;
    assert(decode_wire(wire, wire_len, limits, scratch, sizeof(scratch)) == PBNS_ERR_LIMIT);
    assert(decode_wire(wire, wire_len, default_limits(), scratch, sizeof(scratch) - 1U)
           == PBNS_ERR_LIMIT);
}

int main(void) {
    test_empty_request_matches_golden_vector();
    test_maximum_data_frame_round_trip();
    test_rejects_invalid_encode_arguments_and_semantics();
    test_rejects_short_and_overlapping_encode_buffers();
    test_rejects_header_field_errors_after_valid_crc();
    test_header_crc_precedes_payload_length_use();
    test_rejects_size_record_crc_and_delimiter_errors();
    test_rejects_zero_ack_fields_on_decode();
    test_rejects_configured_limits_and_short_scratch();
    return 0;
}
