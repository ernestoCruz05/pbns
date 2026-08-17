#include "pbns/frame.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/cobs.h"
#include "pbns/crc32c.h"

static const uint8_t frame_magic[4] = {'P', 'B', 'N', 'S'};

_Static_assert(PBNS_FRAME_V1_RAW_MAX
                   == PBNS_FRAME_V1_HEADER_SIZE + PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX
                          + PBNS_FRAME_V1_TRAILER_SIZE,
               "PBNS raw record size mismatch");
_Static_assert(PBNS_FRAME_V1_COBS_MAX
                   == PBNS_FRAME_V1_RAW_MAX + (PBNS_FRAME_V1_RAW_MAX / 254U) + 1U,
               "PBNS COBS record size mismatch");
_Static_assert(PBNS_FRAME_V1_WIRE_MAX == PBNS_FRAME_V1_COBS_MAX + 1U,
               "PBNS wire record size mismatch");

static bool view_is_valid(pbns_view view) {
    return view.ptr != NULL || view.len == 0U;
}

static bool output_buffer_is_valid(pbns_buffer buffer) {
    return buffer.len == 0U && (buffer.ptr != NULL || buffer.cap == 0U);
}

static bool service_is_valid(pbns_service_id service) {
    return service >= PBNS_SERVICE_TRUSTED_TIME && service <= PBNS_SERVICE_ENROLLMENT;
}

static bool message_type_is_valid(pbns_message_type type) {
    return type >= PBNS_MESSAGE_REQUEST && type <= PBNS_MESSAGE_COMPLETE;
}

static void write_u32_be(uint8_t *destination, uint32_t value) {
    destination[0] = (uint8_t)(value >> 24U);
    destination[1] = (uint8_t)(value >> 16U);
    destination[2] = (uint8_t)(value >> 8U);
    destination[3] = (uint8_t)value;
}

static uint32_t read_u32_be(const uint8_t *source) {
    return ((uint32_t)source[0] << 24U) | ((uint32_t)source[1] << 16U)
           | ((uint32_t)source[2] << 8U) | (uint32_t)source[3];
}

static bool ranges_overlap(const uint8_t *left,
                           size_t left_len,
                           const uint8_t *right,
                           size_t right_len) {
    if (left_len == 0U || right_len == 0U) {
        return false;
    }
    const uintptr_t left_start = (uintptr_t)left;
    const uintptr_t right_start = (uintptr_t)right;
    if (left_len > UINTPTR_MAX - left_start || right_len > UINTPTR_MAX - right_start) {
        return true;
    }
    const uintptr_t left_end = left_start + left_len;
    const uintptr_t right_end = right_start + right_len;
    return left_start < right_end && right_start < left_end;
}

typedef struct payload_constraints {
    pbns_message_type type;
    size_t payload_len;
    size_t control_limit;
    size_t data_limit;
} payload_constraints;

static pbns_status validate_payload_length(payload_constraints constraints) {
    switch (constraints.type) {
        case PBNS_MESSAGE_DATA:
            return constraints.payload_len <= constraints.data_limit ? PBNS_OK : PBNS_ERR_LIMIT;
        case PBNS_MESSAGE_ACK:
            return constraints.payload_len == PBNS_ACK_PAYLOAD_SIZE ? PBNS_OK : PBNS_ERR_FORMAT;
        case PBNS_MESSAGE_CANCEL:
        case PBNS_MESSAGE_COMPLETE:
            return constraints.payload_len == 0U ? PBNS_OK : PBNS_ERR_FORMAT;
        case PBNS_MESSAGE_REQUEST:
        case PBNS_MESSAGE_RESPONSE:
        case PBNS_MESSAGE_ERROR:
            return constraints.payload_len <= constraints.control_limit ? PBNS_OK : PBNS_ERR_LIMIT;
        default:
            return PBNS_ERR_MESSAGE_TYPE;
    }
}

static pbns_status validate_ack_payload(pbns_message_type type, pbns_view payload) {
    if (type == PBNS_MESSAGE_ACK
        && (read_u32_be(payload.ptr) == 0U || read_u32_be(payload.ptr + 4U) == 0U)) {
        return PBNS_ERR_FORMAT;
    }
    return PBNS_OK;
}

static bool limits_are_valid(pbns_frame_limits limits) {
    return limits.control_payload_max <= PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX
           && limits.data_payload_max <= PBNS_FRAME_V1_DATA_PAYLOAD_MAX
           && limits.encoded_record_max <= PBNS_FRAME_V1_WIRE_MAX;
}

pbns_status pbns_frame_encode(const pbns_frame *frame,
                              pbns_view payload,
                              pbns_buffer raw_scratch,
                              pbns_buffer output,
                              size_t *written) {
    if (written == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    *written = 0U;
    if (frame == NULL || !view_is_valid(payload) || !output_buffer_is_valid(raw_scratch)
        || !output_buffer_is_valid(output)) {
        return PBNS_ERR_ARGUMENT;
    }
    if (!service_is_valid(frame->service)) {
        return PBNS_ERR_SERVICE;
    }
    if (!message_type_is_valid(frame->type)) {
        return PBNS_ERR_MESSAGE_TYPE;
    }
    if (frame->flags != 0U) {
        return PBNS_ERR_FORMAT;
    }

    pbns_status status = validate_payload_length((payload_constraints){
        .type = frame->type,
        .payload_len = payload.len,
        .control_limit = PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX,
        .data_limit = PBNS_FRAME_V1_DATA_PAYLOAD_MAX,
    });
    if (status != PBNS_OK) {
        return status;
    }
    status = validate_ack_payload(frame->type, payload);
    if (status != PBNS_OK) {
        return status;
    }

    const size_t raw_size = PBNS_FRAME_V1_HEADER_SIZE + payload.len
                            + PBNS_FRAME_V1_TRAILER_SIZE;
    size_t cobs_max = 0U;
    status = pbns_cobs_max_encoded_size(raw_size, &cobs_max);
    if (status != PBNS_OK || cobs_max == SIZE_MAX) {
        return PBNS_ERR_LIMIT;
    }
    const size_t wire_max = cobs_max + 1U;
    if (raw_scratch.cap < raw_size || output.cap < wire_max) {
        return PBNS_ERR_LIMIT;
    }
    if (ranges_overlap(raw_scratch.ptr, raw_size, output.ptr, wire_max)
        || ranges_overlap(payload.ptr, payload.len, raw_scratch.ptr, raw_size)
        || ranges_overlap(payload.ptr, payload.len, output.ptr, wire_max)) {
        return PBNS_ERR_ARGUMENT;
    }

    uint8_t *const raw = raw_scratch.ptr;
    for (size_t index = 0U; index < sizeof(frame_magic); ++index) {
        raw[index] = frame_magic[index];
    }
    raw[4] = PBNS_FRAME_V1_PROTOCOL_VERSION;
    raw[5] = (uint8_t)frame->service;
    raw[6] = (uint8_t)frame->type;
    raw[7] = frame->flags;
    for (size_t index = 0U; index < sizeof(frame->request_id.bytes); ++index) {
        raw[8U + index] = frame->request_id.bytes[index];
    }
    write_u32_be(raw + 24U, frame->sequence);
    write_u32_be(raw + 28U, (uint32_t)payload.len);
    write_u32_be(raw + 32U, pbns_crc32c((pbns_view){raw, 32U}));
    for (size_t index = 0U; index < payload.len; ++index) {
        raw[PBNS_FRAME_V1_HEADER_SIZE + index] = payload.ptr[index];
    }
    write_u32_be(raw + raw_size - PBNS_FRAME_V1_TRAILER_SIZE,
                 pbns_crc32c((pbns_view){raw, raw_size - PBNS_FRAME_V1_TRAILER_SIZE}));

    size_t cobs_written = 0U;
    status = pbns_cobs_encode((pbns_view){raw, raw_size},
                              (pbns_buffer){output.ptr, 0U, output.cap - 1U},
                              &cobs_written);
    if (status != PBNS_OK) {
        return status;
    }
    output.ptr[cobs_written] = UINT8_C(0);
    *written = cobs_written + 1U;
    return PBNS_OK;
}

pbns_status pbns_frame_decode(pbns_view cobs_record,
                              pbns_frame_limits limits,
                              pbns_buffer scratch,
                              pbns_frame *frame,
                              pbns_view *payload) {
    if (frame == NULL || payload == NULL || !view_is_valid(cobs_record)
        || !output_buffer_is_valid(scratch) || !limits_are_valid(limits)) {
        return PBNS_ERR_ARGUMENT;
    }
    *frame = (pbns_frame){0};
    *payload = (pbns_view){0};

    if (cobs_record.len == SIZE_MAX || cobs_record.len + 1U > limits.encoded_record_max) {
        return PBNS_ERR_LIMIT;
    }

    size_t raw_len = 0U;
    pbns_status status = pbns_cobs_decode(cobs_record, scratch, &raw_len);
    if (status != PBNS_OK) {
        return status;
    }
    if (raw_len < PBNS_FRAME_V1_HEADER_SIZE + PBNS_FRAME_V1_TRAILER_SIZE) {
        return PBNS_ERR_FORMAT;
    }

    const uint8_t *const raw = scratch.ptr;
    if (memcmp(raw, frame_magic, sizeof(frame_magic)) != 0) {
        return PBNS_ERR_FORMAT;
    }
    if (raw[4] != PBNS_FRAME_V1_PROTOCOL_VERSION) {
        return PBNS_ERR_VERSION;
    }

    const uint32_t encoded_header_crc = read_u32_be(raw + 32U);
    const uint32_t calculated_header_crc = pbns_crc32c((pbns_view){raw, 32U});
    if (encoded_header_crc != calculated_header_crc) {
        return PBNS_ERR_CRC;
    }

    if (raw[5] < (uint8_t)PBNS_SERVICE_TRUSTED_TIME
        || raw[5] > (uint8_t)PBNS_SERVICE_ENROLLMENT) {
        return PBNS_ERR_SERVICE;
    }
    if (raw[6] < (uint8_t)PBNS_MESSAGE_REQUEST
        || raw[6] > (uint8_t)PBNS_MESSAGE_COMPLETE) {
        return PBNS_ERR_MESSAGE_TYPE;
    }
    const pbns_service_id service = (pbns_service_id)raw[5];
    const pbns_message_type type = (pbns_message_type)raw[6];
    if (raw[7] != 0U) {
        return PBNS_ERR_FORMAT;
    }

    const size_t payload_len = (size_t)read_u32_be(raw + 28U);
    status = validate_payload_length((payload_constraints){
        .type = type,
        .payload_len = payload_len,
        .control_limit = limits.control_payload_max,
        .data_limit = limits.data_payload_max,
    });
    if (status != PBNS_OK) {
        return status;
    }
    const size_t expected_raw_len = PBNS_FRAME_V1_HEADER_SIZE + payload_len
                                    + PBNS_FRAME_V1_TRAILER_SIZE;
    if (raw_len != expected_raw_len) {
        return PBNS_ERR_FORMAT;
    }

    const uint32_t encoded_record_crc = read_u32_be(raw + raw_len - PBNS_FRAME_V1_TRAILER_SIZE);
    const uint32_t calculated_record_crc =
        pbns_crc32c((pbns_view){raw, raw_len - PBNS_FRAME_V1_TRAILER_SIZE});
    if (encoded_record_crc != calculated_record_crc) {
        return PBNS_ERR_CRC;
    }

    const pbns_view decoded_payload = {raw + PBNS_FRAME_V1_HEADER_SIZE, payload_len};
    status = validate_ack_payload(type, decoded_payload);
    if (status != PBNS_OK) {
        return status;
    }

    frame->service = service;
    frame->type = type;
    frame->flags = raw[7];
    for (size_t index = 0U; index < sizeof(frame->request_id.bytes); ++index) {
        frame->request_id.bytes[index] = raw[8U + index];
    }
    frame->sequence = read_u32_be(raw + 24U);
    *payload = decoded_payload;
    return PBNS_OK;
}
