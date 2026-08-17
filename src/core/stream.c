#include "pbns/stream.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static bool view_is_valid(pbns_view view) {
    return view.ptr != NULL || view.len == 0U;
}

static bool service_is_valid(pbns_service_id service) {
    return service >= PBNS_SERVICE_TRUSTED_TIME && service <= PBNS_SERVICE_ENROLLMENT;
}

static bool request_ids_match(pbns_request_id left, pbns_request_id right) {
    for (size_t index = 0U; index < sizeof(left.bytes); ++index) {
        if (left.bytes[index] != right.bytes[index]) {
            return false;
        }
    }
    return true;
}

static uint32_t read_u32_be(const uint8_t *source) {
    return ((uint32_t)source[0] << 24U) | ((uint32_t)source[1] << 16U)
           | ((uint32_t)source[2] << 8U) | (uint32_t)source[3];
}

static pbns_status validate_payload(pbns_message_type type,
                                    pbns_view payload,
                                    bool *terminal) {
    *terminal = false;
    switch (type) {
        case PBNS_MESSAGE_REQUEST:
        case PBNS_MESSAGE_RESPONSE:
            return payload.len <= PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX ? PBNS_OK
                                                                    : PBNS_ERR_LIMIT;
        case PBNS_MESSAGE_DATA:
            return payload.len <= PBNS_FRAME_V1_DATA_PAYLOAD_MAX ? PBNS_OK
                                                                 : PBNS_ERR_LIMIT;
        case PBNS_MESSAGE_ACK:
            if (payload.len != PBNS_ACK_PAYLOAD_SIZE) {
                return PBNS_ERR_FORMAT;
            }
            if (read_u32_be(payload.ptr) == 0U || read_u32_be(payload.ptr + 4U) == 0U) {
                return PBNS_ERR_FORMAT;
            }
            return PBNS_OK;
        case PBNS_MESSAGE_ERROR:
            *terminal = true;
            return payload.len <= PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX ? PBNS_OK
                                                                    : PBNS_ERR_LIMIT;
        case PBNS_MESSAGE_CANCEL:
        case PBNS_MESSAGE_COMPLETE:
            *terminal = true;
            return payload.len == 0U ? PBNS_OK : PBNS_ERR_FORMAT;
        default:
            return PBNS_ERR_MESSAGE_TYPE;
    }
}

static pbns_status fail_stream(pbns_stream_state *state, pbns_status status) {
    state->failed = true;
    return status;
}

void pbns_stream_init(pbns_stream_state *state,
                      pbns_service_id service,
                      pbns_request_id request_id,
                      uint64_t byte_limit) {
    if (state == NULL) {
        return;
    }
    *state = (pbns_stream_state){0};
    if (!service_is_valid(service)) {
        return;
    }
    state->service = service;
    state->request_id = request_id;
    state->byte_limit = byte_limit;
    state->initialized = true;
}

void pbns_stream_reset(pbns_stream_state *state) {
    if (state == NULL || !state->initialized) {
        return;
    }
    state->total_bytes = UINT64_C(0);
    state->next_sequence = UINT32_C(0);
    state->complete = false;
    state->failed = false;
}

pbns_status pbns_stream_accept(pbns_stream_state *state,
                               const pbns_frame *frame,
                               pbns_view payload) {
    if (state == NULL || frame == NULL || !view_is_valid(payload)) {
        return PBNS_ERR_ARGUMENT;
    }
    if (!state->initialized || state->failed) {
        return PBNS_ERR_STATE;
    }
    if (state->complete) {
        return fail_stream(state, PBNS_ERR_STATE);
    }
    if (frame->service != state->service) {
        return fail_stream(state, PBNS_ERR_SERVICE);
    }
    if (!request_ids_match(frame->request_id, state->request_id)) {
        return fail_stream(state, PBNS_ERR_STATE);
    }
    if (frame->flags != 0U) {
        return fail_stream(state, PBNS_ERR_FORMAT);
    }
    if (frame->sequence != state->next_sequence || state->next_sequence == UINT32_MAX) {
        return fail_stream(state, PBNS_ERR_SEQUENCE);
    }

    bool terminal = false;
    const pbns_status payload_status = validate_payload(frame->type, payload, &terminal);
    if (payload_status != PBNS_OK) {
        return fail_stream(state, payload_status);
    }

    const uint64_t payload_bytes = (uint64_t)payload.len;
    if (state->total_bytes > state->byte_limit
        || payload_bytes > UINT64_MAX - state->total_bytes
        || payload_bytes > state->byte_limit - state->total_bytes) {
        return fail_stream(state, PBNS_ERR_LIMIT);
    }

    state->total_bytes += payload_bytes;
    ++state->next_sequence;
    state->complete = terminal;
    return PBNS_OK;
}
