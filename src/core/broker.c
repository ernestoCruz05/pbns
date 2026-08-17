#include "pbns/broker.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "qcbor/qcbor.h"

#define PBNS_BROKER_CANCEL_TIMEOUT_MS UINT32_C(1000)
#define PBNS_ERROR_FIELD_COUNT 3U
#define PBNS_ERROR_DETAIL_MAX 256U
#define PBNS_BROKER_BULK_WINDOW UINT32_C(8)
#define PBNS_ACK_PAYLOAD_SIZE 8U

static void write_u32_be(uint8_t *destination, uint32_t value) {
    destination[0] = (uint8_t)(value >> 24U);
    destination[1] = (uint8_t)(value >> 16U);
    destination[2] = (uint8_t)(value >> 8U);
    destination[3] = (uint8_t)value;
}

static bool view_is_valid(pbns_view view) { return view.ptr != NULL || view.len == 0U; }

static bool buffer_is_valid(pbns_buffer buffer) {
    return buffer.len == 0U && (buffer.ptr != NULL || buffer.cap == 0U);
}

static bool service_is_valid(pbns_service_id service) {
    return service >= PBNS_SERVICE_TRUSTED_TIME && service <= PBNS_SERVICE_ENROLLMENT;
}

static bool ranges_overlap(pbns_buffer left, pbns_buffer right) {
    if (left.cap == 0U || right.cap == 0U) {
        return false;
    }
    const uintptr_t left_start = (uintptr_t)left.ptr;
    const uintptr_t right_start = (uintptr_t)right.ptr;
    if (left.cap > UINTPTR_MAX - left_start || right.cap > UINTPTR_MAX - right_start) {
        return true;
    }
    const uintptr_t left_end = left_start + left.cap;
    const uintptr_t right_end = right_start + right.cap;
    return left_start < right_end && right_start < left_end;
}

static bool storage_is_valid(pbns_broker_storage storage) {
    const size_t minimum_raw = PBNS_FRAME_V1_HEADER_SIZE + PBNS_FRAME_V1_TRAILER_SIZE;
    const size_t minimum_wire = minimum_raw + 2U;
    if (!buffer_is_valid(storage.encoded) || !buffer_is_valid(storage.raw_scratch) ||
        !buffer_is_valid(storage.receive) || !buffer_is_valid(storage.decoded) ||
        storage.encoded.cap < minimum_wire || storage.raw_scratch.cap < minimum_raw ||
        storage.receive.cap == 0U || storage.decoded.cap == 0U) {
        return false;
    }
    const pbns_buffer buffers[] = {
        storage.encoded,
        storage.raw_scratch,
        storage.receive,
        storage.decoded,
    };
    for (size_t left = 0U; left < sizeof(buffers) / sizeof(buffers[0]); ++left) {
        for (size_t right = left + 1U; right < sizeof(buffers) / sizeof(buffers[0]); ++right) {
            if (ranges_overlap(buffers[left], buffers[right])) {
                return false;
            }
        }
    }
    return true;
}

static bool transport_is_valid(pbns_transport transport) {
    return transport.ops != NULL && transport.ops->open != NULL && transport.ops->close != NULL &&
           transport.ops->send != NULL && transport.ops->receive != NULL &&
           transport.ops->cancel != NULL && transport.ops->limits != NULL;
}

static bool platform_is_valid(pbns_broker_platform platform) {
    return platform.ops != NULL && platform.ops->random != NULL &&
           platform.ops->monotonic_ms != NULL;
}

static void wipe_buffer(pbns_buffer buffer) {
    volatile uint8_t *const bytes = buffer.ptr;
    for (size_t index = 0U; index < buffer.cap; ++index) {
        bytes[index] = UINT8_C(0);
    }
}

static void clear_response(pbns_broker_response *response) {
    if (response != NULL) {
        *response = (pbns_broker_response){0};
    }
}

static void wipe_request_storage(pbns_broker *broker, bool preserve_decoded) {
    wipe_buffer(broker->storage.encoded);
    wipe_buffer(broker->storage.raw_scratch);
    wipe_buffer(broker->storage.receive);
    broker->storage.encoded.len = 0U;
    broker->storage.raw_scratch.len = 0U;
    broker->storage.receive.len = 0U;
    if (!preserve_decoded) {
        wipe_buffer(broker->storage.decoded);
        broker->storage.decoded.len = 0U;
    }
}

static size_t minimum_size(size_t left, size_t right) { return left < right ? left : right; }

static pbns_status query_effective_limits(pbns_broker *broker) {
    pbns_frame_limits transport_limits = {0};
    const pbns_status status =
        broker->transport.ops->limits(broker->transport.context, &transport_limits);
    if (status != PBNS_OK) {
        return status;
    }
    if (transport_limits.control_payload_max > PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX ||
        transport_limits.data_payload_max > PBNS_FRAME_V1_DATA_PAYLOAD_MAX ||
        transport_limits.encoded_record_max > PBNS_FRAME_V1_WIRE_MAX ||
        transport_limits.encoded_record_max < 2U) {
        return PBNS_ERR_LIMIT;
    }

    const size_t payload_capacity =
        broker->storage.raw_scratch.cap - PBNS_FRAME_V1_HEADER_SIZE - PBNS_FRAME_V1_TRAILER_SIZE;
    broker->limits.control_payload_max =
        minimum_size(transport_limits.control_payload_max,
                     minimum_size(payload_capacity, broker->storage.decoded.cap));
    broker->limits.data_payload_max =
        minimum_size(transport_limits.data_payload_max,
                     minimum_size(payload_capacity, broker->storage.decoded.cap));
    broker->limits.encoded_record_max =
        minimum_size(transport_limits.encoded_record_max, broker->storage.encoded.cap);
    return PBNS_OK;
}

static pbns_status begin_deadline(pbns_broker *broker, uint32_t timeout_ms) {
    uint64_t now_ms = 0U;
    const pbns_status status =
        broker->platform.ops->monotonic_ms(broker->platform.context, &now_ms);
    if (status != PBNS_OK) {
        return status;
    }
    const uint64_t duration = (uint64_t)timeout_ms;
    broker->deadline_ms = duration > UINT64_MAX - now_ms ? UINT64_MAX : now_ms + duration;
    broker->deadline_active = true;
    return PBNS_OK;
}

static pbns_status remaining_timeout(pbns_broker *broker, uint32_t *remaining_ms) {
    if (remaining_ms == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    *remaining_ms = 0U;
    if (!broker->deadline_active) {
        return PBNS_ERR_STATE;
    }
    uint64_t now_ms = 0U;
    const pbns_status status =
        broker->platform.ops->monotonic_ms(broker->platform.context, &now_ms);
    if (status != PBNS_OK) {
        return status;
    }
    if (now_ms >= broker->deadline_ms) {
        return PBNS_ERR_TIMEOUT;
    }
    const uint64_t remaining = broker->deadline_ms - now_ms;
    *remaining_ms = remaining > (uint64_t)UINT32_MAX ? UINT32_MAX : (uint32_t)remaining;
    return PBNS_OK;
}

static bool request_ids_match(pbns_request_id left, pbns_request_id right) {
    uint8_t difference = UINT8_C(0);
    for (size_t index = 0U; index < sizeof(left.bytes); ++index) {
        difference |= (uint8_t)(left.bytes[index] ^ right.bytes[index]);
    }
    return difference == UINT8_C(0);
}

static bool request_id_is_nonzero(const pbns_request_id *request_id) {
    uint8_t combined = UINT8_C(0);
    for (size_t index = 0U; index < sizeof(request_id->bytes); ++index) {
        combined |= request_id->bytes[index];
    }
    return combined != UINT8_C(0);
}

static bool utf8_is_valid(pbns_view text) {
    size_t index = 0U;
    while (index < text.len) {
        const uint8_t first = text.ptr[index];
        if (first <= UINT8_C(0x7f)) {
            ++index;
            continue;
        }
        if (first >= UINT8_C(0xc2) && first <= UINT8_C(0xdf)) {
            if (index + 1U >= text.len || text.ptr[index + 1U] < UINT8_C(0x80) ||
                text.ptr[index + 1U] > UINT8_C(0xbf)) {
                return false;
            }
            index += 2U;
            continue;
        }
        if (first >= UINT8_C(0xe0) && first <= UINT8_C(0xef)) {
            if (index + 2U >= text.len) {
                return false;
            }
            const uint8_t second = text.ptr[index + 1U];
            const uint8_t third = text.ptr[index + 2U];
            const uint8_t second_min = first == UINT8_C(0xe0) ? UINT8_C(0xa0) : UINT8_C(0x80);
            const uint8_t second_max = first == UINT8_C(0xed) ? UINT8_C(0x9f) : UINT8_C(0xbf);
            if (second < second_min || second > second_max || third < UINT8_C(0x80) ||
                third > UINT8_C(0xbf)) {
                return false;
            }
            index += 3U;
            continue;
        }
        if (first >= UINT8_C(0xf0) && first <= UINT8_C(0xf4)) {
            if (index + 3U >= text.len) {
                return false;
            }
            const uint8_t second = text.ptr[index + 1U];
            const uint8_t third = text.ptr[index + 2U];
            const uint8_t fourth = text.ptr[index + 3U];
            const uint8_t second_min = first == UINT8_C(0xf0) ? UINT8_C(0x90) : UINT8_C(0x80);
            const uint8_t second_max = first == UINT8_C(0xf4) ? UINT8_C(0x8f) : UINT8_C(0xbf);
            if (second < second_min || second > second_max || third < UINT8_C(0x80) ||
                third > UINT8_C(0xbf) || fourth < UINT8_C(0x80) || fourth > UINT8_C(0xbf)) {
                return false;
            }
            index += 4U;
            continue;
        }
        return false;
    }
    return true;
}

static pbns_status next_labeled_item(QCBORDecodeContext *decoder, int64_t expected_label,
                                     QCBORItem *item) {
    if (QCBORDecode_GetNext(decoder, item) != QCBOR_SUCCESS || item->uNestingLevel != 1U ||
        item->uLabelType != QCBOR_TYPE_INT64 || item->label.int64 != expected_label) {
        return PBNS_ERR_FORMAT;
    }
    return PBNS_OK;
}

static bool item_to_uint64(const QCBORItem *item, uint64_t *value) {
    if (item->uDataType == QCBOR_TYPE_INT64 && item->val.int64 >= 0) {
        *value = (uint64_t)item->val.int64;
        return true;
    }
    if (item->uDataType == QCBOR_TYPE_UINT64) {
        *value = item->val.uint64;
        return true;
    }
    return false;
}

static pbns_status decode_remote_error(pbns_broker *broker, pbns_view payload,
                                       pbns_service_id expected_service) {
    QCBORDecodeContext decoder = {0};
    QCBORItem item = {0};
    QCBORDecode_Init(&decoder, (UsefulBufC){payload.ptr, payload.len}, QCBOR_DECODE_MODE_NORMAL);
    if (QCBORDecode_GetNext(&decoder, &item) != QCBOR_SUCCESS || item.uDataType != QCBOR_TYPE_MAP ||
        item.uLabelType != QCBOR_TYPE_NONE || item.val.uCount != PBNS_ERROR_FIELD_COUNT) {
        return PBNS_ERR_FORMAT;
    }

    uint64_t code = 0U;
    uint64_t service = 0U;
    if (next_labeled_item(&decoder, 1, &item) != PBNS_OK || !item_to_uint64(&item, &code) ||
        code < 1U || code > 22U) {
        return PBNS_ERR_FORMAT;
    }
    if (next_labeled_item(&decoder, 2, &item) != PBNS_OK || !item_to_uint64(&item, &service)) {
        return PBNS_ERR_FORMAT;
    }
    if (service != (uint64_t)expected_service) {
        return PBNS_ERR_SERVICE;
    }
    if (next_labeled_item(&decoder, 3, &item) != PBNS_OK ||
        item.uDataType != QCBOR_TYPE_TEXT_STRING || item.val.string.len > PBNS_ERROR_DETAIL_MAX) {
        return PBNS_ERR_FORMAT;
    }
    const pbns_view detail = {item.val.string.ptr, item.val.string.len};
    if (!utf8_is_valid(detail) || QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS) {
        return PBNS_ERR_FORMAT;
    }

    QCBOREncodeContext encoder = {0};
    UsefulBufC canonical = {0};
    QCBOREncode_Init(&encoder,
                     (UsefulBuf){broker->storage.decoded.ptr, broker->storage.decoded.cap});
    QCBOREncode_OpenMap(&encoder);
    QCBOREncode_AddUInt64ToMapN(&encoder, 1, code);
    QCBOREncode_AddUInt64ToMapN(&encoder, 2, service);
    QCBOREncode_AddTextToMapN(&encoder, 3, (UsefulBufC){detail.ptr, detail.len});
    QCBOREncode_CloseMap(&encoder);
    if (QCBOREncode_Finish(&encoder, &canonical) != QCBOR_SUCCESS) {
        return PBNS_ERR_LIMIT;
    }
    if (canonical.len != payload.len ||
        (payload.len > 0U && memcmp(canonical.ptr, payload.ptr, payload.len) != 0)) {
        return PBNS_ERR_FORMAT;
    }
    return (pbns_status)(-(int32_t)code);
}

static pbns_status finish_session(pbns_broker *broker, bool preserve_decoded) {
    pbns_status close_status = PBNS_OK;
    if (broker->opened) {
        close_status = broker->transport.ops->close(broker->transport.context);
    }
    broker->opened = false;
    broker->active = false;
    broker->deadline_active = false;
    broker->deadline_ms = 0U;
    broker->receive_offset = 0U;
    broker->receive_length = 0U;
    broker->bulk_exact_data_size = 0U;
    broker->bulk_received_data_size = 0U;
    broker->bulk_next_ack_sequence = 0U;
    broker->upload_next_sequence = 0U;
    broker->bulk_mode = false;
    broker->bulk_failed = false;
    broker->upload_mode = false;
    broker->upload_response_received = false;
    broker->service = PBNS_SERVICE_INVALID;
    broker->request_id = (pbns_request_id){0};
    pbns_record_reader_reset(&broker->reader);
    broker->stream = (pbns_stream_state){0};
    wipe_request_storage(broker, preserve_decoded);
    return close_status;
}

static pbns_status emit_cancel(pbns_broker *broker) {
    const pbns_frame cancel = {
        .service = broker->service,
        .type = PBNS_MESSAGE_CANCEL,
        .flags = 0U,
        .request_id = broker->request_id,
        .sequence = 1U,
    };
    size_t written = 0U;
    pbns_status status = pbns_frame_encode(
        &cancel, (pbns_view){NULL, 0U},
        (pbns_buffer){broker->storage.raw_scratch.ptr, 0U, broker->storage.raw_scratch.cap},
        (pbns_buffer){broker->storage.encoded.ptr, 0U, broker->storage.encoded.cap}, &written);
    if (status != PBNS_OK) {
        return status;
    }
    status = broker->transport.ops->send(broker->transport.context,
                                         (pbns_view){broker->storage.encoded.ptr, written},
                                         PBNS_BROKER_CANCEL_TIMEOUT_MS);
    return status;
}

pbns_status pbns_broker_init(pbns_broker *broker, pbns_transport transport,
                             pbns_broker_platform platform, pbns_broker_storage storage) {
    if (broker == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    *broker = (pbns_broker){0};
    if (!transport_is_valid(transport) || !platform_is_valid(platform) ||
        !storage_is_valid(storage)) {
        return PBNS_ERR_ARGUMENT;
    }
    broker->transport = transport;
    broker->platform = platform;
    broker->storage = storage;
    pbns_record_reader_init(&broker->reader, broker->storage.encoded);
    if (!broker->reader.initialized) {
        *broker = (pbns_broker){0};
        return PBNS_ERR_ARGUMENT;
    }
    broker->initialized = true;
    return PBNS_OK;
}

pbns_status pbns_broker_receive(pbns_broker *broker, pbns_broker_response *response) {
    clear_response(response);
    if (broker == NULL || response == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    if (!broker->initialized || !broker->active || broker->bulk_mode) {
        return PBNS_ERR_STATE;
    }

    for (;;) {
        if (broker->receive_offset >= broker->receive_length) {
            broker->receive_offset = 0U;
            broker->receive_length = 0U;
            uint32_t remaining_ms = 0U;
            pbns_status status = remaining_timeout(broker, &remaining_ms);
            if (status != PBNS_OK) {
                return status;
            }
            size_t received = 0U;
            status = broker->transport.ops->receive(
                broker->transport.context,
                (pbns_buffer){broker->storage.receive.ptr, 0U, broker->storage.receive.cap},
                remaining_ms, &received);
            if (status == PBNS_ERR_WOULD_BLOCK) {
                if (received != 0U) {
                    return PBNS_ERR_TRANSPORT;
                }
                continue;
            }
            if (status != PBNS_OK) {
                return status;
            }
            if (received == 0U || received > broker->storage.receive.cap) {
                return PBNS_ERR_TRANSPORT;
            }
            broker->receive_length = received;
        }

        const pbns_view input = {
            broker->storage.receive.ptr + broker->receive_offset,
            broker->receive_length - broker->receive_offset,
        };
        size_t consumed = 0U;
        bool ready = false;
        pbns_view record = {0};
        const pbns_status reader_status =
            pbns_record_reader_push(&broker->reader, input, &consumed, &ready, &record);
        broker->receive_offset += consumed;
        if (reader_status == PBNS_ERR_WOULD_BLOCK) {
            continue;
        }
        if (reader_status != PBNS_OK || !ready) {
            return reader_status != PBNS_OK ? reader_status : PBNS_ERR_STATE;
        }

        pbns_frame frame = {0};
        pbns_view payload = {0};
        pbns_status status = pbns_frame_decode(
            record, broker->limits,
            (pbns_buffer){broker->storage.raw_scratch.ptr, 0U, broker->storage.raw_scratch.cap},
            &frame, &payload);
        pbns_record_reader_reset(&broker->reader);
        if (status != PBNS_OK) {
            return status;
        }
        status = pbns_stream_accept(&broker->stream, &frame, payload);
        if (status != PBNS_OK) {
            return status;
        }
        if (!request_ids_match(frame.request_id, broker->request_id)) {
            return PBNS_ERR_STATE;
        }
        if (frame.type == PBNS_MESSAGE_ERROR) {
            return decode_remote_error(broker, payload, broker->service);
        }
        if (frame.type != PBNS_MESSAGE_RESPONSE) {
            return PBNS_ERR_MESSAGE_TYPE;
        }
        if (payload.len > broker->storage.decoded.cap) {
            return PBNS_ERR_LIMIT;
        }
        if (payload.len > 0U) {
            memcpy(broker->storage.decoded.ptr, payload.ptr, payload.len);
        }
        broker->storage.decoded.len = payload.len;
        response->frame = frame;
        response->payload = (pbns_view){broker->storage.decoded.ptr, payload.len};
        return PBNS_OK;
    }
}

static pbns_status fail_bulk_session(pbns_broker *broker, pbns_status status) {
    broker->bulk_failed = true;
    broker->stream.failed = true;
    return status;
}

pbns_status pbns_broker_bulk_begin(pbns_broker *broker, pbns_service_id service,
                                   const pbns_request_id *request_id, pbns_view request_body,
                                   uint64_t exact_data_size, uint32_t timeout_ms) {
    if (broker == NULL || request_id == NULL || !view_is_valid(request_body) ||
        !request_id_is_nonzero(request_id) || exact_data_size == 0U || timeout_ms == 0U) {
        return PBNS_ERR_ARGUMENT;
    }
    const pbns_request_id supplied_request_id = *request_id;
    if (!broker->initialized) {
        return PBNS_ERR_STATE;
    }
    if (!service_is_valid(service)) {
        return PBNS_ERR_SERVICE;
    }
    if (broker->active || broker->opened) {
        return PBNS_ERR_BUSY;
    }

    wipe_request_storage(broker, false);
    pbns_record_reader_reset(&broker->reader);
    broker->request_id = supplied_request_id;
    pbns_status status = begin_deadline(broker, timeout_ms);
    if (status != PBNS_OK) {
        broker->request_id = (pbns_request_id){0};
        wipe_request_storage(broker, false);
        return status;
    }
    status = broker->transport.ops->open(broker->transport.context);
    if (status != PBNS_OK) {
        broker->deadline_active = false;
        broker->request_id = (pbns_request_id){0};
        wipe_request_storage(broker, false);
        return status;
    }
    broker->opened = true;
    status = query_effective_limits(broker);
    if (status == PBNS_OK &&
        (request_body.len > broker->limits.control_payload_max ||
         broker->limits.data_payload_max == 0U ||
         exact_data_size > (uint64_t)broker->limits.data_payload_max *
                               ((uint64_t)UINT32_MAX - UINT64_C(1)))) {
        status = PBNS_ERR_LIMIT;
    }
    if (status != PBNS_OK) {
        (void)finish_session(broker, false);
        return status;
    }
    const pbns_frame request = {
        .service = service,
        .type = PBNS_MESSAGE_REQUEST,
        .flags = 0U,
        .request_id = broker->request_id,
        .sequence = 0U,
    };
    size_t written = 0U;
    status = pbns_frame_encode(
        &request, request_body,
        (pbns_buffer){broker->storage.raw_scratch.ptr, 0U, broker->storage.raw_scratch.cap},
        (pbns_buffer){broker->storage.encoded.ptr, 0U, broker->storage.encoded.cap}, &written);
    if (status != PBNS_OK) {
        (void)finish_session(broker, false);
        return status;
    }
    uint32_t remaining_ms = 0U;
    status = remaining_timeout(broker, &remaining_ms);
    if (status == PBNS_OK) {
        status = broker->transport.ops->send(broker->transport.context,
                                             (pbns_view){broker->storage.encoded.ptr, written},
                                             remaining_ms);
    }
    if (status != PBNS_OK) {
        (void)finish_session(broker, false);
        return status;
    }

    broker->service = service;
    broker->active = true;
    broker->bulk_mode = true;
    broker->bulk_exact_data_size = exact_data_size;
    pbns_stream_init(&broker->stream, service, broker->request_id, UINT64_MAX);
    if (!broker->stream.initialized) {
        (void)finish_session(broker, false);
        return PBNS_ERR_STATE;
    }
    return PBNS_OK;
}

pbns_status pbns_broker_bulk_receive(pbns_broker *broker, pbns_broker_response *response) {
    clear_response(response);
    if (broker == NULL || response == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    if (!broker->initialized || !broker->active || !broker->bulk_mode || broker->bulk_failed ||
        broker->stream.complete) {
        return PBNS_ERR_STATE;
    }

    for (;;) {
        if (broker->receive_offset >= broker->receive_length) {
            broker->receive_offset = 0U;
            broker->receive_length = 0U;
            uint32_t remaining_ms = 0U;
            pbns_status status = remaining_timeout(broker, &remaining_ms);
            if (status != PBNS_OK) {
                return fail_bulk_session(broker, status);
            }
            size_t received = 0U;
            status = broker->transport.ops->receive(
                broker->transport.context,
                (pbns_buffer){broker->storage.receive.ptr, 0U, broker->storage.receive.cap},
                remaining_ms, &received);
            if (status == PBNS_ERR_WOULD_BLOCK) {
                if (received != 0U) {
                    return fail_bulk_session(broker, PBNS_ERR_TRANSPORT);
                }
                continue;
            }
            if (status != PBNS_OK || received == 0U || received > broker->storage.receive.cap) {
                return fail_bulk_session(broker,
                                         status == PBNS_OK ? PBNS_ERR_TRANSPORT : status);
            }
            broker->receive_length = received;
        }

        const pbns_view input = {
            broker->storage.receive.ptr + broker->receive_offset,
            broker->receive_length - broker->receive_offset,
        };
        size_t consumed = 0U;
        bool ready = false;
        pbns_view record = {0};
        const pbns_status reader_status =
            pbns_record_reader_push(&broker->reader, input, &consumed, &ready, &record);
        broker->receive_offset += consumed;
        if (reader_status == PBNS_ERR_WOULD_BLOCK) {
            continue;
        }
        if (reader_status != PBNS_OK || !ready) {
            return fail_bulk_session(broker,
                                     reader_status != PBNS_OK ? reader_status : PBNS_ERR_STATE);
        }

        pbns_frame frame = {0};
        pbns_view payload = {0};
        pbns_status status = pbns_frame_decode(
            record, broker->limits,
            (pbns_buffer){broker->storage.raw_scratch.ptr, 0U, broker->storage.raw_scratch.cap},
            &frame, &payload);
        pbns_record_reader_reset(&broker->reader);
        if (status != PBNS_OK) {
            return fail_bulk_session(broker, status);
        }
        if (frame.type != PBNS_MESSAGE_DATA && frame.type != PBNS_MESSAGE_COMPLETE &&
            frame.type != PBNS_MESSAGE_ERROR) {
            return fail_bulk_session(broker, PBNS_ERR_MESSAGE_TYPE);
        }
        status = pbns_stream_accept(&broker->stream, &frame, payload);
        if (status != PBNS_OK) {
            return fail_bulk_session(broker, status);
        }
        if (frame.type == PBNS_MESSAGE_ERROR) {
            return fail_bulk_session(broker,
                                     decode_remote_error(broker, payload, broker->service));
        }
        if (frame.type == PBNS_MESSAGE_DATA) {
            if (payload.len == 0U) {
                return fail_bulk_session(broker, PBNS_ERR_FORMAT);
            }
            const uint64_t payload_size = (uint64_t)payload.len;
            if (broker->bulk_received_data_size > broker->bulk_exact_data_size ||
                payload_size > broker->bulk_exact_data_size - broker->bulk_received_data_size) {
                return fail_bulk_session(broker, PBNS_ERR_LIMIT);
            }
            broker->bulk_received_data_size += payload_size;
        } else if (broker->bulk_received_data_size != broker->bulk_exact_data_size) {
            return fail_bulk_session(broker, PBNS_ERR_LIMIT);
        }
        if (payload.len > broker->storage.decoded.cap) {
            return fail_bulk_session(broker, PBNS_ERR_LIMIT);
        }
        if (payload.len > 0U) {
            memcpy(broker->storage.decoded.ptr, payload.ptr, payload.len);
        }
        broker->storage.decoded.len = payload.len;
        response->frame = frame;
        response->payload = (pbns_view){broker->storage.decoded.ptr, payload.len};
        return PBNS_OK;
    }
}

pbns_status pbns_broker_bulk_ack(pbns_broker *broker, uint32_t next_data_sequence,
                                 uint32_t window) {
    if (broker == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    if (!broker->initialized || !broker->active || !broker->bulk_mode || broker->bulk_failed ||
        broker->stream.complete) {
        return PBNS_ERR_STATE;
    }
    const uint64_t expected_data_sequence =
        ((uint64_t)broker->bulk_next_ack_sequence + UINT64_C(1)) *
        (uint64_t)PBNS_BROKER_BULK_WINDOW;
    if (next_data_sequence == 0U || next_data_sequence != broker->stream.next_sequence ||
        (uint64_t)next_data_sequence != expected_data_sequence ||
        window != PBNS_BROKER_BULK_WINDOW || broker->bulk_next_ack_sequence == UINT32_MAX) {
        return PBNS_ERR_ARGUMENT;
    }
    uint32_t remaining_ms = 0U;
    pbns_status status = remaining_timeout(broker, &remaining_ms);
    if (status != PBNS_OK) {
        return fail_bulk_session(broker, status);
    }
    uint8_t payload[PBNS_ACK_PAYLOAD_SIZE] = {0};
    write_u32_be(payload, next_data_sequence);
    write_u32_be(payload + 4U, window);
    const pbns_frame ack = {
        .service = broker->service,
        .type = PBNS_MESSAGE_ACK,
        .flags = 0U,
        .request_id = broker->request_id,
        .sequence = broker->bulk_next_ack_sequence,
    };
    size_t written = 0U;
    status = pbns_frame_encode(
        &ack, (pbns_view){payload, sizeof(payload)},
        (pbns_buffer){broker->storage.raw_scratch.ptr, 0U, broker->storage.raw_scratch.cap},
        (pbns_buffer){broker->storage.encoded.ptr, 0U, broker->storage.encoded.cap}, &written);
    if (status == PBNS_OK) {
        status = broker->transport.ops->send(broker->transport.context,
                                             (pbns_view){broker->storage.encoded.ptr, written},
                                             remaining_ms);
    }
    if (status != PBNS_OK) {
        return fail_bulk_session(broker, status);
    }
    ++broker->bulk_next_ack_sequence;
    return PBNS_OK;
}

pbns_status pbns_broker_bulk_finish(pbns_broker *broker) {
    if (broker == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    if (!broker->initialized || !broker->active || !broker->bulk_mode || broker->bulk_failed ||
        !broker->stream.complete || broker->bulk_received_data_size != broker->bulk_exact_data_size) {
        return PBNS_ERR_STATE;
    }
    return finish_session(broker, false);
}

static pbns_status abort_upload_session(pbns_broker *broker,
                                        pbns_status primary);

pbns_status pbns_broker_upload_begin(pbns_broker *broker, pbns_service_id service,
                                     const pbns_request_id *request_id,
                                     pbns_view request_body, uint32_t timeout_ms) {
    if (broker == NULL || request_id == NULL || !view_is_valid(request_body) ||
        !request_id_is_nonzero(request_id) || timeout_ms == 0U) {
        return PBNS_ERR_ARGUMENT;
    }
    const pbns_request_id supplied_request_id = *request_id;
    if (!broker->initialized || broker->active || broker->opened) {
        return PBNS_ERR_STATE;
    }
    if (!service_is_valid(service)) {
        return PBNS_ERR_SERVICE;
    }
    wipe_request_storage(broker, false);
    pbns_record_reader_reset(&broker->reader);
    broker->request_id = supplied_request_id;
    pbns_status status = begin_deadline(broker, timeout_ms);
    if (status != PBNS_OK) {
        broker->request_id = (pbns_request_id){0};
        return status;
    }
    status = broker->transport.ops->open(broker->transport.context);
    if (status != PBNS_OK) {
        broker->deadline_active = false;
        broker->request_id = (pbns_request_id){0};
        return status;
    }
    broker->opened = true;
    status = query_effective_limits(broker);
    if (status == PBNS_OK &&
        (request_body.len > broker->limits.control_payload_max ||
         broker->limits.data_payload_max == 0U)) {
        status = PBNS_ERR_LIMIT;
    }
    if (status != PBNS_OK) {
        (void)finish_session(broker, false);
        return status;
    }
    broker->service = service;
    broker->upload_mode = true;
    broker->upload_next_sequence = 0U;
    pbns_stream_init(&broker->stream, service, supplied_request_id,
                     (uint64_t)broker->limits.control_payload_max);
    if (!broker->stream.initialized) {
        (void)finish_session(broker, false);
        return PBNS_ERR_STATE;
    }
    /* From the first REQUEST attempt onward the session is abortable: every
     * protocol failure attempts one CANCEL and one transport cancellation. */
    broker->active = true;
    const pbns_frame request = {
        .service = service,
        .type = PBNS_MESSAGE_REQUEST,
        .flags = 0U,
        .request_id = supplied_request_id,
        .sequence = 0U,
    };
    size_t written = 0U;
    status = pbns_frame_encode(
        &request, request_body,
        (pbns_buffer){broker->storage.raw_scratch.ptr, 0U, broker->storage.raw_scratch.cap},
        (pbns_buffer){broker->storage.encoded.ptr, 0U, broker->storage.encoded.cap}, &written);
    uint32_t remaining_ms = 0U;
    if (status == PBNS_OK) {
        status = remaining_timeout(broker, &remaining_ms);
    }
    if (status == PBNS_OK) {
        status = broker->transport.ops->send(
            broker->transport.context, (pbns_view){broker->storage.encoded.ptr, written},
            remaining_ms);
    }
    if (status != PBNS_OK) {
        return abort_upload_session(broker, status);
    }
    return PBNS_OK;
}

static pbns_status abort_upload_session(pbns_broker *broker, pbns_status primary) {
    if (broker->active) {
        (void)emit_cancel(broker);
        (void)broker->transport.ops->cancel(broker->transport.context, &broker->request_id);
        (void)finish_session(broker, false);
    }
    return primary;
}

static pbns_status upload_emit(pbns_broker *broker, pbns_message_type type,
                               pbns_view payload, uint32_t sequence) {
    const pbns_frame frame = {
        .service = broker->service,
        .type = type,
        .flags = 0U,
        .request_id = broker->request_id,
        .sequence = sequence,
    };
    size_t written = 0U;
    pbns_status status = pbns_frame_encode(
        &frame, payload,
        (pbns_buffer){broker->storage.raw_scratch.ptr, 0U, broker->storage.raw_scratch.cap},
        (pbns_buffer){broker->storage.encoded.ptr, 0U, broker->storage.encoded.cap}, &written);
    uint32_t remaining_ms = 0U;
    if (status == PBNS_OK) {
        status = remaining_timeout(broker, &remaining_ms);
    }
    if (status == PBNS_OK) {
        status = broker->transport.ops->send(
            broker->transport.context, (pbns_view){broker->storage.encoded.ptr, written},
            remaining_ms);
    }
    return status;
}

pbns_status pbns_broker_upload_send(pbns_broker *broker, pbns_view payload,
                                    bool final_record,
                                    pbns_broker_response *response) {
    clear_response(response);
    if (broker == NULL || response == NULL || !view_is_valid(payload) ||
        payload.len == 0U) {
        return PBNS_ERR_ARGUMENT;
    }
    if (!broker->initialized || !broker->active || !broker->upload_mode ||
        broker->bulk_mode) {
        return PBNS_ERR_STATE;
    }
    if (payload.len > broker->limits.data_payload_max ||
        broker->upload_next_sequence == UINT32_MAX) {
        return abort_upload_session(broker, PBNS_ERR_LIMIT);
    }
    pbns_status status = upload_emit(broker, PBNS_MESSAGE_DATA, payload,
                                     broker->upload_next_sequence);
    if (status == PBNS_OK) {
        ++broker->upload_next_sequence;
    }
    if (status == PBNS_OK && final_record) {
        status = upload_emit(broker, PBNS_MESSAGE_COMPLETE,
                             (pbns_view){NULL, 0U},
                             broker->upload_next_sequence);
    }
    if (status != PBNS_OK) {
        return abort_upload_session(broker, status);
    }
    if (!final_record) {
        return PBNS_OK;
    }
    broker->upload_mode = false;
    status = pbns_broker_receive(broker, response);
    if (status != PBNS_OK) {
        clear_response(response);
        return abort_upload_session(broker, status);
    }
    broker->upload_response_received = true;
    return PBNS_OK;
}

pbns_status pbns_broker_upload_finish(pbns_broker *broker) {
    if (broker == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    if (!broker->initialized || !broker->active || broker->upload_mode ||
        !broker->upload_response_received) {
        return PBNS_ERR_STATE;
    }
    return finish_session(broker, false);
}

pbns_status pbns_broker_cancel(pbns_broker *broker) {
    if (broker == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    if (!broker->initialized || !broker->active) {
        return PBNS_ERR_STATE;
    }
    pbns_status status = emit_cancel(broker);
    const pbns_status local_status =
        broker->transport.ops->cancel(broker->transport.context, &broker->request_id);
    if (status == PBNS_OK && local_status != PBNS_OK && local_status != PBNS_ERR_UNSUPPORTED) {
        status = local_status;
    }
    const pbns_status close_status = finish_session(broker, false);
    if (status == PBNS_OK && close_status != PBNS_OK) {
        status = close_status;
    }
    return status;
}

static pbns_status broker_request(pbns_broker *broker, pbns_service_id service,
                                  const pbns_request_id *supplied_request_id,
                                  pbns_view request_body, uint32_t timeout_ms,
                                  pbns_broker_response *response) {
    clear_response(response);
    if (broker == NULL || response == NULL || !view_is_valid(request_body) || timeout_ms == 0U ||
        (supplied_request_id != NULL && !request_id_is_nonzero(supplied_request_id))) {
        return PBNS_ERR_ARGUMENT;
    }
    if (!broker->initialized) {
        return PBNS_ERR_STATE;
    }
    if (!service_is_valid(service)) {
        return PBNS_ERR_SERVICE;
    }
    if (broker->active || broker->opened) {
        return PBNS_ERR_BUSY;
    }

    wipe_request_storage(broker, false);
    pbns_record_reader_reset(&broker->reader);
    broker->request_id = (pbns_request_id){0};
    pbns_request_id request_id = {0};
    pbns_status status = PBNS_OK;
    if (supplied_request_id == NULL) {
        status = broker->platform.ops->random(
            broker->platform.context,
            (pbns_buffer){request_id.bytes, 0U, sizeof(request_id.bytes)});
        if (status != PBNS_OK) {
            return status;
        }
        if (!request_id_is_nonzero(&request_id)) {
            return PBNS_ERR_ENTROPY;
        }
    } else {
        request_id = *supplied_request_id;
    }
    broker->request_id = request_id;
    status = begin_deadline(broker, timeout_ms);
    if (status != PBNS_OK) {
        broker->request_id = (pbns_request_id){0};
        wipe_request_storage(broker, false);
        return status;
    }
    status = broker->transport.ops->open(broker->transport.context);
    if (status != PBNS_OK) {
        broker->deadline_active = false;
        broker->request_id = (pbns_request_id){0};
        wipe_request_storage(broker, false);
        return status;
    }
    broker->opened = true;
    status = query_effective_limits(broker);
    if (status == PBNS_OK && request_body.len > broker->limits.control_payload_max) {
        status = PBNS_ERR_LIMIT;
    }
    if (status != PBNS_OK) {
        (void)finish_session(broker, false);
        return status;
    }

    const pbns_frame request = {
        .service = service,
        .type = PBNS_MESSAGE_REQUEST,
        .flags = 0U,
        .request_id = broker->request_id,
        .sequence = 0U,
    };
    size_t written = 0U;
    status = pbns_frame_encode(
        &request, request_body,
        (pbns_buffer){broker->storage.raw_scratch.ptr, 0U, broker->storage.raw_scratch.cap},
        (pbns_buffer){broker->storage.encoded.ptr, 0U, broker->storage.encoded.cap}, &written);
    if (status != PBNS_OK) {
        (void)finish_session(broker, false);
        return status;
    }

    uint32_t remaining_ms = 0U;
    status = remaining_timeout(broker, &remaining_ms);
    if (status == PBNS_OK) {
        status = broker->transport.ops->send(broker->transport.context,
                                             (pbns_view){broker->storage.encoded.ptr, written},
                                             remaining_ms);
    }
    if (status != PBNS_OK) {
        const pbns_status close_status = finish_session(broker, false);
        return status != PBNS_OK ? status : close_status;
    }

    broker->service = service;
    broker->active = true;
    pbns_stream_init(&broker->stream, broker->service, broker->request_id,
                     (uint64_t)broker->limits.control_payload_max);
    if (!broker->stream.initialized) {
        (void)finish_session(broker, false);
        return PBNS_ERR_STATE;
    }
    pbns_record_reader_reset(&broker->reader);
    status = pbns_broker_receive(broker, response);
    if (status == PBNS_ERR_TIMEOUT) {
        (void)pbns_broker_cancel(broker);
        clear_response(response);
        return PBNS_ERR_TIMEOUT;
    }
    const bool preserve_decoded = status == PBNS_OK;
    const pbns_status close_status = finish_session(broker, preserve_decoded);
    if (close_status != PBNS_OK) {
        wipe_buffer(broker->storage.decoded);
        broker->storage.decoded.len = 0U;
        clear_response(response);
        if (status == PBNS_OK) {
            return close_status;
        }
    }
    return status;
}

pbns_status pbns_broker_request_with_id(pbns_broker *broker, pbns_service_id service,
                                        const pbns_request_id *request_id, pbns_view request_body,
                                        uint32_t timeout_ms, pbns_broker_response *response) {
    if (request_id == NULL) {
        clear_response(response);
        return PBNS_ERR_ARGUMENT;
    }
    const pbns_request_id supplied_request_id = *request_id;
    return broker_request(broker, service, &supplied_request_id, request_body, timeout_ms,
                          response);
}

pbns_status pbns_broker_request(pbns_broker *broker, pbns_service_id service,
                                pbns_view request_body, uint32_t timeout_ms,
                                pbns_broker_response *response) {
    return broker_request(broker, service, NULL, request_body, timeout_ms, response);
}

void pbns_broker_reset(pbns_broker *broker) {
    if (broker == NULL || !broker->initialized) {
        return;
    }
    if (broker->active) {
        (void)pbns_broker_cancel(broker);
    } else if (broker->opened) {
        (void)broker->transport.ops->close(broker->transport.context);
        broker->opened = false;
    }
    wipe_request_storage(broker, false);
    *broker = (pbns_broker){0};
}
