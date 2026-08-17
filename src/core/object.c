#include "pbns/object.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "qcbor/qcbor.h"

static bool view_is_valid(pbns_view view) {
    return view.ptr != NULL || view.len == 0U;
}

static bool output_buffer_is_valid(pbns_buffer buffer) {
    return buffer.len == 0U && (buffer.ptr != NULL || buffer.cap == 0U);
}

static bool service_is_valid(pbns_service_id service) {
    return service >= PBNS_SERVICE_TRUSTED_TIME && service <= PBNS_SERVICE_ENROLLMENT;
}

static bool ranges_overlap(pbns_view input, pbns_buffer output) {
    if (input.len == 0U || output.cap == 0U) {
        return false;
    }
    const uintptr_t input_start = (uintptr_t)input.ptr;
    const uintptr_t output_start = (uintptr_t)output.ptr;
    if (input.len > UINTPTR_MAX - input_start || output.cap > UINTPTR_MAX - output_start) {
        return true;
    }
    const uintptr_t input_end = input_start + input.len;
    const uintptr_t output_end = output_start + output.cap;
    return input_start < output_end && output_start < input_end;
}

static bool views_match(pbns_view left, pbns_view right) {
    if (left.len != right.len) {
        return false;
    }
    for (size_t index = 0U; index < left.len; ++index) {
        if (left.ptr[index] != right.ptr[index]) {
            return false;
        }
    }
    return true;
}

static bool request_ids_match(pbns_request_id left, const pbns_request_id *right) {
    for (size_t index = 0U; index < sizeof(left.bytes); ++index) {
        if (left.bytes[index] != right->bytes[index]) {
            return false;
        }
    }
    return true;
}

static pbns_status next_labeled_item(QCBORDecodeContext *decoder,
                                     int64_t expected_label,
                                     QCBORItem *item) {
    if (QCBORDecode_GetNext(decoder, item) != QCBOR_SUCCESS) {
        return PBNS_ERR_FORMAT;
    }
    if (item->uNestingLevel != 1U || item->uLabelType != QCBOR_TYPE_INT64
        || item->label.int64 != expected_label) {
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

static pbns_status decode_common(pbns_view encoded, pbns_object_context *context) {
    QCBORDecodeContext decoder = {0};
    QCBORItem item = {0};
    QCBORDecode_Init(&decoder,
                     (UsefulBufC){encoded.ptr, encoded.len},
                     QCBOR_DECODE_MODE_NORMAL);
    if (QCBORDecode_GetNext(&decoder, &item) != QCBOR_SUCCESS
        || item.uDataType != QCBOR_TYPE_MAP
        || item.uLabelType != QCBOR_TYPE_NONE
        || item.val.uCount != PBNS_OBJECT_FIELD_COUNT) {
        return PBNS_ERR_FORMAT;
    }

    if (next_labeled_item(&decoder, 1, &item) != PBNS_OK
        || item.uDataType != QCBOR_TYPE_TEXT_STRING) {
        return PBNS_ERR_FORMAT;
    }
    context->domain = (pbns_view){item.val.string.ptr, item.val.string.len};

    if (next_labeled_item(&decoder, 2, &item) != PBNS_OK
        || !item_to_uint64(&item, &context->object_version)) {
        return PBNS_ERR_FORMAT;
    }

    uint64_t service_value = 0U;
    const pbns_status service_item_status = next_labeled_item(&decoder, 3, &item);
    if (service_item_status != PBNS_OK || !item_to_uint64(&item, &service_value)) {
        return PBNS_ERR_FORMAT;
    }
    if (service_value < (uint64_t)PBNS_SERVICE_TRUSTED_TIME
        || service_value > (uint64_t)PBNS_SERVICE_ENROLLMENT) {
        return PBNS_ERR_SERVICE;
    }
    context->service = (pbns_service_id)service_value;

    if (next_labeled_item(&decoder, 4, &item) != PBNS_OK
        || item.uDataType != QCBOR_TYPE_BYTE_STRING
        || item.val.string.len != PBNS_REQUEST_ID_SIZE) {
        return PBNS_ERR_FORMAT;
    }
    const uint8_t *const request = item.val.string.ptr;
    for (size_t index = 0U; index < sizeof(context->request_id.bytes); ++index) {
        context->request_id.bytes[index] = request[index];
    }

    if (next_labeled_item(&decoder, 5, &item) != PBNS_OK
        || item.uDataType != QCBOR_TYPE_BYTE_STRING
        || (item.val.string.len != 0U
            && item.val.string.len != PBNS_OBJECT_HOST_BINDING_SIZE)) {
        return PBNS_ERR_FORMAT;
    }
    context->host_binding = (pbns_view){item.val.string.ptr, item.val.string.len};

    if (next_labeled_item(&decoder, 6, &item) != PBNS_OK
        || item.uDataType != QCBOR_TYPE_BYTE_STRING
        || item.val.string.len != PBNS_OBJECT_NONCE_SIZE) {
        return PBNS_ERR_FORMAT;
    }
    context->nonce = (pbns_view){item.val.string.ptr, item.val.string.len};

    if (next_labeled_item(&decoder, 7, &item) != PBNS_OK
        || !item_to_uint64(&item, &context->issued_at)) {
        return PBNS_ERR_FORMAT;
    }
    if (next_labeled_item(&decoder, 8, &item) != PBNS_OK
        || !item_to_uint64(&item, &context->expiry_or_max_age)) {
        return PBNS_ERR_FORMAT;
    }
    if (next_labeled_item(&decoder, 9, &item) != PBNS_OK
        || item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        return PBNS_ERR_FORMAT;
    }
    context->body = (pbns_view){item.val.string.ptr, item.val.string.len};

    return QCBORDecode_Finish(&decoder) == QCBOR_SUCCESS ? PBNS_OK : PBNS_ERR_FORMAT;
}

static pbns_status encode_canonical(const pbns_object_context *context,
                                    pbns_buffer output,
                                    size_t *written) {
    QCBOREncodeContext encoder = {0};
    UsefulBufC encoded = {0};
    QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
    QCBOREncode_OpenMap(&encoder);
    QCBOREncode_AddTextToMapN(
        &encoder, 1, (UsefulBufC){context->domain.ptr, context->domain.len});
    QCBOREncode_AddUInt64ToMapN(&encoder, 2, context->object_version);
    QCBOREncode_AddUInt64ToMapN(&encoder, 3, (uint64_t)context->service);
    QCBOREncode_AddBytesToMapN(
        &encoder, 4,
        (UsefulBufC){context->request_id.bytes, sizeof(context->request_id.bytes)});
    QCBOREncode_AddBytesToMapN(
        &encoder, 5,
        (UsefulBufC){context->host_binding.ptr, context->host_binding.len});
    QCBOREncode_AddBytesToMapN(
        &encoder, 6, (UsefulBufC){context->nonce.ptr, context->nonce.len});
    QCBOREncode_AddUInt64ToMapN(&encoder, 7, context->issued_at);
    QCBOREncode_AddUInt64ToMapN(&encoder, 8, context->expiry_or_max_age);
    QCBOREncode_AddBytesToMapN(
        &encoder, 9, (UsefulBufC){context->body.ptr, context->body.len});
    QCBOREncode_CloseMap(&encoder);

    const QCBORError error = QCBOREncode_Finish(&encoder, &encoded);
    if (error == QCBOR_ERR_BUFFER_TOO_SMALL) {
        return PBNS_ERR_LIMIT;
    }
    if (error != QCBOR_SUCCESS) {
        return PBNS_ERR_FORMAT;
    }
    *written = encoded.len;
    return PBNS_OK;
}

pbns_status pbns_object_validate_common(pbns_view encoded,
                                        const char *expected_domain,
                                        pbns_service_id expected_service,
                                        const pbns_request_id *expected_request,
                                        pbns_view expected_nonce,
                                        pbns_buffer canonical_scratch,
                                        pbns_object_context *result) {
    if (result != NULL) {
        *result = (pbns_object_context){0};
    }
    if (!view_is_valid(encoded) || expected_domain == NULL || !service_is_valid(expected_service)
        || expected_request == NULL || !view_is_valid(expected_nonce)
        || expected_nonce.len != PBNS_OBJECT_NONCE_SIZE
        || !output_buffer_is_valid(canonical_scratch) || result == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    if (encoded.len > PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX
        || canonical_scratch.cap < encoded.len) {
        return PBNS_ERR_LIMIT;
    }
    if (ranges_overlap(encoded, canonical_scratch)) {
        return PBNS_ERR_ARGUMENT;
    }

    pbns_object_context parsed = {0};
    pbns_status status = decode_common(encoded, &parsed);
    if (status != PBNS_OK) {
        return status;
    }

    size_t canonical_len = 0U;
    status = encode_canonical(&parsed, canonical_scratch, &canonical_len);
    if (status != PBNS_OK) {
        return status;
    }
    if (canonical_len != encoded.len) {
        return PBNS_ERR_FORMAT;
    }
    for (size_t index = 0U; index < canonical_len; ++index) {
        if (canonical_scratch.ptr[index] != encoded.ptr[index]) {
            return PBNS_ERR_FORMAT;
        }
    }

    const pbns_view expected_domain_view = {
        (const uint8_t *)expected_domain,
        strlen(expected_domain),
    };
    if (parsed.object_version != PBNS_OBJECT_VERSION) {
        return PBNS_ERR_VERSION;
    }
    if (parsed.service != expected_service) {
        return PBNS_ERR_SERVICE;
    }
    if (!views_match(parsed.domain, expected_domain_view)
        || !request_ids_match(parsed.request_id, expected_request)
        || !views_match(parsed.nonce, expected_nonce)) {
        return PBNS_ERR_AUTHENTICATION;
    }

    *result = parsed;
    return PBNS_OK;
}
