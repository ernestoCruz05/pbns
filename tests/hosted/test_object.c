#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/object.h"
#include "qcbor/qcbor_encode.h"

static const uint8_t canonical_object[] = {
    0xa9, 0x01, 0x69, 0x70, 0x62, 0x6e, 0x73, 0x2e, 0x74, 0x69, 0x6d, 0x65,
    0x02, 0x01, 0x03, 0x01, 0x04, 0x50, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x05, 0x40,
    0x06, 0x58, 0x20, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
    0x3e, 0x3f, 0x07, 0x19, 0x03, 0xe8, 0x08, 0x18, 0x3c, 0x09, 0x43,
    0xaa, 0xbb, 0xcc,
};

static const uint8_t request_bytes[PBNS_REQUEST_ID_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const uint8_t nonce_bytes[PBNS_OBJECT_NONCE_SIZE] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};

static const uint8_t body_bytes[] = {0xaa, 0xbb, 0xcc};
static const int64_t canonical_labels[PBNS_OBJECT_FIELD_COUNT] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9,
};

typedef struct object_values {
    const char *domain;
    uint64_t version;
    uint64_t service;
    pbns_view request;
    pbns_view host_binding;
    pbns_view nonce;
    uint64_t issued_at;
    uint64_t expiry_or_max_age;
    pbns_view body;
} object_values;

static object_values valid_values(void) {
    return (object_values){
        .domain = "pbns.time",
        .version = PBNS_OBJECT_VERSION,
        .service = UINT64_C(1),
        .request = {request_bytes, sizeof(request_bytes)},
        .host_binding = {NULL, 0U},
        .nonce = {nonce_bytes, sizeof(nonce_bytes)},
        .issued_at = UINT64_C(1000),
        .expiry_or_max_age = UINT64_C(60),
        .body = {body_bytes, sizeof(body_bytes)},
    };
}

static size_t encode_object(uint8_t *output,
                            size_t output_cap,
                            const object_values *values,
                            const int64_t labels[PBNS_OBJECT_FIELD_COUNT],
                            size_t wrong_type_field) {
    QCBOREncodeContext encoder = {0};
    UsefulBufC encoded = {0};
    QCBOREncode_Init(&encoder, (UsefulBuf){output, output_cap});
    QCBOREncode_OpenMap(&encoder);

    for (size_t index = 0U; index < PBNS_OBJECT_FIELD_COUNT; ++index) {
        const int64_t label = labels[index];
        const size_t field = index + 1U;
        if (field == wrong_type_field) {
            QCBOREncode_AddTextToMapN(&encoder, label,
                                      (UsefulBufC){"wrong", sizeof("wrong") - 1U});
            continue;
        }
        switch (field) {
            case 1U:
                QCBOREncode_AddTextToMapN(
                    &encoder, label,
                    (UsefulBufC){values->domain, strlen(values->domain)});
                break;
            case 2U:
                QCBOREncode_AddUInt64ToMapN(&encoder, label, values->version);
                break;
            case 3U:
                QCBOREncode_AddUInt64ToMapN(&encoder, label, values->service);
                break;
            case 4U:
                QCBOREncode_AddBytesToMapN(
                    &encoder, label,
                    (UsefulBufC){values->request.ptr, values->request.len});
                break;
            case 5U:
                QCBOREncode_AddBytesToMapN(
                    &encoder, label,
                    (UsefulBufC){values->host_binding.ptr, values->host_binding.len});
                break;
            case 6U:
                QCBOREncode_AddBytesToMapN(
                    &encoder, label,
                    (UsefulBufC){values->nonce.ptr, values->nonce.len});
                break;
            case 7U:
                QCBOREncode_AddUInt64ToMapN(&encoder, label, values->issued_at);
                break;
            case 8U:
                QCBOREncode_AddUInt64ToMapN(&encoder, label, values->expiry_or_max_age);
                break;
            case 9U:
                QCBOREncode_AddBytesToMapN(
                    &encoder, label,
                    (UsefulBufC){values->body.ptr, values->body.len});
                break;
            default:
                assert(false);
        }
    }

    QCBOREncode_CloseMap(&encoder);
    assert(QCBOREncode_Finish(&encoder, &encoded) == QCBOR_SUCCESS);
    assert(encoded.ptr == output);
    return encoded.len;
}

static pbns_request_id expected_request(void) {
    pbns_request_id request = {{0}};
    for (size_t index = 0U; index < sizeof(request.bytes); ++index) {
        request.bytes[index] = request_bytes[index];
    }
    return request;
}

static pbns_status validate_with_defaults(pbns_view encoded,
                                          pbns_buffer scratch,
                                          pbns_object_context *result) {
    const pbns_request_id request = expected_request();
    return pbns_object_validate_common(encoded,
                                       "pbns.time",
                                       PBNS_SERVICE_TRUSTED_TIME,
                                       &request,
                                       (pbns_view){nonce_bytes, sizeof(nonce_bytes)},
                                       scratch,
                                       result);
}

static void assert_bytes_equal(pbns_view actual, const uint8_t *expected, size_t expected_len) {
    assert(actual.len == expected_len);
    assert(memcmp(actual.ptr, expected, expected_len) == 0);
}

static void test_qcbor_encoding_matches_canonical_fixture(void) {
    uint8_t encoded[sizeof(canonical_object)] = {0};
    const object_values values = valid_values();
    const size_t written = encode_object(encoded,
                                         sizeof(encoded),
                                         &values,
                                         canonical_labels,
                                         0U);
    assert(written == sizeof(canonical_object));
    assert(memcmp(encoded, canonical_object, sizeof(canonical_object)) == 0);
}

static void test_validates_canonical_common_context(void) {
    uint8_t scratch[sizeof(canonical_object)] = {0};
    pbns_object_context result = {0};
    assert(validate_with_defaults((pbns_view){canonical_object, sizeof(canonical_object)},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &result) == PBNS_OK);
    assert_bytes_equal(result.domain, (const uint8_t *)"pbns.time", 9U);
    assert(result.object_version == PBNS_OBJECT_VERSION);
    assert(result.service == PBNS_SERVICE_TRUSTED_TIME);
    assert(memcmp(result.request_id.bytes, request_bytes, sizeof(request_bytes)) == 0);
    assert(result.host_binding.len == 0U);
    assert_bytes_equal(result.nonce, nonce_bytes, sizeof(nonce_bytes));
    assert(result.issued_at == UINT64_C(1000));
    assert(result.expiry_or_max_age == UINT64_C(60));
    assert_bytes_equal(result.body, body_bytes, sizeof(body_bytes));
}

static void test_rejects_non_shortest_integer_and_trailing_bytes(void) {
    uint8_t non_shortest[sizeof(canonical_object) + 1U] = {0};
    for (size_t index = 0U; index < 13U; ++index) {
        non_shortest[index] = canonical_object[index];
    }
    non_shortest[13] = UINT8_C(0x18);
    non_shortest[14] = UINT8_C(0x01);
    for (size_t index = 14U; index < sizeof(canonical_object); ++index) {
        non_shortest[index + 1U] = canonical_object[index];
    }
    uint8_t scratch[sizeof(non_shortest)] = {0};
    pbns_object_context result = {0};
    assert(validate_with_defaults((pbns_view){non_shortest, sizeof(non_shortest)},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &result) == PBNS_ERR_FORMAT);

    uint8_t trailing[sizeof(canonical_object) + 1U] = {0};
    for (size_t index = 0U; index < sizeof(canonical_object); ++index) {
        trailing[index] = canonical_object[index];
    }
    assert(validate_with_defaults((pbns_view){trailing, sizeof(trailing)},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &result) == PBNS_ERR_FORMAT);
}

static void test_rejects_indefinite_forms(void) {
    uint8_t indefinite_map[sizeof(canonical_object) + 1U] = {0};
    indefinite_map[0] = UINT8_C(0xbf);
    for (size_t index = 1U; index < sizeof(canonical_object); ++index) {
        indefinite_map[index] = canonical_object[index];
    }
    indefinite_map[sizeof(canonical_object)] = UINT8_C(0xff);

    uint8_t indefinite_bstr[sizeof(canonical_object) + 3U] = {0};
    for (size_t index = 0U; index < 79U; ++index) {
        indefinite_bstr[index] = canonical_object[index];
    }
    static const uint8_t bstr_suffix[] = {
        0x5f, 0x41, 0xaa, 0x42, 0xbb, 0xcc, 0xff,
    };
    for (size_t index = 0U; index < sizeof(bstr_suffix); ++index) {
        indefinite_bstr[79U + index] = bstr_suffix[index];
    }

    static const uint8_t indefinite_array[] = {0x9f, 0x01, 0xff};
    uint8_t scratch[sizeof(indefinite_bstr)] = {0};
    pbns_object_context result = {0};
    assert(validate_with_defaults((pbns_view){indefinite_map, sizeof(indefinite_map)},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &result) == PBNS_ERR_FORMAT);
    assert(validate_with_defaults((pbns_view){indefinite_bstr, sizeof(indefinite_bstr)},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &result) == PBNS_ERR_FORMAT);
    assert(validate_with_defaults((pbns_view){indefinite_array, sizeof(indefinite_array)},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &result) == PBNS_ERR_FORMAT);
}

static void test_rejects_duplicate_reordered_and_unknown_labels(void) {
    static const int64_t duplicate_labels[PBNS_OBJECT_FIELD_COUNT] = {
        1, 2, 2, 4, 5, 6, 7, 8, 9,
    };
    static const int64_t reordered_labels[PBNS_OBJECT_FIELD_COUNT] = {
        1, 3, 2, 4, 5, 6, 7, 8, 9,
    };
    static const int64_t unknown_labels[PBNS_OBJECT_FIELD_COUNT] = {
        1, 2, 3, 4, 5, 6, 7, 8, 10,
    };
    const object_values values = valid_values();
    uint8_t encoded[256] = {0};
    uint8_t scratch[256] = {0};
    pbns_object_context result = {0};

    size_t written = encode_object(encoded, sizeof(encoded), &values, duplicate_labels, 0U);
    assert(validate_with_defaults((pbns_view){encoded, written},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &result) == PBNS_ERR_FORMAT);
    written = encode_object(encoded, sizeof(encoded), &values, reordered_labels, 0U);
    assert(validate_with_defaults((pbns_view){encoded, written},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &result) == PBNS_ERR_FORMAT);
    written = encode_object(encoded, sizeof(encoded), &values, unknown_labels, 0U);
    assert(validate_with_defaults((pbns_view){encoded, written},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &result) == PBNS_ERR_FORMAT);
}

static void test_rejects_wrong_types_and_field_lengths(void) {
    object_values values = valid_values();
    uint8_t encoded[256] = {0};
    uint8_t scratch[256] = {0};
    pbns_object_context result = {0};

    size_t written = encode_object(encoded, sizeof(encoded), &values, canonical_labels, 2U);
    assert(validate_with_defaults((pbns_view){encoded, written},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &result) == PBNS_ERR_FORMAT);

    values.request.len = PBNS_REQUEST_ID_SIZE - 1U;
    written = encode_object(encoded, sizeof(encoded), &values, canonical_labels, 0U);
    assert(validate_with_defaults((pbns_view){encoded, written},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &result) == PBNS_ERR_FORMAT);

    static const uint8_t one_byte[] = {0x01};
    values = valid_values();
    values.host_binding = (pbns_view){one_byte, sizeof(one_byte)};
    written = encode_object(encoded, sizeof(encoded), &values, canonical_labels, 0U);
    assert(validate_with_defaults((pbns_view){encoded, written},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &result) == PBNS_ERR_FORMAT);
}

static void test_rejects_context_mismatches_with_typed_status(void) {
    uint8_t scratch[256] = {0};
    pbns_object_context result = {0};
    pbns_request_id request = expected_request();
    uint8_t changed_nonce[sizeof(nonce_bytes)] = {0};
    for (size_t index = 0U; index < sizeof(changed_nonce); ++index) {
        changed_nonce[index] = nonce_bytes[index];
    }
    changed_nonce[0] ^= UINT8_C(1);

    assert(pbns_object_validate_common(
               (pbns_view){canonical_object, sizeof(canonical_object)},
               "pbns.attest",
               PBNS_SERVICE_TRUSTED_TIME,
               &request,
               (pbns_view){nonce_bytes, sizeof(nonce_bytes)},
               (pbns_buffer){scratch, 0U, sizeof(scratch)},
               &result) == PBNS_ERR_AUTHENTICATION);

    assert(pbns_object_validate_common(
               (pbns_view){canonical_object, sizeof(canonical_object)},
               "pbns.time",
               PBNS_SERVICE_PLATFORM_ATTESTATION,
               &request,
               (pbns_view){nonce_bytes, sizeof(nonce_bytes)},
               (pbns_buffer){scratch, 0U, sizeof(scratch)},
               &result) == PBNS_ERR_SERVICE);

    request.bytes[0] ^= UINT8_C(1);
    assert(pbns_object_validate_common(
               (pbns_view){canonical_object, sizeof(canonical_object)},
               "pbns.time",
               PBNS_SERVICE_TRUSTED_TIME,
               &request,
               (pbns_view){nonce_bytes, sizeof(nonce_bytes)},
               (pbns_buffer){scratch, 0U, sizeof(scratch)},
               &result) == PBNS_ERR_AUTHENTICATION);

    request = expected_request();
    assert(pbns_object_validate_common(
               (pbns_view){canonical_object, sizeof(canonical_object)},
               "pbns.time",
               PBNS_SERVICE_TRUSTED_TIME,
               &request,
               (pbns_view){changed_nonce, sizeof(changed_nonce)},
               (pbns_buffer){scratch, 0U, sizeof(scratch)},
               &result) == PBNS_ERR_AUTHENTICATION);

    object_values values = valid_values();
    uint8_t encoded[256] = {0};
    values.version = UINT64_C(2);
    size_t written = encode_object(encoded, sizeof(encoded), &values, canonical_labels, 0U);
    assert(validate_with_defaults((pbns_view){encoded, written},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &result) == PBNS_ERR_VERSION);

    values = valid_values();
    values.service = UINT64_C(2);
    written = encode_object(encoded, sizeof(encoded), &values, canonical_labels, 0U);
    assert(validate_with_defaults((pbns_view){encoded, written},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &result) == PBNS_ERR_SERVICE);
}

static void test_rejects_invalid_arguments_and_scratch(void) {
    uint8_t scratch[sizeof(canonical_object)] = {0};
    uint8_t overlap[sizeof(canonical_object)] = {0};
    for (size_t index = 0U; index < sizeof(overlap); ++index) {
        overlap[index] = canonical_object[index];
    }
    pbns_object_context result = {0};
    const pbns_request_id request = expected_request();

    assert(pbns_object_validate_common(
               (pbns_view){canonical_object, sizeof(canonical_object)},
               "pbns.time",
               PBNS_SERVICE_TRUSTED_TIME,
               &request,
               (pbns_view){nonce_bytes, sizeof(nonce_bytes)},
               (pbns_buffer){scratch, 0U, sizeof(scratch) - 1U},
               &result) == PBNS_ERR_LIMIT);
    assert(pbns_object_validate_common(
               (pbns_view){overlap, sizeof(overlap)},
               "pbns.time",
               PBNS_SERVICE_TRUSTED_TIME,
               &request,
               (pbns_view){nonce_bytes, sizeof(nonce_bytes)},
               (pbns_buffer){overlap, 0U, sizeof(overlap)},
               &result) == PBNS_ERR_ARGUMENT);
    assert(pbns_object_validate_common(
               (pbns_view){canonical_object, sizeof(canonical_object)},
               NULL,
               PBNS_SERVICE_TRUSTED_TIME,
               &request,
               (pbns_view){nonce_bytes, sizeof(nonce_bytes)},
               (pbns_buffer){scratch, 0U, sizeof(scratch)},
               &result) == PBNS_ERR_ARGUMENT);
    assert(pbns_object_validate_common(
               (pbns_view){canonical_object, sizeof(canonical_object)},
               "pbns.time",
               PBNS_SERVICE_TRUSTED_TIME,
               &request,
               (pbns_view){nonce_bytes, sizeof(nonce_bytes) - 1U},
               (pbns_buffer){scratch, 0U, sizeof(scratch)},
               &result) == PBNS_ERR_ARGUMENT);
}

int main(void) {
    test_qcbor_encoding_matches_canonical_fixture();
    test_validates_canonical_common_context();
    test_rejects_non_shortest_integer_and_trailing_bytes();
    test_rejects_indefinite_forms();
    test_rejects_duplicate_reordered_and_unknown_labels();
    test_rejects_wrong_types_and_field_lengths();
    test_rejects_context_mismatches_with_typed_status();
    test_rejects_invalid_arguments_and_scratch();
    return 0;
}
