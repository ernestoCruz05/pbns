#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/buffer.h"
#include "pbns/cobs.h"
#include "pbns/crc32c.h"
#include "pbns/status.h"

static void test_status_strings_are_stable(void) {
    assert(strcmp(pbns_status_string(PBNS_OK), "ok") == 0);
    assert(strcmp(pbns_status_string(PBNS_ERR_LIMIT), "limit") == 0);
    assert(strcmp(pbns_status_string(PBNS_ERR_AUTHENTICATION), "authentication") == 0);
}

static void test_crc32c_standard_vector(void) {
    static const uint8_t input[] = "123456789";
    assert(pbns_crc32c((pbns_view){input, sizeof(input) - 1U}) == UINT32_C(0xe3069283));
}

static void test_crc32c_empty_vector(void) {
    assert(pbns_crc32c((pbns_view){NULL, 0U}) == UINT32_C(0));
}

static void test_cobs_empty_round_trip(void) {
    uint8_t encoded[1] = {0};
    uint8_t decoded[1] = {0};
    size_t encoded_len = 0U;
    size_t decoded_len = 1U;

    assert(pbns_cobs_encode((pbns_view){NULL, 0U},
                            (pbns_buffer){encoded, 0U, sizeof(encoded)},
                            &encoded_len) == PBNS_OK);
    assert(encoded_len == 1U);
    assert(encoded[0] == UINT8_C(1));
    assert(pbns_cobs_decode((pbns_view){encoded, encoded_len},
                            (pbns_buffer){decoded, 0U, sizeof(decoded)},
                            &decoded_len) == PBNS_OK);
    assert(decoded_len == 0U);
}

static void test_cobs_round_trip_embedded_zeroes(void) {
    static const uint8_t input[] = {0x11, 0x00, 0x22, 0x00, 0x00, 0x33};
    static const uint8_t expected[] = {0x02, 0x11, 0x02, 0x22, 0x01, 0x02, 0x33};
    uint8_t encoded[sizeof(expected)] = {0};
    uint8_t decoded[sizeof(input)] = {0};
    size_t encoded_len = 0U;
    size_t decoded_len = 0U;

    assert(pbns_cobs_encode((pbns_view){input, sizeof(input)},
                            (pbns_buffer){encoded, 0U, sizeof(encoded)},
                            &encoded_len) == PBNS_OK);
    assert(encoded_len == sizeof(expected));
    assert(memcmp(encoded, expected, sizeof(expected)) == 0);
    assert(pbns_cobs_decode((pbns_view){encoded, encoded_len},
                            (pbns_buffer){decoded, 0U, sizeof(decoded)},
                            &decoded_len) == PBNS_OK);
    assert(decoded_len == sizeof(input));
    assert(memcmp(decoded, input, sizeof(input)) == 0);
}

static void test_cobs_exact_254_byte_run(void) {
    uint8_t input[254] = {0};
    uint8_t encoded[256] = {0};
    uint8_t decoded[sizeof(input)] = {0};
    size_t encoded_len = 0U;
    size_t decoded_len = 0U;

    for (size_t index = 0U; index < sizeof(input); ++index) {
        input[index] = (uint8_t)(index % UINT8_MAX + 1U);
    }

    assert(pbns_cobs_encode((pbns_view){input, sizeof(input)},
                            (pbns_buffer){encoded, 0U, sizeof(encoded)},
                            &encoded_len) == PBNS_OK);
    assert(encoded_len == sizeof(encoded));
    assert(encoded[0] == UINT8_MAX);
    assert(encoded[sizeof(encoded) - 1U] == UINT8_C(1));
    assert(pbns_cobs_decode((pbns_view){encoded, encoded_len},
                            (pbns_buffer){decoded, 0U, sizeof(decoded)},
                            &decoded_len) == PBNS_OK);
    assert(decoded_len == sizeof(input));
    assert(memcmp(decoded, input, sizeof(input)) == 0);
}

static void test_cobs_rejects_small_encode_buffer(void) {
    static const uint8_t input[] = {0x11, 0x00, 0x22};
    uint8_t encoded[3] = {0};
    size_t written = 99U;

    assert(pbns_cobs_encode((pbns_view){input, sizeof(input)},
                            (pbns_buffer){encoded, 0U, sizeof(encoded)},
                            &written) == PBNS_ERR_LIMIT);
    assert(written == 0U);
}

static void test_cobs_rejects_small_decode_buffer(void) {
    static const uint8_t encoded[] = {0x04, 0x11, 0x22, 0x33};
    uint8_t decoded[2] = {0};
    size_t written = 99U;

    assert(pbns_cobs_decode((pbns_view){encoded, sizeof(encoded)},
                            (pbns_buffer){decoded, 0U, sizeof(decoded)},
                            &written) == PBNS_ERR_LIMIT);
    assert(written == 0U);
}

static void test_cobs_rejects_zero_in_encoded_input(void) {
    static const uint8_t encoded[] = {0x03, 0x11, 0x00};
    uint8_t decoded[2] = {0};
    size_t written = 99U;

    assert(pbns_cobs_decode((pbns_view){encoded, sizeof(encoded)},
                            (pbns_buffer){decoded, 0U, sizeof(decoded)},
                            &written) == PBNS_ERR_FORMAT);
    assert(written == 0U);
}

static void test_cobs_rejects_malformed_overrun(void) {
    static const uint8_t encoded[] = {0x03, 0x11};
    uint8_t decoded[2] = {0};
    size_t written = 99U;

    assert(pbns_cobs_decode((pbns_view){encoded, sizeof(encoded)},
                            (pbns_buffer){decoded, 0U, sizeof(decoded)},
                            &written) == PBNS_ERR_FORMAT);
    assert(written == 0U);
}

static void test_cobs_rejects_empty_encoded_record(void) {
    uint8_t decoded[1] = {0};
    size_t written = 99U;

    assert(pbns_cobs_decode((pbns_view){NULL, 0U},
                            (pbns_buffer){decoded, 0U, sizeof(decoded)},
                            &written) == PBNS_ERR_FORMAT);
    assert(written == 0U);
}

static void test_cobs_rejects_invalid_pointer_length_pairs(void) {
    uint8_t storage[4] = {0};
    size_t written = 99U;

    assert(pbns_cobs_encode((pbns_view){NULL, 1U},
                            (pbns_buffer){storage, 0U, sizeof(storage)},
                            &written) == PBNS_ERR_ARGUMENT);
    assert(pbns_cobs_encode((pbns_view){storage, 1U},
                            (pbns_buffer){NULL, 0U, sizeof(storage)},
                            &written) == PBNS_ERR_ARGUMENT);
    assert(pbns_cobs_encode((pbns_view){storage, 1U},
                            (pbns_buffer){storage, 0U, sizeof(storage)},
                            NULL) == PBNS_ERR_ARGUMENT);
    assert(pbns_cobs_encode((pbns_view){storage, 1U},
                            (pbns_buffer){storage, 1U, sizeof(storage)},
                            &written) == PBNS_ERR_ARGUMENT);
    assert(written == 0U);
}

static void test_cobs_max_size_checks_overflow(void) {
    size_t result = 0U;

    assert(pbns_cobs_max_encoded_size(0U, &result) == PBNS_OK);
    assert(result == 1U);
    assert(pbns_cobs_max_encoded_size(254U, &result) == PBNS_OK);
    assert(result == 256U);
    assert(pbns_cobs_max_encoded_size(SIZE_MAX, &result) == PBNS_ERR_LIMIT);
    assert(pbns_cobs_max_encoded_size(1U, NULL) == PBNS_ERR_ARGUMENT);
}

int main(void) {
    test_status_strings_are_stable();
    test_crc32c_standard_vector();
    test_crc32c_empty_vector();
    test_cobs_empty_round_trip();
    test_cobs_round_trip_embedded_zeroes();
    test_cobs_exact_254_byte_run();
    test_cobs_rejects_small_encode_buffer();
    test_cobs_rejects_small_decode_buffer();
    test_cobs_rejects_zero_in_encoded_input();
    test_cobs_rejects_malformed_overrun();
    test_cobs_rejects_empty_encoded_record();
    test_cobs_rejects_invalid_pointer_length_pairs();
    test_cobs_max_size_checks_overflow();
    return 0;
}
