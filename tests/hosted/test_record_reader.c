#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/record_reader.h"

static const uint8_t golden_empty_request[] = {
    0x08, 0x50, 0x42, 0x4e, 0x53, 0x01, 0x01, 0x01, 0x01, 0x10, 0x01, 0x02,
    0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x08, 0xfd,
    0xca, 0xa5, 0xd2, 0x03, 0xcd, 0x38, 0x01, 0x00,
};

static void assert_golden_record(pbns_view record) {
    assert(record.len == sizeof(golden_empty_request) - 1U);
    assert(memcmp(record.ptr, golden_empty_request, record.len) == 0);
}

static void test_every_fragmentation_split(void) {
    for (size_t split = 0U; split <= sizeof(golden_empty_request); ++split) {
        uint8_t storage[sizeof(golden_empty_request) - 1U] = {0};
        pbns_record_reader reader = {0};
        pbns_record_reader_init(&reader, (pbns_buffer){storage, 0U, sizeof(storage)});

        size_t consumed = SIZE_MAX;
        bool ready = true;
        pbns_view record = {golden_empty_request, 1U};
        const pbns_status first = pbns_record_reader_push(
            &reader,
            (pbns_view){golden_empty_request, split},
            &consumed,
            &ready,
            &record);
        assert(consumed == split);

        if (split == sizeof(golden_empty_request)) {
            assert(first == PBNS_OK);
            assert(ready);
            assert_golden_record(record);
        } else {
            assert(first == PBNS_ERR_WOULD_BLOCK);
            assert(!ready);
            assert(record.ptr == NULL);
            assert(record.len == 0U);

            consumed = SIZE_MAX;
            ready = false;
            record = (pbns_view){0};
            assert(pbns_record_reader_push(
                       &reader,
                       (pbns_view){golden_empty_request + split,
                                   sizeof(golden_empty_request) - split},
                       &consumed,
                       &ready,
                       &record) == PBNS_OK);
            assert(consumed == sizeof(golden_empty_request) - split);
            assert(ready);
            assert_golden_record(record);
        }

        consumed = SIZE_MAX;
        ready = true;
        record = (pbns_view){golden_empty_request, 1U};
        assert(pbns_record_reader_push(&reader,
                                       (pbns_view){NULL, 0U},
                                       &consumed,
                                       &ready,
                                       &record) == PBNS_ERR_STATE);
        assert(consumed == 0U);
        assert(!ready);
        assert(record.ptr == NULL);
        assert(record.len == 0U);
    }
}

static void test_multiple_records_in_one_input_chunk(void) {
    uint8_t storage[sizeof(golden_empty_request) - 1U] = {0};
    uint8_t combined[sizeof(golden_empty_request) * 2U] = {0};
    for (size_t index = 0U; index < sizeof(combined); ++index) {
        combined[index] = golden_empty_request[index % sizeof(golden_empty_request)];
    }

    pbns_record_reader reader = {0};
    pbns_record_reader_init(&reader, (pbns_buffer){storage, 0U, sizeof(storage)});
    size_t consumed = 0U;
    bool ready = false;
    pbns_view record = {0};
    assert(pbns_record_reader_push(&reader,
                                   (pbns_view){combined, sizeof(combined)},
                                   &consumed,
                                   &ready,
                                   &record) == PBNS_OK);
    assert(consumed == sizeof(golden_empty_request));
    assert(ready);
    assert_golden_record(record);

    pbns_record_reader_reset(&reader);
    ready = false;
    record = (pbns_view){0};
    size_t second_consumed = 0U;
    assert(pbns_record_reader_push(&reader,
                                   (pbns_view){combined + consumed,
                                               sizeof(combined) - consumed},
                                   &second_consumed,
                                   &ready,
                                   &record) == PBNS_OK);
    assert(second_consumed == sizeof(golden_empty_request));
    assert(ready);
    assert_golden_record(record);
}

static void test_empty_delimiter_requires_reset(void) {
    uint8_t storage[8] = {0};
    static const uint8_t empty_record[] = {0x00};
    static const uint8_t valid_record[] = {0x01, 0x00};
    pbns_record_reader reader = {0};
    pbns_record_reader_init(&reader, (pbns_buffer){storage, 0U, sizeof(storage)});

    size_t consumed = 0U;
    bool ready = false;
    pbns_view record = {0};
    assert(pbns_record_reader_push(&reader,
                                   (pbns_view){empty_record, sizeof(empty_record)},
                                   &consumed,
                                   &ready,
                                   &record) == PBNS_ERR_FORMAT);
    assert(consumed == sizeof(empty_record));
    assert(!ready);

    consumed = SIZE_MAX;
    assert(pbns_record_reader_push(&reader,
                                   (pbns_view){valid_record, sizeof(valid_record)},
                                   &consumed,
                                   &ready,
                                   &record) == PBNS_ERR_STATE);
    assert(consumed == 0U);

    pbns_record_reader_reset(&reader);
    assert(pbns_record_reader_push(&reader,
                                   (pbns_view){valid_record, sizeof(valid_record)},
                                   &consumed,
                                   &ready,
                                   &record) == PBNS_OK);
    assert(consumed == sizeof(valid_record));
    assert(ready);
    assert(record.len == 1U);
    assert(record.ptr[0] == UINT8_C(1));
}

static void test_oversized_record_discards_through_delimiter(void) {
    uint8_t storage[4] = {0};
    static const uint8_t first[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    static const uint8_t second[] = {0x07, 0x00, 0x09};
    static const uint8_t exact[] = {0x01, 0x02, 0x03, 0x04, 0x00};
    pbns_record_reader reader = {0};
    pbns_record_reader_init(&reader, (pbns_buffer){storage, 0U, sizeof(storage)});

    size_t consumed = 0U;
    bool ready = false;
    pbns_view record = {0};
    assert(pbns_record_reader_push(&reader,
                                   (pbns_view){first, sizeof(first)},
                                   &consumed,
                                   &ready,
                                   &record) == PBNS_ERR_WOULD_BLOCK);
    assert(consumed == sizeof(first));
    assert(!ready);

    assert(pbns_record_reader_push(&reader,
                                   (pbns_view){second, sizeof(second)},
                                   &consumed,
                                   &ready,
                                   &record) == PBNS_ERR_LIMIT);
    assert(consumed == 2U);
    assert(!ready);

    consumed = SIZE_MAX;
    assert(pbns_record_reader_push(&reader,
                                   (pbns_view){second + 2U, 1U},
                                   &consumed,
                                   &ready,
                                   &record) == PBNS_ERR_STATE);
    assert(consumed == 0U);

    pbns_record_reader_reset(&reader);
    assert(pbns_record_reader_push(&reader,
                                   (pbns_view){exact, sizeof(exact)},
                                   &consumed,
                                   &ready,
                                   &record) == PBNS_OK);
    assert(consumed == sizeof(exact));
    assert(ready);
    assert(record.len == sizeof(storage));
    assert(memcmp(record.ptr, exact, sizeof(storage)) == 0);
}

static void test_rejects_overlapping_input_and_storage(void) {
    uint8_t storage[8] = {0x01, 0x02, 0x03, 0x00};
    pbns_record_reader reader = {0};
    pbns_record_reader_init(&reader, (pbns_buffer){storage, 0U, sizeof(storage)});
    size_t consumed = SIZE_MAX;
    bool ready = true;
    pbns_view record = {storage, 1U};

    assert(pbns_record_reader_push(&reader,
                                   (pbns_view){storage, 4U},
                                   &consumed,
                                   &ready,
                                   &record) == PBNS_ERR_ARGUMENT);
    assert(consumed == 0U);
    assert(!ready);
    assert(record.ptr == NULL);
    assert(record.len == 0U);
    assert(reader.storage.len == 0U);
}

static void test_invalid_arguments_and_zero_state(void) {
    uint8_t storage[8] = {0};
    static const uint8_t input[] = {0x01, 0x00};
    pbns_record_reader reader = {0};
    size_t consumed = SIZE_MAX;
    bool ready = true;
    pbns_view record = {input, 1U};

    pbns_record_reader_init(NULL, (pbns_buffer){storage, 0U, sizeof(storage)});
    pbns_record_reader_reset(NULL);
    pbns_record_reader_reset(&reader);
    assert(pbns_record_reader_push(&reader,
                                   (pbns_view){input, sizeof(input)},
                                   &consumed,
                                   &ready,
                                   &record) == PBNS_ERR_STATE);
    assert(consumed == 0U);
    assert(!ready);
    assert(record.ptr == NULL);

    pbns_record_reader_init(&reader, (pbns_buffer){storage, 1U, sizeof(storage)});
    assert(pbns_record_reader_push(&reader,
                                   (pbns_view){input, sizeof(input)},
                                   &consumed,
                                   &ready,
                                   &record) == PBNS_ERR_STATE);

    pbns_record_reader_init(&reader, (pbns_buffer){storage, 0U, sizeof(storage)});
    assert(pbns_record_reader_push(&reader,
                                   (pbns_view){NULL, 1U},
                                   &consumed,
                                   &ready,
                                   &record) == PBNS_ERR_ARGUMENT);
    assert(consumed == 0U);
    assert(!ready);
    assert(record.ptr == NULL);
    assert(pbns_record_reader_push(&reader,
                                   (pbns_view){input, sizeof(input)},
                                   NULL,
                                   &ready,
                                   &record) == PBNS_ERR_ARGUMENT);
    assert(pbns_record_reader_push(&reader,
                                   (pbns_view){input, sizeof(input)},
                                   &consumed,
                                   NULL,
                                   &record) == PBNS_ERR_ARGUMENT);
    assert(pbns_record_reader_push(&reader,
                                   (pbns_view){input, sizeof(input)},
                                   &consumed,
                                   &ready,
                                   NULL) == PBNS_ERR_ARGUMENT);
}

int main(void) {
    test_every_fragmentation_split();
    test_multiple_records_in_one_input_chunk();
    test_empty_delimiter_requires_reset();
    test_oversized_record_discards_through_delimiter();
    test_rejects_overlapping_input_and_storage();
    test_invalid_arguments_and_zero_state();
    return 0;
}
