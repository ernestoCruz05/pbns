#include "pbns/record_reader.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static bool view_is_valid(pbns_view view) {
    return view.ptr != NULL || view.len == 0U;
}

static bool storage_is_valid(pbns_buffer storage) {
    return storage.len == 0U && (storage.ptr != NULL || storage.cap == 0U);
}

static bool ranges_overlap(pbns_view input, pbns_buffer storage) {
    if (input.len == 0U || storage.cap == 0U) {
        return false;
    }
    const uintptr_t input_start = (uintptr_t)input.ptr;
    const uintptr_t storage_start = (uintptr_t)storage.ptr;
    if (input.len > UINTPTR_MAX - input_start || storage.cap > UINTPTR_MAX - storage_start) {
        return true;
    }
    const uintptr_t input_end = input_start + input.len;
    const uintptr_t storage_end = storage_start + storage.cap;
    return input_start < storage_end && storage_start < input_end;
}

void pbns_record_reader_init(pbns_record_reader *reader, pbns_buffer storage) {
    if (reader == NULL) {
        return;
    }
    *reader = (pbns_record_reader){0};
    if (!storage_is_valid(storage)) {
        return;
    }
    reader->storage = storage;
    reader->initialized = true;
}

void pbns_record_reader_reset(pbns_record_reader *reader) {
    if (reader == NULL || !reader->initialized) {
        return;
    }
    reader->storage.len = 0U;
    reader->discarding = false;
    reader->ready = false;
    reader->failed = false;
}

pbns_status pbns_record_reader_push(pbns_record_reader *reader,
                                    pbns_view input,
                                    size_t *consumed,
                                    bool *record_ready,
                                    pbns_view *cobs_record) {
    if (consumed != NULL) {
        *consumed = 0U;
    }
    if (record_ready != NULL) {
        *record_ready = false;
    }
    if (cobs_record != NULL) {
        *cobs_record = (pbns_view){0};
    }
    if (reader == NULL || consumed == NULL || record_ready == NULL || cobs_record == NULL
        || !view_is_valid(input)) {
        return PBNS_ERR_ARGUMENT;
    }
    if (!reader->initialized || reader->ready || reader->failed) {
        return PBNS_ERR_STATE;
    }
    if (ranges_overlap(input, reader->storage)) {
        return PBNS_ERR_ARGUMENT;
    }

    for (size_t index = 0U; index < input.len; ++index) {
        const uint8_t octet = input.ptr[index];
        *consumed = index + 1U;

        if (reader->discarding) {
            if (octet == UINT8_C(0)) {
                reader->failed = true;
                return PBNS_ERR_LIMIT;
            }
            continue;
        }

        if (octet == UINT8_C(0)) {
            if (reader->storage.len == 0U) {
                reader->failed = true;
                return PBNS_ERR_FORMAT;
            }
            reader->ready = true;
            *record_ready = true;
            *cobs_record = (pbns_view){reader->storage.ptr, reader->storage.len};
            return PBNS_OK;
        }

        if (reader->storage.len >= reader->storage.cap) {
            reader->discarding = true;
            continue;
        }
        reader->storage.ptr[reader->storage.len] = octet;
        ++reader->storage.len;
    }

    return PBNS_ERR_WOULD_BLOCK;
}
