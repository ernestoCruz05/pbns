#include "pbns/cobs.h"

#include <stdbool.h>
#include <stdint.h>

static bool view_is_valid(pbns_view view) {
    return view.ptr != NULL || view.len == 0U;
}

static bool buffer_is_valid(pbns_buffer buffer) {
    return buffer.len == 0U && (buffer.ptr != NULL || buffer.cap == 0U);
}

pbns_status pbns_cobs_max_encoded_size(size_t input_len, size_t *result) {
    if (result == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    *result = 0U;

    const size_t overhead = input_len / 254U + 1U;
    if (input_len > SIZE_MAX - overhead) {
        return PBNS_ERR_LIMIT;
    }
    *result = input_len + overhead;
    return PBNS_OK;
}

pbns_status pbns_cobs_encode(pbns_view input, pbns_buffer output, size_t *written) {
    if (written == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    *written = 0U;
    if (!view_is_valid(input) || !buffer_is_valid(output)) {
        return PBNS_ERR_ARGUMENT;
    }
    if (output.cap == 0U) {
        return PBNS_ERR_LIMIT;
    }

    size_t read_index = 0U;
    size_t write_index = 1U;
    size_t code_index = 0U;
    uint8_t code = UINT8_C(1);

    while (read_index < input.len) {
        if (input.ptr[read_index] == UINT8_C(0)) {
            output.ptr[code_index] = code;
            code = UINT8_C(1);
            code_index = write_index;
            if (write_index >= output.cap) {
                return PBNS_ERR_LIMIT;
            }
            ++write_index;
            ++read_index;
            continue;
        }

        if (write_index >= output.cap) {
            return PBNS_ERR_LIMIT;
        }
        output.ptr[write_index] = input.ptr[read_index];
        ++write_index;
        ++read_index;
        ++code;

        if (code == UINT8_MAX) {
            output.ptr[code_index] = code;
            code = UINT8_C(1);
            code_index = write_index;
            if (write_index >= output.cap) {
                return PBNS_ERR_LIMIT;
            }
            /* Reservar este índice evita deslocar dados quando o tamanho do bloco só é conhecido no fim. */
            ++write_index;
        }
    }

    output.ptr[code_index] = code;
    *written = write_index;
    return PBNS_OK;
}

pbns_status pbns_cobs_decode(pbns_view input, pbns_buffer output, size_t *written) {
    if (written == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    *written = 0U;
    if (!view_is_valid(input) || !buffer_is_valid(output)) {
        return PBNS_ERR_ARGUMENT;
    }
    if (input.len == 0U) {
        return PBNS_ERR_FORMAT;
    }

    size_t read_index = 0U;
    size_t write_index = 0U;
    while (read_index < input.len) {
        const uint8_t code = input.ptr[read_index];
        ++read_index;
        if (code == UINT8_C(0)) {
            return PBNS_ERR_FORMAT;
        }

        const size_t run_length = (size_t)code - 1U;
        if (run_length > input.len - read_index) {
            return PBNS_ERR_FORMAT;
        }
        if (run_length > output.cap - write_index) {
            return PBNS_ERR_LIMIT;
        }

        for (size_t offset = 0U; offset < run_length; ++offset) {
            const uint8_t value = input.ptr[read_index + offset];
            if (value == UINT8_C(0)) {
                return PBNS_ERR_FORMAT;
            }
            output.ptr[write_index + offset] = value;
        }
        read_index += run_length;
        write_index += run_length;

        if (code != UINT8_MAX && read_index < input.len) {
            if (write_index >= output.cap) {
                return PBNS_ERR_LIMIT;
            }
            output.ptr[write_index] = UINT8_C(0);
            ++write_index;
        }
    }

    *written = write_index;
    return PBNS_OK;
}
