#ifndef PBNS_COBS_H
#define PBNS_COBS_H

#include <stddef.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

pbns_status pbns_cobs_max_encoded_size(size_t input_len, size_t *result);
pbns_status pbns_cobs_encode(pbns_view input, pbns_buffer output, size_t *written);
pbns_status pbns_cobs_decode(pbns_view input, pbns_buffer output, size_t *written);

#endif
