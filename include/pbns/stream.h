#ifndef PBNS_STREAM_H
#define PBNS_STREAM_H

#include <stdbool.h>
#include <stdint.h>

#include "pbns/frame.h"

typedef struct pbns_stream_state {
    pbns_service_id service;
    pbns_request_id request_id;
    uint64_t byte_limit;
    uint64_t total_bytes;
    uint32_t next_sequence;
    bool initialized;
    bool complete;
    bool failed;
} pbns_stream_state;

void pbns_stream_init(pbns_stream_state *state,
                      pbns_service_id service,
                      pbns_request_id request_id,
                      uint64_t byte_limit);

/* Preserva a associação ao pedido e reinicia apenas o progresso do fluxo. */
void pbns_stream_reset(pbns_stream_state *state);

pbns_status pbns_stream_accept(pbns_stream_state *state,
                               const pbns_frame *frame,
                               pbns_view payload);

#endif
