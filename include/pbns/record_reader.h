#ifndef PBNS_RECORD_READER_H
#define PBNS_RECORD_READER_H

#include <stdbool.h>
#include <stddef.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

typedef struct pbns_record_reader {
    pbns_buffer storage;
    bool initialized;
    bool discarding;
    bool ready;
    bool failed;
} pbns_record_reader;

void pbns_record_reader_init(pbns_record_reader *reader, pbns_buffer storage);
void pbns_record_reader_reset(pbns_record_reader *reader);

/* A entrada não pode sobrepor-se ao armazenamento; a vista é válida até ao reset. */
pbns_status pbns_record_reader_push(pbns_record_reader *reader,
                                    pbns_view input,
                                    size_t *consumed,
                                    bool *record_ready,
                                    pbns_view *cobs_record);

#endif
