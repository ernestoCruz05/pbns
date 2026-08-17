#ifndef PBNS_PROXY_BYTE_RING_H
#define PBNS_PROXY_BYTE_RING_H

#include <stdbool.h>
#include <stddef.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

typedef struct pbns_byte_ring {
  pbns_buffer storage;
  size_t head;
  size_t length;
  bool initialized;
} pbns_byte_ring;

void pbns_byte_ring_init(pbns_byte_ring *ring, pbns_buffer storage);
void pbns_byte_ring_reset(pbns_byte_ring *ring);
size_t pbns_byte_ring_capacity(const pbns_byte_ring *ring);
size_t pbns_byte_ring_size(const pbns_byte_ring *ring);
pbns_status pbns_byte_ring_writable(pbns_byte_ring *ring,
                                    pbns_buffer *writable);
pbns_status pbns_byte_ring_commit(pbns_byte_ring *ring, size_t amount);
pbns_status pbns_byte_ring_readable(const pbns_byte_ring *ring,
                                    pbns_view *readable);
pbns_status pbns_byte_ring_consume(pbns_byte_ring *ring, size_t amount);

#endif
