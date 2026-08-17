#include "pbns_proxy/byte_ring.h"

#include <stdbool.h>
#include <stddef.h>

static bool storage_is_valid(pbns_buffer storage) {
  return storage.ptr != NULL && storage.len == 0U && storage.cap > 0U;
}

static bool ring_is_valid(const pbns_byte_ring *ring) {
  return ring != NULL && ring->initialized && storage_is_valid(ring->storage) &&
         ring->head < ring->storage.cap && ring->length <= ring->storage.cap;
}

static size_t ring_tail(const pbns_byte_ring *ring) {
  const size_t distance_to_end = ring->storage.cap - ring->head;
  return ring->length >= distance_to_end ? ring->length - distance_to_end
                                         : ring->head + ring->length;
}

static size_t writable_length(const pbns_byte_ring *ring) {
  if (ring->length == ring->storage.cap) {
    return 0U;
  }
  const size_t tail = ring_tail(ring);
  return tail < ring->head ? ring->head - tail : ring->storage.cap - tail;
}

void pbns_byte_ring_init(pbns_byte_ring *ring, pbns_buffer storage) {
  if (ring == NULL) {
    return;
  }
  *ring = (pbns_byte_ring){0};
  if (!storage_is_valid(storage)) {
    return;
  }
  ring->storage = storage;
  ring->initialized = true;
}

void pbns_byte_ring_reset(pbns_byte_ring *ring) {
  if (!ring_is_valid(ring)) {
    return;
  }
  ring->head = 0U;
  ring->length = 0U;
}

size_t pbns_byte_ring_capacity(const pbns_byte_ring *ring) {
  return ring_is_valid(ring) ? ring->storage.cap : 0U;
}

size_t pbns_byte_ring_size(const pbns_byte_ring *ring) {
  return ring_is_valid(ring) ? ring->length : 0U;
}

pbns_status pbns_byte_ring_writable(pbns_byte_ring *ring,
                                    pbns_buffer *writable) {
  if (writable == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *writable = (pbns_buffer){0};
  if (!ring_is_valid(ring)) {
    return PBNS_ERR_STATE;
  }
  const size_t available = writable_length(ring);
  if (available == 0U) {
    return PBNS_OK;
  }
  const size_t tail = ring_tail(ring);
  *writable = (pbns_buffer){ring->storage.ptr + tail, 0U, available};
  return PBNS_OK;
}

pbns_status pbns_byte_ring_commit(pbns_byte_ring *ring, size_t amount) {
  if (!ring_is_valid(ring)) {
    return PBNS_ERR_STATE;
  }
  if (amount > writable_length(ring)) {
    return PBNS_ERR_LIMIT;
  }
  ring->length += amount;
  return PBNS_OK;
}

pbns_status pbns_byte_ring_readable(const pbns_byte_ring *ring,
                                    pbns_view *readable) {
  if (readable == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *readable = (pbns_view){0};
  if (!ring_is_valid(ring)) {
    return PBNS_ERR_STATE;
  }
  if (ring->length == 0U) {
    return PBNS_OK;
  }
  const size_t contiguous = ring->length < ring->storage.cap - ring->head
                                ? ring->length
                                : ring->storage.cap - ring->head;
  *readable = (pbns_view){ring->storage.ptr + ring->head, contiguous};
  return PBNS_OK;
}

pbns_status pbns_byte_ring_consume(pbns_byte_ring *ring, size_t amount) {
  if (!ring_is_valid(ring)) {
    return PBNS_ERR_STATE;
  }
  const size_t contiguous = ring->length < ring->storage.cap - ring->head
                                ? ring->length
                                : ring->storage.cap - ring->head;
  if (amount > contiguous) {
    return PBNS_ERR_LIMIT;
  }
  if (amount == ring->length) {
    ring->head = 0U;
    ring->length = 0U;
    return PBNS_OK;
  }
  ring->head += amount;
  ring->length -= amount;
  if (ring->head == ring->storage.cap) {
    ring->head = 0U;
  }
  return PBNS_OK;
}
