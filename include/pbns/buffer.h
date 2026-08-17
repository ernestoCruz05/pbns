#ifndef PBNS_BUFFER_H
#define PBNS_BUFFER_H

#include <stddef.h>
#include <stdint.h>

typedef struct pbns_view {
    const uint8_t *ptr;
    size_t len;
} pbns_view;

typedef struct pbns_buffer {
    uint8_t *ptr;
    size_t len;
    size_t cap;
} pbns_buffer;

#endif
