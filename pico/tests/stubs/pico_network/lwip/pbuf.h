#ifndef PBNS_TEST_LWIP_PBUF_H
#define PBNS_TEST_LWIP_PBUF_H

#include <stdint.h>

typedef uint16_t u16_t;
typedef uint8_t u8_t;

struct pbuf {
  u16_t tot_len;
};

u8_t pbuf_free(struct pbuf *packet);
u16_t pbuf_copy_partial(const struct pbuf *packet, void *destination,
                        u16_t length, u16_t offset);

#endif
