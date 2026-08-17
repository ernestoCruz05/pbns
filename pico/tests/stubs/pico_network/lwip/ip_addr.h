#ifndef PBNS_TEST_LWIP_IP_ADDR_H
#define PBNS_TEST_LWIP_IP_ADDR_H

#include <stdint.h>

typedef struct ip_addr {
  uint32_t address;
  uint8_t type;
} ip_addr_t;

#define IP_GET_TYPE(address) ((address)->type)
#define ip_addr_copy(destination, source) ((destination) = (source))

#endif
