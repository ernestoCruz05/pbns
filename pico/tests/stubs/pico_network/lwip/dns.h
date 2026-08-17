#ifndef PBNS_TEST_LWIP_DNS_H
#define PBNS_TEST_LWIP_DNS_H

#include "lwip/err.h"
#include "lwip/ip_addr.h"

typedef void (*dns_found_callback)(const char *hostname,
                                   const ip_addr_t *address, void *context);

err_t dns_gethostbyname(const char *hostname, ip_addr_t *address,
                        dns_found_callback callback, void *context);

#endif
