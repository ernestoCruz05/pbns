#ifndef PBNS_PROXY_ENTROPY_H
#define PBNS_PROXY_ENTROPY_H

#include <stddef.h>

int mbedtls_hardware_poll(void *context, unsigned char *output, size_t length,
                          size_t *written);

#endif
