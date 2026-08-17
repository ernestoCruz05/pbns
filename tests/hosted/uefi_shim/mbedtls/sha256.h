#ifndef PBNS_TEST_MBEDTLS_SHA256_H
#define PBNS_TEST_MBEDTLS_SHA256_H

#include <stddef.h>

int mbedtls_sha256(const unsigned char *input, size_t ilen,
                   unsigned char output[32], int is224);

#endif
