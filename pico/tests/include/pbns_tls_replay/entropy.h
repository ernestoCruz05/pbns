#ifndef PBNS_TLS_REPLAY_ENTROPY_H
#define PBNS_TLS_REPLAY_ENTROPY_H

#include <stdbool.h>
#include <stddef.h>

void pbns_tls_replay_entropy_reset(bool fail);
int mbedtls_hardware_poll(void *context, unsigned char *output, size_t length,
                          size_t *written);

#endif
