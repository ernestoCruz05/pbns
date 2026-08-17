#include "pbns_tls_replay/entropy.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "mbedtls/entropy.h"

#define PBNS_TLS_REPLAY_ENTROPY_SEED UINT64_C(0x50424e53544c5331)

static uint64_t entropy_state = PBNS_TLS_REPLAY_ENTROPY_SEED;
static bool entropy_fails;

void pbns_tls_replay_entropy_reset(bool fail) {
  entropy_state = PBNS_TLS_REPLAY_ENTROPY_SEED;
  entropy_fails = fail;
}

static uint64_t next_word(void) {
  uint64_t value = entropy_state;
  value ^= value << 13U;
  value ^= value >> 7U;
  value ^= value << 17U;
  entropy_state = value;
  return value;
}

int mbedtls_hardware_poll(void *context, unsigned char *output, size_t length,
                          size_t *written) {
  (void)context;
  if (written == NULL) {
    return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
  }
  *written = 0U;
  if (entropy_fails || (output == NULL && length > 0U)) {
    return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
  }
  while (*written < length) {
    const uint64_t value = next_word();
    const size_t remaining = length - *written;
    const size_t amount = remaining < sizeof(value) ? remaining : sizeof(value);
    memcpy(output + *written, &value, amount);
    *written += amount;
  }
  return 0;
}
