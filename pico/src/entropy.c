#include "pbns_proxy/entropy.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "mbedtls/entropy.h"
#include "pico/rand.h"

int mbedtls_hardware_poll(void *context, unsigned char *output, size_t length,
                          size_t *written) {
  (void)context;
  if (written == NULL) {
    return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
  }
  *written = 0U;
  if (output == NULL && length > 0U) {
    return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
  }
  while (*written < length) {
    const uint64_t random_value = get_rand_64();
    const size_t remaining = length - *written;
    const size_t amount =
        remaining < sizeof(random_value) ? remaining : sizeof(random_value);
    memcpy(output + *written, &random_value, amount);
    *written += amount;
  }
  return 0;
}
