#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns_proxy/entropy.h"
#include "pico/rand.h"

static uint64_t random_value = UINT64_C(0x1020304050607080);

uint64_t get_rand_64(void) {
  const uint64_t result = random_value;
  ++random_value;
  return result;
}

static void test_exact_bounded_writes(void) {
  static const size_t lengths[] = {0U, 1U, 7U, 8U, 9U, 15U};
  for (size_t index = 0U; index < sizeof(lengths) / sizeof(lengths[0]);
       ++index) {
    uint8_t guarded[19] = {0};
    memset(guarded, 0xa5, sizeof(guarded));
    const size_t length = lengths[index];
    size_t written = SIZE_MAX;
    assert(mbedtls_hardware_poll(NULL, guarded + 2U, length, &written) == 0);
    assert(written == length);
    assert(guarded[0] == UINT8_C(0xa5));
    assert(guarded[1] == UINT8_C(0xa5));
    assert(guarded[2U + length] == UINT8_C(0xa5));
    assert(guarded[3U + length] == UINT8_C(0xa5));
  }
}

static void test_rejects_invalid_outputs(void) {
  uint8_t output[1] = {0};
  size_t written = SIZE_MAX;
  assert(mbedtls_hardware_poll(NULL, output, sizeof(output), NULL) != 0);
  assert(mbedtls_hardware_poll(NULL, NULL, 1U, &written) != 0);
  assert(written == 0U);
  written = SIZE_MAX;
  assert(mbedtls_hardware_poll(NULL, NULL, 0U, &written) == 0);
  assert(written == 0U);
}

int main(void) {
  test_exact_bounded_writes();
  test_rejects_invalid_outputs();
  return 0;
}
