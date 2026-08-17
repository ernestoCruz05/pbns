#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "PbnsUefiClockMath.h"

static void test_zero_elapsed_time(void) {
  uint64_t milliseconds = UINT64_MAX;
  assert(pbns_uefi_clock_elapsed_ms(UINT64_C(77), UINT64_C(77),
                                    UINT64_C(1000000000), &milliseconds));
  assert(milliseconds == UINT64_C(0));
}

static void test_exact_and_truncated_milliseconds(void) {
  uint64_t milliseconds = UINT64_MAX;
  assert(pbns_uefi_clock_elapsed_ms(UINT64_C(115000), UINT64_C(100000),
                                    UINT64_C(1000000000), &milliseconds));
  assert(milliseconds == UINT64_C(15));
  assert(pbns_uefi_clock_elapsed_ms(UINT64_C(114999), UINT64_C(100000),
                                    UINT64_C(1000000000), &milliseconds));
  assert(milliseconds == UINT64_C(14));
}

static void test_invalid_inputs_fail(void) {
  uint64_t milliseconds = UINT64_MAX;
  assert(
      !pbns_uefi_clock_elapsed_ms(UINT64_C(1), UINT64_C(0), UINT64_C(1), NULL));
  assert(!pbns_uefi_clock_elapsed_ms(UINT64_C(1), UINT64_C(0), UINT64_C(0),
                                     &milliseconds));
  assert(!pbns_uefi_clock_elapsed_ms(UINT64_C(9), UINT64_C(10), UINT64_C(1),
                                     &milliseconds));
}

static void test_checked_product_boundary(void) {
  uint64_t milliseconds = UINT64_MAX;
  const uint64_t safe_period = UINT64_MAX / UINT64_C(2);
  assert(pbns_uefi_clock_elapsed_ms(UINT64_C(2), UINT64_C(0), safe_period,
                                    &milliseconds));
  assert(milliseconds == UINT64_C(18446744));
  assert(!pbns_uefi_clock_elapsed_ms(UINT64_C(2), UINT64_C(0),
                                     safe_period + UINT64_C(1), &milliseconds));
  assert(pbns_uefi_clock_elapsed_ms(UINT64_C(1), UINT64_C(0), UINT64_MAX,
                                    &milliseconds));
  assert(milliseconds == UINT64_C(18446744));
}

int main(void) {
  test_zero_elapsed_time();
  test_exact_and_truncated_milliseconds();
  test_invalid_inputs_fail();
  test_checked_product_boundary();
  return 0;
}
