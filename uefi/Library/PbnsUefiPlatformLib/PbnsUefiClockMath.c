#include "PbnsUefiClockMath.h"

#include <stddef.h>
#include <stdint.h>

#define PBNS_UEFI_FEMTOSECONDS_PER_MILLISECOND UINT64_C(1000000000000)

bool pbns_uefi_clock_elapsed_ms(uint64_t current_ticks, uint64_t origin_ticks,
                                uint64_t femtoseconds_per_tick,
                                uint64_t *milliseconds) {
  if (milliseconds == NULL) {
    return false;
  }
  *milliseconds = UINT64_C(0);
  if (femtoseconds_per_tick == UINT64_C(0) || current_ticks < origin_ticks) {
    return false;
  }
  const uint64_t elapsed_ticks = current_ticks - origin_ticks;
  if (elapsed_ticks != UINT64_C(0) &&
      femtoseconds_per_tick > UINT64_MAX / elapsed_ticks) {
    return false;
  }
  *milliseconds = (elapsed_ticks * femtoseconds_per_tick) /
                  PBNS_UEFI_FEMTOSECONDS_PER_MILLISECOND;
  return true;
}
