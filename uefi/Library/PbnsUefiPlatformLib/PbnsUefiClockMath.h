#ifndef PBNS_UEFI_CLOCK_MATH_H
#define PBNS_UEFI_CLOCK_MATH_H

#include <stdbool.h>
#include <stdint.h>

bool pbns_uefi_clock_elapsed_ms(uint64_t current_ticks, uint64_t origin_ticks,
                                uint64_t femtoseconds_per_tick,
                                uint64_t *milliseconds);

#endif
