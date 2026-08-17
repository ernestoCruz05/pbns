#ifndef PBNS_PROXY_TAIL_DEADLINE_H
#define PBNS_PROXY_TAIL_DEADLINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Estado de prazo final independente do relógio. O firmware fornece as
 * marcas temporais e a geração de leituras USB de origem bem-sucedidas e não
 * nulas. */
typedef struct pbns_tail_deadline {
  uint64_t last_input_us;
  size_t observed_input_generation;
  bool pending;
  bool initialized;
} pbns_tail_deadline;

void pbns_tail_deadline_init(pbns_tail_deadline *deadline,
                             size_t input_generation);
void pbns_tail_deadline_reset(pbns_tail_deadline *deadline,
                              size_t input_generation);
void pbns_tail_deadline_observe_input(pbns_tail_deadline *deadline,
                                      size_t input_generation,
                                      uint64_t now_us);
void pbns_tail_deadline_set_pending(pbns_tail_deadline *deadline,
                                    bool pending);
bool pbns_tail_deadline_should_force(const pbns_tail_deadline *deadline,
                                     uint64_t now_us, uint64_t delay_us);

#endif
