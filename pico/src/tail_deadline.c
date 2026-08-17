#include "pbns_proxy/tail_deadline.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void pbns_tail_deadline_init(pbns_tail_deadline *deadline,
                             size_t input_generation) {
  if (deadline == NULL) {
    return;
  }
  *deadline = (pbns_tail_deadline){
      .observed_input_generation = input_generation,
      .initialized = true,
  };
}

void pbns_tail_deadline_reset(pbns_tail_deadline *deadline,
                              size_t input_generation) {
  if (deadline == NULL) {
    return;
  }
  *deadline = (pbns_tail_deadline){
      .observed_input_generation = input_generation,
      .initialized = true,
  };
}

void pbns_tail_deadline_observe_input(pbns_tail_deadline *deadline,
                                      size_t input_generation,
                                      uint64_t now_us) {
  if (deadline == NULL || !deadline->initialized) {
    return;
  }
  if (deadline->observed_input_generation != input_generation) {
    deadline->observed_input_generation = input_generation;
    deadline->last_input_us = now_us;
  }
}

void pbns_tail_deadline_set_pending(pbns_tail_deadline *deadline,
                                    bool pending) {
  if (deadline == NULL || !deadline->initialized) {
    return;
  }
  deadline->pending = pending;
}

bool pbns_tail_deadline_should_force(const pbns_tail_deadline *deadline,
                                     uint64_t now_us, uint64_t delay_us) {
  return deadline != NULL && deadline->initialized && deadline->pending &&
         now_us - deadline->last_input_us >= delay_us;
}
