#ifndef PBNS_RANDOM_POLICY_H
#define PBNS_RANDOM_POLICY_H

#include "pbns/buffer.h"
#include "pbns/status.h"

typedef pbns_status (*pbns_random_source_fill)(void *context,
                                               pbns_buffer output);

typedef struct pbns_random_source {
  pbns_random_source_fill fill;
  void *context;
} pbns_random_source;

pbns_status pbns_random_priority_fill(const pbns_random_source *primary,
                                      const pbns_random_source *fallback,
                                      pbns_buffer output);

#endif
