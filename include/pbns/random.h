#ifndef PBNS_RANDOM_H
#define PBNS_RANDOM_H

#include "pbns/buffer.h"
#include "pbns/status.h"

typedef struct pbns_random_ops pbns_random_ops;
typedef struct pbns_random pbns_random;

struct pbns_random_ops {
  pbns_status (*fill)(void *context, pbns_buffer output);
};

struct pbns_random {
  const pbns_random_ops *ops;
  void *context;
};

pbns_status pbns_random_fill(const pbns_random *random, pbns_buffer output);

#endif
