#include "pbns/random.h"

#include <stddef.h>
#include <string.h>

pbns_status pbns_random_fill(const pbns_random *random, pbns_buffer output) {
  if (random == NULL || random->ops == NULL || random->ops->fill == NULL ||
      random->context == NULL || output.ptr == NULL || output.len != 0U ||
      output.cap == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status status = random->ops->fill(random->context, output);
  if (status != PBNS_OK) {
    memset(output.ptr, 0, output.cap);
  }
  return status;
}
