#include "PbnsRandomPolicy.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static bool source_is_valid(const pbns_random_source *source) {
  return source == NULL || (source->fill != NULL && source->context != NULL);
}

static void clear_output(pbns_buffer output) {
  if (output.ptr != NULL && output.cap > 0U) {
    memset(output.ptr, 0, output.cap);
  }
}

pbns_status pbns_random_priority_fill(const pbns_random_source *primary,
                                      const pbns_random_source *fallback,
                                      pbns_buffer output) {
  if (output.ptr == NULL || output.len != 0U || output.cap == 0U ||
      !source_is_valid(primary) || !source_is_valid(fallback)) {
    clear_output(output);
    return PBNS_ERR_ARGUMENT;
  }
  clear_output(output);

  pbns_status status = PBNS_ERR_UNSUPPORTED;
  if (primary != NULL) {
    status = primary->fill(primary->context, output);
  }
  if (status == PBNS_OK) {
    return PBNS_OK;
  }
  clear_output(output);
  if (status != PBNS_ERR_UNSUPPORTED) {
    return PBNS_ERR_ENTROPY;
  }
  if (fallback == NULL) {
    return PBNS_ERR_ENTROPY;
  }

  status = fallback->fill(fallback->context, output);
  if (status == PBNS_OK) {
    return PBNS_OK;
  }
  clear_output(output);
  return PBNS_ERR_ENTROPY;
}
