#include "PbnsTlsTransportContextRegionCore.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

pbns_status pbns_tls_transport_context_region_core(
    const void *live_object, size_t concrete_size, bool usable,
    pbns_view *region) {
  if (region == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *region = (pbns_view){0};
  if (live_object == NULL || concrete_size == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!usable) {
    return PBNS_ERR_STATE;
  }
  *region = (pbns_view){(const uint8_t *)live_object, concrete_size};
  return PBNS_OK;
}
