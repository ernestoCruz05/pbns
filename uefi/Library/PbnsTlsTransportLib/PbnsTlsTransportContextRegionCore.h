#ifndef PBNS_TLS_TRANSPORT_CONTEXT_REGION_CORE_H
#define PBNS_TLS_TRANSPORT_CONTEXT_REGION_CORE_H

#include <stdbool.h>
#include <stddef.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

pbns_status pbns_tls_transport_context_region_core(
    const void *live_object, size_t concrete_size, bool usable,
    pbns_view *region);

#endif
