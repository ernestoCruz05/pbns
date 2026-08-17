#ifndef PBNS_OBJECT_H
#define PBNS_OBJECT_H

#include <stdint.h>

#include "pbns/frame.h"

#define PBNS_OBJECT_VERSION UINT64_C(1)
#define PBNS_OBJECT_FIELD_COUNT 9U
#define PBNS_OBJECT_NONCE_SIZE 32U
#define PBNS_OBJECT_HOST_BINDING_SIZE 32U

typedef struct pbns_object_context {
    pbns_view domain;
    uint64_t object_version;
    pbns_service_id service;
    pbns_request_id request_id;
    pbns_view host_binding;
    pbns_view nonce;
    uint64_t issued_at;
    uint64_t expiry_or_max_age;
    pbns_view body;
} pbns_object_context;

/* As vistas no resultado referenciam o objeto codificado fornecido pelo chamador. */
pbns_status pbns_object_validate_common(pbns_view encoded,
                                        const char *expected_domain,
                                        pbns_service_id expected_service,
                                        const pbns_request_id *expected_request,
                                        pbns_view expected_nonce,
                                        pbns_buffer canonical_scratch,
                                        pbns_object_context *result);

#endif
