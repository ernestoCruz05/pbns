#ifndef PBNS_TLS_TRANSPORT_H
#define PBNS_TLS_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/status.h"
#include "pbns/transport.h"

typedef struct pbns_tls_transport pbns_tls_transport;

typedef struct pbns_tls_client_config {
  pbns_view expected_server_name;
  pbns_view pinned_leaf_spki_sha256;
  uint32_t handshake_timeout_ms;
} pbns_tls_client_config;

typedef struct pbns_tls_platform_ops {
  pbns_status (*random)(void *context, pbns_buffer output);
  pbns_status (*monotonic_ms)(void *context, uint64_t *now_ms);
  void *(*allocate)(void *context, size_t size);
  void (*release)(void *context, void *allocation, size_t size);
} pbns_tls_platform_ops;

typedef struct pbns_tls_platform {
  const pbns_tls_platform_ops *ops;
  void *context;
} pbns_tls_platform;

pbns_status pbns_tls_transport_create(pbns_transport lower,
                                      const pbns_tls_client_config *config,
                                      pbns_tls_platform platform,
                                      pbns_tls_transport **result);
void pbns_tls_transport_destroy(pbns_tls_transport *transport);
pbns_transport pbns_tls_transport_as_transport(pbns_tls_transport *transport);

#endif
