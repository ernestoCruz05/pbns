#ifndef PBNS_TLS_REPLAY_ENDPOINT_H
#define PBNS_TLS_REPLAY_ENDPOINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/status.h"
#include "pbns_proxy/byte_pump.h"

typedef struct pbns_tls_replay_endpoint_config {
  size_t read_limit;
  size_t write_limit;
  uint32_t would_block_period;
  uint32_t fail_read_at;
  uint32_t fail_write_at;
  uint64_t deadline_ms;
} pbns_tls_replay_endpoint_config;

typedef struct pbns_tls_replay_endpoint {
  pbns_tls_replay_endpoint_config config;
  int descriptor;
  uint32_t read_operations;
  uint32_t write_operations;
  bool initialized;
} pbns_tls_replay_endpoint;

pbns_status
pbns_tls_replay_endpoint_connect(pbns_tls_replay_endpoint *endpoint,
                                 uint16_t port,
                                 const pbns_tls_replay_endpoint_config *config);
pbns_status
pbns_tls_replay_endpoint_adopt(pbns_tls_replay_endpoint *endpoint,
                               int descriptor,
                               const pbns_tls_replay_endpoint_config *config);
pbns_status pbns_tls_replay_endpoint_read(void *context,
                                          pbns_buffer destination,
                                          size_t *received);
pbns_status pbns_tls_replay_endpoint_write(void *context, pbns_view source,
                                           size_t *written);
pbns_pump_endpoint
pbns_tls_replay_endpoint_callbacks(pbns_tls_replay_endpoint *endpoint);
pbns_status pbns_tls_replay_endpoint_close(pbns_tls_replay_endpoint *endpoint);

#endif
