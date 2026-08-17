#ifndef PBNS_PROXY_TCP_WRITE_OUTCOME_H
#define PBNS_PROXY_TCP_WRITE_OUTCOME_H

#include <stddef.h>

#include "pbns/status.h"

typedef enum pbns_tcp_io_result {
  PBNS_TCP_IO_NOT_RUN = 0,
  PBNS_TCP_IO_OK,
  PBNS_TCP_IO_RETRY,
  PBNS_TCP_IO_FAILED
} pbns_tcp_io_result;

pbns_status pbns_tcp_write_outcome(pbns_tcp_io_result write_result,
                                   pbns_tcp_io_result output_result,
                                   size_t queued_bytes, size_t *written);

#endif
