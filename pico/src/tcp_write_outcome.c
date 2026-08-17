#include "pbns_proxy/tcp_write_outcome.h"

#include <stddef.h>

pbns_status pbns_tcp_write_outcome(pbns_tcp_io_result write_result,
                                   pbns_tcp_io_result output_result,
                                   size_t queued_bytes, size_t *written) {
  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (queued_bytes == 0U) {
    return PBNS_ERR_ARGUMENT;
  }

  switch (write_result) {
  case PBNS_TCP_IO_RETRY:
    return output_result == PBNS_TCP_IO_NOT_RUN ? PBNS_ERR_WOULD_BLOCK
                                                : PBNS_ERR_ARGUMENT;
  case PBNS_TCP_IO_FAILED:
    return output_result == PBNS_TCP_IO_NOT_RUN ? PBNS_ERR_TRANSPORT
                                                : PBNS_ERR_ARGUMENT;
  case PBNS_TCP_IO_OK:
    break;
  case PBNS_TCP_IO_NOT_RUN:
  default:
    return PBNS_ERR_ARGUMENT;
  }

  switch (output_result) {
  case PBNS_TCP_IO_OK:
    *written = queued_bytes;
    return PBNS_OK;
  case PBNS_TCP_IO_RETRY:
  case PBNS_TCP_IO_FAILED:
    return PBNS_ERR_TRANSPORT;
  case PBNS_TCP_IO_NOT_RUN:
  default:
    return PBNS_ERR_ARGUMENT;
  }
}
