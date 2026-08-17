#include "pbns_tls_replay/endpoint.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#define PBNS_TLS_REPLAY_IO_LIMIT 16384U

static bool config_is_valid(const pbns_tls_replay_endpoint_config *config) {
  return config != NULL && config->read_limit > 0U &&
         config->read_limit <= PBNS_TLS_REPLAY_IO_LIMIT &&
         config->write_limit > 0U &&
         config->write_limit <= PBNS_TLS_REPLAY_IO_LIMIT &&
         config->deadline_ms > 0U;
}

static pbns_status monotonic_ms(uint64_t *milliseconds) {
  if (milliseconds == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  struct timespec now = {0};
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0 ||
      now.tv_nsec < 0) {
    return PBNS_ERR_STATE;
  }
  const uint64_t seconds = (uint64_t)now.tv_sec;
  if (seconds > UINT64_MAX / UINT64_C(1000)) {
    return PBNS_ERR_LIMIT;
  }
  *milliseconds =
      seconds * UINT64_C(1000) + (uint64_t)now.tv_nsec / UINT64_C(1000000);
  return PBNS_OK;
}

static pbns_status deadline_status(const pbns_tls_replay_endpoint *endpoint) {
  uint64_t now_ms = 0U;
  const pbns_status status = monotonic_ms(&now_ms);
  if (status != PBNS_OK) {
    return status;
  }
  return now_ms >= endpoint->config.deadline_ms ? PBNS_ERR_TIMEOUT : PBNS_OK;
}

static pbns_status configure_descriptor(int descriptor) {
  const int flags = fcntl(descriptor, F_GETFL);
  if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
    return PBNS_ERR_TRANSPORT;
  }
  return PBNS_OK;
}

pbns_status
pbns_tls_replay_endpoint_adopt(pbns_tls_replay_endpoint *endpoint,
                               int descriptor,
                               const pbns_tls_replay_endpoint_config *config) {
  if (endpoint == NULL || descriptor < 0 || !config_is_valid(config)) {
    return PBNS_ERR_ARGUMENT;
  }
  if (endpoint->initialized) {
    return PBNS_ERR_BUSY;
  }
  const pbns_status status = configure_descriptor(descriptor);
  if (status != PBNS_OK) {
    return status;
  }
  *endpoint = (pbns_tls_replay_endpoint){
      .config = *config,
      .descriptor = descriptor,
      .initialized = true,
  };
  return PBNS_OK;
}

static int remaining_poll_ms(uint64_t deadline_ms) {
  uint64_t now_ms = 0U;
  if (monotonic_ms(&now_ms) != PBNS_OK || now_ms >= deadline_ms) {
    return 0;
  }
  const uint64_t remaining = deadline_ms - now_ms;
  return remaining > (uint64_t)INT_MAX ? INT_MAX : (int)remaining;
}

static pbns_status wait_for_connect(int descriptor, uint64_t deadline_ms) {
  struct pollfd descriptor_state = {
      .fd = descriptor,
      .events = POLLOUT,
  };
  while (true) {
    const int timeout_ms = remaining_poll_ms(deadline_ms);
    if (timeout_ms <= 0) {
      return PBNS_ERR_TIMEOUT;
    }
    const int result = poll(&descriptor_state, 1U, timeout_ms);
    if (result < 0 && errno == EINTR) {
      continue;
    }
    if (result <= 0) {
      return result == 0 ? PBNS_ERR_TIMEOUT : PBNS_ERR_TRANSPORT;
    }
    int socket_error = 0;
    socklen_t length = (socklen_t)sizeof(socket_error);
    if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socket_error, &length) !=
            0 ||
        length != (socklen_t)sizeof(socket_error) || socket_error != 0) {
      return PBNS_ERR_TRANSPORT;
    }
    return PBNS_OK;
  }
}

pbns_status pbns_tls_replay_endpoint_connect(
    pbns_tls_replay_endpoint *endpoint, uint16_t port,
    const pbns_tls_replay_endpoint_config *config) {
  if (endpoint == NULL || port == 0U || !config_is_valid(config) ||
      endpoint->initialized) {
    return PBNS_ERR_ARGUMENT;
  }
  const int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (descriptor < 0) {
    return PBNS_ERR_RESOURCE;
  }
  struct sockaddr_in address = {
      .sin_family = AF_INET,
      .sin_port = htons(port),
  };
  if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) {
    return close(descriptor) == 0 ? PBNS_ERR_STATE : PBNS_ERR_TRANSPORT;
  }
  pbns_status status = PBNS_OK;
  if (connect(descriptor, (const struct sockaddr *)&address, sizeof(address)) !=
      0) {
    status = errno == EINPROGRESS
                 ? wait_for_connect(descriptor, config->deadline_ms)
                 : PBNS_ERR_TRANSPORT;
  }
  if (status == PBNS_OK) {
    status = pbns_tls_replay_endpoint_adopt(endpoint, descriptor, config);
  }
  if (status != PBNS_OK && close(descriptor) != 0) {
    status = PBNS_ERR_TRANSPORT;
  }
  return status;
}

static pbns_status next_operation(pbns_tls_replay_endpoint *endpoint,
                                  uint32_t *operations, uint32_t fail_at) {
  const pbns_status time_status = deadline_status(endpoint);
  if (time_status != PBNS_OK) {
    return time_status;
  }
  if (*operations == UINT32_MAX) {
    return PBNS_ERR_LIMIT;
  }
  ++*operations;
  if (fail_at != 0U && *operations == fail_at) {
    return PBNS_ERR_TRANSPORT;
  }
  if (endpoint->config.would_block_period != 0U &&
      *operations % endpoint->config.would_block_period == 0U) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  return PBNS_OK;
}

pbns_status pbns_tls_replay_endpoint_read(void *context,
                                          pbns_buffer destination,
                                          size_t *received) {
  pbns_tls_replay_endpoint *const endpoint = context;
  if (received == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *received = 0U;
  if (endpoint == NULL || !endpoint->initialized || destination.ptr == NULL ||
      destination.len != 0U || destination.cap == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status operation_status = next_operation(
      endpoint, &endpoint->read_operations, endpoint->config.fail_read_at);
  if (operation_status != PBNS_OK) {
    return operation_status;
  }
  const size_t amount = destination.cap < endpoint->config.read_limit
                            ? destination.cap
                            : endpoint->config.read_limit;
  while (true) {
    const ssize_t result =
        recv(endpoint->descriptor, destination.ptr, amount, 0);
    if (result > 0) {
      *received = (size_t)result;
      return PBNS_OK;
    }
    if (result == 0) {
      return PBNS_ERR_TRANSPORT;
    }
    if (errno == EINTR) {
      const pbns_status time_status = deadline_status(endpoint);
      if (time_status == PBNS_OK) {
        continue;
      }
      return time_status;
    }
    return errno == EAGAIN || errno == EWOULDBLOCK ? PBNS_ERR_WOULD_BLOCK
                                                   : PBNS_ERR_TRANSPORT;
  }
}

pbns_status pbns_tls_replay_endpoint_write(void *context, pbns_view source,
                                           size_t *written) {
  pbns_tls_replay_endpoint *const endpoint = context;
  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (endpoint == NULL || !endpoint->initialized || source.ptr == NULL ||
      source.len == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status operation_status = next_operation(
      endpoint, &endpoint->write_operations, endpoint->config.fail_write_at);
  if (operation_status != PBNS_OK) {
    return operation_status;
  }
  const size_t amount = source.len < endpoint->config.write_limit
                            ? source.len
                            : endpoint->config.write_limit;
  while (true) {
    const ssize_t result =
        send(endpoint->descriptor, source.ptr, amount, MSG_NOSIGNAL);
    if (result > 0) {
      *written = (size_t)result;
      return PBNS_OK;
    }
    if (result == 0) {
      return PBNS_ERR_TRANSPORT;
    }
    if (errno == EINTR) {
      const pbns_status time_status = deadline_status(endpoint);
      if (time_status == PBNS_OK) {
        continue;
      }
      return time_status;
    }
    return errno == EAGAIN || errno == EWOULDBLOCK ? PBNS_ERR_WOULD_BLOCK
                                                   : PBNS_ERR_TRANSPORT;
  }
}

pbns_pump_endpoint
pbns_tls_replay_endpoint_callbacks(pbns_tls_replay_endpoint *endpoint) {
  if (endpoint == NULL) {
    return (pbns_pump_endpoint){0};
  }
  return (pbns_pump_endpoint){
      .read = pbns_tls_replay_endpoint_read,
      .write = pbns_tls_replay_endpoint_write,
      .context = endpoint,
  };
}

pbns_status pbns_tls_replay_endpoint_close(pbns_tls_replay_endpoint *endpoint) {
  if (endpoint == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!endpoint->initialized) {
    return PBNS_OK;
  }
  const int descriptor = endpoint->descriptor;
  *endpoint = (pbns_tls_replay_endpoint){0};
  endpoint->descriptor = -1;
  return close(descriptor) == 0 ? PBNS_OK : PBNS_ERR_TRANSPORT;
}
