#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "mbedtls/entropy.h"
#include "pbns/status.h"
#include "pbns_tls_replay/endpoint.h"
#include "pbns_tls_replay/entropy.h"

static uint64_t monotonic_ms(void) {
  struct timespec now = {0};
  assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
  return (uint64_t)now.tv_sec * UINT64_C(1000) +
         (uint64_t)now.tv_nsec / UINT64_C(1000000);
}

static pbns_tls_replay_endpoint_config default_config(void) {
  return (pbns_tls_replay_endpoint_config){
      .read_limit = 5U,
      .write_limit = 4U,
      .deadline_ms = monotonic_ms() + UINT64_C(5000),
  };
}

static void test_entropy_is_deterministic_and_fails_closed(void) {
  unsigned char first[37] = {0};
  unsigned char second[37] = {0};
  size_t written = SIZE_MAX;

  pbns_tls_replay_entropy_reset(false);
  assert(mbedtls_hardware_poll(NULL, first, sizeof(first), &written) == 0);
  assert(written == sizeof(first));
  pbns_tls_replay_entropy_reset(false);
  assert(mbedtls_hardware_poll(NULL, second, sizeof(second), &written) == 0);
  assert(written == sizeof(second));
  assert(memcmp(first, second, sizeof(first)) == 0);

  pbns_tls_replay_entropy_reset(true);
  written = SIZE_MAX;
  assert(mbedtls_hardware_poll(NULL, first, sizeof(first), &written) ==
         MBEDTLS_ERR_ENTROPY_SOURCE_FAILED);
  assert(written == 0U);
  assert(mbedtls_hardware_poll(NULL, first, sizeof(first), NULL) ==
         MBEDTLS_ERR_ENTROPY_SOURCE_FAILED);
  written = SIZE_MAX;
  assert(mbedtls_hardware_poll(NULL, NULL, 1U, &written) ==
         MBEDTLS_ERR_ENTROPY_SOURCE_FAILED);
  assert(written == 0U);
}

static void test_callbacks_exist_before_connection(void) {
  pbns_tls_replay_endpoint endpoint = {0};
  const pbns_pump_endpoint callbacks =
      pbns_tls_replay_endpoint_callbacks(&endpoint);
  assert(callbacks.read == pbns_tls_replay_endpoint_read);
  assert(callbacks.write == pbns_tls_replay_endpoint_write);
  assert(callbacks.context == &endpoint);
}

static void test_short_io_and_would_block(void) {
  int sockets[2] = {-1, -1};
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets) == 0);
  pbns_tls_replay_endpoint endpoint = {0};
  const pbns_tls_replay_endpoint_config config = default_config();
  assert(pbns_tls_replay_endpoint_adopt(&endpoint, sockets[0], &config) ==
         PBNS_OK);
  sockets[0] = -1;

  static const uint8_t source[] = {1U, 2U, 3U, 4U, 5U, 6U};
  size_t written = SIZE_MAX;
  assert(pbns_tls_replay_endpoint_write(&endpoint,
                                        (pbns_view){source, sizeof(source)},
                                        &written) == PBNS_OK);
  assert(written == config.write_limit);
  uint8_t peer[8] = {0};
  assert(recv(sockets[1], peer, sizeof(peer), 0) == (ssize_t)written);
  assert(memcmp(source, peer, written) == 0);

  uint8_t destination[8] = {0};
  size_t received = SIZE_MAX;
  assert(pbns_tls_replay_endpoint_read(
             &endpoint, (pbns_buffer){destination, 0U, sizeof(destination)},
             &received) == PBNS_ERR_WOULD_BLOCK);
  assert(received == 0U);
  assert(send(sockets[1], source, sizeof(source), 0) ==
         (ssize_t)sizeof(source));
  assert(pbns_tls_replay_endpoint_read(
             &endpoint, (pbns_buffer){destination, 0U, sizeof(destination)},
             &received) == PBNS_OK);
  assert(received == config.read_limit);
  assert(memcmp(source, destination, received) == 0);

  const pbns_pump_endpoint callbacks =
      pbns_tls_replay_endpoint_callbacks(&endpoint);
  assert(callbacks.read == pbns_tls_replay_endpoint_read);
  assert(callbacks.write == pbns_tls_replay_endpoint_write);
  assert(callbacks.context == &endpoint);

  assert(pbns_tls_replay_endpoint_close(&endpoint) == PBNS_OK);
  assert(pbns_tls_replay_endpoint_close(&endpoint) == PBNS_OK);
  assert(close(sockets[1]) == 0);
}

static void test_scheduled_would_block_and_failures(void) {
  int sockets[2] = {-1, -1};
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets) == 0);
  pbns_tls_replay_endpoint endpoint = {0};
  pbns_tls_replay_endpoint_config config = default_config();
  config.would_block_period = 2U;
  assert(pbns_tls_replay_endpoint_adopt(&endpoint, sockets[0], &config) ==
         PBNS_OK);
  sockets[0] = -1;

  static const uint8_t source[] = {9U, 8U, 7U};
  size_t written = SIZE_MAX;
  assert(pbns_tls_replay_endpoint_write(&endpoint,
                                        (pbns_view){source, sizeof(source)},
                                        &written) == PBNS_OK);
  assert(written > 0U);
  assert(pbns_tls_replay_endpoint_write(&endpoint,
                                        (pbns_view){source, sizeof(source)},
                                        &written) == PBNS_ERR_WOULD_BLOCK);
  assert(written == 0U);
  assert(pbns_tls_replay_endpoint_close(&endpoint) == PBNS_OK);
  assert(close(sockets[1]) == 0);

  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets) == 0);
  endpoint = (pbns_tls_replay_endpoint){0};
  config = default_config();
  config.fail_write_at = 1U;
  assert(pbns_tls_replay_endpoint_adopt(&endpoint, sockets[0], &config) ==
         PBNS_OK);
  sockets[0] = -1;
  assert(pbns_tls_replay_endpoint_write(&endpoint,
                                        (pbns_view){source, sizeof(source)},
                                        &written) == PBNS_ERR_TRANSPORT);
  assert(written == 0U);
  assert(pbns_tls_replay_endpoint_close(&endpoint) == PBNS_OK);
  assert(close(sockets[1]) == 0);
}

static void test_expired_deadline_times_out_without_io(void) {
  int sockets[2] = {-1, -1};
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets) == 0);
  pbns_tls_replay_endpoint endpoint = {0};
  pbns_tls_replay_endpoint_config config = default_config();
  config.deadline_ms = monotonic_ms();
  assert(pbns_tls_replay_endpoint_adopt(&endpoint, sockets[0], &config) ==
         PBNS_OK);
  sockets[0] = -1;

  static const uint8_t source[] = {1U};
  size_t written = SIZE_MAX;
  assert(pbns_tls_replay_endpoint_write(&endpoint,
                                        (pbns_view){source, sizeof(source)},
                                        &written) == PBNS_ERR_TIMEOUT);
  assert(written == 0U);
  assert(pbns_tls_replay_endpoint_close(&endpoint) == PBNS_OK);
  assert(close(sockets[1]) == 0);
}

int main(void) {
  test_entropy_is_deterministic_and_fails_closed();
  test_callbacks_exist_before_connection();
  test_short_io_and_would_block();
  test_scheduled_would_block_and_failures();
  test_expired_deadline_times_out_without_io();
  return 0;
}
