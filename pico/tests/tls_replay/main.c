#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pbns/status.h"
#include "pbns_proxy/tls_client.h"
#include "pbns_tls_replay/endpoint.h"
#include "pbns_tls_replay/entropy.h"
#include "pbns_tls_replay/observer.h"

#define PBNS_TLS_REPLAY_DEFAULT_READ_LIMIT 16384U
#define PBNS_TLS_REPLAY_DEFAULT_WRITE_LIMIT 2048U
#define PBNS_TLS_REPLAY_DEFAULT_DEADLINE_MS UINT64_C(15000)
#define PBNS_TLS_REPLAY_WAIT_QUANTUM_MS 10

static int fail_with_message(const char *message, int status) {
  return fputs(message, stderr) >= 0 && fflush(stderr) == 0 ? status : 1;
}

static void secure_zero(void *pointer, size_t size) {
  volatile uint8_t *cursor = pointer;
  while (size > 0U) {
    *cursor = UINT8_C(0);
    ++cursor;
    --size;
  }
}

static bool parse_u64(const char *text, uint64_t minimum, uint64_t maximum,
                      uint64_t *value) {
  if (text == NULL || value == NULL || text[0] == '\0' || text[0] == '-') {
    return false;
  }
  errno = 0;
  char *end = NULL;
  const unsigned long long parsed = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' ||
      parsed > (unsigned long long)UINT64_MAX) {
    return false;
  }
  const uint64_t converted = (uint64_t)parsed;
  if (converted < minimum || converted > maximum) {
    return false;
  }
  *value = converted;
  return true;
}

static int hexadecimal_nibble(char character) {
  if (character >= '0' && character <= '9') {
    return character - '0';
  }
  if (character >= 'a' && character <= 'f') {
    return character - 'a' + 10;
  }
  return -1;
}

static bool decode_spki(const char *encoded,
                        uint8_t output[PBNS_TLS_SPKI_SHA256_SIZE]) {
  if (encoded == NULL ||
      strlen(encoded) != (size_t)PBNS_TLS_SPKI_SHA256_SIZE * 2U) {
    return false;
  }
  for (size_t index = 0U; index < PBNS_TLS_SPKI_SHA256_SIZE; ++index) {
    const int high = hexadecimal_nibble(encoded[index * 2U]);
    const int low = hexadecimal_nibble(encoded[index * 2U + 1U]);
    if (high < 0 || low < 0) {
      secure_zero(output, PBNS_TLS_SPKI_SHA256_SIZE);
      return false;
    }
    output[index] = (uint8_t)((unsigned)high << 4U | (unsigned)low);
  }
  return true;
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

static pbns_status wait_for_network(const pbns_tls_replay_endpoint *endpoint,
                                    uint64_t deadline_ms) {
  uint64_t now_ms = 0U;
  pbns_status status = monotonic_ms(&now_ms);
  if (status != PBNS_OK) {
    return status;
  }
  if (now_ms >= deadline_ms) {
    return PBNS_ERR_TIMEOUT;
  }
  const uint64_t remaining = deadline_ms - now_ms;
  const int timeout = remaining < (uint64_t)PBNS_TLS_REPLAY_WAIT_QUANTUM_MS
                          ? (int)remaining
                          : PBNS_TLS_REPLAY_WAIT_QUANTUM_MS;
  struct pollfd descriptor = {
      .fd = endpoint->descriptor,
      .events = POLLIN,
  };
  const int poll_status = poll(&descriptor, 1U, timeout > 0 ? timeout : 1);
  if (poll_status < 0 && errno != EINTR) {
    status = PBNS_ERR_TRANSPORT;
  }
  return status;
}

static bool emit_snapshot(const pbns_tls_replay_snapshot *snapshot) {
  if (!pbns_tls_replay_snapshot_is_valid(snapshot)) {
    return false;
  }
  if (printf("{\"terminal\":\"%s\",\"milestones\":[",
             pbns_tls_replay_terminal_name(snapshot->terminal)) < 0) {
    return false;
  }
  for (unsigned index = 0U; index < PBNS_TLS_REPLAY_MILESTONE_COUNT; ++index) {
    if (printf("%s%s", index == 0U ? "" : ",",
               snapshot->milestones[index] ? "true" : "false") < 0) {
      return false;
    }
  }
  return printf("]}\n") >= 0 && fflush(stdout) == 0;
}

typedef struct replay_arguments {
  pbns_tls_replay_endpoint_config endpoint;
  uint64_t heap_bytes;
  uint64_t deadline_duration_ms;
  const char *encoded_spki;
  uint16_t port;
  bool entropy_fail;
  bool has_port;
} replay_arguments;

static bool parse_arguments(int argc, char **argv,
                            replay_arguments *arguments) {
  if (arguments == NULL) {
    return false;
  }
  *arguments = (replay_arguments){
      .endpoint =
          {
              .read_limit = PBNS_TLS_REPLAY_DEFAULT_READ_LIMIT,
              .write_limit = PBNS_TLS_REPLAY_DEFAULT_WRITE_LIMIT,
          },
      .heap_bytes = UINT64_C(65536),
      .deadline_duration_ms = PBNS_TLS_REPLAY_DEFAULT_DEADLINE_MS,
  };
  static const struct option options[] = {
      {"port", required_argument, NULL, 'p'},
      {"spki", required_argument, NULL, 's'},
      {"heap-bytes", required_argument, NULL, 'h'},
      {"read-limit", required_argument, NULL, 'r'},
      {"write-limit", required_argument, NULL, 'w'},
      {"would-block-period", required_argument, NULL, 'b'},
      {"fail-read-at", required_argument, NULL, 'R'},
      {"fail-write-at", required_argument, NULL, 'W'},
      {"entropy-fail", no_argument, NULL, 'e'},
      {"deadline-ms", required_argument, NULL, 'd'},
      {NULL, 0, NULL, 0},
  };
  opterr = 0;
  int option = 0;
  while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
    uint64_t parsed = 0U;
    switch (option) {
    case 'p':
      if (!parse_u64(optarg, 1U, UINT16_MAX, &parsed)) {
        return false;
      }
      arguments->port = (uint16_t)parsed;
      arguments->has_port = true;
      break;
    case 's':
      arguments->encoded_spki = optarg;
      break;
    case 'h':
      if (!parse_u64(optarg, 1U, UINT64_C(65536), &arguments->heap_bytes)) {
        return false;
      }
      break;
    case 'r':
      if (!parse_u64(optarg, 1U, UINT64_C(16384), &parsed)) {
        return false;
      }
      arguments->endpoint.read_limit = (size_t)parsed;
      break;
    case 'w':
      if (!parse_u64(optarg, 1U, UINT64_C(16384), &parsed)) {
        return false;
      }
      arguments->endpoint.write_limit = (size_t)parsed;
      break;
    case 'b':
      if (!parse_u64(optarg, 0U, UINT64_C(1000000), &parsed)) {
        return false;
      }
      arguments->endpoint.would_block_period = (uint32_t)parsed;
      break;
    case 'R':
      if (!parse_u64(optarg, 0U, UINT64_C(1000000), &parsed)) {
        return false;
      }
      arguments->endpoint.fail_read_at = (uint32_t)parsed;
      break;
    case 'W':
      if (!parse_u64(optarg, 0U, UINT64_C(1000000), &parsed)) {
        return false;
      }
      arguments->endpoint.fail_write_at = (uint32_t)parsed;
      break;
    case 'e':
      arguments->entropy_fail = true;
      break;
    case 'd':
      if (!parse_u64(optarg, 1U, UINT64_C(30000),
                     &arguments->deadline_duration_ms)) {
        return false;
      }
      break;
    default:
      return false;
    }
  }
  return optind == argc && arguments->has_port &&
         arguments->encoded_spki != NULL;
}

int main(int argc, char **argv) {
  replay_arguments arguments = {0};
  uint8_t expected_spki[PBNS_TLS_SPKI_SHA256_SIZE] = {0};
  if (!parse_arguments(argc, argv, &arguments) ||
      !decode_spki(arguments.encoded_spki, expected_spki)) {
    return fail_with_message("invalid replay arguments\n", 2);
  }

  uint64_t now_ms = 0U;
  if (monotonic_ms(&now_ms) != PBNS_OK ||
      now_ms > UINT64_MAX - arguments.deadline_duration_ms) {
    secure_zero(expected_spki, sizeof(expected_spki));
    return fail_with_message("replay clock failed\n", 1);
  }
  arguments.endpoint.deadline_ms = now_ms + arguments.deadline_duration_ms;

  pbns_tls_replay_observer_reset();
  if (!pbns_tls_replay_observer_set_heap_bytes((size_t)arguments.heap_bytes)) {
    secure_zero(expected_spki, sizeof(expected_spki));
    return fail_with_message("invalid replay arguments\n", 2);
  }
  pbns_tls_replay_entropy_reset(arguments.entropy_fail);

  pbns_tls_replay_endpoint endpoint = {0};
  pbns_tls_client client = {0};
  const pbns_pump_endpoint encrypted =
      pbns_tls_replay_endpoint_callbacks(&endpoint);
  pbns_status status = pbns_tls_client_init(
      &client, (pbns_view){(const uint8_t *)"127.0.0.1", 9U},
      (pbns_view){expected_spki, sizeof(expected_spki)}, encrypted);
  const bool client_initialized = status == PBNS_OK;
  if (status == PBNS_OK) {
    status = pbns_tls_replay_endpoint_connect(&endpoint, arguments.port,
                                              &arguments.endpoint);
    if (status != PBNS_OK) {
      pbns_tls_client_free(&client);
      secure_zero(expected_spki, sizeof(expected_spki));
      return fail_with_message("replay connection failed\n", 1);
    }
  }
  while (status == PBNS_OK || status == PBNS_ERR_WOULD_BLOCK) {
    status = pbns_tls_client_step(&client);
    if (status != PBNS_ERR_WOULD_BLOCK) {
      break;
    }
    status = wait_for_network(&endpoint, arguments.endpoint.deadline_ms);
  }

  const pbns_tls_replay_snapshot snapshot = pbns_tls_replay_observer_snapshot();
  if (client_initialized) {
    pbns_tls_client_free(&client);
  }
  const pbns_status close_status = pbns_tls_replay_endpoint_close(&endpoint);
  secure_zero(expected_spki, sizeof(expected_spki));

  if (close_status != PBNS_OK) {
    return fail_with_message("replay cleanup failed\n", 1);
  }
  if (!snapshot.terminal_set || !pbns_tls_replay_snapshot_is_valid(&snapshot) ||
      !emit_snapshot(&snapshot)) {
    return fail_with_message("invalid replay snapshot\n", 1);
  }
  return 0;
}
