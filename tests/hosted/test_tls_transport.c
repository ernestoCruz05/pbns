#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include "pbns/broker.h"
#include "pbns/frame.h"
#include "pbns/tls_transport.h"

#define QUEUE_CAPACITY 131072U
#define TRANSCRIPT_CAPACITY 262144U
#define TEST_TIMEOUT_MS 1000U

typedef struct byte_queue {
  uint8_t bytes[QUEUE_CAPACITY];
  size_t offset;
  size_t length;
} byte_queue;

typedef struct replay_state {
  byte_queue client_to_server;
  byte_queue server_to_client;
  uint8_t transcript[TRANSCRIPT_CAPACITY];
  size_t transcript_length;
  uint8_t server_received[32768];
  size_t server_received_length;
  uint8_t server_auto_response[256];
  size_t server_auto_response_length;
  const uint8_t *server_send;
  size_t server_send_length;
  size_t server_send_offset;
  mbedtls_ssl_context server_ssl;
  mbedtls_ssl_config server_config;
  mbedtls_x509_crt server_certificate;
  mbedtls_pk_context server_key;
  mbedtls_ctr_drbg_context server_drbg;
  uint64_t now_ms;
  uint64_t previous_now_ms;
  size_t open_calls;
  size_t close_calls;
  size_t cancel_calls;
  size_t release_calls;
  size_t send_calls;
  size_t receive_calls;
  size_t maximum_client_to_server;
  size_t maximum_server_to_client;
  uint32_t rng_state;
  uint32_t would_block_period;
  uint32_t operation_count;
  uint32_t fail_clock_after;
  uint32_t regress_clock_after;
  uint32_t advance_clock_on_receive;
  size_t fail_send_at;
  size_t fail_receive_at;
  size_t eof_after_receive;
  bool entropy_failure;
  bool lower_open_failure;
  bool lower_close_failure;
  bool eof_on_receive;
  bool disable_alpn;
  bool incompatible_cipher;
  bool incompatible_version;
  bool force_receive_would_block;
  const char *certificate_path;
  const char *key_path;
  int server_error;
  int server_ssl_state;
  bool server_initialized;
  bool server_handshake_complete;
  bool server_handshake_ever_complete;
  bool server_peer_closed;
  bool auto_response;
  bool auto_response_ready;
  bool released_all_zero;
} replay_state;

static const uint8_t expected_pin[32] = {
    0xa0, 0xd2, 0x19, 0x23, 0xdd, 0xfc, 0xcb, 0xa1, 0x2d, 0x0a, 0x7b,
    0xbd, 0x74, 0x08, 0x65, 0x0c, 0xb8, 0xc5, 0x4f, 0x1b, 0xe5, 0x37,
    0xfe, 0x3a, 0x7e, 0x69, 0xad, 0xb1, 0x37, 0x6d, 0xa1, 0x06,
};
static const uint8_t expected_name[] = "pbns-gateway.test";

static void queue_reset(byte_queue *queue) { *queue = (byte_queue){0}; }

static bool queue_append(byte_queue *queue, const uint8_t *bytes,
                         size_t length) {
  if (bytes == NULL || length == 0U ||
      length > QUEUE_CAPACITY - queue->length) {
    return false;
  }
  if (queue->offset != 0U &&
      queue->offset + queue->length + length > QUEUE_CAPACITY) {
    memmove(queue->bytes, queue->bytes + queue->offset, queue->length);
    queue->offset = 0U;
  }
  if (queue->offset + queue->length + length > QUEUE_CAPACITY) {
    return false;
  }
  memcpy(queue->bytes + queue->offset + queue->length, bytes, length);
  queue->length += length;
  return true;
}

static size_t queue_take(byte_queue *queue, uint8_t *output, size_t capacity,
                         size_t fragment) {
  if (queue->length == 0U || capacity == 0U || fragment == 0U) {
    return 0U;
  }
  size_t amount = queue->length < capacity ? queue->length : capacity;
  if (amount > fragment) {
    amount = fragment;
  }
  memcpy(output, queue->bytes + queue->offset, amount);
  queue->offset += amount;
  queue->length -= amount;
  if (queue->length == 0U) {
    queue->offset = 0U;
  }
  return amount;
}

static int test_rng(void *context, unsigned char *output, size_t length) {
  replay_state *const state = context;
  for (size_t index = 0U; index < length; ++index) {
    state->rng_state =
        state->rng_state * UINT32_C(1664525) + UINT32_C(1013904223);
    output[index] = (unsigned char)(state->rng_state >> 24U);
  }
  return 0;
}

static int server_send(void *context, const unsigned char *bytes,
                       size_t length) {
  replay_state *const state = context;
  if (!queue_append(&state->server_to_client, bytes, length)) {
    return MBEDTLS_ERR_SSL_ALLOC_FAILED;
  }
  if (state->server_to_client.length > state->maximum_server_to_client) {
    state->maximum_server_to_client = state->server_to_client.length;
  }
  return (int)length;
}

static int server_receive(void *context, unsigned char *bytes, size_t length) {
  replay_state *const state = context;
  const size_t amount =
      queue_take(&state->client_to_server, bytes, length, QUEUE_CAPACITY);
  return amount == 0U ? MBEDTLS_ERR_SSL_WANT_READ : (int)amount;
}

static void server_free(replay_state *state) {
  if (!state->server_initialized) {
    return;
  }
  mbedtls_ssl_free(&state->server_ssl);
  mbedtls_ssl_config_free(&state->server_config);
  mbedtls_x509_crt_free(&state->server_certificate);
  mbedtls_pk_free(&state->server_key);
  mbedtls_ctr_drbg_free(&state->server_drbg);
  state->server_initialized = false;
  state->server_handshake_complete = false;
}

static size_t read_file(const char *path, uint8_t *output, size_t capacity) {
  FILE *const stream = fopen(path, "rb");
  assert(stream != NULL);
  const size_t length = fread(output, 1U, capacity, stream);
  assert(ferror(stream) == 0);
  assert(feof(stream) != 0);
  assert(fclose(stream) == 0);
  return length;
}

static void server_initialize(replay_state *state, const char *certificate_path,
                              const char *key_path) {
  static const unsigned char personalization[] = "PBNS-TLS-TEST-SERVER-v1";
  uint8_t certificate[4096] = {0};
  uint8_t key[4096] = {0};
  const size_t certificate_length =
      read_file(certificate_path, certificate, sizeof(certificate));
  const size_t key_length = read_file(key_path, key, sizeof(key));
  state->server_received_length = 0U;
  state->server_send_offset = 0U;
  state->server_peer_closed = false;
  queue_reset(&state->client_to_server);
  queue_reset(&state->server_to_client);
  static const char *alpn[] = {"pbns/1", NULL};
  static const int compatible_ciphers[] = {
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      0,
  };
  static const int incompatible_ciphers[] = {
      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      0,
  };
  mbedtls_ssl_init(&state->server_ssl);
  mbedtls_ssl_config_init(&state->server_config);
  mbedtls_x509_crt_init(&state->server_certificate);
  mbedtls_pk_init(&state->server_key);
  mbedtls_ctr_drbg_init(&state->server_drbg);
  assert(mbedtls_ctr_drbg_seed(&state->server_drbg, test_rng, state,
                               personalization,
                               sizeof(personalization) - 1U) == 0);
  assert(mbedtls_x509_crt_parse_der(&state->server_certificate, certificate,
                                    certificate_length) == 0);
  assert(mbedtls_pk_parse_key(&state->server_key, key, key_length, NULL, 0U,
                              test_rng, state) == 0);
  assert(mbedtls_ssl_config_defaults(
             &state->server_config, MBEDTLS_SSL_IS_SERVER,
             MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) == 0);
  mbedtls_ssl_conf_rng(&state->server_config, mbedtls_ctr_drbg_random,
                       &state->server_drbg);
  mbedtls_ssl_conf_authmode(&state->server_config, MBEDTLS_SSL_VERIFY_NONE);
  mbedtls_ssl_conf_min_tls_version(&state->server_config,
                                   MBEDTLS_SSL_VERSION_TLS1_2);
  mbedtls_ssl_conf_max_tls_version(&state->server_config,
                                   MBEDTLS_SSL_VERSION_TLS1_2);
  mbedtls_ssl_conf_ciphersuites(
      &state->server_config,
      state->incompatible_cipher ? incompatible_ciphers : compatible_ciphers);
  if (!state->disable_alpn) {
    assert(mbedtls_ssl_conf_alpn_protocols(&state->server_config, alpn) == 0);
  }
  memset(key, 0, sizeof(key));
  memset(certificate, 0, sizeof(certificate));
  assert(mbedtls_ssl_conf_own_cert(&state->server_config,
                                   &state->server_certificate,
                                   &state->server_key) == 0);
  assert(mbedtls_ssl_setup(&state->server_ssl, &state->server_config) == 0);
  mbedtls_ssl_set_bio(&state->server_ssl, state, server_send, server_receive,
                      NULL);
  state->server_initialized = true;
}

static void server_prepare_auto_response(replay_state *state) {
  if (!state->auto_response || state->auto_response_ready ||
      state->server_received_length == 0U) {
    return;
  }
  size_t record_length = 0U;
  while (record_length < state->server_received_length &&
         state->server_received[record_length] != 0U) {
    ++record_length;
  }
  if (record_length == state->server_received_length) {
    return;
  }
  uint8_t scratch[PBNS_FRAME_V1_RAW_MAX] = {0};
  pbns_frame request = {0};
  pbns_view payload = {0};
  const pbns_frame_limits limits = {4096U, 16384U, 20000U};
  assert(pbns_frame_decode((pbns_view){state->server_received, record_length},
                           limits, (pbns_buffer){scratch, 0U, sizeof(scratch)},
                           &request, &payload) == PBNS_OK);
  const pbns_frame response = {
      .service = request.service,
      .type = PBNS_MESSAGE_RESPONSE,
      .flags = 0U,
      .request_id = request.request_id,
      .sequence = 0U,
  };
  static const uint8_t body[] = {0xa0U};
  uint8_t raw[PBNS_FRAME_V1_RAW_MAX] = {0};
  assert(pbns_frame_encode(&response, (pbns_view){body, sizeof(body)},
                           (pbns_buffer){raw, 0U, sizeof(raw)},
                           (pbns_buffer){state->server_auto_response, 0U,
                                         sizeof(state->server_auto_response)},
                           &state->server_auto_response_length) == PBNS_OK);
  state->server_send = state->server_auto_response;
  state->server_send_length = state->server_auto_response_length;
  state->auto_response_ready = true;
}

static void server_drive(replay_state *state) {
  for (uint32_t steps = 0U; steps < 512U; ++steps) {
    if (!state->server_handshake_complete) {
      const int result = mbedtls_ssl_handshake(&state->server_ssl);
      if (result == 0) {
        state->server_handshake_complete = true;
        state->server_handshake_ever_complete = true;
        continue;
      }
      if (result == MBEDTLS_ERR_SSL_WANT_READ ||
          result == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return;
      }
      state->server_error = result;
      state->server_ssl_state = (int)state->server_ssl.MBEDTLS_PRIVATE(state);
      return;
    }
    if (state->server_received_length < sizeof(state->server_received)) {
      const int result = mbedtls_ssl_read(
          &state->server_ssl,
          state->server_received + state->server_received_length,
          sizeof(state->server_received) - state->server_received_length);
      if (result > 0) {
        state->server_received_length += (size_t)result;
        continue;
      }
      if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        state->server_peer_closed = true;
        (void)mbedtls_ssl_close_notify(&state->server_ssl);
        return;
      }
      if (result != MBEDTLS_ERR_SSL_WANT_READ &&
          result != MBEDTLS_ERR_SSL_WANT_WRITE) {
        state->server_error = result;
        state->server_ssl_state = (int)state->server_ssl.MBEDTLS_PRIVATE(state);
        return;
      }
    }
    server_prepare_auto_response(state);
    if (state->server_send != NULL &&
        state->server_send_offset < state->server_send_length) {
      const int result = mbedtls_ssl_write(
          &state->server_ssl, state->server_send + state->server_send_offset,
          state->server_send_length - state->server_send_offset);
      if (result > 0) {
        state->server_send_offset += (size_t)result;
        continue;
      }
      if (result == MBEDTLS_ERR_SSL_WANT_READ ||
          result == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return;
      }
    }
    return;
  }
}

static bool contains_view(const uint8_t *haystack, size_t haystack_length,
                          const uint8_t *needle, size_t needle_length) {
  if (needle_length == 0U || haystack_length < needle_length) {
    return false;
  }
  for (size_t index = 0U; index <= haystack_length - needle_length; ++index) {
    if (memcmp(haystack + index, needle, needle_length) == 0) {
      return true;
    }
  }
  return false;
}

static pbns_status lower_open(void *context) {
  replay_state *const state = context;
  ++state->open_calls;
  if (state->lower_open_failure) {
    return PBNS_ERR_TRANSPORT;
  }
  if (!state->server_initialized) {
    server_initialize(state, state->certificate_path, state->key_path);
  }
  return PBNS_OK;
}

static pbns_status lower_close(void *context) {
  replay_state *const state = context;
  ++state->close_calls;
  server_drive(state);
  server_free(state);
  queue_reset(&state->client_to_server);
  queue_reset(&state->server_to_client);
  return state->lower_close_failure ? PBNS_ERR_TRANSPORT : PBNS_OK;
}

static pbns_status lower_send(void *context, pbns_view bytes,
                              uint32_t timeout_ms) {
  replay_state *const state = context;
  assert(timeout_ms > 0U);
  ++state->send_calls;
  ++state->operation_count;
  if (state->fail_send_at != 0U && state->send_calls >= state->fail_send_at) {
    return PBNS_ERR_TRANSPORT;
  }
  if (state->would_block_period != 0U &&
      state->operation_count % state->would_block_period == 0U) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  if (!queue_append(&state->client_to_server, bytes.ptr, bytes.len) ||
      bytes.len > TRANSCRIPT_CAPACITY - state->transcript_length) {
    return PBNS_ERR_RESOURCE;
  }
  memcpy(state->transcript + state->transcript_length, bytes.ptr, bytes.len);
  state->transcript_length += bytes.len;
  if (state->client_to_server.length > state->maximum_client_to_server) {
    state->maximum_client_to_server = state->client_to_server.length;
  }
  server_drive(state);
  return PBNS_OK;
}

static pbns_status lower_receive(void *context, pbns_buffer buffer,
                                 uint32_t timeout_ms, size_t *received) {
  replay_state *const state = context;
  assert(timeout_ms > 0U);
  assert(received != NULL);
  *received = 0U;
  ++state->receive_calls;
  ++state->operation_count;
  if (state->fail_receive_at != 0U &&
      state->receive_calls >= state->fail_receive_at) {
    return PBNS_ERR_TRANSPORT;
  }
  if (state->advance_clock_on_receive != 0U) {
    state->now_ms += state->advance_clock_on_receive;
  }
  if (state->force_receive_would_block ||
      (state->would_block_period != 0U &&
       state->operation_count % state->would_block_period == 0U)) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  server_drive(state);
  if (state->eof_on_receive ||
      (state->eof_after_receive != 0U &&
       state->receive_calls > state->eof_after_receive)) {
    return PBNS_OK;
  }
  *received = queue_take(&state->server_to_client, buffer.ptr, buffer.cap, 31U);
  return *received == 0U ? PBNS_ERR_WOULD_BLOCK : PBNS_OK;
}

static pbns_status lower_cancel(void *context,
                                const pbns_request_id *request_id) {
  replay_state *const state = context;
  assert(request_id != NULL);
  ++state->cancel_calls;
  return PBNS_OK;
}

static pbns_status lower_limits(void *context, pbns_frame_limits *limits) {
  replay_state *const state = context;
  if (!state->server_handshake_complete) {
    return PBNS_ERR_STATE;
  }
  *limits = (pbns_frame_limits){4096U, 16384U, 20000U};
  return PBNS_OK;
}

static pbns_status platform_random(void *context, pbns_buffer output) {
  replay_state *const state = context;
  if (state->entropy_failure) {
    return PBNS_ERR_ENTROPY;
  }
  for (size_t index = 0U; index < output.cap; ++index) {
    state->rng_state =
        state->rng_state * UINT32_C(1103515245) + UINT32_C(12345);
    output.ptr[index] = (uint8_t)(state->rng_state >> 24U);
  }
  return PBNS_OK;
}

static pbns_status platform_now(void *context, uint64_t *now_ms) {
  replay_state *const state = context;
  ++state->operation_count;
  if (state->fail_clock_after != 0U &&
      state->operation_count >= state->fail_clock_after) {
    return PBNS_ERR_STATE;
  }
  if (state->regress_clock_after != 0U &&
      state->operation_count >= state->regress_clock_after) {
    *now_ms = state->previous_now_ms - 1U;
    return PBNS_OK;
  }
  state->previous_now_ms = state->now_ms;
  *now_ms = state->now_ms;
  return PBNS_OK;
}

static void *platform_allocate(void *context, size_t size) {
  (void)context;
  return calloc(1U, size);
}

static void platform_release(void *context, void *allocation, size_t size) {
  replay_state *const state = context;
  const uint8_t *const bytes = allocation;
  state->released_all_zero = true;
  for (size_t index = 0U; index < size; ++index) {
    if (bytes[index] != 0U) {
      state->released_all_zero = false;
      break;
    }
  }
  ++state->release_calls;
  free(allocation);
}

static const pbns_transport_ops lower_ops = {
    .open = lower_open,
    .close = lower_close,
    .send = lower_send,
    .receive = lower_receive,
    .cancel = lower_cancel,
    .limits = lower_limits,
};
static const pbns_tls_platform_ops platform_ops = {
    .random = platform_random,
    .monotonic_ms = platform_now,
    .allocate = platform_allocate,
    .release = platform_release,
};
static const pbns_broker_platform_ops broker_platform_ops = {
    .random = platform_random,
    .monotonic_ms = platform_now,
};

static pbns_transport create_transport(replay_state *state,
                                       const char *certificate_path,
                                       const char *key_path, pbns_view name,
                                       pbns_view pin,
                                       pbns_tls_transport **owner) {
  *state = (replay_state){
      .now_ms = 1U,
      .rng_state = UINT32_C(0x12345678),
      .certificate_path = certificate_path,
      .key_path = key_path,
  };
  server_initialize(state, certificate_path, key_path);
  *owner = NULL;
  const pbns_tls_client_config config = {
      .expected_server_name = name,
      .pinned_leaf_spki_sha256 = pin,
      .handshake_timeout_ms = TEST_TIMEOUT_MS,
  };
  assert(pbns_tls_transport_create((pbns_transport){&lower_ops, state}, &config,
                                   (pbns_tls_platform){&platform_ops, state},
                                   owner) == PBNS_OK);
  return pbns_tls_transport_as_transport(*owner);
}

static void destroy_transport(replay_state *state, pbns_tls_transport *owner) {
  pbns_tls_transport_destroy(owner);
  server_free(state);
  assert(state->release_calls == 1U);
  assert(state->released_all_zero);
}

static void test_handshake_streaming_and_reconnect(const char *certificate_path,
                                                   const char *key_path) {
  replay_state state = {0};
  pbns_tls_transport *owner = NULL;
  const pbns_view name = {expected_name, sizeof(expected_name) - 1U};
  const pbns_transport transport =
      create_transport(&state, certificate_path, key_path, name,
                       (pbns_view){expected_pin, sizeof(expected_pin)}, &owner);
  assert(transport.ops->limits(transport.context, &(pbns_frame_limits){0}) ==
         PBNS_ERR_STATE);
  const pbns_status open_status = transport.ops->open(transport.context);
  assert(open_status == PBNS_OK);
  pbns_frame_limits limits = {0};
  assert(transport.ops->limits(transport.context, &limits) == PBNS_OK);
  assert(limits.data_payload_max == 16384U);

  state.would_block_period = 7U;
  uint8_t payload[24577];
  for (size_t index = 0U; index < sizeof(payload); ++index) {
    payload[index] = (uint8_t)(index * 17U + 3U);
  }
  assert(transport.ops->send(transport.context,
                             (pbns_view){payload, sizeof(payload)},
                             TEST_TIMEOUT_MS) == PBNS_OK);
  server_drive(&state);
  assert(state.server_received_length == sizeof(payload));
  assert(memcmp(state.server_received, payload, sizeof(payload)) == 0);
  assert(!contains_view(state.transcript, state.transcript_length, payload,
                        sizeof(payload)));
  static const uint8_t canary_one[64] =
      "PBNS-PLAINTEXT-CANARY-ONE-0123456789-ABCDEFGHIJKLMN";
  static const uint8_t canary_two[64] =
      "PBNS-PLAINTEXT-CANARY-TWO-9876543210-NMLKJIHGFEDCBA";
  static const uint8_t frame_header[16] = {
      'P',   'B',   'N',   'S',   1U, 0U, 0U, 0U,
      0xdeU, 0xadU, 0xbeU, 0xefU, 0U, 0U, 0U, 1U,
  };
  assert(!contains_view(state.transcript, state.transcript_length, canary_one,
                        sizeof(canary_one)));
  assert(!contains_view(state.transcript, state.transcript_length, canary_two,
                        sizeof(canary_two)));
  assert(!contains_view(state.transcript, state.transcript_length, frame_header,
                        sizeof(frame_header)));
  assert(state.maximum_client_to_server <= QUEUE_CAPACITY);
  assert(state.maximum_server_to_client <= QUEUE_CAPACITY);

  uint8_t response[5003];
  for (size_t index = 0U; index < sizeof(response); ++index) {
    response[index] = (uint8_t)(index * 13U + 9U);
  }
  state.server_send = response;
  state.server_send_length = sizeof(response);
  uint8_t received[sizeof(response)] = {0};
  size_t total = 0U;
  while (total < sizeof(received)) {
    size_t count = 0U;
    assert(transport.ops->receive(
               transport.context,
               (pbns_buffer){received + total, 0U, sizeof(received) - total},
               TEST_TIMEOUT_MS, &count) == PBNS_OK);
    assert(count > 0U);
    total += count;
  }
  assert(memcmp(received, response, sizeof(response)) == 0);
  assert(transport.ops->close(transport.context) == PBNS_OK);
  assert(state.server_peer_closed);

  state.transcript_length = 0U;
  assert(transport.ops->open(transport.context) == PBNS_OK);
  const uint8_t fresh[] = "fresh-session";
  assert(transport.ops->send(transport.context,
                             (pbns_view){fresh, sizeof(fresh) - 1U},
                             TEST_TIMEOUT_MS) == PBNS_OK);
  server_drive(&state);
  assert(state.server_received_length == sizeof(fresh) - 1U);
  assert(memcmp(state.server_received, fresh, sizeof(fresh) - 1U) == 0);
  assert(transport.ops->close(transport.context) == PBNS_OK);
  destroy_transport(&state, owner);
}

static void test_authentication_failures(const char *certificate_path,
                                         const char *key_path) {
  const pbns_view valid_name = {expected_name, sizeof(expected_name) - 1U};
  uint8_t wrong_pin[sizeof(expected_pin)] = {0};
  for (size_t case_index = 0U; case_index < 4U; ++case_index) {
    replay_state state = {0};
    pbns_tls_transport *owner = NULL;
    pbns_view name = valid_name;
    pbns_view pin = {expected_pin, sizeof(expected_pin)};
    pbns_transport transport =
        create_transport(&state, certificate_path, key_path, name, pin, &owner);
    if (case_index == 0U) {
      pin = (pbns_view){wrong_pin, sizeof(wrong_pin)};
      pbns_tls_transport_destroy(owner);
      server_free(&state);
      transport = create_transport(&state, certificate_path, key_path, name,
                                   pin, &owner);
    } else if (case_index == 1U) {
      name = (pbns_view){(const uint8_t *)"other.test", 10U};
      pbns_tls_transport_destroy(owner);
      server_free(&state);
      transport = create_transport(&state, certificate_path, key_path, name,
                                   pin, &owner);
    } else if (case_index == 2U) {
      state.disable_alpn = true;
      server_free(&state);
      server_initialize(&state, certificate_path, key_path);
    } else if (case_index == 3U) {
      state.incompatible_cipher = true;
      server_free(&state);
      server_initialize(&state, certificate_path, key_path);
    }
    assert(transport.ops->open(transport.context) != PBNS_OK);
    assert(transport.ops->send(transport.context,
                               (pbns_view){(const uint8_t *)"x", 1U},
                               1U) == PBNS_ERR_STATE);
    destroy_transport(&state, owner);
  }
}

static void test_lifecycle_and_clock_failures(const char *certificate_path,
                                              const char *key_path) {
  const pbns_view name = {expected_name, sizeof(expected_name) - 1U};
  const pbns_view pin = {expected_pin, sizeof(expected_pin)};
  replay_state state = {0};
  pbns_tls_transport *owner = NULL;
  pbns_transport transport =
      create_transport(&state, certificate_path, key_path, name, pin, &owner);
  state.lower_open_failure = true;
  assert(transport.ops->open(transport.context) == PBNS_ERR_TRANSPORT);
  assert(state.close_calls == 1U);
  state.lower_open_failure = false;
  assert(transport.ops->open(transport.context) == PBNS_OK);
  const pbns_request_id request = {{0}};
  assert(transport.ops->cancel(transport.context, &request) == PBNS_OK);
  assert(state.cancel_calls == 1U);
  assert(transport.ops->open(transport.context) == PBNS_OK);
  state.lower_close_failure = true;
  assert(transport.ops->close(transport.context) == PBNS_ERR_TRANSPORT);
  state.lower_close_failure = false;
  assert(transport.ops->open(transport.context) == PBNS_OK);
  state.fail_clock_after = state.operation_count + 1U;
  assert(transport.ops->send(transport.context,
                             (pbns_view){(const uint8_t *)"x", 1U},
                             TEST_TIMEOUT_MS) == PBNS_ERR_STATE);
  state.fail_clock_after = 0U;
  assert(transport.ops->open(transport.context) == PBNS_OK);
  state.regress_clock_after = state.operation_count + 2U;
  uint8_t byte = 0U;
  size_t count = 0U;
  assert(transport.ops->receive(transport.context, (pbns_buffer){&byte, 0U, 1U},
                                TEST_TIMEOUT_MS, &count) == PBNS_ERR_STATE);
  destroy_transport(&state, owner);
}

static void test_broker_over_tls_composition(const char *certificate_path,
                                             const char *key_path) {
  const pbns_view name = {expected_name, sizeof(expected_name) - 1U};
  const pbns_view pin = {expected_pin, sizeof(expected_pin)};
  replay_state state = {0};
  pbns_tls_transport *owner = NULL;
  const pbns_transport transport =
      create_transport(&state, certificate_path, key_path, name, pin, &owner);
  state.auto_response = true;
  uint8_t encoded[512] = {0};
  uint8_t raw[512] = {0};
  uint8_t receive[512] = {0};
  uint8_t decoded[512] = {0};
  pbns_broker broker = {0};
  assert(pbns_broker_init(&broker, transport,
                          (pbns_broker_platform){&broker_platform_ops, &state},
                          (pbns_broker_storage){
                              .encoded = {encoded, 0U, sizeof(encoded)},
                              .raw_scratch = {raw, 0U, sizeof(raw)},
                              .receive = {receive, 0U, sizeof(receive)},
                              .decoded = {decoded, 0U, sizeof(decoded)},
                          }) == PBNS_OK);
  static const uint8_t request[] = {0xa0U};
  pbns_broker_response response = {0};
  assert(pbns_broker_request(&broker, PBNS_SERVICE_TRUSTED_TIME,
                             (pbns_view){request, sizeof(request)},
                             TEST_TIMEOUT_MS, &response) == PBNS_OK);
  assert(response.frame.type == PBNS_MESSAGE_RESPONSE);
  assert(response.payload.len == 1U && response.payload.ptr[0] == 0xa0U);
  assert(state.open_calls == 1U && state.server_auto_response_length != 0U);
  pbns_broker_reset(&broker);
  assert(state.close_calls >= 1U);
  destroy_transport(&state, owner);
}

static void test_lower_fatal_failures(const char *certificate_path,
                                      const char *key_path) {
  const pbns_view name = {expected_name, sizeof(expected_name) - 1U};
  const pbns_view pin = {expected_pin, sizeof(expected_pin)};
  replay_state state = {0};
  pbns_tls_transport *owner = NULL;
  pbns_transport transport =
      create_transport(&state, certificate_path, key_path, name, pin, &owner);
  state.fail_send_at = 1U;
  assert(transport.ops->open(transport.context) == PBNS_ERR_TRANSPORT);
  destroy_transport(&state, owner);

  transport =
      create_transport(&state, certificate_path, key_path, name, pin, &owner);
  state.fail_receive_at = 1U;
  assert(transport.ops->open(transport.context) == PBNS_ERR_TRANSPORT);
  destroy_transport(&state, owner);

  transport =
      create_transport(&state, certificate_path, key_path, name, pin, &owner);
  assert(transport.ops->open(transport.context) == PBNS_OK);
  state.fail_send_at = state.send_calls + 1U;
  assert(transport.ops->send(transport.context,
                             (pbns_view){(const uint8_t *)"x", 1U},
                             TEST_TIMEOUT_MS) == PBNS_ERR_TRANSPORT);
  destroy_transport(&state, owner);

  transport =
      create_transport(&state, certificate_path, key_path, name, pin, &owner);
  assert(transport.ops->open(transport.context) == PBNS_OK);
  state.fail_receive_at = state.receive_calls + 1U;
  uint8_t byte = 0U;
  size_t count = 0U;
  assert(transport.ops->receive(transport.context, (pbns_buffer){&byte, 0U, 1U},
                                TEST_TIMEOUT_MS, &count) == PBNS_ERR_TRANSPORT);
  assert(count == 0U);
  destroy_transport(&state, owner);
}

static void test_fail_closed_conditions(const char *certificate_path,
                                        const char *key_path) {
  const pbns_view name = {expected_name, sizeof(expected_name) - 1U};
  const pbns_view pin = {expected_pin, sizeof(expected_pin)};
  replay_state state = {0};
  pbns_tls_transport *owner = NULL;
  pbns_transport transport =
      create_transport(&state, certificate_path, key_path, name, pin, &owner);
  state.entropy_failure = true;
  assert(transport.ops->open(transport.context) == PBNS_ERR_ENTROPY);
  assert(state.close_calls == 1U);
  state.entropy_failure = false;
  assert(transport.ops->open(transport.context) == PBNS_OK);
  state.eof_on_receive = true;
  uint8_t byte = 0U;
  size_t count = 1U;
  assert(transport.ops->receive(transport.context, (pbns_buffer){&byte, 0U, 1U},
                                TEST_TIMEOUT_MS, &count) == PBNS_ERR_TRANSPORT);
  assert(count == 0U);
  destroy_transport(&state, owner);

  transport =
      create_transport(&state, certificate_path, key_path, name, pin, &owner);
  state.eof_on_receive = true;
  assert(transport.ops->open(transport.context) == PBNS_ERR_TRANSPORT);
  destroy_transport(&state, owner);

  transport =
      create_transport(&state, certificate_path, key_path, name, pin, &owner);
  state.eof_after_receive = 1U;
  assert(transport.ops->open(transport.context) == PBNS_ERR_TRANSPORT);
  destroy_transport(&state, owner);

  transport =
      create_transport(&state, certificate_path, key_path, name, pin, &owner);
  assert(transport.ops->open(transport.context) == PBNS_OK);
  state.force_receive_would_block = true;
  count = 0U;
  assert(transport.ops->receive(transport.context, (pbns_buffer){&byte, 0U, 1U},
                                TEST_TIMEOUT_MS, &count) == PBNS_ERR_TRANSPORT);
  destroy_transport(&state, owner);

  transport =
      create_transport(&state, certificate_path, key_path, name, pin, &owner);
  assert(transport.ops->open(transport.context) == PBNS_OK);
  static const uint8_t timeout_message[] = "deadline-after-progress";
  state.server_send = timeout_message;
  state.server_send_length = sizeof(timeout_message) - 1U;
  state.advance_clock_on_receive = TEST_TIMEOUT_MS;
  count = 0U;
  assert(transport.ops->receive(transport.context, (pbns_buffer){&byte, 0U, 1U},
                                TEST_TIMEOUT_MS, &count) == PBNS_ERR_TIMEOUT);
  assert(count == 0U);
  destroy_transport(&state, owner);
}

int main(int argc, char **argv) {
  assert(argc == 3);
  test_handshake_streaming_and_reconnect(argv[1], argv[2]);
  test_authentication_failures(argv[1], argv[2]);
  test_lifecycle_and_clock_failures(argv[1], argv[2]);
  test_broker_over_tls_composition(argv[1], argv[2]);
  test_lower_fatal_failures(argv[1], argv[2]);
  test_fail_closed_conditions(argv[1], argv[2]);
  return 0;
}
