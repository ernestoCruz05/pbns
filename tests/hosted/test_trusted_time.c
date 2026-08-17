#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/trusted_time.h"

static const uint8_t KEY_ID[] = "time-key-1";
static const uint8_t QUALITY[] = "test-synchronized";

static bool bytes_are_zero(const uint8_t *bytes, size_t length) {
  uint8_t aggregate = 0U;
  for (size_t index = 0U; index < length; ++index) {
    aggregate |= bytes[index];
  }
  return aggregate == 0U;
}

static pbns_trusted_time_assertion assertion(void) {
  pbns_trusted_time_assertion value = {
      .domain = {(const uint8_t *)"PBNS-TIME-v1", 12U},
      .version = 1U,
      .service = 1U,
      .unix_seconds = 10,
      .nanoseconds = 0U,
      .uncertainty_ns = 10U,
      .quality = {QUALITY, sizeof(QUALITY) - 1U},
      .key_id = {KEY_ID, sizeof(KEY_ID) - 1U},
      .max_age_ms = 1000U,
  };
  for (size_t index = 0U; index < sizeof(value.request_id); ++index) {
    value.request_id[index] = (uint8_t)index;
  }
  memset(value.host_fingerprint, 0x22, sizeof(value.host_fingerprint));
  memset(value.nonce, 0x33, sizeof(value.nonce));
  return value;
}

static void test_interval_formula(void) {
  pbns_trusted_time_assertion value = assertion();
  pbns_time_interval interval = {0};
  assert(pbns_time_interval_from_assertion(&value, UINT64_C(40), &interval) ==
         PBNS_OK);
  assert(interval.earliest_ns == INT64_C(9999999990));
  assert(interval.latest_ns == INT64_C(10000000050));
  assert(!pbns_time_interval_within(&interval, INT64_C(10000000000),
                                    INT64_C(11000000000)));
  assert(pbns_time_interval_within(&interval, INT64_C(9999999990),
                                   INT64_C(10000000050)));

  value.unix_seconds = 0;
  value.nanoseconds = 0U;
  value.uncertainty_ns = 0U;
  assert(pbns_time_interval_from_assertion(&value, 0U, &interval) == PBNS_OK);
  assert(interval.earliest_ns == 0 && interval.latest_ns == 0);
}

static void test_timeout_and_arithmetic_rejection(void) {
  pbns_trusted_time_assertion value = assertion();
  pbns_time_interval interval = {0};
  assert(pbns_trusted_time_accept_verified_assertion(
             &value, value.request_id, value.host_fingerprint, value.nonce,
             100U, 100U, NULL, &interval) == PBNS_OK);
  assert(pbns_trusted_time_accept_verified_assertion(
             &value, value.request_id, value.host_fingerprint, value.nonce,
             101U, 100U, NULL, &interval) == PBNS_ERR_TIMEOUT);
  value.max_age_ms = 0U;
  assert(pbns_trusted_time_accept_verified_assertion(
             &value, value.request_id, value.host_fingerprint, value.nonce, 0U,
             100U, NULL, &interval) == PBNS_ERR_FORMAT);

  value = assertion();
  value.unix_seconds = -1;
  assert(pbns_time_interval_from_assertion(&value, 0U, &interval) ==
         PBNS_ERR_FORMAT);
  value.unix_seconds = INT64_MAX;
  assert(pbns_time_interval_from_assertion(&value, 0U, &interval) ==
         PBNS_ERR_LIMIT);
  value = assertion();
  value.nanoseconds = UINT32_C(1000000000);
  assert(pbns_time_interval_from_assertion(&value, 0U, &interval) ==
         PBNS_ERR_FORMAT);
  value = assertion();
  value.uncertainty_ns = UINT64_MAX;
  assert(pbns_time_interval_from_assertion(&value, 0U, &interval) ==
         PBNS_ERR_LIMIT);
  assert(pbns_time_interval_from_assertion(&value, UINT64_MAX, &interval) ==
         PBNS_ERR_LIMIT);
}

static void test_context_and_replay_rejection(void) {
  pbns_trusted_time_assertion value = assertion();
  pbns_time_interval interval = {0};
  uint8_t request[16] = {0};
  uint8_t host[32] = {0};
  uint8_t nonce[32] = {0};
  memcpy(request, value.request_id, sizeof(request));
  memcpy(host, value.host_fingerprint, sizeof(host));
  memcpy(nonce, value.nonce, sizeof(nonce));
  assert(pbns_trusted_time_accept_verified_assertion(&value, request, host,
                                                     nonce, 1U, 100U, NULL,
                                                     &interval) == PBNS_OK);
  request[0] ^= 1U;
  assert(pbns_trusted_time_accept_verified_assertion(
             &value, request, host, nonce, 1U, 100U, NULL, &interval) ==
         PBNS_ERR_AUTHENTICATION);
  request[0] ^= 1U;
  host[0] ^= 1U;
  assert(pbns_trusted_time_accept_verified_assertion(
             &value, request, host, nonce, 1U, 100U, NULL, &interval) ==
         PBNS_ERR_AUTHENTICATION);
  host[0] ^= 1U;
  nonce[0] ^= 1U;
  assert(pbns_trusted_time_accept_verified_assertion(
             &value, request, host, nonce, 1U, 100U, NULL, &interval) ==
         PBNS_ERR_AUTHENTICATION);
  nonce[0] ^= 1U;

  value.domain = (pbns_view){(const uint8_t *)"OTHER", 5U};
  assert(pbns_trusted_time_accept_verified_assertion(
             &value, request, host, nonce, 1U, 100U, NULL, &interval) ==
         PBNS_ERR_AUTHENTICATION);
  value = assertion();
  const pbns_time_interval malformed = {
      .earliest_ns = 2,
      .latest_ns = 1,
  };
  assert(pbns_trusted_time_accept_verified_assertion(
             &value, request, host, nonce, 1U, 100U, &malformed, &interval) ==
         PBNS_ERR_ARGUMENT);
  const pbns_time_interval newer = {
      .earliest_ns = INT64_C(11000000000),
      .latest_ns = INT64_C(11000000100),
  };
  assert(pbns_trusted_time_accept_verified_assertion(
             &value, request, host, nonce, 1U, 100U, &newer, &interval) ==
         PBNS_ERR_REPLAY);
  const pbns_time_interval same_assertion_shorter_rtt = {
      .earliest_ns = INT64_C(9999999990),
      .latest_ns = INT64_C(10001000010),
  };
  assert(pbns_trusted_time_accept_verified_assertion(
             &value, request, host, nonce, 2U, 100U,
             &same_assertion_shorter_rtt, &interval) == PBNS_ERR_REPLAY);
}

static void test_invalid_validity_windows(void) {
  const pbns_time_interval interval = {
      .earliest_ns = INT64_C(100),
      .latest_ns = INT64_C(200),
  };
  assert(!pbns_time_interval_within(NULL, 0, 1000));
  assert(!pbns_time_interval_within(&interval, 201, 300));
  assert(!pbns_time_interval_within(&interval, 0, 199));
  assert(!pbns_time_interval_within(&interval, 300, 200));
  assert(pbns_time_interval_within(&interval, 100, 200));
}

static void test_request_and_assertion_canonical_codecs(void) {
  pbns_trusted_time_request request = {
      .max_age_ms = 1000U,
  };
  for (size_t index = 0U; index < sizeof(request.request_id); ++index) {
    request.request_id[index] = (uint8_t)(index + 1U);
  }
  memset(request.host_fingerprint, 0x22, sizeof(request.host_fingerprint));
  memset(request.nonce, 0x33, sizeof(request.nonce));
  uint8_t encoded_request[256] = {0};
  size_t request_length = 0U;
  assert(pbns_trusted_time_request_encode(
             &request,
             (pbns_buffer){encoded_request, 0U, sizeof(encoded_request)},
             &request_length) == PBNS_OK);
  assert(request_length > 0U && encoded_request[0] == 0xa7U);
  request.max_age_ms = 0U;
  assert(pbns_trusted_time_request_encode(
             &request,
             (pbns_buffer){encoded_request, 0U, sizeof(encoded_request)},
             &request_length) == PBNS_ERR_FORMAT);

  pbns_trusted_time_assertion value = assertion();
  uint8_t encoded[512] = {0};
  uint8_t scratch[512] = {0};
  size_t encoded_length = 0U;
  assert(pbns_trusted_time_assertion_encode(
             &value, (pbns_buffer){encoded, 0U, sizeof(encoded)},
             &encoded_length) == PBNS_OK);
  pbns_trusted_time_assertion decoded = {0};
  assert(pbns_trusted_time_decode_verified_assertion(
             (pbns_view){encoded, encoded_length},
             (pbns_view){KEY_ID, sizeof(KEY_ID) - 1U},
             (pbns_buffer){scratch, 0U, sizeof(scratch)}, &decoded) == PBNS_OK);
  assert(decoded.unix_seconds == value.unix_seconds);
  assert(decoded.nanoseconds == value.nanoseconds);
  assert(decoded.uncertainty_ns == value.uncertainty_ns);
  assert(decoded.max_age_ms == value.max_age_ms);
  assert(decoded.quality.len == sizeof(QUALITY) - 1U);

  static const uint8_t wrong_key[] = "other-key";
  assert(pbns_trusted_time_decode_verified_assertion(
             (pbns_view){encoded, encoded_length},
             (pbns_view){wrong_key, sizeof(wrong_key) - 1U},
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded) == PBNS_ERR_AUTHENTICATION);

  uint8_t noncanonical[513] = {0};
  noncanonical[0] = encoded[0];
  noncanonical[1] = 0x18U;
  noncanonical[2] = encoded[1];
  memcpy(noncanonical + 3U, encoded + 2U, encoded_length - 2U);
  assert(pbns_trusted_time_decode_verified_assertion(
             (pbns_view){noncanonical, encoded_length + 1U},
             (pbns_view){KEY_ID, sizeof(KEY_ID) - 1U},
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded) == PBNS_ERR_FORMAT);
}

typedef struct query_environment {
  uint8_t assertion_payload[PBNS_TIME_ENCODED_MAX_SIZE];
  size_t assertion_length;
  uint8_t expected_aad[160];
  size_t expected_aad_length;
  uint64_t clock_values[2];
  size_t clock_index;
  bool fail_verification;
} query_environment;

static pbns_status query_random(void *context, pbns_buffer output) {
  (void)context;
  if (output.ptr == NULL || output.len != 0U || output.cap != 48U) {
    return PBNS_ERR_ARGUMENT;
  }
  for (size_t index = 0U; index < 16U; ++index) {
    output.ptr[index] = (uint8_t)index;
  }
  memset(output.ptr + 16U, 0x33, 32U);
  return PBNS_OK;
}

static pbns_status query_sign(void *context, pbns_view payload, pbns_view aad,
                              pbns_buffer output, size_t *written) {
  (void)context;
  static const uint8_t expected_aad[] = PBNS_TIME_REQUEST_AAD;
  if (payload.ptr == NULL || payload.len == 0U ||
      aad.len != sizeof(expected_aad) - 1U ||
      memcmp(aad.ptr, expected_aad, aad.len) != 0 || output.ptr == NULL ||
      output.cap < 1U || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  output.ptr[0] = 0xa1U;
  *written = 1U;
  return PBNS_OK;
}

static pbns_status query_exchange(void *context, pbns_view request,
                                  pbns_buffer response, size_t *written) {
  (void)context;
  if (request.ptr == NULL || request.len != 1U || request.ptr[0] != 0xa1U ||
      response.ptr == NULL || response.cap < 1U || written == NULL) {
    return PBNS_ERR_TRANSPORT;
  }
  response.ptr[0] = 0xa2U;
  *written = 1U;
  return PBNS_OK;
}

static pbns_status query_verify(void *context, pbns_view message, pbns_view aad,
                                pbns_view *payload) {
  query_environment *environment = context;
  if (environment->fail_verification || message.ptr == NULL ||
      message.len != 1U || message.ptr[0] != 0xa2U ||
      aad.len != environment->expected_aad_length ||
      memcmp(aad.ptr, environment->expected_aad, aad.len) != 0 ||
      payload == NULL) {
    return PBNS_ERR_AUTHENTICATION;
  }
  *payload = (pbns_view){environment->assertion_payload,
                         environment->assertion_length};
  return PBNS_OK;
}

static pbns_status query_clock(void *context, uint64_t *milliseconds) {
  query_environment *environment = context;
  if (milliseconds == NULL || environment->clock_index >= 2U) {
    return PBNS_ERR_STATE;
  }
  *milliseconds = environment->clock_values[environment->clock_index];
  ++environment->clock_index;
  return PBNS_OK;
}

static void test_trusted_time_query_pipeline(void) {
  query_environment environment = {
      .clock_values = {100U, 140U},
  };
  pbns_trusted_time_assertion value = assertion();
  value.max_age_ms = 100U;
  assert(pbns_trusted_time_assertion_encode(
             &value,
             (pbns_buffer){environment.assertion_payload, 0U,
                           sizeof(environment.assertion_payload)},
             &environment.assertion_length) == PBNS_OK);
  assert(pbns_trusted_time_assertion_aad(
             value.request_id, value.host_fingerprint, value.nonce,
             value.key_id,
             (pbns_buffer){environment.expected_aad, 0U,
                           sizeof(environment.expected_aad)},
             &environment.expected_aad_length) == PBNS_OK);

  uint8_t request_payload[PBNS_TIME_ENCODED_MAX_SIZE] = {0};
  uint8_t signed_request[768] = {0};
  uint8_t signed_response[1024] = {0};
  uint8_t scratch[PBNS_TIME_ENCODED_MAX_SIZE] = {0};
  uint8_t aad[192] = {0};
  pbns_trusted_time_workspace workspace = {
      .request_payload = {request_payload, 0U, sizeof(request_payload)},
      .signed_request = {signed_request, 0U, sizeof(signed_request)},
      .signed_response = {signed_response, 0U, sizeof(signed_response)},
      .canonical_scratch = {scratch, 0U, sizeof(scratch)},
      .aad = {aad, 0U, sizeof(aad)},
  };
  pbns_trusted_time_client client = {
      .random_fill = query_random,
      .sign_request = query_sign,
      .exchange = query_exchange,
      .verify_assertion = query_verify,
      .monotonic_ms = query_clock,
      .random_context = &environment,
      .sign_context = &environment,
      .exchange_context = &environment,
      .verify_context = &environment,
      .clock_context = &environment,
      .time_key_id = {KEY_ID, sizeof(KEY_ID) - 1U},
      .maximum_round_trip_ms = 100U,
  };
  uint8_t host[PBNS_TIME_FINGERPRINT_SIZE] = {0};
  memset(host, 0x22, sizeof(host));
  pbns_time_interval interval = {0};
  const pbns_status query_status =
      pbns_trusted_time_query(&client, host, NULL, &workspace, &interval);
  assert(query_status == PBNS_OK);
  assert(interval.earliest_ns == INT64_C(9999999990));
  assert(interval.latest_ns == INT64_C(10040000010));
  assert(bytes_are_zero(request_payload, sizeof(request_payload)));
  assert(bytes_are_zero(signed_request, sizeof(signed_request)));
  assert(bytes_are_zero(signed_response, sizeof(signed_response)));
  assert(bytes_are_zero(scratch, sizeof(scratch)));
  assert(bytes_are_zero(aad, sizeof(aad)));

  const pbns_time_interval previous = interval;
  environment.clock_index = 0U;
  assert(pbns_trusted_time_query(&client, host, &previous, &workspace,
                                 &interval) == PBNS_ERR_REPLAY);
  environment.clock_index = 0U;
  environment.clock_values[1] = 201U;
  assert(pbns_trusted_time_query(&client, host, NULL, &workspace, &interval) ==
         PBNS_ERR_TIMEOUT);
  environment.clock_index = 0U;
  environment.clock_values[1] = 140U;
  environment.fail_verification = true;
  assert(pbns_trusted_time_query(&client, host, NULL, &workspace, &interval) ==
         PBNS_ERR_AUTHENTICATION);
}

static void test_assertion_external_aad(void) {
  const pbns_trusted_time_assertion value = assertion();
  uint8_t aad[160] = {0};
  size_t written = 0U;
  assert(pbns_trusted_time_assertion_aad(
             value.request_id, value.host_fingerprint, value.nonce,
             value.key_id, (pbns_buffer){aad, 0U, sizeof(aad)},
             &written) == PBNS_OK);
  static const uint8_t prefix[] = "PBNS-TIME-ASSERTION-v1";
  assert(written == sizeof(prefix) - 1U + sizeof(value.request_id) +
                        sizeof(value.host_fingerprint) + sizeof(value.nonce) +
                        value.key_id.len);
  assert(memcmp(aad, prefix, sizeof(prefix) - 1U) == 0);
  assert(memcmp(aad + written - value.key_id.len, value.key_id.ptr,
                value.key_id.len) == 0);
}

int main(void) {
  test_interval_formula();
  test_timeout_and_arithmetic_rejection();
  test_context_and_replay_rejection();
  test_invalid_validity_windows();
  test_request_and_assertion_canonical_codecs();
  test_assertion_external_aad();
  test_trusted_time_query_pipeline();
  return 0;
}
