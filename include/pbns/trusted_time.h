#ifndef PBNS_TRUSTED_TIME_H
#define PBNS_TRUSTED_TIME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_TIME_DOMAIN "PBNS-TIME-v1"
#define PBNS_TIME_REQUEST_AAD "PBNS-TIME-REQUEST-v1"
#define PBNS_TIME_ASSERTION_AAD "PBNS-TIME-ASSERTION-v1"
#define PBNS_TIME_VERSION UINT64_C(1)
#define PBNS_TIME_SERVICE UINT64_C(1)
#define PBNS_TIME_REQUEST_ID_SIZE 16U
#define PBNS_TIME_FINGERPRINT_SIZE 32U
#define PBNS_TIME_NONCE_SIZE 32U
#define PBNS_TIME_QUALITY_MAX_SIZE 64U
#define PBNS_TIME_KEY_ID_MAX_SIZE 64U
#define PBNS_TIME_MAX_AGE_MS UINT32_C(60000)
#define PBNS_TIME_ENCODED_MAX_SIZE 512U
#define PBNS_TIME_SIGNED_MAX_SIZE 65536U
#define PBNS_TIME_AAD_MAX_SIZE 192U

typedef struct pbns_trusted_time_request {
  uint8_t request_id[PBNS_TIME_REQUEST_ID_SIZE];
  uint8_t host_fingerprint[PBNS_TIME_FINGERPRINT_SIZE];
  uint8_t nonce[PBNS_TIME_NONCE_SIZE];
  uint32_t max_age_ms;
} pbns_trusted_time_request;

typedef struct pbns_trusted_time_assertion {
  pbns_view domain;
  uint64_t version;
  uint64_t service;
  uint8_t request_id[PBNS_TIME_REQUEST_ID_SIZE];
  uint8_t host_fingerprint[PBNS_TIME_FINGERPRINT_SIZE];
  uint8_t nonce[PBNS_TIME_NONCE_SIZE];
  int64_t unix_seconds;
  uint32_t nanoseconds;
  uint64_t uncertainty_ns;
  pbns_view quality;
  pbns_view key_id;
  uint32_t max_age_ms;
} pbns_trusted_time_assertion;

typedef struct pbns_time_interval {
  int64_t earliest_ns;
  int64_t latest_ns;
} pbns_time_interval;

typedef pbns_status (*pbns_trusted_time_random_fn)(void *context,
                                                   pbns_buffer output);
typedef pbns_status (*pbns_trusted_time_sign_fn)(void *context,
                                                 pbns_view payload,
                                                 pbns_view external_aad,
                                                 pbns_buffer output,
                                                 size_t *written);
typedef pbns_status (*pbns_trusted_time_exchange_fn)(void *context,
                                                     pbns_view request,
                                                     pbns_buffer response,
                                                     size_t *written);
typedef pbns_status (*pbns_trusted_time_verify_fn)(void *context,
                                                   pbns_view message,
                                                   pbns_view external_aad,
                                                   pbns_view *verified_payload);
typedef pbns_status (*pbns_trusted_time_monotonic_fn)(void *context,
                                                      uint64_t *milliseconds);

typedef struct pbns_trusted_time_client {
  pbns_trusted_time_random_fn random_fill;
  pbns_trusted_time_sign_fn sign_request;
  pbns_trusted_time_exchange_fn exchange;
  pbns_trusted_time_verify_fn verify_assertion;
  pbns_trusted_time_monotonic_fn monotonic_ms;
  void *random_context;
  void *sign_context;
  void *exchange_context;
  void *verify_context;
  void *clock_context;
  pbns_view time_key_id;
  uint64_t maximum_round_trip_ms;
} pbns_trusted_time_client;

typedef struct pbns_trusted_time_workspace {
  pbns_buffer request_payload;
  pbns_buffer signed_request;
  pbns_buffer signed_response;
  pbns_buffer canonical_scratch;
  pbns_buffer aad;
} pbns_trusted_time_workspace;

pbns_status
pbns_trusted_time_request_encode(const pbns_trusted_time_request *request,
                                 pbns_buffer output, size_t *written);

pbns_status
pbns_trusted_time_assertion_encode(const pbns_trusted_time_assertion *assertion,
                                   pbns_buffer output, size_t *written);

/* As vistas devolvidas referenciam a carga verificada fornecida pelo chamador.
 */
pbns_status pbns_trusted_time_decode_verified_assertion(
    pbns_view verified_payload, pbns_view expected_key_id,
    pbns_buffer canonical_scratch, pbns_trusted_time_assertion *assertion);

pbns_status pbns_trusted_time_assertion_aad(
    const uint8_t request_id[PBNS_TIME_REQUEST_ID_SIZE],
    const uint8_t host_fingerprint[PBNS_TIME_FINGERPRINT_SIZE],
    const uint8_t nonce[PBNS_TIME_NONCE_SIZE], pbns_view key_id,
    pbns_buffer output, size_t *written);

pbns_status pbns_trusted_time_query(
    const pbns_trusted_time_client *client,
    const uint8_t host_fingerprint[PBNS_TIME_FINGERPRINT_SIZE],
    const pbns_time_interval *previous_interval,
    pbns_trusted_time_workspace *workspace, pbns_time_interval *interval);

pbns_status
pbns_time_interval_from_assertion(const pbns_trusted_time_assertion *assertion,
                                  uint64_t round_trip_ns,
                                  pbns_time_interval *interval);

bool pbns_time_interval_within(const pbns_time_interval *interval,
                               int64_t not_before_ns, int64_t not_after_ns);

/* A chamada exige uma asserção já verificada com a chave de função temporal. */
pbns_status pbns_trusted_time_accept_verified_assertion(
    const pbns_trusted_time_assertion *assertion,
    const uint8_t expected_request_id[PBNS_TIME_REQUEST_ID_SIZE],
    const uint8_t expected_host_fingerprint[PBNS_TIME_FINGERPRINT_SIZE],
    const uint8_t expected_nonce[PBNS_TIME_NONCE_SIZE], uint64_t round_trip_ms,
    uint64_t maximum_round_trip_ms, const pbns_time_interval *previous_interval,
    pbns_time_interval *interval);

#endif
