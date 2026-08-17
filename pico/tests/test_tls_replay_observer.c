#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "mbedtls/ssl.h"
#include "pbns/status.h"
#include "pbns_proxy/tls_client.h"
#include "pbns_tls_replay/observer.h"

_Static_assert(PBNS_TLS_REPLAY_MILESTONE_COUNT == 13,
               "unexpected TLS replay milestone count");

static void observe_through(pbns_tls_replay_milestone last) {
  for (unsigned value = 0U; value <= (unsigned)last; ++value) {
    assert(pbns_tls_replay_observe_milestone((pbns_tls_replay_milestone)value));
  }
}

static void test_ready_requires_exact_order(void) {
  pbns_tls_replay_observer_reset();
  observe_through(PBNS_TLS_REPLAY_PROFILE_VALIDATED);
  assert(pbns_tls_replay_observe_terminal(PBNS_TLS_REPLAY_READY));
  const pbns_tls_replay_snapshot snapshot = pbns_tls_replay_observer_snapshot();
  assert(pbns_tls_replay_snapshot_is_valid(&snapshot));
  assert(snapshot.terminal_set);
  assert(snapshot.terminal == PBNS_TLS_REPLAY_READY);
  assert(strcmp(pbns_tls_replay_terminal_name(snapshot.terminal), "ready") ==
         0);
}

static void test_milestones_reject_gaps_and_allow_observed_io(void) {
  pbns_tls_replay_observer_reset();
  assert(!pbns_tls_replay_observe_milestone(
      PBNS_TLS_REPLAY_PIN_VERIFIER_INITIALIZED));
  observe_through(PBNS_TLS_REPLAY_ENCRYPTED_BIO_INSTALLED);
  assert(pbns_tls_replay_observe_milestone(
      PBNS_TLS_REPLAY_FIRST_CLIENT_BYTES_WRITTEN));
  assert(pbns_tls_replay_observe_milestone(
      PBNS_TLS_REPLAY_FIRST_CLIENT_BYTES_WRITTEN));
  assert(pbns_tls_replay_observe_milestone(
      PBNS_TLS_REPLAY_FIRST_SERVER_BYTES_RECEIVED));
  assert(pbns_tls_replay_observe_milestone(
      PBNS_TLS_REPLAY_FIRST_SERVER_BYTES_RECEIVED));
  assert(!pbns_tls_replay_observe_milestone(PBNS_TLS_REPLAY_LEAF_SPKI_MATCHED));
}

static void test_terminal_is_first_writer_wins(void) {
  pbns_tls_replay_observer_reset();
  observe_through(PBNS_TLS_REPLAY_PIN_VERIFIER_INITIALIZED);
  assert(pbns_tls_replay_observe_terminal(PBNS_TLS_REPLAY_INIT_ENTROPY));
  assert(!pbns_tls_replay_observe_terminal(PBNS_TLS_REPLAY_UNKNOWN));
  const pbns_tls_replay_snapshot snapshot = pbns_tls_replay_observer_snapshot();
  assert(snapshot.terminal == PBNS_TLS_REPLAY_INIT_ENTROPY);
  assert(pbns_tls_replay_snapshot_is_valid(&snapshot));
}

static void test_handshake_error_mapping(void) {
  static const int peer_or_protocol[] = {
      MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION,
      MBEDTLS_ERR_SSL_NO_APPLICATION_PROTOCOL,
      MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE,
      MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE,
      MBEDTLS_ERR_SSL_UNRECOGNIZED_NAME,
      MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY,
      MBEDTLS_ERR_SSL_BAD_CERTIFICATE,
      MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION,
      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE,
      MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH,
      MBEDTLS_ERR_SSL_UNEXPECTED_RECORD,
  };

  pbns_tls_replay_observer_reset();
  pbns_tls_replay_observe_handshake_error(MBEDTLS_ERR_SSL_ALLOC_FAILED,
                                          PBNS_OK);
  assert(pbns_tls_replay_observer_snapshot().terminal ==
         PBNS_TLS_REPLAY_HANDSHAKE_ALLOCATOR);

  pbns_tls_replay_observer_reset();
  pbns_tls_replay_observe_handshake_error(MBEDTLS_ERR_SSL_ALLOC_FAILED,
                                          PBNS_ERR_TRANSPORT);
  assert(pbns_tls_replay_observer_snapshot().terminal ==
         PBNS_TLS_REPLAY_HANDSHAKE_ENCRYPTED_IO);

  for (size_t index = 0U;
       index < sizeof(peer_or_protocol) / sizeof(peer_or_protocol[0]);
       ++index) {
    pbns_tls_replay_observer_reset();
    pbns_tls_replay_observe_handshake_error(peer_or_protocol[index], PBNS_OK);
    assert(pbns_tls_replay_observer_snapshot().terminal ==
           PBNS_TLS_REPLAY_HANDSHAKE_PEER_OR_PROTOCOL);
  }

  pbns_tls_replay_observer_reset();
  pbns_tls_replay_observe_handshake_error(-12345, PBNS_OK);
  assert(pbns_tls_replay_observer_snapshot().terminal ==
         PBNS_TLS_REPLAY_UNKNOWN);
}

static void test_selected_profile_classification(void) {
  pbns_tls_replay_observer_reset();
  observe_through(PBNS_TLS_REPLAY_HANDSHAKE_COMPLETED);
  pbns_tls_replay_observe_selected_profile(
      PBNS_TLS_VERSION_1_2, PBNS_TLS_ECDHE_ECDSA_AES128_GCM_SHA256);
  assert(!pbns_tls_replay_observer_snapshot().terminal_set);

  pbns_tls_replay_observer_reset();
  observe_through(PBNS_TLS_REPLAY_HANDSHAKE_COMPLETED);
  pbns_tls_replay_observe_selected_profile(UINT16_C(0x0302), UINT16_C(0xc02f));
  pbns_tls_replay_snapshot snapshot = pbns_tls_replay_observer_snapshot();
  assert(snapshot.terminal == PBNS_TLS_REPLAY_PROFILE_VERSION_UNSUPPORTED);
  assert(pbns_tls_replay_snapshot_is_valid(&snapshot));

  pbns_tls_replay_observer_reset();
  observe_through(PBNS_TLS_REPLAY_HANDSHAKE_COMPLETED);
  pbns_tls_replay_observe_selected_profile(PBNS_TLS_VERSION_1_2,
                                           UINT16_C(0xc02f));
  snapshot = pbns_tls_replay_observer_snapshot();
  assert(snapshot.terminal == PBNS_TLS_REPLAY_PROFILE_CIPHER_UNSUPPORTED);
  assert(pbns_tls_replay_snapshot_is_valid(&snapshot));

  static const int invalid_ciphers[] = {-1, (int)UINT16_MAX + 1};
  for (size_t index = 0U;
       index < sizeof(invalid_ciphers) / sizeof(invalid_ciphers[0]); ++index) {
    pbns_tls_replay_observer_reset();
    observe_through(PBNS_TLS_REPLAY_HANDSHAKE_COMPLETED);
    pbns_tls_replay_observe_selected_profile(PBNS_TLS_VERSION_1_2,
                                             invalid_ciphers[index]);
    assert(pbns_tls_replay_observer_snapshot().terminal ==
           PBNS_TLS_REPLAY_PROFILE_CIPHER_UNSUPPORTED);
  }

  pbns_tls_replay_observer_reset();
  observe_through(PBNS_TLS_REPLAY_CERTIFICATE_VERIFIER_ENTERED);
  assert(pbns_tls_replay_observe_terminal(PBNS_TLS_REPLAY_HANDSHAKE_PIN));
  pbns_tls_replay_observe_selected_profile(UINT16_C(0x0302), UINT16_C(0xc02f));
  assert(pbns_tls_replay_observer_snapshot().terminal ==
         PBNS_TLS_REPLAY_HANDSHAKE_PIN);
}

static void test_selected_alpn_classification(void) {
  pbns_tls_replay_observer_reset();
  observe_through(PBNS_TLS_REPLAY_HANDSHAKE_COMPLETED);
  pbns_tls_replay_observe_selected_alpn(true);
  assert(!pbns_tls_replay_observer_snapshot().terminal_set);

  pbns_tls_replay_observer_reset();
  observe_through(PBNS_TLS_REPLAY_HANDSHAKE_COMPLETED);
  pbns_tls_replay_observe_selected_alpn(false);
  pbns_tls_replay_snapshot snapshot = pbns_tls_replay_observer_snapshot();
  assert(snapshot.terminal == PBNS_TLS_REPLAY_PROFILE_ALPN_UNSUPPORTED);
  assert(pbns_tls_replay_snapshot_is_valid(&snapshot));

  pbns_tls_replay_observer_reset();
  observe_through(PBNS_TLS_REPLAY_HANDSHAKE_COMPLETED);
  pbns_tls_replay_observe_selected_profile(UINT16_C(0x0302), UINT16_C(0xc02f));
  pbns_tls_replay_observe_selected_alpn(false);
  assert(pbns_tls_replay_observer_snapshot().terminal ==
         PBNS_TLS_REPLAY_PROFILE_VERSION_UNSUPPORTED);

  pbns_tls_replay_observer_reset();
  pbns_tls_replay_observe_selected_alpn(false);
  snapshot = pbns_tls_replay_observer_snapshot();
  assert(!pbns_tls_replay_snapshot_is_valid(&snapshot));
}

static pbns_tls_replay_snapshot
observe_selected_version(bool handshake_over, bool version_is_unknown,
                         bool version_is_tls12, bool version_is_tls13,
                         bool pbns_conversion_matches) {
  pbns_tls_replay_observer_reset();
  observe_through(PBNS_TLS_REPLAY_HANDSHAKE_COMPLETED);
  pbns_tls_replay_observe_selected_version(handshake_over, version_is_unknown,
                                           version_is_tls12, version_is_tls13,
                                           pbns_conversion_matches);
  return pbns_tls_replay_observer_snapshot();
}

static void test_selected_version_classification(void) {
  pbns_tls_replay_snapshot snapshot =
      observe_selected_version(true, false, true, false, true);
  assert(!snapshot.terminal_set);

  snapshot = observe_selected_version(false, false, true, false, true);
  assert(snapshot.terminal ==
         PBNS_TLS_REPLAY_PROFILE_VERSION_HANDSHAKE_INCOMPLETE);
  assert(pbns_tls_replay_snapshot_is_valid(&snapshot));

  snapshot = observe_selected_version(true, true, false, false, false);
  assert(snapshot.terminal == PBNS_TLS_REPLAY_PROFILE_VERSION_UNKNOWN);
  assert(pbns_tls_replay_snapshot_is_valid(&snapshot));

  snapshot = observe_selected_version(true, false, false, true, false);
  assert(snapshot.terminal == PBNS_TLS_REPLAY_PROFILE_VERSION_TLS13);
  assert(pbns_tls_replay_snapshot_is_valid(&snapshot));

  snapshot = observe_selected_version(true, false, true, false, false);
  assert(snapshot.terminal ==
         PBNS_TLS_REPLAY_PROFILE_VERSION_CONVERSION_INCONSISTENT);
  assert(pbns_tls_replay_snapshot_is_valid(&snapshot));

  snapshot = observe_selected_version(true, false, false, false, false);
  assert(snapshot.terminal == PBNS_TLS_REPLAY_PROFILE_VERSION_OTHER);
  assert(pbns_tls_replay_snapshot_is_valid(&snapshot));

  static const bool otherwise_valid[][4] = {
      {true, false, false, false},
      {false, true, false, true},
      {false, false, true, false},
      {false, false, false, false},
  };
  for (size_t index = 0U;
       index < sizeof(otherwise_valid) / sizeof(otherwise_valid[0]); ++index) {
    snapshot = observe_selected_version(
        false, otherwise_valid[index][0], otherwise_valid[index][1],
        otherwise_valid[index][2], otherwise_valid[index][3]);
    assert(snapshot.terminal ==
           PBNS_TLS_REPLAY_PROFILE_VERSION_HANDSHAKE_INCOMPLETE);
  }

  snapshot = observe_selected_version(true, true, true, false, true);
  assert(!snapshot.terminal_set);
  snapshot = observe_selected_version(true, false, false, false, true);
  assert(!snapshot.terminal_set);

  pbns_tls_replay_observer_reset();
  observe_through(PBNS_TLS_REPLAY_CERTIFICATE_VERIFIER_ENTERED);
  assert(pbns_tls_replay_observe_terminal(PBNS_TLS_REPLAY_HANDSHAKE_PIN));
  pbns_tls_replay_observe_selected_version(true, true, false, false, false);
  assert(pbns_tls_replay_observer_snapshot().terminal ==
         PBNS_TLS_REPLAY_HANDSHAKE_PIN);

  pbns_tls_replay_observer_reset();
  pbns_tls_replay_observe_selected_version(true, true, false, false, false);
  snapshot = pbns_tls_replay_observer_snapshot();
  assert(!pbns_tls_replay_snapshot_is_valid(&snapshot));
}

static void test_heap_limit_is_bounded(void) {
  pbns_tls_replay_observer_reset();
  assert(pbns_tls_replay_heap_bytes(65536U) == 65536U);
  assert(pbns_tls_replay_observer_set_heap_bytes(4096U));
  assert(pbns_tls_replay_heap_bytes(65536U) == 4096U);
  assert(!pbns_tls_replay_observer_set_heap_bytes(0U));
  assert(!pbns_tls_replay_observer_set_heap_bytes(65537U));
  assert(pbns_tls_replay_heap_bytes(65536U) == 4096U);
  assert(pbns_tls_replay_heap_bytes(1024U) == 0U);
}

static void test_terminal_names_are_exact(void) {
  static const char *const expected[] = {
      "none",
      "ready",
      "init-entropy",
      "init-resource",
      "init-contract",
      "handshake-encrypted-io",
      "handshake-allocator",
      "handshake-certificate-flags",
      "handshake-pin",
      "handshake-peer-or-protocol",
      "profile-version-handshake-incomplete",
      "profile-version-unknown",
      "profile-version-tls13",
      "profile-version-conversion-inconsistent",
      "profile-version-other",
      "profile-version-unsupported",
      "profile-cipher-unsupported",
      "profile-alpn-unsupported",
      "profile-unsupported",
      "unknown",
  };
  for (size_t index = 0U; index < sizeof(expected) / sizeof(expected[0]);
       ++index) {
    assert(
        strcmp(pbns_tls_replay_terminal_name((pbns_tls_replay_terminal)index),
               expected[index]) == 0);
  }
  assert(strcmp(pbns_tls_replay_terminal_name((pbns_tls_replay_terminal)99),
                "invalid") == 0);
}

int main(void) {
  test_ready_requires_exact_order();
  test_milestones_reject_gaps_and_allow_observed_io();
  test_terminal_is_first_writer_wins();
  test_handshake_error_mapping();
  test_selected_profile_classification();
  test_selected_alpn_classification();
  test_selected_version_classification();
  test_heap_limit_is_bounded();
  test_terminal_names_are_exact();
  return 0;
}
