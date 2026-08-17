#include "pbns_tls_replay/observer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mbedtls/ssl.h"
#include "pbns_proxy/tls_client.h"

#define PBNS_TLS_REPLAY_EXACT_HEAP_BYTES 65536U

static pbns_tls_replay_snapshot current_snapshot;
static size_t selected_heap_bytes = PBNS_TLS_REPLAY_EXACT_HEAP_BYTES;

void pbns_tls_replay_observer_reset(void) {
  current_snapshot = (pbns_tls_replay_snapshot){0};
  selected_heap_bytes = PBNS_TLS_REPLAY_EXACT_HEAP_BYTES;
}

bool pbns_tls_replay_observer_set_heap_bytes(size_t bytes) {
  if (bytes == 0U || bytes > PBNS_TLS_REPLAY_EXACT_HEAP_BYTES) {
    return false;
  }
  selected_heap_bytes = bytes;
  return true;
}

size_t pbns_tls_replay_heap_bytes(size_t backing_bytes) {
  return selected_heap_bytes <= backing_bytes ? selected_heap_bytes : 0U;
}

bool pbns_tls_replay_observe_milestone(pbns_tls_replay_milestone milestone) {
  if ((unsigned)milestone >= (unsigned)PBNS_TLS_REPLAY_MILESTONE_COUNT ||
      current_snapshot.terminal_set) {
    return false;
  }
  if (current_snapshot.milestones[milestone]) {
    return true;
  }
  for (unsigned value = 0U; value < (unsigned)milestone; ++value) {
    if (!current_snapshot.milestones[value]) {
      return false;
    }
  }
  current_snapshot.milestones[milestone] = true;
  return true;
}

bool pbns_tls_replay_observe_terminal(pbns_tls_replay_terminal terminal) {
  if (terminal <= PBNS_TLS_REPLAY_NONE || terminal > PBNS_TLS_REPLAY_UNKNOWN ||
      current_snapshot.terminal_set) {
    return false;
  }
  current_snapshot.terminal = terminal;
  current_snapshot.terminal_set = true;
  return true;
}

static bool is_peer_or_protocol_error(int error) {
  switch (error) {
  case MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION:
  case MBEDTLS_ERR_SSL_NO_APPLICATION_PROTOCOL:
  case MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE:
  case MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE:
  case MBEDTLS_ERR_SSL_UNRECOGNIZED_NAME:
  case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
  case MBEDTLS_ERR_SSL_BAD_CERTIFICATE:
  case MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION:
  case MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE:
  case MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH:
  case MBEDTLS_ERR_SSL_UNEXPECTED_RECORD:
    return true;
  default:
    return false;
  }
}

static pbns_tls_replay_terminal
classify_handshake_error(int library_error, pbns_status endpoint_failure) {
  if (endpoint_failure != PBNS_OK && endpoint_failure != PBNS_ERR_WOULD_BLOCK) {
    return PBNS_TLS_REPLAY_HANDSHAKE_ENCRYPTED_IO;
  }
  if (library_error == MBEDTLS_ERR_SSL_ALLOC_FAILED) {
    return PBNS_TLS_REPLAY_HANDSHAKE_ALLOCATOR;
  }
  if (is_peer_or_protocol_error(library_error)) {
    return PBNS_TLS_REPLAY_HANDSHAKE_PEER_OR_PROTOCOL;
  }
  return PBNS_TLS_REPLAY_UNKNOWN;
}

void pbns_tls_replay_observe_handshake_error(int library_error,
                                             pbns_status endpoint_failure) {
  (void)pbns_tls_replay_observe_terminal(
      classify_handshake_error(library_error, endpoint_failure));
}

void pbns_tls_replay_observe_selected_version(bool handshake_over,
                                              bool version_is_unknown,
                                              bool version_is_tls12,
                                              bool version_is_tls13,
                                              bool pbns_conversion_matches) {
  const unsigned symbolic_categories = (unsigned)version_is_unknown +
                                       (unsigned)version_is_tls12 +
                                       (unsigned)version_is_tls13;
  if (symbolic_categories > 1U ||
      (pbns_conversion_matches && !version_is_tls12)) {
    return;
  }
  if (!handshake_over) {
    (void)pbns_tls_replay_observe_terminal(
        PBNS_TLS_REPLAY_PROFILE_VERSION_HANDSHAKE_INCOMPLETE);
  } else if (version_is_unknown) {
    (void)pbns_tls_replay_observe_terminal(
        PBNS_TLS_REPLAY_PROFILE_VERSION_UNKNOWN);
  } else if (version_is_tls13) {
    (void)pbns_tls_replay_observe_terminal(
        PBNS_TLS_REPLAY_PROFILE_VERSION_TLS13);
  } else if (version_is_tls12 && !pbns_conversion_matches) {
    (void)pbns_tls_replay_observe_terminal(
        PBNS_TLS_REPLAY_PROFILE_VERSION_CONVERSION_INCONSISTENT);
  } else if (!version_is_tls12) {
    (void)pbns_tls_replay_observe_terminal(
        PBNS_TLS_REPLAY_PROFILE_VERSION_OTHER);
  }
}

void pbns_tls_replay_observe_selected_profile(uint16_t protocol_version,
                                              int cipher_suite) {
  if (protocol_version != PBNS_TLS_VERSION_1_2) {
    (void)pbns_tls_replay_observe_terminal(
        PBNS_TLS_REPLAY_PROFILE_VERSION_UNSUPPORTED);
    return;
  }
  if (cipher_suite < 0 || cipher_suite > UINT16_MAX ||
      (uint16_t)cipher_suite != PBNS_TLS_ECDHE_ECDSA_AES128_GCM_SHA256) {
    (void)pbns_tls_replay_observe_terminal(
        PBNS_TLS_REPLAY_PROFILE_CIPHER_UNSUPPORTED);
  }
}

void pbns_tls_replay_observe_selected_alpn(bool selected) {
  if (!selected) {
    (void)pbns_tls_replay_observe_terminal(
        PBNS_TLS_REPLAY_PROFILE_ALPN_UNSUPPORTED);
  }
}

pbns_tls_replay_snapshot pbns_tls_replay_observer_snapshot(void) {
  return current_snapshot;
}

static bool milestones_are_a_prefix(const pbns_tls_replay_snapshot *snapshot) {
  bool gap_seen = false;
  for (unsigned value = 0U; value < PBNS_TLS_REPLAY_MILESTONE_COUNT; ++value) {
    if (!snapshot->milestones[value]) {
      gap_seen = true;
    } else if (gap_seen) {
      return false;
    }
  }
  return true;
}

bool pbns_tls_replay_snapshot_is_valid(
    const pbns_tls_replay_snapshot *snapshot) {
  if (snapshot == NULL || !milestones_are_a_prefix(snapshot)) {
    return false;
  }
  if (!snapshot->terminal_set) {
    return snapshot->terminal == PBNS_TLS_REPLAY_NONE;
  }
  if (snapshot->terminal <= PBNS_TLS_REPLAY_NONE ||
      snapshot->terminal > PBNS_TLS_REPLAY_UNKNOWN) {
    return false;
  }
  switch (snapshot->terminal) {
  case PBNS_TLS_REPLAY_READY:
    return snapshot->milestones[PBNS_TLS_REPLAY_PROFILE_VALIDATED];
  case PBNS_TLS_REPLAY_INIT_ENTROPY:
    return snapshot->milestones[PBNS_TLS_REPLAY_PIN_VERIFIER_INITIALIZED] &&
           !snapshot->milestones[PBNS_TLS_REPLAY_DRBG_SEEDED];
  case PBNS_TLS_REPLAY_INIT_CONTRACT:
    return !snapshot->milestones[PBNS_TLS_REPLAY_ALLOCATOR_INSTALLED];
  case PBNS_TLS_REPLAY_PROFILE_VERSION_HANDSHAKE_INCOMPLETE:
  case PBNS_TLS_REPLAY_PROFILE_VERSION_UNKNOWN:
  case PBNS_TLS_REPLAY_PROFILE_VERSION_TLS13:
  case PBNS_TLS_REPLAY_PROFILE_VERSION_CONVERSION_INCONSISTENT:
  case PBNS_TLS_REPLAY_PROFILE_VERSION_OTHER:
  case PBNS_TLS_REPLAY_PROFILE_VERSION_UNSUPPORTED:
  case PBNS_TLS_REPLAY_PROFILE_CIPHER_UNSUPPORTED:
  case PBNS_TLS_REPLAY_PROFILE_ALPN_UNSUPPORTED:
  case PBNS_TLS_REPLAY_PROFILE_UNSUPPORTED:
    return snapshot->milestones[PBNS_TLS_REPLAY_HANDSHAKE_COMPLETED] &&
           !snapshot->milestones[PBNS_TLS_REPLAY_PROFILE_VALIDATED];
  case PBNS_TLS_REPLAY_HANDSHAKE_CERTIFICATE_FLAGS:
  case PBNS_TLS_REPLAY_HANDSHAKE_PIN:
    return snapshot->milestones[PBNS_TLS_REPLAY_CERTIFICATE_VERIFIER_ENTERED] &&
           !snapshot->milestones[PBNS_TLS_REPLAY_HANDSHAKE_COMPLETED];
  case PBNS_TLS_REPLAY_INIT_RESOURCE:
  case PBNS_TLS_REPLAY_HANDSHAKE_ENCRYPTED_IO:
  case PBNS_TLS_REPLAY_HANDSHAKE_ALLOCATOR:
  case PBNS_TLS_REPLAY_HANDSHAKE_PEER_OR_PROTOCOL:
  case PBNS_TLS_REPLAY_UNKNOWN:
    return true;
  case PBNS_TLS_REPLAY_NONE:
  default:
    return false;
  }
}

const char *pbns_tls_replay_terminal_name(pbns_tls_replay_terminal terminal) {
  static const char *const names[] = {
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
  if (terminal < PBNS_TLS_REPLAY_NONE || terminal > PBNS_TLS_REPLAY_UNKNOWN) {
    return "invalid";
  }
  return names[terminal];
}
