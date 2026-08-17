#ifndef PBNS_TLS_REPLAY_OBSERVER_H
#define PBNS_TLS_REPLAY_OBSERVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/status.h"

typedef enum pbns_tls_replay_milestone {
  PBNS_TLS_REPLAY_ALLOCATOR_INSTALLED = 0,
  PBNS_TLS_REPLAY_PIN_VERIFIER_INITIALIZED,
  PBNS_TLS_REPLAY_DRBG_SEEDED,
  PBNS_TLS_REPLAY_TLS_DEFAULTS_CONFIGURED,
  PBNS_TLS_REPLAY_SSL_CONTEXT_CONFIGURED,
  PBNS_TLS_REPLAY_HOSTNAME_INSTALLED,
  PBNS_TLS_REPLAY_ENCRYPTED_BIO_INSTALLED,
  PBNS_TLS_REPLAY_FIRST_CLIENT_BYTES_WRITTEN,
  PBNS_TLS_REPLAY_FIRST_SERVER_BYTES_RECEIVED,
  PBNS_TLS_REPLAY_CERTIFICATE_VERIFIER_ENTERED,
  PBNS_TLS_REPLAY_LEAF_SPKI_MATCHED,
  PBNS_TLS_REPLAY_HANDSHAKE_COMPLETED,
  PBNS_TLS_REPLAY_PROFILE_VALIDATED,
  PBNS_TLS_REPLAY_MILESTONE_COUNT
} pbns_tls_replay_milestone;

typedef enum pbns_tls_replay_terminal {
  PBNS_TLS_REPLAY_NONE = 0,
  PBNS_TLS_REPLAY_READY,
  PBNS_TLS_REPLAY_INIT_ENTROPY,
  PBNS_TLS_REPLAY_INIT_RESOURCE,
  PBNS_TLS_REPLAY_INIT_CONTRACT,
  PBNS_TLS_REPLAY_HANDSHAKE_ENCRYPTED_IO,
  PBNS_TLS_REPLAY_HANDSHAKE_ALLOCATOR,
  PBNS_TLS_REPLAY_HANDSHAKE_CERTIFICATE_FLAGS,
  PBNS_TLS_REPLAY_HANDSHAKE_PIN,
  PBNS_TLS_REPLAY_HANDSHAKE_PEER_OR_PROTOCOL,
  PBNS_TLS_REPLAY_PROFILE_VERSION_HANDSHAKE_INCOMPLETE,
  PBNS_TLS_REPLAY_PROFILE_VERSION_UNKNOWN,
  PBNS_TLS_REPLAY_PROFILE_VERSION_TLS13,
  PBNS_TLS_REPLAY_PROFILE_VERSION_CONVERSION_INCONSISTENT,
  PBNS_TLS_REPLAY_PROFILE_VERSION_OTHER,
  PBNS_TLS_REPLAY_PROFILE_VERSION_UNSUPPORTED,
  PBNS_TLS_REPLAY_PROFILE_CIPHER_UNSUPPORTED,
  PBNS_TLS_REPLAY_PROFILE_ALPN_UNSUPPORTED,
  PBNS_TLS_REPLAY_PROFILE_UNSUPPORTED,
  PBNS_TLS_REPLAY_UNKNOWN
} pbns_tls_replay_terminal;

typedef struct pbns_tls_replay_snapshot {
  bool milestones[PBNS_TLS_REPLAY_MILESTONE_COUNT];
  pbns_tls_replay_terminal terminal;
  bool terminal_set;
} pbns_tls_replay_snapshot;

void pbns_tls_replay_observer_reset(void);
bool pbns_tls_replay_observer_set_heap_bytes(size_t bytes);
size_t pbns_tls_replay_heap_bytes(size_t backing_bytes);
bool pbns_tls_replay_observe_milestone(pbns_tls_replay_milestone milestone);
bool pbns_tls_replay_observe_terminal(pbns_tls_replay_terminal terminal);
void pbns_tls_replay_observe_handshake_error(int library_error,
                                             pbns_status endpoint_failure);
void pbns_tls_replay_observe_selected_version(bool handshake_over,
                                              bool version_is_unknown,
                                              bool version_is_tls12,
                                              bool version_is_tls13,
                                              bool pbns_conversion_matches);
void pbns_tls_replay_observe_selected_profile(uint16_t protocol_version,
                                              int cipher_suite);
void pbns_tls_replay_observe_selected_alpn(bool selected);
pbns_tls_replay_snapshot pbns_tls_replay_observer_snapshot(void);
bool pbns_tls_replay_snapshot_is_valid(
    const pbns_tls_replay_snapshot *snapshot);
const char *pbns_tls_replay_terminal_name(pbns_tls_replay_terminal terminal);

#endif
