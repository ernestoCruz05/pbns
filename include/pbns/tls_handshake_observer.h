#ifndef PBNS_TLS_HANDSHAKE_OBSERVER_H
#define PBNS_TLS_HANDSHAKE_OBSERVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_TLS_OBSERVER_ACCEPTED_CERTIFICATE_COUNT 1U

/*
 * Este observador limita apenas a mensagem Certificate TLS 1.2 em claro
 * antes de a entregar ao Mbed TLS. O Mbed TLS mantém autoridade sobre os
 * registos TLS, o handshake, DER e a validação criptográfica.
 */
typedef struct pbns_tls_handshake_observer {
  uint8_t record_header[5];
  uint8_t handshake_header[4];
  uint8_t certificate_list_length[3];
  uint8_t certificate_entry_length[3];
  size_t record_header_used;
  size_t record_remaining;
  size_t handshake_header_used;
  size_t handshake_remaining;
  size_t certificate_list_length_used;
  size_t certificate_entry_length_used;
  size_t certificate_body_used;
  uint32_t handshake_length;
  uint32_t certificate_list_length_value;
  uint32_t certificate_entry_length_value;
  bool complete;
  bool failed;
  bool certificate_active;
} pbns_tls_handshake_observer;

void pbns_tls_handshake_observer_init(pbns_tls_handshake_observer *observer);
pbns_status
pbns_tls_handshake_observer_observe(pbns_tls_handshake_observer *observer,
                                    pbns_view encrypted_tls_bytes);
bool pbns_tls_handshake_observer_complete(
    const pbns_tls_handshake_observer *observer);

#endif
