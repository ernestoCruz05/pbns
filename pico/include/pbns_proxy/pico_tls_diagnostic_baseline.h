#ifndef PBNS_PROXY_PICO_TLS_DIAGNOSTIC_BASELINE_H
#define PBNS_PROXY_PICO_TLS_DIAGNOSTIC_BASELINE_H

#if !defined(PBNS_PICO_FIRMWARE)
#error pico_tls_diagnostic_baseline.h is firmware-only
#endif

#include <stdbool.h>
#include <stdint.h>

#include "lwip/ip_addr.h"
#include "pbns/status.h"
#include "pbns_proxy/byte_pump.h"
#include "pbns_proxy/credentials.h"
#include "pbns_proxy/network.h"
#include "pbns_proxy/tls_client.h"

#define PBNS_PICO_TLS_DIAGNOSTIC_MAX_CONTENT_LENGTH 16384U
#define PBNS_PICO_TLS_DIAGNOSTIC_MAX_ENCRYPTED_OVERHEAD 2048U
#define PBNS_PICO_TLS_DIAGNOSTIC_RX_CAPACITY                                   \
  (PBNS_PICO_TLS_DIAGNOSTIC_MAX_CONTENT_LENGTH +                               \
   PBNS_PICO_TLS_DIAGNOSTIC_MAX_ENCRYPTED_OVERHEAD)

typedef struct pbns_pico_tls_diagnostic_baseline {
  char ssid[PBNS_CREDENTIALS_SSID_MAX + 1U];
  char psk[PBNS_CREDENTIALS_PSK_MAX + 1U];
  char hostname[PBNS_CREDENTIALS_HOSTNAME_MAX + 1U];
  uint16_t port;
  uint8_t expected_spki[PBNS_TLS_SPKI_SHA256_SIZE];
  pbns_tls_client tls;
  pbns_byte_ring encrypted_rx;
  uint8_t encrypted_rx_storage[PBNS_PICO_TLS_DIAGNOSTIC_RX_CAPACITY];
  ip_addr_t resolved_address;
  void *connection;
  pbns_status asynchronous_status;
  bool initialized;
  bool cyw43_initialized;
  bool dns_started;
  bool dns_ready;
  bool tcp_started;
  bool tcp_connected;
  bool tls_initialized;
  bool remote_closed;
} pbns_pico_tls_diagnostic_baseline;

pbns_status pbns_pico_tls_diagnostic_baseline_init(
    pbns_pico_tls_diagnostic_baseline *baseline,
    const pbns_credentials *credentials);
void pbns_pico_tls_diagnostic_baseline_deinit(
    pbns_pico_tls_diagnostic_baseline *baseline);
pbns_network_ops pbns_pico_tls_diagnostic_baseline_operations(
    pbns_pico_tls_diagnostic_baseline *baseline);
pbns_pump_endpoint pbns_pico_tls_diagnostic_baseline_plaintext_endpoint(
    pbns_pico_tls_diagnostic_baseline *baseline);
void pbns_pico_tls_diagnostic_baseline_fail(
    pbns_pico_tls_diagnostic_baseline *baseline, pbns_status status);

#endif
