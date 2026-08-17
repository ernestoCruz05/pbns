#ifndef PBNS_PROXY_NETWORK_H
#define PBNS_PROXY_NETWORK_H

#include <stdbool.h>
#include <stdint.h>

#include "pbns/status.h"

#define PBNS_NETWORK_WIFI_TIMEOUT_MS UINT64_C(30000)
#define PBNS_NETWORK_TCP_TIMEOUT_MS UINT64_C(10000)
#define PBNS_NETWORK_SESSION_TIMEOUT_MS UINT64_C(15000)

typedef enum pbns_network_state {
  PBNS_NETWORK_DOWN = 0,
  PBNS_NETWORK_WIFI_CONNECTING,
  PBNS_NETWORK_TCP_CONNECTING,
  PBNS_NETWORK_SESSION_CONNECTING,
  PBNS_NETWORK_READY,
  PBNS_NETWORK_BACKOFF
} pbns_network_state;

typedef pbns_status (*pbns_network_action_fn)(void *context);
typedef void (*pbns_network_close_fn)(void *context);
typedef pbns_status (*pbns_network_random_fn)(void *context, uint32_t *value);

typedef struct pbns_network_ops {
  pbns_network_action_fn wifi_start;
  pbns_network_action_fn wifi_poll;
  pbns_network_action_fn tcp_poll;
  pbns_network_action_fn session_poll;
  pbns_network_close_fn close;
  pbns_network_random_fn random_u32;
  void *context;
} pbns_network_ops;

typedef struct pbns_network {
  pbns_network_state state;
  uint32_t failure_count;
  uint64_t retry_deadline_ms;
  uint64_t state_entered_ms;
  pbns_status failure;
  bool initialized;
  bool connection_active;
} pbns_network;

void pbns_network_init(pbns_network *network);
pbns_status pbns_network_step(pbns_network *network,
                              const pbns_network_ops *ops, uint64_t now_ms,
                              bool usb_connected, bool *made_progress);

#if defined(PBNS_PICO_FIRMWARE)
#include "lwip/ip_addr.h"
#include "pbns_proxy/byte_pump.h"
#include "pbns_proxy/credentials.h"
#if defined(PBNS_RAW_TUNNEL_DIAGNOSTIC)
#include "pbns_proxy/raw_tunnel_diagnostic.h"
#endif

/* O anel mantém o limite medido da fase 6 como margem de controlo de fluxo. */
#define PBNS_PICO_TCP_RX_CAPACITY 18432U

typedef struct pbns_pico_network {
  char ssid[PBNS_CREDENTIALS_SSID_MAX + 1U];
  char psk[PBNS_CREDENTIALS_PSK_MAX + 1U];
  char hostname[PBNS_CREDENTIALS_HOSTNAME_MAX + 1U];
  uint16_t port;
  pbns_byte_ring tcp_rx;
  uint8_t tcp_rx_storage[PBNS_PICO_TCP_RX_CAPACITY];
  ip_addr_t resolved_address;
  void *connection;
#if defined(PBNS_RAW_TUNNEL_DIAGNOSTIC)
  pbns_raw_diagnostic_state *diagnostic;
#endif
  pbns_status asynchronous_status;
  bool initialized;
  bool cyw43_initialized;
  bool dns_started;
  bool dns_ready;
  bool tcp_started;
  bool tcp_connected;
  bool remote_closed;
} pbns_pico_network;

pbns_status pbns_pico_network_init(pbns_pico_network *network,
                                   const pbns_credentials *credentials);
void pbns_pico_network_deinit(pbns_pico_network *network);
pbns_network_ops pbns_pico_network_operations(pbns_pico_network *network);
pbns_pump_endpoint pbns_pico_network_tcp_endpoint(pbns_pico_network *network);
void pbns_pico_network_fail(pbns_pico_network *network, pbns_status status);
#if defined(PBNS_RAW_TUNNEL_DIAGNOSTIC)
pbns_status
pbns_pico_network_attach_diagnostic(pbns_pico_network *network,
                                    pbns_raw_diagnostic_state *diagnostic);
pbns_status pbns_pico_network_observe_diagnostic(
    pbns_pico_network *network, pbns_raw_diagnostic_observation observation);
#if defined(PBNS_PICO_NETWORK_TEST)
#include "lwip/err.h"
struct pbuf;
struct tcp_pcb;
err_t pbns_pico_network_test_receive(pbns_pico_network *network,
                                     struct tcp_pcb *pcb, struct pbuf *packet,
                                     err_t error);
#endif
#endif
#endif

#endif
