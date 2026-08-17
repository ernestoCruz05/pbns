#ifndef PBNS_PROXY_DIAGNOSTIC_H
#define PBNS_PROXY_DIAGNOSTIC_H

#include <stdbool.h>
#include <stdint.h>

#include "pbns/status.h"
#include "pbns_proxy/network.h"

#define PBNS_DIAGNOSTIC_MAGIC UINT32_C(0x50424431)

typedef enum pbns_diagnostic_result {
  PBNS_DIAGNOSTIC_AWAITING_DTR = 0x9100,
  PBNS_DIAGNOSTIC_CREDENTIAL_FAILURE = 0x9110,
  PBNS_DIAGNOSTIC_NETWORK_INIT_FAILURE = 0x9120,
  PBNS_DIAGNOSTIC_DTR_TIMEOUT = 0x9130,
  PBNS_DIAGNOSTIC_WIFI_START_FAILURE = 0x9140,
  PBNS_DIAGNOSTIC_WIFI_AUTH_FAILURE = 0x9141,
  PBNS_DIAGNOSTIC_WIFI_LINK_FAILURE = 0x9142,
  PBNS_DIAGNOSTIC_WIFI_TIMEOUT = 0x9143,
  PBNS_DIAGNOSTIC_TCP_FAILURE = 0x9150,
  PBNS_DIAGNOSTIC_TCP_TIMEOUT = 0x9151,
  PBNS_DIAGNOSTIC_TLS_FAILURE = 0x9160,
  PBNS_DIAGNOSTIC_TLS_TIMEOUT = 0x9161,
  PBNS_DIAGNOSTIC_WIFI_TIMEOUT_DOWN = 0x9170,
  PBNS_DIAGNOSTIC_WIFI_TIMEOUT_JOIN = 0x9171,
  PBNS_DIAGNOSTIC_WIFI_TIMEOUT_NOIP = 0x9172,
  PBNS_DIAGNOSTIC_WIFI_TIMEOUT_UNKNOWN = 0x9173,
  PBNS_DIAGNOSTIC_TLS_READY = 0x9190,
  PBNS_DIAGNOSTIC_INTERNAL_FAILURE = 0x9199
} pbns_diagnostic_result;

typedef enum pbns_diagnostic_wifi_pending {
  PBNS_DIAGNOSTIC_WIFI_PENDING_UNKNOWN = 0,
  PBNS_DIAGNOSTIC_WIFI_PENDING_DOWN,
  PBNS_DIAGNOSTIC_WIFI_PENDING_JOIN,
  PBNS_DIAGNOSTIC_WIFI_PENDING_NOIP
} pbns_diagnostic_wifi_pending;

bool pbns_diagnostic_result_is_terminal(pbns_diagnostic_result result);
pbns_diagnostic_result
pbns_diagnostic_result_for_wifi_timeout(pbns_diagnostic_wifi_pending pending);
pbns_diagnostic_result
pbns_diagnostic_result_for_network(pbns_network_state stage,
                                   pbns_status status);
bool pbns_diagnostic_scratch_decode(uint32_t magic, uint32_t code,
                                    uint32_t complement,
                                    pbns_diagnostic_result *result);

#endif
