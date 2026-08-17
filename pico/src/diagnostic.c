#include "pbns_proxy/diagnostic.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool pbns_diagnostic_result_is_terminal(pbns_diagnostic_result result) {
  switch (result) {
  case PBNS_DIAGNOSTIC_CREDENTIAL_FAILURE:
  case PBNS_DIAGNOSTIC_NETWORK_INIT_FAILURE:
  case PBNS_DIAGNOSTIC_DTR_TIMEOUT:
  case PBNS_DIAGNOSTIC_WIFI_START_FAILURE:
  case PBNS_DIAGNOSTIC_WIFI_AUTH_FAILURE:
  case PBNS_DIAGNOSTIC_WIFI_LINK_FAILURE:
  case PBNS_DIAGNOSTIC_WIFI_TIMEOUT:
  case PBNS_DIAGNOSTIC_TCP_FAILURE:
  case PBNS_DIAGNOSTIC_TCP_TIMEOUT:
  case PBNS_DIAGNOSTIC_TLS_FAILURE:
  case PBNS_DIAGNOSTIC_TLS_TIMEOUT:
  case PBNS_DIAGNOSTIC_WIFI_TIMEOUT_DOWN:
  case PBNS_DIAGNOSTIC_WIFI_TIMEOUT_JOIN:
  case PBNS_DIAGNOSTIC_WIFI_TIMEOUT_NOIP:
  case PBNS_DIAGNOSTIC_WIFI_TIMEOUT_UNKNOWN:
  case PBNS_DIAGNOSTIC_TLS_READY:
  case PBNS_DIAGNOSTIC_INTERNAL_FAILURE:
    return true;
  case PBNS_DIAGNOSTIC_AWAITING_DTR:
  default:
    return false;
  }
}

pbns_diagnostic_result
pbns_diagnostic_result_for_wifi_timeout(pbns_diagnostic_wifi_pending pending) {
  switch (pending) {
  case PBNS_DIAGNOSTIC_WIFI_PENDING_DOWN:
    return PBNS_DIAGNOSTIC_WIFI_TIMEOUT_DOWN;
  case PBNS_DIAGNOSTIC_WIFI_PENDING_JOIN:
    return PBNS_DIAGNOSTIC_WIFI_TIMEOUT_JOIN;
  case PBNS_DIAGNOSTIC_WIFI_PENDING_NOIP:
    return PBNS_DIAGNOSTIC_WIFI_TIMEOUT_NOIP;
  case PBNS_DIAGNOSTIC_WIFI_PENDING_UNKNOWN:
  default:
    return PBNS_DIAGNOSTIC_WIFI_TIMEOUT_UNKNOWN;
  }
}

pbns_diagnostic_result
pbns_diagnostic_result_for_network(pbns_network_state stage,
                                   pbns_status status) {
  if (status == PBNS_ERR_ENTROPY || status == PBNS_OK ||
      status == PBNS_ERR_WOULD_BLOCK) {
    return stage == PBNS_NETWORK_READY && status == PBNS_OK
               ? PBNS_DIAGNOSTIC_TLS_READY
               : PBNS_DIAGNOSTIC_INTERNAL_FAILURE;
  }

  switch (stage) {
  case PBNS_NETWORK_DOWN:
    return PBNS_DIAGNOSTIC_WIFI_START_FAILURE;
  case PBNS_NETWORK_WIFI_CONNECTING:
    if (status == PBNS_ERR_AUTHENTICATION) {
      return PBNS_DIAGNOSTIC_WIFI_AUTH_FAILURE;
    }
    return status == PBNS_ERR_TIMEOUT ? PBNS_DIAGNOSTIC_WIFI_TIMEOUT
                                      : PBNS_DIAGNOSTIC_WIFI_LINK_FAILURE;
  case PBNS_NETWORK_TCP_CONNECTING:
    return status == PBNS_ERR_TIMEOUT ? PBNS_DIAGNOSTIC_TCP_TIMEOUT
                                      : PBNS_DIAGNOSTIC_TCP_FAILURE;
  case PBNS_NETWORK_SESSION_CONNECTING:
    return status == PBNS_ERR_TIMEOUT ? PBNS_DIAGNOSTIC_TLS_TIMEOUT
                                      : PBNS_DIAGNOSTIC_TLS_FAILURE;
  case PBNS_NETWORK_READY:
  case PBNS_NETWORK_BACKOFF:
  default:
    return PBNS_DIAGNOSTIC_INTERNAL_FAILURE;
  }
}

bool pbns_diagnostic_scratch_decode(uint32_t magic, uint32_t code,
                                    uint32_t complement,
                                    pbns_diagnostic_result *result) {
  if (result == NULL || magic != PBNS_DIAGNOSTIC_MAGIC || complement != ~code ||
      code > UINT16_MAX) {
    return false;
  }
  const pbns_diagnostic_result decoded = (pbns_diagnostic_result)code;
  if (!pbns_diagnostic_result_is_terminal(decoded)) {
    return false;
  }
  *result = decoded;
  return true;
}
