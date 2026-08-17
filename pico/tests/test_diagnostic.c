#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns_proxy/diagnostic.h"
#include "pbns_proxy/diagnostic_storage.h"

_Static_assert(PBNS_DIAGNOSTIC_AWAITING_DTR == UINT16_C(0x9100),
               "unexpected awaiting-DTR result");
_Static_assert(PBNS_DIAGNOSTIC_CREDENTIAL_FAILURE == UINT16_C(0x9110),
               "unexpected credential result");
_Static_assert(PBNS_DIAGNOSTIC_NETWORK_INIT_FAILURE == UINT16_C(0x9120),
               "unexpected network-init result");
_Static_assert(PBNS_DIAGNOSTIC_DTR_TIMEOUT == UINT16_C(0x9130),
               "unexpected DTR-timeout result");
_Static_assert(PBNS_DIAGNOSTIC_WIFI_START_FAILURE == UINT16_C(0x9140),
               "unexpected WiFi-start result");
_Static_assert(PBNS_DIAGNOSTIC_WIFI_AUTH_FAILURE == UINT16_C(0x9141),
               "unexpected WiFi-auth result");
_Static_assert(PBNS_DIAGNOSTIC_WIFI_LINK_FAILURE == UINT16_C(0x9142),
               "unexpected WiFi-link result");
_Static_assert(PBNS_DIAGNOSTIC_WIFI_TIMEOUT == UINT16_C(0x9143),
               "unexpected WiFi-timeout result");
_Static_assert(PBNS_DIAGNOSTIC_TCP_FAILURE == UINT16_C(0x9150),
               "unexpected TCP-failure result");
_Static_assert(PBNS_DIAGNOSTIC_TCP_TIMEOUT == UINT16_C(0x9151),
               "unexpected TCP-timeout result");
_Static_assert(PBNS_DIAGNOSTIC_TLS_FAILURE == UINT16_C(0x9160),
               "unexpected TLS-failure result");
_Static_assert(PBNS_DIAGNOSTIC_TLS_TIMEOUT == UINT16_C(0x9161),
               "unexpected TLS-timeout result");
_Static_assert(PBNS_DIAGNOSTIC_TLS_READY == UINT16_C(0x9190),
               "unexpected TLS-ready result");
_Static_assert(PBNS_DIAGNOSTIC_WIFI_TIMEOUT_DOWN == UINT16_C(0x9170),
               "unexpected WiFi DOWN timeout result");
_Static_assert(PBNS_DIAGNOSTIC_WIFI_TIMEOUT_JOIN == UINT16_C(0x9171),
               "unexpected WiFi JOIN timeout result");
_Static_assert(PBNS_DIAGNOSTIC_WIFI_TIMEOUT_NOIP == UINT16_C(0x9172),
               "unexpected WiFi NOIP timeout result");
_Static_assert(PBNS_DIAGNOSTIC_WIFI_TIMEOUT_UNKNOWN == UINT16_C(0x9173),
               "unexpected WiFi unknown timeout result");
_Static_assert(PBNS_DIAGNOSTIC_INTERNAL_FAILURE == UINT16_C(0x9199),
               "unexpected internal result");

static void test_network_result_mapping(void) {
  assert(pbns_diagnostic_result_for_network(PBNS_NETWORK_DOWN,
                                            PBNS_ERR_TRANSPORT) ==
         PBNS_DIAGNOSTIC_WIFI_START_FAILURE);
  assert(pbns_diagnostic_result_for_network(PBNS_NETWORK_WIFI_CONNECTING,
                                            PBNS_ERR_AUTHENTICATION) ==
         PBNS_DIAGNOSTIC_WIFI_AUTH_FAILURE);
  assert(pbns_diagnostic_result_for_network(PBNS_NETWORK_WIFI_CONNECTING,
                                            PBNS_ERR_TIMEOUT) ==
         PBNS_DIAGNOSTIC_WIFI_TIMEOUT);
  assert(pbns_diagnostic_result_for_network(PBNS_NETWORK_WIFI_CONNECTING,
                                            PBNS_ERR_TRANSPORT) ==
         PBNS_DIAGNOSTIC_WIFI_LINK_FAILURE);
  assert(pbns_diagnostic_result_for_network(PBNS_NETWORK_TCP_CONNECTING,
                                            PBNS_ERR_TIMEOUT) ==
         PBNS_DIAGNOSTIC_TCP_TIMEOUT);
  assert(pbns_diagnostic_result_for_network(PBNS_NETWORK_TCP_CONNECTING,
                                            PBNS_ERR_TRANSPORT) ==
         PBNS_DIAGNOSTIC_TCP_FAILURE);
  assert(pbns_diagnostic_result_for_network(PBNS_NETWORK_SESSION_CONNECTING,
                                            PBNS_ERR_TIMEOUT) ==
         PBNS_DIAGNOSTIC_TLS_TIMEOUT);
  assert(pbns_diagnostic_result_for_network(PBNS_NETWORK_SESSION_CONNECTING,
                                            PBNS_ERR_AUTHENTICATION) ==
         PBNS_DIAGNOSTIC_TLS_FAILURE);
  assert(pbns_diagnostic_result_for_network(PBNS_NETWORK_READY, PBNS_OK) ==
         PBNS_DIAGNOSTIC_TLS_READY);
  assert(
      pbns_diagnostic_result_for_network(PBNS_NETWORK_DOWN, PBNS_ERR_ENTROPY) ==
      PBNS_DIAGNOSTIC_INTERNAL_FAILURE);
}

static void test_wifi_timeout_refinement(void) {
  static const pbns_diagnostic_wifi_pending observations[] = {
      PBNS_DIAGNOSTIC_WIFI_PENDING_UNKNOWN,
      PBNS_DIAGNOSTIC_WIFI_PENDING_DOWN,
      PBNS_DIAGNOSTIC_WIFI_PENDING_JOIN,
      PBNS_DIAGNOSTIC_WIFI_PENDING_NOIP,
  };
  static const pbns_diagnostic_result expected[] = {
      PBNS_DIAGNOSTIC_WIFI_TIMEOUT_UNKNOWN,
      PBNS_DIAGNOSTIC_WIFI_TIMEOUT_DOWN,
      PBNS_DIAGNOSTIC_WIFI_TIMEOUT_JOIN,
      PBNS_DIAGNOSTIC_WIFI_TIMEOUT_NOIP,
  };
  _Static_assert(sizeof(observations) / sizeof(observations[0]) ==
                     sizeof(expected) / sizeof(expected[0]),
                 "WiFi timeout test vectors differ");

  for (size_t index = 0U;
       index < sizeof(observations) / sizeof(observations[0]); ++index) {
    const pbns_diagnostic_result result =
        pbns_diagnostic_result_for_wifi_timeout(observations[index]);
    assert(result == expected[index]);
    assert(pbns_diagnostic_result_is_terminal(result));
    pbns_diagnostic_result decoded = PBNS_DIAGNOSTIC_AWAITING_DTR;
    const uint32_t code = (uint32_t)result;
    assert(pbns_diagnostic_scratch_decode(PBNS_DIAGNOSTIC_MAGIC, code, ~code,
                                          &decoded));
    assert(decoded == result);
  }
  assert(pbns_diagnostic_result_for_wifi_timeout(
             (pbns_diagnostic_wifi_pending)99) ==
         PBNS_DIAGNOSTIC_WIFI_TIMEOUT_UNKNOWN);
}

static void test_scratch_record_requires_magic_complement_and_terminal(void) {
  pbns_diagnostic_result result = PBNS_DIAGNOSTIC_AWAITING_DTR;
  const uint32_t code = PBNS_DIAGNOSTIC_WIFI_AUTH_FAILURE;
  assert(pbns_diagnostic_scratch_decode(PBNS_DIAGNOSTIC_MAGIC, code, ~code,
                                        &result));
  assert(result == PBNS_DIAGNOSTIC_WIFI_AUTH_FAILURE);
  assert(!pbns_diagnostic_scratch_decode(0U, code, ~code, &result));
  assert(!pbns_diagnostic_scratch_decode(PBNS_DIAGNOSTIC_MAGIC, code, code,
                                         &result));
  assert(!pbns_diagnostic_scratch_decode(
      PBNS_DIAGNOSTIC_MAGIC, PBNS_DIAGNOSTIC_AWAITING_DTR,
      ~(uint32_t)PBNS_DIAGNOSTIC_AWAITING_DTR, &result));
  assert(!pbns_diagnostic_scratch_decode(
      PBNS_DIAGNOSTIC_MAGIC, UINT32_C(0x9188), ~UINT32_C(0x9188), &result));
}

static void test_storage_is_bounded_and_read_only(void) {
  uint8_t flash[PBNS_CREDENTIALS_SECTOR_SIZE * 2U] = {0};
  for (size_t index = 0U; index < sizeof(flash); ++index) {
    flash[index] = (uint8_t)index;
  }
  pbns_diagnostic_storage diagnostic = {0};
  assert(pbns_diagnostic_storage_init(&diagnostic, flash, sizeof(flash)) ==
         PBNS_OK);
  uint8_t output[32] = {0};
  assert(diagnostic.credentials.ops->read(
             diagnostic.credentials.context, 16U,
             (pbns_buffer){output, 0U, sizeof(output)}) == PBNS_OK);
  assert(memcmp(output, flash + 16U, sizeof(output)) == 0);
  assert(diagnostic.credentials.ops->read(
             diagnostic.credentials.context, sizeof(flash) - 8U,
             (pbns_buffer){output, 0U, sizeof(output)}) == PBNS_ERR_ARGUMENT);
  assert(diagnostic.credentials.ops->erase(diagnostic.credentials.context, 0U,
                                           PBNS_CREDENTIALS_SECTOR_SIZE) ==
         PBNS_ERR_STATE);
  assert(diagnostic.credentials.ops->program(
             diagnostic.credentials.context, 0U,
             (pbns_view){output, sizeof(output)}) == PBNS_ERR_STATE);
  assert(diagnostic.credentials.slot_offsets[0] == 0U);
  assert(diagnostic.credentials.slot_offsets[1] ==
         PBNS_CREDENTIALS_SECTOR_SIZE);
}

int main(void) {
  test_network_result_mapping();
  test_wifi_timeout_refinement();
  test_scratch_record_requires_magic_complement_and_terminal();
  test_storage_is_bounded_and_read_only();
  return 0;
}
