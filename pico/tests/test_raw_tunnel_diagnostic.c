#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/crc32c.h"
#include "pbns_proxy/raw_tunnel_diagnostic.h"

static const uint32_t stage_dtr = PBNS_RAW_MILESTONE_DTR;
static const uint32_t stage_credentials =
    PBNS_RAW_MILESTONE_DTR | PBNS_RAW_MILESTONE_CREDENTIALS;
static const uint32_t stage_network = PBNS_RAW_MILESTONE_DTR |
                                      PBNS_RAW_MILESTONE_CREDENTIALS |
                                      PBNS_RAW_MILESTONE_NETWORK_INITIALIZED;
static const uint32_t stage_wifi_started =
    PBNS_RAW_MILESTONE_DTR | PBNS_RAW_MILESTONE_CREDENTIALS |
    PBNS_RAW_MILESTONE_NETWORK_INITIALIZED | PBNS_RAW_MILESTONE_WIFI_STARTED;
static const uint32_t stage_wifi_ready =
    PBNS_RAW_MILESTONE_DTR | PBNS_RAW_MILESTONE_CREDENTIALS |
    PBNS_RAW_MILESTONE_NETWORK_INITIALIZED | PBNS_RAW_MILESTONE_WIFI_STARTED |
    PBNS_RAW_MILESTONE_WIFI_READY;
static const uint32_t stage_tcp_ready =
    PBNS_RAW_MILESTONE_DTR | PBNS_RAW_MILESTONE_CREDENTIALS |
    PBNS_RAW_MILESTONE_NETWORK_INITIALIZED | PBNS_RAW_MILESTONE_WIFI_STARTED |
    PBNS_RAW_MILESTONE_WIFI_READY | PBNS_RAW_MILESTONE_TCP_READY;
static const uint32_t all_milestones =
    PBNS_RAW_MILESTONE_DTR | PBNS_RAW_MILESTONE_CREDENTIALS |
    PBNS_RAW_MILESTONE_NETWORK_INITIALIZED | PBNS_RAW_MILESTONE_WIFI_STARTED |
    PBNS_RAW_MILESTONE_WIFI_READY | PBNS_RAW_MILESTONE_TCP_READY |
    PBNS_RAW_MILESTONE_CDC_RX | PBNS_RAW_MILESTONE_TCP_WRITE |
    PBNS_RAW_MILESTONE_TCP_OUTPUT | PBNS_RAW_MILESTONE_TCP_RX |
    PBNS_RAW_MILESTONE_CDC_TX_ENQUEUE | PBNS_RAW_MILESTONE_CDC_TX_FLUSH |
    PBNS_RAW_MILESTONE_CDC_TX_COMPLETE;

static void
refresh_scratch_crc(uint32_t words[PBNS_RAW_DIAGNOSTIC_SCRATCH_WORDS]) {
  uint8_t encoded[24] = {0};
  for (size_t index = 0U; index < 6U; ++index) {
    const uint32_t value = words[index + 1U];
    encoded[index * 4U] = (uint8_t)value;
    encoded[index * 4U + 1U] = (uint8_t)(value >> 8U);
    encoded[index * 4U + 2U] = (uint8_t)(value >> 16U);
    encoded[index * 4U + 3U] = (uint8_t)(value >> 24U);
  }
  words[7] = pbns_crc32c((pbns_view){encoded, sizeof(encoded)});
}

static pbns_raw_diagnostic_state stage_state(uint32_t milestones) {
  pbns_raw_diagnostic_state state = {0};
  pbns_raw_diagnostic_init(&state);
  state.milestones = milestones;
  return state;
}

static pbns_raw_diagnostic_state complete_state(void) {
  pbns_raw_diagnostic_state state = {0};
  pbns_raw_diagnostic_init(&state);
  state.milestones = all_milestones;
  state.cdc_rx_callbacks = 1U;
  state.tcp_rx_callbacks = 1U;
  state.cdc_tx_enqueues = 1U;
  state.cdc_tx_flushes = 1U;
  state.cdc_tx_completions = 1U;
  state.tcp_write_result = PBNS_TCP_IO_OK;
  state.tcp_output_result = PBNS_TCP_IO_OK;
  return state;
}

static void test_init_and_observers(void) {
  pbns_raw_diagnostic_state state = {
      .milestones = UINT32_MAX,
      .cdc_rx_callbacks = UINT16_MAX,
      .tcp_rx_callbacks = UINT16_MAX,
      .cdc_tx_enqueues = UINT16_MAX,
      .cdc_tx_flushes = UINT16_MAX,
      .cdc_tx_completions = UINT16_MAX,
      .tcp_write_result = PBNS_TCP_IO_FAILED,
      .tcp_output_result = PBNS_TCP_IO_FAILED,
  };
  pbns_raw_diagnostic_init(&state);
  assert(state.milestones == 0U);
  assert(state.tcp_write_result == PBNS_TCP_IO_NOT_RUN);
  assert(state.tcp_output_result == PBNS_TCP_IO_NOT_RUN);
  assert(pbns_raw_diagnostic_observe_milestone(
             &state, PBNS_RAW_MILESTONE_DTR) == PBNS_OK);
  assert(pbns_raw_diagnostic_observe_milestone(
             &state, (pbns_raw_diagnostic_milestone)0) == PBNS_ERR_ARGUMENT);
  assert(pbns_raw_diagnostic_observe_milestone(
             &state,
             (pbns_raw_diagnostic_milestone)(PBNS_RAW_MILESTONE_DTR |
                                             PBNS_RAW_MILESTONE_CREDENTIALS)) ==
         PBNS_ERR_ARGUMENT);

  state.cdc_rx_callbacks = UINT16_MAX;
  state.tcp_rx_callbacks = UINT16_MAX;
  state.cdc_tx_enqueues = UINT16_MAX;
  state.cdc_tx_flushes = UINT16_MAX;
  state.cdc_tx_completions = UINT16_MAX;
  assert(pbns_raw_diagnostic_observe_cdc_rx(&state) == PBNS_OK);
  assert(pbns_raw_diagnostic_observe_tcp_rx(&state) == PBNS_OK);
  assert(pbns_raw_diagnostic_observe_cdc_tx_enqueue(&state) == PBNS_OK);
  assert(pbns_raw_diagnostic_observe_cdc_tx_flush(&state) == PBNS_OK);
  assert(pbns_raw_diagnostic_observe_cdc_tx_complete(&state) == PBNS_OK);
  assert(state.cdc_rx_callbacks == UINT16_MAX);
  assert(state.tcp_rx_callbacks == UINT16_MAX);
  assert(state.cdc_tx_enqueues == UINT16_MAX);
  assert(state.cdc_tx_flushes == UINT16_MAX);
  assert(state.cdc_tx_completions == UINT16_MAX);
  assert((state.milestones & PBNS_RAW_MILESTONE_CDC_RX) != 0U);
  assert((state.milestones & PBNS_RAW_MILESTONE_TCP_RX) != 0U);
  assert((state.milestones & PBNS_RAW_MILESTONE_CDC_TX_ENQUEUE) != 0U);
  assert((state.milestones & PBNS_RAW_MILESTONE_CDC_TX_FLUSH) != 0U);
  assert((state.milestones & PBNS_RAW_MILESTONE_CDC_TX_COMPLETE) != 0U);

  assert(pbns_raw_diagnostic_observe_tcp_io(&state, PBNS_TCP_IO_OK,
                                            PBNS_TCP_IO_FAILED) == PBNS_OK);
  assert(state.tcp_write_result == PBNS_TCP_IO_OK);
  assert(state.tcp_output_result == PBNS_TCP_IO_FAILED);
  assert(pbns_raw_diagnostic_observe_tcp_io(
             &state, PBNS_TCP_IO_RETRY, PBNS_TCP_IO_OK) == PBNS_ERR_ARGUMENT);
  assert(pbns_raw_diagnostic_observe_tcp_io(
             NULL, PBNS_TCP_IO_OK, PBNS_TCP_IO_OK) == PBNS_ERR_ARGUMENT);
}

static void test_all_terminal_classifications(void) {
  pbns_raw_diagnostic_state state = stage_state(0U);
  assert(pbns_raw_diagnostic_classify(&state,
                                      PBNS_RAW_TRIGGER_APPLICATION_TIMEOUT) ==
         PBNS_RAW_RESULT_NO_CDC_CIPHERTEXT);
  state = stage_state(stage_dtr);
  assert(pbns_raw_diagnostic_classify(&state,
                                      PBNS_RAW_TRIGGER_CREDENTIAL_FAILURE) ==
         PBNS_RAW_RESULT_CREDENTIAL_FAILURE);
  state = stage_state(stage_credentials);
  assert(pbns_raw_diagnostic_classify(&state,
                                      PBNS_RAW_TRIGGER_NETWORK_INIT_FAILURE) ==
         PBNS_RAW_RESULT_NETWORK_INIT_FAILURE);
  state = stage_state(stage_network);
  assert(pbns_raw_diagnostic_classify(&state,
                                      PBNS_RAW_TRIGGER_WIFI_START_FAILURE) ==
         PBNS_RAW_RESULT_WIFI_START_FAILURE);
  state = stage_state(stage_wifi_started);
  assert(pbns_raw_diagnostic_classify(&state, PBNS_RAW_TRIGGER_WIFI_FAILURE) ==
         PBNS_RAW_RESULT_WIFI_FAILURE);
  assert(pbns_raw_diagnostic_classify(&state, PBNS_RAW_TRIGGER_WIFI_TIMEOUT) ==
         PBNS_RAW_RESULT_WIFI_TIMEOUT);
  state = stage_state(stage_wifi_ready);
  assert(pbns_raw_diagnostic_classify(&state, PBNS_RAW_TRIGGER_TCP_FAILURE) ==
         PBNS_RAW_RESULT_TCP_FAILURE);
  assert(pbns_raw_diagnostic_classify(&state, PBNS_RAW_TRIGGER_TCP_TIMEOUT) ==
         PBNS_RAW_RESULT_TCP_TIMEOUT);

  state = stage_state(stage_tcp_ready);
  assert(pbns_raw_diagnostic_observe_cdc_rx(&state) == PBNS_OK);
  assert(pbns_raw_diagnostic_classify(&state,
                                      PBNS_RAW_TRIGGER_APPLICATION_TIMEOUT) ==
         PBNS_RAW_RESULT_TCP_WRITE_FAILURE);
  assert(pbns_raw_diagnostic_observe_tcp_io(&state, PBNS_TCP_IO_FAILED,
                                            PBNS_TCP_IO_NOT_RUN) == PBNS_OK);
  assert(pbns_raw_diagnostic_classify(&state,
                                      PBNS_RAW_TRIGGER_TCP_WRITE_FAILURE) ==
         PBNS_RAW_RESULT_TCP_WRITE_FAILURE);
  assert(pbns_raw_diagnostic_classify(&state,
                                      PBNS_RAW_TRIGGER_APPLICATION_TIMEOUT) ==
         PBNS_RAW_RESULT_TCP_WRITE_FAILURE);

  state = stage_state(stage_tcp_ready);
  assert(pbns_raw_diagnostic_observe_cdc_rx(&state) == PBNS_OK);
  assert(pbns_raw_diagnostic_observe_tcp_io(&state, PBNS_TCP_IO_OK,
                                            PBNS_TCP_IO_FAILED) == PBNS_OK);
  assert(pbns_raw_diagnostic_classify(&state,
                                      PBNS_RAW_TRIGGER_TCP_OUTPUT_FAILURE) ==
         PBNS_RAW_RESULT_TCP_OUTPUT_FAILURE);
  assert(pbns_raw_diagnostic_classify(&state,
                                      PBNS_RAW_TRIGGER_APPLICATION_TIMEOUT) ==
         PBNS_RAW_RESULT_TCP_OUTPUT_FAILURE);

  state = stage_state(stage_tcp_ready);
  assert(pbns_raw_diagnostic_observe_cdc_rx(&state) == PBNS_OK);
  assert(pbns_raw_diagnostic_observe_tcp_io(&state, PBNS_TCP_IO_OK,
                                            PBNS_TCP_IO_OK) == PBNS_OK);
  assert(pbns_raw_diagnostic_classify(&state,
                                      PBNS_RAW_TRIGGER_APPLICATION_TIMEOUT) ==
         PBNS_RAW_RESULT_NO_TCP_RX);
  assert(pbns_raw_diagnostic_observe_tcp_rx(&state) == PBNS_OK);
  assert(pbns_raw_diagnostic_classify(&state,
                                      PBNS_RAW_TRIGGER_APPLICATION_TIMEOUT) ==
         PBNS_RAW_RESULT_TCP_RX_WITHOUT_CDC_TX);
  assert(pbns_raw_diagnostic_observe_cdc_tx_enqueue(&state) == PBNS_OK);
  assert(pbns_raw_diagnostic_classify(&state,
                                      PBNS_RAW_TRIGGER_APPLICATION_TIMEOUT) ==
         PBNS_RAW_RESULT_CDC_ENQUEUE_WITHOUT_FLUSH);
  assert(pbns_raw_diagnostic_observe_cdc_tx_flush(&state) == PBNS_OK);
  assert(pbns_raw_diagnostic_classify(&state,
                                      PBNS_RAW_TRIGGER_APPLICATION_TIMEOUT) ==
         PBNS_RAW_RESULT_CDC_FLUSH_WITHOUT_COMPLETE);
  assert(pbns_raw_diagnostic_observe_cdc_tx_complete(&state) == PBNS_OK);
  assert(pbns_raw_diagnostic_classify(&state,
                                      PBNS_RAW_TRIGGER_APPLICATION_TIMEOUT) ==
         PBNS_RAW_RESULT_APPLICATION_TIMEOUT);
  assert(pbns_raw_diagnostic_classify(&state, PBNS_RAW_TRIGGER_DTR_CLOSED) ==
         PBNS_RAW_RESULT_COMPLETE);
  assert(pbns_raw_diagnostic_classify(&state, PBNS_RAW_TRIGGER_COMPLETE) ==
         PBNS_RAW_RESULT_COMPLETE);
  assert(
      pbns_raw_diagnostic_classify(&state, PBNS_RAW_TRIGGER_INTERNAL_FAILURE) ==
      PBNS_RAW_RESULT_INTERNAL_FAILURE);

  state = stage_state(stage_tcp_ready);
  assert(pbns_raw_diagnostic_classify(&state, PBNS_RAW_TRIGGER_DTR_CLOSED) ==
         PBNS_RAW_RESULT_NO_CDC_CIPHERTEXT);
}

static void test_inconsistent_state_fails_internal(void) {
  pbns_raw_diagnostic_state state = complete_state();
  state.cdc_tx_flushes = 2U;
  assert(pbns_raw_diagnostic_classify(&state, PBNS_RAW_TRIGGER_COMPLETE) ==
         PBNS_RAW_RESULT_INTERNAL_FAILURE);
  state = complete_state();
  state.cdc_tx_completions = 2U;
  assert(pbns_raw_diagnostic_classify(&state, PBNS_RAW_TRIGGER_COMPLETE) ==
         PBNS_RAW_RESULT_INTERNAL_FAILURE);
  state = complete_state();
  state.milestones |= UINT32_C(1) << 31U;
  assert(pbns_raw_diagnostic_classify(&state,
                                      PBNS_RAW_TRIGGER_APPLICATION_TIMEOUT) ==
         PBNS_RAW_RESULT_INTERNAL_FAILURE);
  assert(pbns_raw_diagnostic_classify(NULL, PBNS_RAW_TRIGGER_COMPLETE) ==
         PBNS_RAW_RESULT_INTERNAL_FAILURE);
  state = stage_state(PBNS_RAW_MILESTONE_CREDENTIALS);
  assert(pbns_raw_diagnostic_classify(&state,
                                      PBNS_RAW_TRIGGER_NETWORK_INIT_FAILURE) ==
         PBNS_RAW_RESULT_INTERNAL_FAILURE);
}

static void test_scratch_round_trip_and_integrity(void) {
  const pbns_raw_diagnostic_state state = complete_state();
  uint32_t words[PBNS_RAW_DIAGNOSTIC_SCRATCH_WORDS] = {0};
  assert(pbns_raw_diagnostic_scratch_encode(&state, PBNS_RAW_RESULT_COMPLETE,
                                            words) == PBNS_OK);
  assert(words[0] == PBNS_RAW_DIAGNOSTIC_MAGIC);
  assert(words[1] == (uint32_t)PBNS_RAW_RESULT_COMPLETE);
  assert(words[2] == ~(uint32_t)PBNS_RAW_RESULT_COMPLETE);
  assert(words[3] == all_milestones);
  assert(words[4] == UINT32_C(0x00010001));
  assert(words[5] == UINT32_C(0x00010001));
  assert(words[6] == UINT32_C(0x00010101));

  pbns_raw_diagnostic_state decoded = {0};
  pbns_raw_diagnostic_result result = PBNS_RAW_RESULT_INTERNAL_FAILURE;
  assert(pbns_raw_diagnostic_scratch_decode(words, &decoded, &result) ==
         PBNS_OK);
  assert(decoded.milestones == state.milestones);
  assert(decoded.cdc_rx_callbacks == state.cdc_rx_callbacks);
  assert(decoded.tcp_rx_callbacks == state.tcp_rx_callbacks);
  assert(decoded.cdc_tx_enqueues == state.cdc_tx_enqueues);
  assert(decoded.cdc_tx_flushes == state.cdc_tx_flushes);
  assert(decoded.cdc_tx_completions == state.cdc_tx_completions);
  assert(decoded.tcp_write_result == state.tcp_write_result);
  assert(decoded.tcp_output_result == state.tcp_output_result);

  pbns_raw_diagnostic_state empty = {0};
  pbns_raw_diagnostic_init(&empty);
  uint32_t mismatch[PBNS_RAW_DIAGNOSTIC_SCRATCH_WORDS] = {0};
  const pbns_raw_diagnostic_result terminal_results[] = {
      PBNS_RAW_RESULT_CREDENTIAL_FAILURE,
      PBNS_RAW_RESULT_NETWORK_INIT_FAILURE,
      PBNS_RAW_RESULT_WIFI_START_FAILURE,
      PBNS_RAW_RESULT_WIFI_FAILURE,
      PBNS_RAW_RESULT_WIFI_TIMEOUT,
      PBNS_RAW_RESULT_TCP_FAILURE,
      PBNS_RAW_RESULT_TCP_TIMEOUT,
      PBNS_RAW_RESULT_NO_CDC_CIPHERTEXT,
      PBNS_RAW_RESULT_TCP_WRITE_FAILURE,
      PBNS_RAW_RESULT_TCP_OUTPUT_FAILURE,
      PBNS_RAW_RESULT_NO_TCP_RX,
      PBNS_RAW_RESULT_TCP_RX_WITHOUT_CDC_TX,
      PBNS_RAW_RESULT_CDC_ENQUEUE_WITHOUT_FLUSH,
      PBNS_RAW_RESULT_CDC_FLUSH_WITHOUT_COMPLETE,
      PBNS_RAW_RESULT_APPLICATION_TIMEOUT,
      PBNS_RAW_RESULT_COMPLETE,
  };
  for (size_t index = 0U;
       index < sizeof(terminal_results) / sizeof(terminal_results[0]);
       ++index) {
    const pbns_status empty_status = pbns_raw_diagnostic_scratch_encode(
        &empty, terminal_results[index], mismatch);
    assert(empty_status ==
           (terminal_results[index] == PBNS_RAW_RESULT_NO_CDC_CIPHERTEXT
                ? PBNS_OK
                : PBNS_ERR_ARGUMENT));
    if (terminal_results[index] != PBNS_RAW_RESULT_APPLICATION_TIMEOUT &&
        terminal_results[index] != PBNS_RAW_RESULT_COMPLETE) {
      assert(pbns_raw_diagnostic_scratch_encode(&state, terminal_results[index],
                                                mismatch) == PBNS_ERR_ARGUMENT);
    }
  }
  assert(pbns_raw_diagnostic_scratch_encode(
             &empty, PBNS_RAW_RESULT_INTERNAL_FAILURE, mismatch) == PBNS_OK);
  mismatch[1] = PBNS_RAW_RESULT_COMPLETE;
  mismatch[2] = ~mismatch[1];
  refresh_scratch_crc(mismatch);
  assert(pbns_raw_diagnostic_scratch_decode(mismatch, &decoded, &result) ==
         PBNS_ERR_FORMAT);

  uint32_t corrupt[PBNS_RAW_DIAGNOSTIC_SCRATCH_WORDS] = {0};
  memcpy(corrupt, words, sizeof(corrupt));
  corrupt[0] = 0U;
  assert(pbns_raw_diagnostic_scratch_decode(corrupt, &decoded, &result) ==
         PBNS_ERR_FORMAT);
  memcpy(corrupt, words, sizeof(corrupt));
  corrupt[2] ^= 1U;
  assert(pbns_raw_diagnostic_scratch_decode(corrupt, &decoded, &result) ==
         PBNS_ERR_FORMAT);
  memcpy(corrupt, words, sizeof(corrupt));
  corrupt[7] ^= 1U;
  assert(pbns_raw_diagnostic_scratch_decode(corrupt, &decoded, &result) ==
         PBNS_ERR_FORMAT);
  memcpy(corrupt, words, sizeof(corrupt));
  corrupt[1] = PBNS_RAW_DIAGNOSTIC_AWAITING_BCD;
  corrupt[2] = ~corrupt[1];
  refresh_scratch_crc(corrupt);
  assert(pbns_raw_diagnostic_scratch_decode(corrupt, &decoded, &result) ==
         PBNS_ERR_FORMAT);
  assert(!pbns_raw_diagnostic_result_is_terminal(
      (pbns_raw_diagnostic_result)PBNS_RAW_DIAGNOSTIC_AWAITING_BCD));
  assert(pbns_raw_diagnostic_scratch_encode(
             &state,
             (pbns_raw_diagnostic_result)PBNS_RAW_DIAGNOSTIC_AWAITING_BCD,
             corrupt) == PBNS_ERR_ARGUMENT);
  assert(pbns_raw_diagnostic_scratch_decode(NULL, &decoded, &result) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_raw_diagnostic_scratch_decode(words, NULL, &result) ==
         PBNS_ERR_ARGUMENT);
}

int main(void) {
  test_init_and_observers();
  test_all_terminal_classifications();
  test_inconsistent_state_fails_internal();
  test_scratch_round_trip_and_integrity();
  return 0;
}
