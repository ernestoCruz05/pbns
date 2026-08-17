#include "pbns_proxy/raw_tunnel_diagnostic.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/crc32c.h"

#define PBNS_RAW_MILESTONE_MASK UINT32_C(0x00001fff)
#define PBNS_RAW_RESULT_CLASS_MASK UINT32_C(0xffff0303)
#define PBNS_RAW_STAGE_DTR ((uint32_t)PBNS_RAW_MILESTONE_DTR)
#define PBNS_RAW_STAGE_CREDENTIALS                                             \
  (PBNS_RAW_STAGE_DTR | (uint32_t)PBNS_RAW_MILESTONE_CREDENTIALS)
#define PBNS_RAW_STAGE_NETWORK                                                 \
  (PBNS_RAW_STAGE_CREDENTIALS |                                                \
   (uint32_t)PBNS_RAW_MILESTONE_NETWORK_INITIALIZED)
#define PBNS_RAW_STAGE_WIFI_STARTED                                            \
  (PBNS_RAW_STAGE_NETWORK | (uint32_t)PBNS_RAW_MILESTONE_WIFI_STARTED)
#define PBNS_RAW_STAGE_WIFI_READY                                              \
  (PBNS_RAW_STAGE_WIFI_STARTED | (uint32_t)PBNS_RAW_MILESTONE_WIFI_READY)
#define PBNS_RAW_STAGE_TCP_READY                                               \
  (PBNS_RAW_STAGE_WIFI_READY | (uint32_t)PBNS_RAW_MILESTONE_TCP_READY)
#define PBNS_RAW_DATA_MILESTONES                                               \
  ((uint32_t)PBNS_RAW_MILESTONE_CDC_RX |                                       \
   (uint32_t)PBNS_RAW_MILESTONE_TCP_WRITE |                                    \
   (uint32_t)PBNS_RAW_MILESTONE_TCP_OUTPUT |                                   \
   (uint32_t)PBNS_RAW_MILESTONE_TCP_RX |                                       \
   (uint32_t)PBNS_RAW_MILESTONE_CDC_TX_ENQUEUE |                               \
   (uint32_t)PBNS_RAW_MILESTONE_CDC_TX_FLUSH |                                 \
   (uint32_t)PBNS_RAW_MILESTONE_CDC_TX_COMPLETE)

static bool io_result_is_valid(pbns_tcp_io_result result) {
  switch (result) {
  case PBNS_TCP_IO_NOT_RUN:
  case PBNS_TCP_IO_OK:
  case PBNS_TCP_IO_RETRY:
  case PBNS_TCP_IO_FAILED:
    return true;
  default:
    return false;
  }
}

static bool io_pair_is_valid(pbns_tcp_io_result write_result,
                             pbns_tcp_io_result output_result) {
  if (!io_result_is_valid(write_result) || !io_result_is_valid(output_result)) {
    return false;
  }
  if (write_result == PBNS_TCP_IO_NOT_RUN) {
    return output_result == PBNS_TCP_IO_NOT_RUN;
  }
  if (write_result == PBNS_TCP_IO_RETRY || write_result == PBNS_TCP_IO_FAILED) {
    return output_result == PBNS_TCP_IO_NOT_RUN;
  }
  return output_result != PBNS_TCP_IO_NOT_RUN;
}

static bool milestone_matches_counter(uint32_t milestones, uint32_t milestone,
                                      uint16_t counter) {
  return ((milestones & milestone) != 0U) == (counter != 0U);
}

static bool stage_progression_is_valid(uint32_t milestones) {
  return ((milestones & (uint32_t)PBNS_RAW_MILESTONE_CREDENTIALS) == 0U ||
          (milestones & PBNS_RAW_STAGE_DTR) == PBNS_RAW_STAGE_DTR) &&
         ((milestones & (uint32_t)PBNS_RAW_MILESTONE_NETWORK_INITIALIZED) ==
              0U ||
          (milestones & PBNS_RAW_STAGE_CREDENTIALS) ==
              PBNS_RAW_STAGE_CREDENTIALS) &&
         ((milestones & (uint32_t)PBNS_RAW_MILESTONE_WIFI_STARTED) == 0U ||
          (milestones & PBNS_RAW_STAGE_NETWORK) == PBNS_RAW_STAGE_NETWORK) &&
         ((milestones & (uint32_t)PBNS_RAW_MILESTONE_WIFI_READY) == 0U ||
          (milestones & PBNS_RAW_STAGE_WIFI_STARTED) ==
              PBNS_RAW_STAGE_WIFI_STARTED) &&
         ((milestones & (uint32_t)PBNS_RAW_MILESTONE_TCP_READY) == 0U ||
          (milestones & PBNS_RAW_STAGE_WIFI_READY) ==
              PBNS_RAW_STAGE_WIFI_READY) &&
         ((milestones & PBNS_RAW_DATA_MILESTONES) == 0U ||
          (milestones & PBNS_RAW_STAGE_TCP_READY) == PBNS_RAW_STAGE_TCP_READY);
}

static bool state_is_consistent(const pbns_raw_diagnostic_state *state) {
  if (state == NULL || (state->milestones & ~PBNS_RAW_MILESTONE_MASK) != 0U ||
      !stage_progression_is_valid(state->milestones) ||
      !io_pair_is_valid(state->tcp_write_result, state->tcp_output_result) ||
      state->cdc_tx_flushes > state->cdc_tx_enqueues ||
      state->cdc_tx_completions > state->cdc_tx_flushes) {
    return false;
  }
  if (!milestone_matches_counter(state->milestones, PBNS_RAW_MILESTONE_CDC_RX,
                                 state->cdc_rx_callbacks) ||
      !milestone_matches_counter(state->milestones, PBNS_RAW_MILESTONE_TCP_RX,
                                 state->tcp_rx_callbacks) ||
      !milestone_matches_counter(state->milestones,
                                 PBNS_RAW_MILESTONE_CDC_TX_ENQUEUE,
                                 state->cdc_tx_enqueues) ||
      !milestone_matches_counter(state->milestones,
                                 PBNS_RAW_MILESTONE_CDC_TX_FLUSH,
                                 state->cdc_tx_flushes) ||
      !milestone_matches_counter(state->milestones,
                                 PBNS_RAW_MILESTONE_CDC_TX_COMPLETE,
                                 state->cdc_tx_completions)) {
    return false;
  }
  const bool write_observed =
      (state->milestones & PBNS_RAW_MILESTONE_TCP_WRITE) != 0U;
  const bool output_observed =
      (state->milestones & PBNS_RAW_MILESTONE_TCP_OUTPUT) != 0U;
  return write_observed == (state->tcp_write_result != PBNS_TCP_IO_NOT_RUN) &&
         output_observed == (state->tcp_output_result != PBNS_TCP_IO_NOT_RUN);
}

static bool no_transport_activity(const pbns_raw_diagnostic_state *state) {
  return (state->milestones & PBNS_RAW_DATA_MILESTONES) == 0U &&
         state->cdc_rx_callbacks == 0U && state->tcp_rx_callbacks == 0U &&
         state->cdc_tx_enqueues == 0U && state->cdc_tx_flushes == 0U &&
         state->cdc_tx_completions == 0U &&
         state->tcp_write_result == PBNS_TCP_IO_NOT_RUN &&
         state->tcp_output_result == PBNS_TCP_IO_NOT_RUN;
}

static bool pipeline_is_complete(const pbns_raw_diagnostic_state *state) {
  return state->milestones == PBNS_RAW_MILESTONE_MASK &&
         state->cdc_rx_callbacks != 0U && state->tcp_rx_callbacks != 0U &&
         state->cdc_tx_enqueues != 0U && state->cdc_tx_flushes != 0U &&
         state->cdc_tx_completions != 0U &&
         state->tcp_write_result == PBNS_TCP_IO_OK &&
         state->tcp_output_result == PBNS_TCP_IO_OK;
}

static bool result_matches_state(const pbns_raw_diagnostic_state *state,
                                 pbns_raw_diagnostic_result result) {
  if (!state_is_consistent(state)) {
    return false;
  }
  switch (result) {
  case PBNS_RAW_RESULT_CREDENTIAL_FAILURE:
    return state->milestones == PBNS_RAW_STAGE_DTR &&
           no_transport_activity(state);
  case PBNS_RAW_RESULT_NETWORK_INIT_FAILURE:
    return state->milestones == PBNS_RAW_STAGE_CREDENTIALS &&
           no_transport_activity(state);
  case PBNS_RAW_RESULT_WIFI_START_FAILURE:
    return state->milestones == PBNS_RAW_STAGE_NETWORK &&
           no_transport_activity(state);
  case PBNS_RAW_RESULT_WIFI_FAILURE:
  case PBNS_RAW_RESULT_WIFI_TIMEOUT:
    return state->milestones == PBNS_RAW_STAGE_WIFI_STARTED &&
           no_transport_activity(state);
  case PBNS_RAW_RESULT_TCP_FAILURE:
  case PBNS_RAW_RESULT_TCP_TIMEOUT:
    return state->milestones == PBNS_RAW_STAGE_WIFI_READY &&
           no_transport_activity(state);
  case PBNS_RAW_RESULT_NO_CDC_CIPHERTEXT:
    return (state->milestones == 0U ||
            state->milestones == PBNS_RAW_STAGE_TCP_READY) &&
           no_transport_activity(state);
  case PBNS_RAW_RESULT_TCP_WRITE_FAILURE:
    return state->cdc_rx_callbacks != 0U &&
           state->tcp_write_result != PBNS_TCP_IO_OK &&
           state->tcp_output_result == PBNS_TCP_IO_NOT_RUN &&
           state->tcp_rx_callbacks == 0U && state->cdc_tx_enqueues == 0U &&
           state->cdc_tx_flushes == 0U &&
           ((state->tcp_write_result == PBNS_TCP_IO_NOT_RUN &&
             state->milestones == (PBNS_RAW_STAGE_TCP_READY |
                                   (uint32_t)PBNS_RAW_MILESTONE_CDC_RX)) ||
            (state->tcp_write_result != PBNS_TCP_IO_NOT_RUN &&
             state->milestones == (PBNS_RAW_STAGE_TCP_READY |
                                   (uint32_t)PBNS_RAW_MILESTONE_CDC_RX |
                                   (uint32_t)PBNS_RAW_MILESTONE_TCP_WRITE)));
  case PBNS_RAW_RESULT_TCP_OUTPUT_FAILURE:
    return state->milestones ==
               (PBNS_RAW_STAGE_TCP_READY | (uint32_t)PBNS_RAW_MILESTONE_CDC_RX |
                (uint32_t)PBNS_RAW_MILESTONE_TCP_WRITE |
                (uint32_t)PBNS_RAW_MILESTONE_TCP_OUTPUT) &&
           state->cdc_rx_callbacks != 0U &&
           state->tcp_write_result == PBNS_TCP_IO_OK &&
           state->tcp_output_result != PBNS_TCP_IO_OK &&
           state->tcp_output_result != PBNS_TCP_IO_NOT_RUN &&
           state->tcp_rx_callbacks == 0U && state->cdc_tx_enqueues == 0U &&
           state->cdc_tx_flushes == 0U;
  case PBNS_RAW_RESULT_NO_TCP_RX:
    return state->milestones ==
               (PBNS_RAW_STAGE_TCP_READY | (uint32_t)PBNS_RAW_MILESTONE_CDC_RX |
                (uint32_t)PBNS_RAW_MILESTONE_TCP_WRITE |
                (uint32_t)PBNS_RAW_MILESTONE_TCP_OUTPUT) &&
           state->cdc_rx_callbacks != 0U &&
           state->tcp_write_result == PBNS_TCP_IO_OK &&
           state->tcp_output_result == PBNS_TCP_IO_OK &&
           state->tcp_rx_callbacks == 0U && state->cdc_tx_enqueues == 0U &&
           state->cdc_tx_flushes == 0U;
  case PBNS_RAW_RESULT_TCP_RX_WITHOUT_CDC_TX:
    return state->milestones ==
               (PBNS_RAW_STAGE_TCP_READY | (uint32_t)PBNS_RAW_MILESTONE_CDC_RX |
                (uint32_t)PBNS_RAW_MILESTONE_TCP_WRITE |
                (uint32_t)PBNS_RAW_MILESTONE_TCP_OUTPUT |
                (uint32_t)PBNS_RAW_MILESTONE_TCP_RX) &&
           state->cdc_rx_callbacks != 0U && state->tcp_rx_callbacks != 0U &&
           state->tcp_write_result == PBNS_TCP_IO_OK &&
           state->tcp_output_result == PBNS_TCP_IO_OK &&
           state->cdc_tx_enqueues == 0U && state->cdc_tx_flushes == 0U;
  case PBNS_RAW_RESULT_CDC_ENQUEUE_WITHOUT_FLUSH:
    return state->milestones ==
               (PBNS_RAW_MILESTONE_MASK &
                ~((uint32_t)PBNS_RAW_MILESTONE_CDC_TX_FLUSH |
                  (uint32_t)PBNS_RAW_MILESTONE_CDC_TX_COMPLETE)) &&
           state->cdc_rx_callbacks != 0U && state->tcp_rx_callbacks != 0U &&
           state->cdc_tx_enqueues != 0U && state->cdc_tx_flushes == 0U &&
           state->cdc_tx_completions == 0U &&
           state->tcp_write_result == PBNS_TCP_IO_OK &&
           state->tcp_output_result == PBNS_TCP_IO_OK;
  case PBNS_RAW_RESULT_CDC_FLUSH_WITHOUT_COMPLETE:
    return state->milestones ==
               (PBNS_RAW_MILESTONE_MASK &
                ~(uint32_t)PBNS_RAW_MILESTONE_CDC_TX_COMPLETE) &&
           state->cdc_rx_callbacks != 0U && state->tcp_rx_callbacks != 0U &&
           state->cdc_tx_enqueues != 0U && state->cdc_tx_flushes != 0U &&
           state->cdc_tx_completions == 0U &&
           state->tcp_write_result == PBNS_TCP_IO_OK &&
           state->tcp_output_result == PBNS_TCP_IO_OK;
  case PBNS_RAW_RESULT_APPLICATION_TIMEOUT:
  case PBNS_RAW_RESULT_COMPLETE:
    return pipeline_is_complete(state);
  case PBNS_RAW_RESULT_INTERNAL_FAILURE:
    return true;
  default:
    return false;
  }
}

static pbns_raw_diagnostic_result
incomplete_pipeline_result(const pbns_raw_diagnostic_state *state) {
  if (state->cdc_rx_callbacks == 0U) {
    return PBNS_RAW_RESULT_NO_CDC_CIPHERTEXT;
  }
  if (state->tcp_write_result != PBNS_TCP_IO_OK) {
    return PBNS_RAW_RESULT_TCP_WRITE_FAILURE;
  }
  if (state->tcp_output_result != PBNS_TCP_IO_OK) {
    return PBNS_RAW_RESULT_TCP_OUTPUT_FAILURE;
  }
  if (state->tcp_rx_callbacks == 0U) {
    return PBNS_RAW_RESULT_NO_TCP_RX;
  }
  if (state->cdc_tx_enqueues == 0U) {
    return PBNS_RAW_RESULT_TCP_RX_WITHOUT_CDC_TX;
  }
  if (state->cdc_tx_flushes == 0U) {
    return PBNS_RAW_RESULT_CDC_ENQUEUE_WITHOUT_FLUSH;
  }
  if (state->cdc_tx_completions == 0U) {
    return PBNS_RAW_RESULT_CDC_FLUSH_WITHOUT_COMPLETE;
  }
  return PBNS_RAW_RESULT_APPLICATION_TIMEOUT;
}

static void increment_saturated(uint16_t *counter) {
  if (*counter != UINT16_MAX) {
    ++*counter;
  }
}

static pbns_status observe_counter(pbns_raw_diagnostic_state *state,
                                   uint16_t *counter, uint32_t milestone) {
  if (state == NULL || counter == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  increment_saturated(counter);
  state->milestones |= milestone;
  return PBNS_OK;
}

static void store_u32_le(uint8_t output[4], uint32_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8U);
  output[2] = (uint8_t)(value >> 16U);
  output[3] = (uint8_t)(value >> 24U);
}

static uint32_t
scratch_crc(const uint32_t words[PBNS_RAW_DIAGNOSTIC_SCRATCH_WORDS]) {
  uint8_t encoded[24] = {0};
  for (size_t index = 0U; index < 6U; ++index) {
    store_u32_le(&encoded[index * 4U], words[index + 1U]);
  }
  return pbns_crc32c((pbns_view){encoded, sizeof(encoded)});
}

void pbns_raw_diagnostic_init(pbns_raw_diagnostic_state *state) {
  if (state == NULL) {
    return;
  }
  *state = (pbns_raw_diagnostic_state){
      .tcp_write_result = PBNS_TCP_IO_NOT_RUN,
      .tcp_output_result = PBNS_TCP_IO_NOT_RUN,
  };
}

pbns_status
pbns_raw_diagnostic_observe_milestone(pbns_raw_diagnostic_state *state,
                                      pbns_raw_diagnostic_milestone milestone) {
  const uint32_t value = (uint32_t)milestone;
  if (state == NULL || value == 0U || (value & (value - 1U)) != 0U ||
      (value & ~PBNS_RAW_MILESTONE_MASK) != 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  state->milestones |= value;
  return PBNS_OK;
}

pbns_status
pbns_raw_diagnostic_observe_cdc_rx(pbns_raw_diagnostic_state *state) {
  return state == NULL ? PBNS_ERR_ARGUMENT
                       : observe_counter(state, &state->cdc_rx_callbacks,
                                         PBNS_RAW_MILESTONE_CDC_RX);
}

pbns_status
pbns_raw_diagnostic_observe_tcp_rx(pbns_raw_diagnostic_state *state) {
  return state == NULL ? PBNS_ERR_ARGUMENT
                       : observe_counter(state, &state->tcp_rx_callbacks,
                                         PBNS_RAW_MILESTONE_TCP_RX);
}

pbns_status
pbns_raw_diagnostic_observe_cdc_tx_enqueue(pbns_raw_diagnostic_state *state) {
  return state == NULL ? PBNS_ERR_ARGUMENT
                       : observe_counter(state, &state->cdc_tx_enqueues,
                                         PBNS_RAW_MILESTONE_CDC_TX_ENQUEUE);
}

pbns_status
pbns_raw_diagnostic_observe_cdc_tx_flush(pbns_raw_diagnostic_state *state) {
  return state == NULL ? PBNS_ERR_ARGUMENT
                       : observe_counter(state, &state->cdc_tx_flushes,
                                         PBNS_RAW_MILESTONE_CDC_TX_FLUSH);
}

pbns_status
pbns_raw_diagnostic_observe_cdc_tx_complete(pbns_raw_diagnostic_state *state) {
  return state == NULL ? PBNS_ERR_ARGUMENT
                       : observe_counter(state, &state->cdc_tx_completions,
                                         PBNS_RAW_MILESTONE_CDC_TX_COMPLETE);
}

pbns_status
pbns_raw_diagnostic_observe_tcp_io(pbns_raw_diagnostic_state *state,
                                   pbns_tcp_io_result write_result,
                                   pbns_tcp_io_result output_result) {
  if (state == NULL || write_result == PBNS_TCP_IO_NOT_RUN ||
      !io_pair_is_valid(write_result, output_result)) {
    return PBNS_ERR_ARGUMENT;
  }
  state->tcp_write_result = write_result;
  state->tcp_output_result = output_result;
  state->milestones |= PBNS_RAW_MILESTONE_TCP_WRITE;
  if (output_result != PBNS_TCP_IO_NOT_RUN) {
    state->milestones |= PBNS_RAW_MILESTONE_TCP_OUTPUT;
  } else {
    state->milestones &= ~(uint32_t)PBNS_RAW_MILESTONE_TCP_OUTPUT;
  }
  return PBNS_OK;
}

bool pbns_raw_diagnostic_result_is_terminal(pbns_raw_diagnostic_result result) {
  switch (result) {
  case PBNS_RAW_RESULT_CREDENTIAL_FAILURE:
  case PBNS_RAW_RESULT_NETWORK_INIT_FAILURE:
  case PBNS_RAW_RESULT_WIFI_START_FAILURE:
  case PBNS_RAW_RESULT_WIFI_FAILURE:
  case PBNS_RAW_RESULT_WIFI_TIMEOUT:
  case PBNS_RAW_RESULT_TCP_FAILURE:
  case PBNS_RAW_RESULT_TCP_TIMEOUT:
  case PBNS_RAW_RESULT_NO_CDC_CIPHERTEXT:
  case PBNS_RAW_RESULT_TCP_WRITE_FAILURE:
  case PBNS_RAW_RESULT_TCP_OUTPUT_FAILURE:
  case PBNS_RAW_RESULT_NO_TCP_RX:
  case PBNS_RAW_RESULT_TCP_RX_WITHOUT_CDC_TX:
  case PBNS_RAW_RESULT_CDC_ENQUEUE_WITHOUT_FLUSH:
  case PBNS_RAW_RESULT_CDC_FLUSH_WITHOUT_COMPLETE:
  case PBNS_RAW_RESULT_APPLICATION_TIMEOUT:
  case PBNS_RAW_RESULT_COMPLETE:
  case PBNS_RAW_RESULT_INTERNAL_FAILURE:
    return true;
  default:
    return false;
  }
}

pbns_raw_diagnostic_result
pbns_raw_diagnostic_classify(const pbns_raw_diagnostic_state *state,
                             pbns_raw_diagnostic_trigger trigger) {
  if (!state_is_consistent(state)) {
    return PBNS_RAW_RESULT_INTERNAL_FAILURE;
  }
  pbns_raw_diagnostic_result candidate = PBNS_RAW_RESULT_INTERNAL_FAILURE;
  switch (trigger) {
  case PBNS_RAW_TRIGGER_CREDENTIAL_FAILURE:
    candidate = PBNS_RAW_RESULT_CREDENTIAL_FAILURE;
    break;
  case PBNS_RAW_TRIGGER_NETWORK_INIT_FAILURE:
    candidate = PBNS_RAW_RESULT_NETWORK_INIT_FAILURE;
    break;
  case PBNS_RAW_TRIGGER_WIFI_START_FAILURE:
    candidate = PBNS_RAW_RESULT_WIFI_START_FAILURE;
    break;
  case PBNS_RAW_TRIGGER_WIFI_FAILURE:
    candidate = PBNS_RAW_RESULT_WIFI_FAILURE;
    break;
  case PBNS_RAW_TRIGGER_WIFI_TIMEOUT:
    candidate = PBNS_RAW_RESULT_WIFI_TIMEOUT;
    break;
  case PBNS_RAW_TRIGGER_TCP_FAILURE:
    candidate = PBNS_RAW_RESULT_TCP_FAILURE;
    break;
  case PBNS_RAW_TRIGGER_TCP_TIMEOUT:
    candidate = PBNS_RAW_RESULT_TCP_TIMEOUT;
    break;
  case PBNS_RAW_TRIGGER_TCP_WRITE_FAILURE:
    candidate = PBNS_RAW_RESULT_TCP_WRITE_FAILURE;
    break;
  case PBNS_RAW_TRIGGER_TCP_OUTPUT_FAILURE:
    candidate = PBNS_RAW_RESULT_TCP_OUTPUT_FAILURE;
    break;
  case PBNS_RAW_TRIGGER_INTERNAL_FAILURE:
    return PBNS_RAW_RESULT_INTERNAL_FAILURE;
  case PBNS_RAW_TRIGGER_DTR_CLOSED:
    candidate = pipeline_is_complete(state) ? PBNS_RAW_RESULT_COMPLETE
                                            : incomplete_pipeline_result(state);
    break;
  case PBNS_RAW_TRIGGER_APPLICATION_TIMEOUT:
    candidate = incomplete_pipeline_result(state);
    break;
  case PBNS_RAW_TRIGGER_COMPLETE:
    candidate = PBNS_RAW_RESULT_COMPLETE;
    break;
  default:
    return PBNS_RAW_RESULT_INTERNAL_FAILURE;
  }
  return result_matches_state(state, candidate)
             ? candidate
             : PBNS_RAW_RESULT_INTERNAL_FAILURE;
}

pbns_status pbns_raw_diagnostic_scratch_encode(
    const pbns_raw_diagnostic_state *state, pbns_raw_diagnostic_result result,
    uint32_t words[PBNS_RAW_DIAGNOSTIC_SCRATCH_WORDS]) {
  if (words == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  for (size_t index = 0U; index < PBNS_RAW_DIAGNOSTIC_SCRATCH_WORDS; ++index) {
    words[index] = 0U;
  }
  if (!pbns_raw_diagnostic_result_is_terminal(result) ||
      !result_matches_state(state, result)) {
    return PBNS_ERR_ARGUMENT;
  }
  words[1] = (uint32_t)result;
  words[2] = ~words[1];
  words[3] = state->milestones;
  words[4] = (uint32_t)state->cdc_rx_callbacks |
             ((uint32_t)state->tcp_rx_callbacks << 16U);
  words[5] = (uint32_t)state->cdc_tx_enqueues |
             ((uint32_t)state->cdc_tx_flushes << 16U);
  words[6] = (uint32_t)state->tcp_write_result |
             ((uint32_t)state->tcp_output_result << 8U) |
             ((uint32_t)state->cdc_tx_completions << 16U);
  words[7] = scratch_crc(words);
  words[0] = PBNS_RAW_DIAGNOSTIC_MAGIC;
  return PBNS_OK;
}

pbns_status pbns_raw_diagnostic_scratch_decode(
    const uint32_t words[PBNS_RAW_DIAGNOSTIC_SCRATCH_WORDS],
    pbns_raw_diagnostic_state *state, pbns_raw_diagnostic_result *result) {
  if (state != NULL) {
    pbns_raw_diagnostic_init(state);
  }
  if (result != NULL) {
    *result = PBNS_RAW_RESULT_INTERNAL_FAILURE;
  }
  if (words == NULL || state == NULL || result == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_raw_diagnostic_result decoded_result =
      (pbns_raw_diagnostic_result)words[1];
  if (words[0] != PBNS_RAW_DIAGNOSTIC_MAGIC || words[2] != ~words[1] ||
      !pbns_raw_diagnostic_result_is_terminal(decoded_result) ||
      words[7] != scratch_crc(words) ||
      (words[6] & ~PBNS_RAW_RESULT_CLASS_MASK) != 0U) {
    return PBNS_ERR_FORMAT;
  }
  const pbns_raw_diagnostic_state decoded = {
      .milestones = words[3],
      .cdc_rx_callbacks = (uint16_t)words[4],
      .tcp_rx_callbacks = (uint16_t)(words[4] >> 16U),
      .cdc_tx_enqueues = (uint16_t)words[5],
      .cdc_tx_flushes = (uint16_t)(words[5] >> 16U),
      .cdc_tx_completions = (uint16_t)(words[6] >> 16U),
      .tcp_write_result = (pbns_tcp_io_result)(words[6] & UINT32_C(0xff)),
      .tcp_output_result =
          (pbns_tcp_io_result)((words[6] >> 8U) & UINT32_C(0xff)),
  };
  if (!result_matches_state(&decoded, decoded_result)) {
    return PBNS_ERR_FORMAT;
  }
  *state = decoded;
  *result = decoded_result;
  return PBNS_OK;
}
