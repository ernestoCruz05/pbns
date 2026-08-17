#ifndef PBNS_PROXY_RAW_TUNNEL_DIAGNOSTIC_H
#define PBNS_PROXY_RAW_TUNNEL_DIAGNOSTIC_H

#include <stdbool.h>
#include <stdint.h>

#include "pbns/status.h"
#include "pbns_proxy/tcp_write_outcome.h"

#define PBNS_RAW_DIAGNOSTIC_MAGIC UINT32_C(0x50425244)
#define PBNS_RAW_DIAGNOSTIC_SCRATCH_WORDS 8U
#define PBNS_RAW_DIAGNOSTIC_AWAITING_BCD UINT16_C(0x9200)

typedef enum pbns_raw_diagnostic_milestone {
  PBNS_RAW_MILESTONE_DTR = UINT32_C(1) << 0U,
  PBNS_RAW_MILESTONE_CREDENTIALS = UINT32_C(1) << 1U,
  PBNS_RAW_MILESTONE_NETWORK_INITIALIZED = UINT32_C(1) << 2U,
  PBNS_RAW_MILESTONE_WIFI_STARTED = UINT32_C(1) << 3U,
  PBNS_RAW_MILESTONE_WIFI_READY = UINT32_C(1) << 4U,
  PBNS_RAW_MILESTONE_TCP_READY = UINT32_C(1) << 5U,
  PBNS_RAW_MILESTONE_CDC_RX = UINT32_C(1) << 6U,
  PBNS_RAW_MILESTONE_TCP_WRITE = UINT32_C(1) << 7U,
  PBNS_RAW_MILESTONE_TCP_OUTPUT = UINT32_C(1) << 8U,
  PBNS_RAW_MILESTONE_TCP_RX = UINT32_C(1) << 9U,
  PBNS_RAW_MILESTONE_CDC_TX_ENQUEUE = UINT32_C(1) << 10U,
  PBNS_RAW_MILESTONE_CDC_TX_FLUSH = UINT32_C(1) << 11U,
  PBNS_RAW_MILESTONE_CDC_TX_COMPLETE = UINT32_C(1) << 12U
} pbns_raw_diagnostic_milestone;

typedef enum pbns_raw_diagnostic_result {
  PBNS_RAW_RESULT_CREDENTIAL_FAILURE = 0x9201,
  PBNS_RAW_RESULT_NETWORK_INIT_FAILURE = 0x9202,
  PBNS_RAW_RESULT_WIFI_START_FAILURE = 0x9203,
  PBNS_RAW_RESULT_WIFI_FAILURE = 0x9204,
  PBNS_RAW_RESULT_WIFI_TIMEOUT = 0x9205,
  PBNS_RAW_RESULT_TCP_FAILURE = 0x9206,
  PBNS_RAW_RESULT_TCP_TIMEOUT = 0x9207,
  PBNS_RAW_RESULT_NO_CDC_CIPHERTEXT = 0x9208,
  PBNS_RAW_RESULT_TCP_WRITE_FAILURE = 0x9209,
  PBNS_RAW_RESULT_TCP_OUTPUT_FAILURE = 0x9210,
  PBNS_RAW_RESULT_NO_TCP_RX = 0x9211,
  PBNS_RAW_RESULT_TCP_RX_WITHOUT_CDC_TX = 0x9212,
  PBNS_RAW_RESULT_CDC_ENQUEUE_WITHOUT_FLUSH = 0x9213,
  PBNS_RAW_RESULT_APPLICATION_TIMEOUT = 0x9214,
  PBNS_RAW_RESULT_CDC_FLUSH_WITHOUT_COMPLETE = 0x9215,
  PBNS_RAW_RESULT_COMPLETE = 0x9298,
  PBNS_RAW_RESULT_INTERNAL_FAILURE = 0x9299
} pbns_raw_diagnostic_result;

typedef enum pbns_raw_diagnostic_trigger {
  PBNS_RAW_TRIGGER_CREDENTIAL_FAILURE = 0,
  PBNS_RAW_TRIGGER_NETWORK_INIT_FAILURE,
  PBNS_RAW_TRIGGER_WIFI_START_FAILURE,
  PBNS_RAW_TRIGGER_WIFI_FAILURE,
  PBNS_RAW_TRIGGER_WIFI_TIMEOUT,
  PBNS_RAW_TRIGGER_TCP_FAILURE,
  PBNS_RAW_TRIGGER_TCP_TIMEOUT,
  PBNS_RAW_TRIGGER_TCP_WRITE_FAILURE,
  PBNS_RAW_TRIGGER_TCP_OUTPUT_FAILURE,
  PBNS_RAW_TRIGGER_APPLICATION_TIMEOUT,
  PBNS_RAW_TRIGGER_DTR_CLOSED,
  PBNS_RAW_TRIGGER_COMPLETE,
  PBNS_RAW_TRIGGER_INTERNAL_FAILURE
} pbns_raw_diagnostic_trigger;

typedef enum pbns_raw_diagnostic_observation {
  PBNS_RAW_OBSERVE_NETWORK_INITIALIZED = 0,
  PBNS_RAW_OBSERVE_WIFI_STARTED,
  PBNS_RAW_OBSERVE_WIFI_READY,
  PBNS_RAW_OBSERVE_TCP_READY,
  PBNS_RAW_OBSERVE_CDC_RX,
  PBNS_RAW_OBSERVE_CDC_TX_ENQUEUE,
  PBNS_RAW_OBSERVE_CDC_TX_FLUSH,
  PBNS_RAW_OBSERVE_CDC_TX_COMPLETE
} pbns_raw_diagnostic_observation;

typedef struct pbns_raw_diagnostic_state {
  uint32_t milestones;
  uint16_t cdc_rx_callbacks;
  uint16_t tcp_rx_callbacks;
  uint16_t cdc_tx_enqueues;
  uint16_t cdc_tx_flushes;
  uint16_t cdc_tx_completions;
  pbns_tcp_io_result tcp_write_result;
  pbns_tcp_io_result tcp_output_result;
} pbns_raw_diagnostic_state;

void pbns_raw_diagnostic_init(pbns_raw_diagnostic_state *state);
pbns_status
pbns_raw_diagnostic_observe_milestone(pbns_raw_diagnostic_state *state,
                                      pbns_raw_diagnostic_milestone milestone);
pbns_status
pbns_raw_diagnostic_observe_cdc_rx(pbns_raw_diagnostic_state *state);
pbns_status
pbns_raw_diagnostic_observe_tcp_rx(pbns_raw_diagnostic_state *state);
pbns_status
pbns_raw_diagnostic_observe_cdc_tx_enqueue(pbns_raw_diagnostic_state *state);
pbns_status
pbns_raw_diagnostic_observe_cdc_tx_flush(pbns_raw_diagnostic_state *state);
pbns_status
pbns_raw_diagnostic_observe_cdc_tx_complete(pbns_raw_diagnostic_state *state);
pbns_status
pbns_raw_diagnostic_observe_tcp_io(pbns_raw_diagnostic_state *state,
                                   pbns_tcp_io_result write_result,
                                   pbns_tcp_io_result output_result);
bool pbns_raw_diagnostic_result_is_terminal(pbns_raw_diagnostic_result result);
bool pbns_raw_diagnostic_usb_set_bcd_device(uint16_t bcd_device);
pbns_raw_diagnostic_result
pbns_raw_diagnostic_classify(const pbns_raw_diagnostic_state *state,
                             pbns_raw_diagnostic_trigger trigger);
pbns_status pbns_raw_diagnostic_scratch_encode(
    const pbns_raw_diagnostic_state *state, pbns_raw_diagnostic_result result,
    uint32_t words[PBNS_RAW_DIAGNOSTIC_SCRATCH_WORDS]);
pbns_status pbns_raw_diagnostic_scratch_decode(
    const uint32_t words[PBNS_RAW_DIAGNOSTIC_SCRATCH_WORDS],
    pbns_raw_diagnostic_state *state, pbns_raw_diagnostic_result *result);

#endif
