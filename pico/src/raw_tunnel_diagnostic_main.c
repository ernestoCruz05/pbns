#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bsp/board_api.h"
#include "hardware/regs/addressmap.h"
#include "hardware/structs/watchdog.h"
#include "hardware/sync.h"
#include "hardware/watchdog.h"
#include "pbns_proxy/byte_pump.h"
#include "pbns_proxy/credentials.h"
#include "pbns_proxy/diagnostic_storage.h"
#include "pbns_proxy/network.h"
#include "pbns_proxy/raw_tunnel_diagnostic.h"
#include "pbns_proxy/tail_deadline.h"
#include "pico/stdlib.h"
#include "tusb.h"

#define DIAGNOSTIC_CDC_INSTANCE UINT8_C(0)
#define DIAGNOSTIC_CDC_WRITE_MAX 63U
#define DIAGNOSTIC_DTR_TIMEOUT_MS UINT64_C(120000)
#define DIAGNOSTIC_SESSION_TIMEOUT_MS UINT64_C(90000)
#define TUNNEL_RING_CAPACITY 4096U
#define TUNNEL_AGGREGATION_THRESHOLD 2048U
#define TUNNEL_AGGREGATION_DEADLINE_US UINT64_C(5000)

_Static_assert(PICO_FLASH_SIZE_BYTES == PBNS_FLASH_TOTAL_SIZE_BYTES,
               "PBNS raw diagnostic and Pico physical flash sizes differ");

static pbns_pico_network pico_network;
static pbns_network network_controller;
static pbns_raw_diagnostic_state diagnostic_state;
static pbns_byte_pump tunnel_pump;
static uint8_t usb_to_tcp_storage[TUNNEL_RING_CAPACITY];
static uint8_t tcp_to_usb_storage[TUNNEL_RING_CAPACITY];
static pbns_tail_deadline usb_to_tcp_tail;
static bool network_initialized;
static bool cdc_flush_pending;
static bool cdc_transfer_pending;
static bool cdc_completion_observation_failed;

static void secure_zero(void *pointer, size_t size) {
  volatile uint8_t *cursor = pointer;
  while (size > 0U) {
    *cursor = UINT8_C(0);
    ++cursor;
    --size;
  }
}

_Noreturn static void terminal_loop(void) {
  while (true) {
    tud_task();
    sleep_ms(1U);
  }
}

_Noreturn static void
write_scratch_and_reboot(pbns_raw_diagnostic_result result) {
  uint32_t words[PBNS_RAW_DIAGNOSTIC_SCRATCH_WORDS] = {0};
  if (pbns_raw_diagnostic_scratch_encode(&diagnostic_state, result, words) !=
      PBNS_OK) {
    pbns_raw_diagnostic_init(&diagnostic_state);
    (void)pbns_raw_diagnostic_scratch_encode(
        &diagnostic_state, PBNS_RAW_RESULT_INTERNAL_FAILURE, words);
  }

  (void)save_and_disable_interrupts();
  /* O SDK altera scratch[4], por isso o temporizador precede o commit. */
  watchdog_reboot(0U, 0U, 10U);
  watchdog_hw->scratch[0] = 0U;
  for (size_t index = 1U; index < PBNS_RAW_DIAGNOSTIC_SCRATCH_WORDS; ++index) {
    watchdog_hw->scratch[index] = words[index];
  }
  __compiler_memory_barrier();
  /* A magia é escrita no fim para invalidar um registo interrompido. */
  watchdog_hw->scratch[0] = words[0];
  __compiler_memory_barrier();
  secure_zero(words, sizeof(words));
  secure_zero(&diagnostic_state, sizeof(diagnostic_state));
  while (true) {
    tight_loop_contents();
  }
}

_Noreturn static void finish(pbns_raw_diagnostic_trigger trigger) {
  if (network_initialized) {
    pbns_pico_network_deinit(&pico_network);
    network_initialized = false;
  }
  pbns_byte_pump_cancel(&tunnel_pump);
  secure_zero(usb_to_tcp_storage, sizeof(usb_to_tcp_storage));
  secure_zero(tcp_to_usb_storage, sizeof(tcp_to_usb_storage));
  const pbns_raw_diagnostic_result result =
      pbns_raw_diagnostic_classify(&diagnostic_state, trigger);
  write_scratch_and_reboot(result);
}

static pbns_status usb_read(void *context, pbns_buffer destination,
                            size_t *received) {
  (void)context;
  if (received == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *received = 0U;
  if (destination.len != 0U || destination.ptr == NULL ||
      destination.cap == 0U || destination.cap > UINT32_MAX) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!tud_cdc_n_connected(DIAGNOSTIC_CDC_INSTANCE)) {
    return PBNS_OK;
  }
  const uint32_t available = tud_cdc_n_available(DIAGNOSTIC_CDC_INSTANCE);
  if (available == 0U) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  const size_t amount =
      destination.cap < (size_t)available ? destination.cap : (size_t)available;
  const uint32_t actual = tud_cdc_n_read(DIAGNOSTIC_CDC_INSTANCE,
                                         destination.ptr, (uint32_t)amount);
  if (actual == 0U) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  if (actual > amount ||
      pbns_pico_network_observe_diagnostic(
          &pico_network, PBNS_RAW_OBSERVE_CDC_RX) != PBNS_OK) {
    return PBNS_ERR_IO;
  }
  *received = actual;
  return PBNS_OK;
}

static pbns_status usb_write(void *context, pbns_view source, size_t *written) {
  (void)context;
  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (source.ptr == NULL || source.len == 0U || source.len > UINT32_MAX) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!tud_cdc_n_connected(DIAGNOSTIC_CDC_INSTANCE)) {
    return PBNS_ERR_TRANSPORT;
  }
  if (cdc_flush_pending || cdc_transfer_pending) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  const uint32_t available = tud_cdc_n_write_available(DIAGNOSTIC_CDC_INSTANCE);
  if (available == 0U) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  size_t amount =
      source.len < (size_t)available ? source.len : (size_t)available;
  if (amount > DIAGNOSTIC_CDC_WRITE_MAX) {
    amount = DIAGNOSTIC_CDC_WRITE_MAX;
  }
  const uint32_t actual =
      tud_cdc_n_write(DIAGNOSTIC_CDC_INSTANCE, source.ptr, (uint32_t)amount);
  if (actual == 0U) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  if (actual > amount ||
      pbns_pico_network_observe_diagnostic(
          &pico_network, PBNS_RAW_OBSERVE_CDC_TX_ENQUEUE) != PBNS_OK) {
    return PBNS_ERR_IO;
  }
  cdc_flush_pending = true;
  *written = actual;
  return PBNS_OK;
}

void tud_cdc_tx_complete_cb(uint8_t instance) {
  if (instance != DIAGNOSTIC_CDC_INSTANCE) {
    return;
  }
  if (!cdc_transfer_pending ||
      pbns_pico_network_observe_diagnostic(
          &pico_network, PBNS_RAW_OBSERVE_CDC_TX_COMPLETE) != PBNS_OK) {
    cdc_completion_observation_failed = true;
    return;
  }
  cdc_transfer_pending = false;
}

static void flush_cdc(void) {
  if (cdc_flush_pending &&
      tud_cdc_n_write_flush(DIAGNOSTIC_CDC_INSTANCE) > 0U) {
    if (pbns_pico_network_observe_diagnostic(
            &pico_network, PBNS_RAW_OBSERVE_CDC_TX_FLUSH) != PBNS_OK) {
      finish(PBNS_RAW_TRIGGER_INTERNAL_FAILURE);
    }
    cdc_flush_pending = false;
    cdc_transfer_pending = true;
  }
}

static void wait_for_dtr(void) {
  const uint64_t started_ms = to_ms_64_since_boot(get_absolute_time());
  while (!tud_cdc_n_connected(DIAGNOSTIC_CDC_INSTANCE)) {
    tud_task();
    const uint64_t now_ms = to_ms_64_since_boot(get_absolute_time());
    if (now_ms >= started_ms &&
        now_ms - started_ms >= DIAGNOSTIC_DTR_TIMEOUT_MS) {
      finish(PBNS_RAW_TRIGGER_APPLICATION_TIMEOUT);
    }
    sleep_ms(1U);
  }
  if (pbns_raw_diagnostic_observe_milestone(
          &diagnostic_state, PBNS_RAW_MILESTONE_DTR) != PBNS_OK) {
    finish(PBNS_RAW_TRIGGER_INTERNAL_FAILURE);
  }
}

static pbns_raw_diagnostic_trigger
network_failure_trigger(pbns_network_state stage, pbns_status status) {
  switch (stage) {
  case PBNS_NETWORK_DOWN:
    return PBNS_RAW_TRIGGER_WIFI_START_FAILURE;
  case PBNS_NETWORK_WIFI_CONNECTING:
    return status == PBNS_ERR_TIMEOUT ? PBNS_RAW_TRIGGER_WIFI_TIMEOUT
                                      : PBNS_RAW_TRIGGER_WIFI_FAILURE;
  case PBNS_NETWORK_TCP_CONNECTING:
  case PBNS_NETWORK_SESSION_CONNECTING:
    return status == PBNS_ERR_TIMEOUT ? PBNS_RAW_TRIGGER_TCP_TIMEOUT
                                      : PBNS_RAW_TRIGGER_TCP_FAILURE;
  case PBNS_NETWORK_READY:
    return PBNS_RAW_TRIGGER_APPLICATION_TIMEOUT;
  case PBNS_NETWORK_BACKOFF:
  default:
    return PBNS_RAW_TRIGGER_INTERNAL_FAILURE;
  }
}

static void observe_network_transition(pbns_network_state before,
                                       pbns_network_state after) {
  pbns_status status = PBNS_OK;
  if (before == PBNS_NETWORK_DOWN && after == PBNS_NETWORK_WIFI_CONNECTING) {
    status = pbns_pico_network_observe_diagnostic(
        &pico_network, PBNS_RAW_OBSERVE_WIFI_STARTED);
  } else if (after == PBNS_NETWORK_TCP_CONNECTING) {
    status = pbns_pico_network_observe_diagnostic(&pico_network,
                                                  PBNS_RAW_OBSERVE_WIFI_READY);
  } else if (after == PBNS_NETWORK_SESSION_CONNECTING) {
    status = pbns_pico_network_observe_diagnostic(&pico_network,
                                                  PBNS_RAW_OBSERVE_TCP_READY);
  }
  if (status != PBNS_OK) {
    finish(PBNS_RAW_TRIGGER_INTERNAL_FAILURE);
  }
}

static void initialize_network(void) {
  pbns_diagnostic_storage storage = {0};
  if (pbns_diagnostic_storage_init(&storage,
                                   (const uint8_t *)(uintptr_t)XIP_BASE,
                                   PBNS_FLASH_TOTAL_SIZE_BYTES) != PBNS_OK) {
    finish(PBNS_RAW_TRIGGER_INTERNAL_FAILURE);
  }

  pbns_credentials credentials = {0};
  if (pbns_credentials_load(&storage.credentials, &credentials) != PBNS_OK) {
    secure_zero(&credentials, sizeof(credentials));
    finish(PBNS_RAW_TRIGGER_CREDENTIAL_FAILURE);
  }
  if (pbns_raw_diagnostic_observe_milestone(
          &diagnostic_state, PBNS_RAW_MILESTONE_CREDENTIALS) != PBNS_OK) {
    secure_zero(&credentials, sizeof(credentials));
    finish(PBNS_RAW_TRIGGER_INTERNAL_FAILURE);
  }
  const pbns_status init_status =
      pbns_pico_network_init(&pico_network, &credentials);
  secure_zero(&credentials, sizeof(credentials));
  if (init_status != PBNS_OK) {
    finish(PBNS_RAW_TRIGGER_NETWORK_INIT_FAILURE);
  }
  network_initialized = true;
  if (pbns_pico_network_attach_diagnostic(&pico_network, &diagnostic_state) !=
          PBNS_OK ||
      pbns_pico_network_observe_diagnostic(
          &pico_network, PBNS_RAW_OBSERVE_NETWORK_INITIALIZED) != PBNS_OK) {
    finish(PBNS_RAW_TRIGGER_INTERNAL_FAILURE);
  }
  pbns_network_init(&network_controller);
  pbns_byte_pump_init(
      &tunnel_pump,
      (pbns_buffer){usb_to_tcp_storage, 0U, sizeof(usb_to_tcp_storage)},
      (pbns_buffer){tcp_to_usb_storage, 0U, sizeof(tcp_to_usb_storage)});
  if (!tunnel_pump.initialized) {
    finish(PBNS_RAW_TRIGGER_INTERNAL_FAILURE);
  }
  pbns_tail_deadline_init(&usb_to_tcp_tail,
                          tunnel_pump.usb_to_tls_read_generation);
}

static void run_bridge(void) {
  const uint64_t started_ms = to_ms_64_since_boot(get_absolute_time());
  const pbns_network_ops operations =
      pbns_pico_network_operations(&pico_network);
  bool was_ready = false;
  while (true) {
    tud_task();
    if (cdc_completion_observation_failed) {
      finish(PBNS_RAW_TRIGGER_INTERNAL_FAILURE);
    }
    flush_cdc();
    const uint64_t now_ms = to_ms_64_since_boot(get_absolute_time());
    if (now_ms < started_ms ||
        now_ms - started_ms >= DIAGNOSTIC_SESSION_TIMEOUT_MS) {
      finish(PBNS_RAW_TRIGGER_APPLICATION_TIMEOUT);
    }
    if (!tud_cdc_n_connected(DIAGNOSTIC_CDC_INSTANCE)) {
      finish(PBNS_RAW_TRIGGER_DTR_CLOSED);
    }

    const pbns_network_state before = network_controller.state;
    bool network_progress = false;
    const pbns_status network_status = pbns_network_step(
        &network_controller, &operations, now_ms, true, &network_progress);
    observe_network_transition(before, network_controller.state);
    if (network_status != PBNS_OK) {
      finish(network_failure_trigger(before, network_status));
    }
    const bool ready = network_controller.state == PBNS_NETWORK_READY;
    if (ready != was_ready) {
      pbns_byte_pump_reset(&tunnel_pump);
      pbns_tail_deadline_reset(&usb_to_tcp_tail,
                               tunnel_pump.usb_to_tls_read_generation);
      was_ready = ready;
    }
    if (!ready) {
      sleep_ms(1U);
      continue;
    }

    const pbns_pump_endpoint usb = {
        .read = usb_read,
        .write = usb_write,
        .context = NULL,
    };
    const pbns_pump_endpoint tcp =
        pbns_pico_network_tcp_endpoint(&pico_network);
    const uint64_t now_us = time_us_64();
    const pbns_byte_pump_policy policy = {
        .usb_to_tls_minimum_write = TUNNEL_AGGREGATION_THRESHOLD,
        .tls_to_usb_minimum_writable = TUNNEL_AGGREGATION_THRESHOLD,
        .force_usb_to_tls_write = pbns_tail_deadline_should_force(
            &usb_to_tcp_tail, now_us, TUNNEL_AGGREGATION_DEADLINE_US),
    };
    size_t pump_steps = 0U;
    bool pump_progress = false;
    const pbns_status pump_status = pbns_byte_pump_batch_with_policy(
        &tunnel_pump, usb, tcp, &policy, &pump_steps, &pump_progress);
    (void)pump_steps;
    flush_cdc();
    if (pump_status != PBNS_OK) {
      finish(PBNS_RAW_TRIGGER_APPLICATION_TIMEOUT);
    }
    pbns_tail_deadline_observe_input(
        &usb_to_tcp_tail, tunnel_pump.usb_to_tls_read_generation, time_us_64());
    const size_t pending = pbns_byte_ring_size(&tunnel_pump.usb_to_tls);
    pbns_tail_deadline_set_pending(&usb_to_tcp_tail,
                                   pending != 0U &&
                                       pending < TUNNEL_AGGREGATION_THRESHOLD &&
                                       !tunnel_pump.usb_source_closed);
    const bool rings_pending =
        pbns_byte_ring_size(&tunnel_pump.usb_to_tls) != 0U ||
        pbns_byte_ring_size(&tunnel_pump.tls_to_usb) != 0U;
    if (!network_progress && !pump_progress && !rings_pending &&
        !usb_to_tcp_tail.pending && !cdc_flush_pending &&
        !cdc_transfer_pending) {
      sleep_us(50U);
    }
  }
}

int main(void) {
  pbns_raw_diagnostic_init(&diagnostic_state);
  uint32_t scratch[PBNS_RAW_DIAGNOSTIC_SCRATCH_WORDS] = {0};
  for (size_t index = 0U; index < PBNS_RAW_DIAGNOSTIC_SCRATCH_WORDS; ++index) {
    scratch[index] = watchdog_hw->scratch[index];
  }
  pbns_raw_diagnostic_state retained_state = {0};
  pbns_raw_diagnostic_result retained_result = PBNS_RAW_RESULT_INTERNAL_FAILURE;
  const bool terminal =
      pbns_raw_diagnostic_scratch_decode(scratch, &retained_state,
                                         &retained_result) == PBNS_OK;
  secure_zero(scratch, sizeof(scratch));
  secure_zero(&retained_state, sizeof(retained_state));
  const uint16_t bcd_device =
      terminal ? (uint16_t)retained_result : PBNS_RAW_DIAGNOSTIC_AWAITING_BCD;
  if (!pbns_raw_diagnostic_usb_set_bcd_device(bcd_device)) {
    while (true) {
      tight_loop_contents();
    }
  }

  board_init();
  if (!tusb_init()) {
    while (true) {
      tight_loop_contents();
    }
  }
  if (terminal) {
    terminal_loop();
  }
  wait_for_dtr();
  initialize_network();
  run_bridge();
  return 1;
}
