#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bsp/board_api.h"
#include "hardware/regs/addressmap.h"
#include "hardware/structs/watchdog.h"
#include "hardware/sync.h"
#include "hardware/watchdog.h"
#include "pbns_proxy/credentials.h"
#include "pbns_proxy/diagnostic.h"
#include "pbns_proxy/diagnostic_storage.h"
#include "pbns_proxy/diagnostic_usb.h"
#include "pbns_proxy/network.h"
#include "pbns_proxy/pico_tls_diagnostic_baseline.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"
#include "tusb.h"

#define DIAGNOSTIC_CDC_INSTANCE UINT8_C(0)
#define DIAGNOSTIC_DTR_TIMEOUT_MS UINT32_C(300000)

_Static_assert(PICO_FLASH_SIZE_BYTES == PBNS_FLASH_TOTAL_SIZE_BYTES,
               "PBNS diagnostic and Pico physical flash sizes differ");

static pbns_pico_tls_diagnostic_baseline tls_baseline;
static bool tls_baseline_initialized;

static void secure_zero(void *pointer, size_t size) {
  volatile uint8_t *cursor = pointer;
  while (size > 0U) {
    *cursor = UINT8_C(0);
    ++cursor;
    --size;
  }
}

static void terminal_loop(void) {
  while (true) {
    tud_task();
    sleep_ms(1U);
  }
}

static void record_result_and_reboot(pbns_diagnostic_result result,
                                     pbns_credentials *credentials) {
  if (!pbns_diagnostic_result_is_terminal(result)) {
    result = PBNS_DIAGNOSTIC_INTERNAL_FAILURE;
  }
  if (tls_baseline_initialized) {
    pbns_pico_tls_diagnostic_baseline_deinit(&tls_baseline);
    tls_baseline_initialized = false;
  }
  if (credentials != NULL) {
    secure_zero(credentials, sizeof(*credentials));
  }

  watchdog_hw->scratch[0] = 0U;
  watchdog_hw->scratch[1] = (uint32_t)result;
  watchdog_hw->scratch[2] = ~(uint32_t)result;
  __compiler_memory_barrier();
  /* A magia é escrita no fim para invalidar um registo interrompido. */
  watchdog_hw->scratch[0] = PBNS_DIAGNOSTIC_MAGIC;
  __compiler_memory_barrier();
  watchdog_reboot(0U, 0U, 0U);
  while (true) {
    tight_loop_contents();
  }
}

static void wait_for_dtr_or_reboot(void) {
  const absolute_time_t deadline =
      make_timeout_time_ms(DIAGNOSTIC_DTR_TIMEOUT_MS);
  while (!tud_cdc_n_connected(DIAGNOSTIC_CDC_INSTANCE)) {
    tud_task();
    if (time_reached(deadline)) {
      record_result_and_reboot(PBNS_DIAGNOSTIC_DTR_TIMEOUT, NULL);
    }
    sleep_ms(1U);
  }
}

static pbns_diagnostic_wifi_pending sample_wifi_pending(void) {
  cyw43_arch_lwip_begin();
  const int status = cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA);
  cyw43_arch_lwip_end();
  switch (status) {
  case CYW43_LINK_DOWN:
    return PBNS_DIAGNOSTIC_WIFI_PENDING_DOWN;
  case CYW43_LINK_JOIN:
    return PBNS_DIAGNOSTIC_WIFI_PENDING_JOIN;
  case CYW43_LINK_NOIP:
    return PBNS_DIAGNOSTIC_WIFI_PENDING_NOIP;
  default:
    return PBNS_DIAGNOSTIC_WIFI_PENDING_UNKNOWN;
  }
}

static void run_network_diagnostic(void) {
  wait_for_dtr_or_reboot();

  pbns_diagnostic_storage storage = {0};
  if (pbns_diagnostic_storage_init(&storage,
                                   (const uint8_t *)(uintptr_t)XIP_BASE,
                                   PBNS_FLASH_TOTAL_SIZE_BYTES) != PBNS_OK) {
    record_result_and_reboot(PBNS_DIAGNOSTIC_INTERNAL_FAILURE, NULL);
  }

  pbns_credentials credentials = {0};
  if (pbns_credentials_load(&storage.credentials, &credentials) != PBNS_OK) {
    record_result_and_reboot(PBNS_DIAGNOSTIC_CREDENTIAL_FAILURE, &credentials);
  }
  if (pbns_pico_tls_diagnostic_baseline_init(&tls_baseline, &credentials) !=
      PBNS_OK) {
    record_result_and_reboot(PBNS_DIAGNOSTIC_NETWORK_INIT_FAILURE,
                             &credentials);
  }
  tls_baseline_initialized = true;
  secure_zero(&credentials, sizeof(credentials));

  pbns_network controller = {0};
  pbns_network_init(&controller);
  const pbns_network_ops operations =
      pbns_pico_tls_diagnostic_baseline_operations(&tls_baseline);
  pbns_diagnostic_wifi_pending last_wifi = PBNS_DIAGNOSTIC_WIFI_PENDING_UNKNOWN;
  while (true) {
    tud_task();
    const pbns_network_state stage = controller.state;
    if (stage == PBNS_NETWORK_WIFI_CONNECTING) {
      last_wifi = sample_wifi_pending();
    }
    bool made_progress = false;
    const pbns_status status = pbns_network_step(
        &controller, &operations, to_ms_64_since_boot(get_absolute_time()),
        true, &made_progress);
    (void)made_progress;
    if (controller.state == PBNS_NETWORK_READY) {
      record_result_and_reboot(PBNS_DIAGNOSTIC_TLS_READY, &credentials);
    }
    if (status != PBNS_OK) {
      const pbns_diagnostic_result result =
          stage == PBNS_NETWORK_WIFI_CONNECTING && status == PBNS_ERR_TIMEOUT
              ? pbns_diagnostic_result_for_wifi_timeout(last_wifi)
              : pbns_diagnostic_result_for_network(stage, status);
      record_result_and_reboot(result, &credentials);
    }
    sleep_ms(1U);
  }
}

int main(void) {
  pbns_diagnostic_result terminal_result = PBNS_DIAGNOSTIC_AWAITING_DTR;
  const bool terminal = pbns_diagnostic_scratch_decode(
      watchdog_hw->scratch[0], watchdog_hw->scratch[1], watchdog_hw->scratch[2],
      &terminal_result);
  const uint16_t bcd_device = terminal ? (uint16_t)terminal_result
                                       : (uint16_t)PBNS_DIAGNOSTIC_AWAITING_DTR;
  if (!pbns_diagnostic_usb_set_bcd_device(bcd_device)) {
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
  run_network_diagnostic();
  return 1;
}
