#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bsp/board_api.h"
#include "hardware/flash.h"
#include "hardware/gpio.h"
#include "hardware/regs/io_qspi.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/sio.h"
#include "hardware/sync.h"
#include "hardware/watchdog.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
#include "pbns_proxy/byte_pump.h"
#include "pbns_proxy/credentials.h"
#include "pbns_proxy/network.h"
#include "pbns_proxy/provision_gate.h"
#include "pbns_proxy/tail_deadline.h"
#include "pico/flash.h"
#include "pico/stdlib.h"
#include "tusb.h"

#define DATA_CDC_INSTANCE UINT8_C(0)
#define PROVISION_CDC_INSTANCE UINT8_C(1)
#define BOOTSEL_QSPI_PIN 1U
#define TUNNEL_RING_CAPACITY 4096U
#define TUNNEL_AGGREGATION_THRESHOLD 2048U
#define TUNNEL_AGGREGATION_DEADLINE_US UINT64_C(5000)
#define TUNNEL_IDLE_PACING_US 50U
#define CONTROL_LINE_CAPACITY 608U
#define FLASH_OPERATION_TIMEOUT_MS UINT32_C(1000)
#define PBNS_CREDENTIALS_FLASH_BYTES                                           \
  (PBNS_CREDENTIALS_SECTOR_SIZE * PBNS_CREDENTIALS_SLOT_COUNT)
#define PBNS_CREDENTIALS_SLOT0_OFFSET                                          \
  (PBNS_FLASH_TOTAL_SIZE_BYTES - PBNS_CREDENTIALS_FLASH_BYTES)
#define PBNS_CREDENTIALS_SLOT1_OFFSET                                          \
  (PBNS_FLASH_TOTAL_SIZE_BYTES - PBNS_CREDENTIALS_SECTOR_SIZE)

_Static_assert(PICO_FLASH_SIZE_BYTES == PBNS_FLASH_TOTAL_SIZE_BYTES,
               "PBNS and Pico physical flash sizes differ");
_Static_assert(PBNS_FLASH_TOTAL_SIZE_BYTES >= PBNS_CREDENTIALS_FLASH_BYTES,
               "PBNS credential sectors exceed physical flash");
_Static_assert(PBNS_CREDENTIALS_SLOT0_OFFSET % PBNS_CREDENTIALS_SECTOR_SIZE ==
                   0U,
               "PBNS credential sector alignment mismatch");

typedef enum flash_mutation_type {
  FLASH_MUTATION_ERASE,
  FLASH_MUTATION_PROGRAM
} flash_mutation_type;

typedef struct flash_mutation {
  flash_mutation_type type;
  size_t offset;
  size_t length;
  const uint8_t *source;
} flash_mutation;

typedef struct provisioning_parser {
  uint8_t line[CONTROL_LINE_CAPACITY];
  size_t line_len;
  bool discarding;
  bool ready_sent;
  bool provisioned;
} provisioning_parser;

static const pbns_credentials_storage_ops credential_storage_ops;
static pbns_pico_network pico_network;
static pbns_network network_controller;
static pbns_byte_pump tunnel_pump;
static pbns_pump_session tunnel_session;
static uint8_t usb_to_tcp_storage[TUNNEL_RING_CAPACITY];
static uint8_t tcp_to_usb_storage[TUNNEL_RING_CAPACITY];
static bool tunnel_available;
static bool tunnel_was_ready;
static bool data_usb_bytes_queued;
static pbns_tail_deadline usb_to_tcp_tail;
static pbns_provision_gate provision_gate;
static pbns_provision_session provision_session;
static provisioning_parser provision_parser;
static bool provisioning_mode;

static void secure_zero(void *pointer, size_t size) {
  volatile uint8_t *cursor = pointer;
  while (size > 0U) {
    *cursor = UINT8_C(0);
    ++cursor;
    --size;
  }
}

static bool __no_inline_not_in_flash_func(bootsel_is_pressed)(void) {
  const uint32_t interrupt_state = save_and_disable_interrupts();
  hw_write_masked(&ioqspi_hw->io[BOOTSEL_QSPI_PIN].ctrl,
                  (uint32_t)GPIO_OVERRIDE_LOW
                      << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                  IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);
  for (volatile size_t delay = 0U; delay < 1000U; ++delay) {
  }
  const bool pressed =
      (sio_hw->gpio_hi_in & (UINT32_C(1) << BOOTSEL_QSPI_PIN)) == 0U;
  hw_write_masked(&ioqspi_hw->io[BOOTSEL_QSPI_PIN].ctrl,
                  (uint32_t)GPIO_OVERRIDE_NORMAL
                      << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                  IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);
  restore_interrupts(interrupt_state);
  return pressed;
}

static void __no_inline_not_in_flash_func(apply_flash_mutation)(void *context) {
  const flash_mutation *const mutation = context;
  if (mutation->type == FLASH_MUTATION_ERASE) {
    flash_range_erase((uint32_t)mutation->offset, mutation->length);
  } else {
    flash_range_program((uint32_t)mutation->offset, mutation->source,
                        mutation->length);
  }
}

static bool flash_range_is_valid(size_t offset, size_t length) {
  return offset <= PBNS_FLASH_TOTAL_SIZE_BYTES &&
         length <= PBNS_FLASH_TOTAL_SIZE_BYTES - offset;
}

static pbns_status credential_flash_read(void *context, size_t offset,
                                         pbns_buffer destination) {
  (void)context;
  if (destination.ptr == NULL || destination.len != 0U ||
      !flash_range_is_valid(offset, destination.cap)) {
    return PBNS_ERR_ARGUMENT;
  }
  memcpy(destination.ptr, (const uint8_t *)(XIP_BASE + (uintptr_t)offset),
         destination.cap);
  return PBNS_OK;
}

static pbns_status credential_flash_erase(void *context, size_t offset,
                                          size_t length) {
  (void)context;
  if (offset % PBNS_CREDENTIALS_SECTOR_SIZE != 0U ||
      length != PBNS_CREDENTIALS_SECTOR_SIZE ||
      !flash_range_is_valid(offset, length)) {
    return PBNS_ERR_ARGUMENT;
  }
  flash_mutation mutation = {
      .type = FLASH_MUTATION_ERASE,
      .offset = offset,
      .length = length,
      .source = NULL,
  };
  return flash_safe_execute(apply_flash_mutation, &mutation,
                            FLASH_OPERATION_TIMEOUT_MS) == PICO_OK
             ? PBNS_OK
             : PBNS_ERR_IO;
}

static pbns_status credential_flash_program(void *context, size_t offset,
                                            pbns_view source) {
  (void)context;
  if (source.ptr == NULL || source.len == 0U ||
      offset % PBNS_CREDENTIALS_PAGE_SIZE != 0U ||
      source.len % PBNS_CREDENTIALS_PAGE_SIZE != 0U ||
      !flash_range_is_valid(offset, source.len)) {
    return PBNS_ERR_ARGUMENT;
  }
  flash_mutation mutation = {
      .type = FLASH_MUTATION_PROGRAM,
      .offset = offset,
      .length = source.len,
      .source = source.ptr,
  };
  return flash_safe_execute(apply_flash_mutation, &mutation,
                            FLASH_OPERATION_TIMEOUT_MS) == PICO_OK
             ? PBNS_OK
             : PBNS_ERR_IO;
}

static const pbns_credentials_storage_ops credential_storage_ops = {
    .read = credential_flash_read,
    .erase = credential_flash_erase,
    .program = credential_flash_program,
};

static pbns_credentials_storage credential_storage(void) {
  return (pbns_credentials_storage){
      .ops = &credential_storage_ops,
      .context = NULL,
      .slot_offsets =
          {
              PBNS_CREDENTIALS_SLOT0_OFFSET,
              PBNS_CREDENTIALS_SLOT1_OFFSET,
          },
  };
}

static bool send_text(const char *text) {
  const size_t length = strlen(text);
  size_t offset = 0U;
  const absolute_time_t deadline = make_timeout_time_ms(1000U);
  while (offset < length && !time_reached(deadline)) {
    const uint32_t written = tud_cdc_n_write(
        PROVISION_CDC_INSTANCE, text + offset, (uint32_t)(length - offset));
    offset += written;
    tud_cdc_n_write_flush(PROVISION_CDC_INSTANCE);
    tud_task();
  }
  return offset == length;
}

static char hexadecimal_digit(uint8_t value) {
  return value < UINT8_C(10) ? (char)('0' + value)
                             : (char)('a' + value - UINT8_C(10));
}

static bool send_record_fingerprint(const uint8_t *record, size_t record_len) {
  uint8_t digest[PBNS_CREDENTIALS_SPKI_SIZE] = {0};
  char response[3U + PBNS_CREDENTIALS_SPKI_SIZE * 2U + 2U] = {0};
  if (mbedtls_sha256(record, record_len, digest, 0) != 0) {
    (void)send_text("ERROR internal failure\n");
    secure_zero(digest, sizeof(digest));
    secure_zero(response, sizeof(response));
    return false;
  }
  response[0] = 'O';
  response[1] = 'K';
  response[2] = ' ';
  for (size_t index = 0U; index < sizeof(digest); ++index) {
    response[3U + index * 2U] = hexadecimal_digit(digest[index] >> 4U);
    response[4U + index * 2U] =
        hexadecimal_digit(digest[index] & UINT8_C(0x0f));
  }
  response[3U + sizeof(digest) * 2U] = '\n';
  const bool sent = send_text(response);
  secure_zero(digest, sizeof(digest));
  secure_zero(response, sizeof(response));
  return sent;
}

static bool process_set_command(const uint8_t *line, size_t line_len) {
  if (line_len <= 4U || memcmp(line, "SET ", 4U) != 0) {
    return false;
  }
  uint8_t record[PBNS_CREDENTIALS_CBOR_MAX] = {0};
  size_t record_len = 0U;
  const int decode_status = mbedtls_base64_decode(
      record, sizeof(record), &record_len, line + 4U, line_len - 4U);
  pbns_credentials credentials = {0};
  pbns_status status = decode_status == 0
                           ? pbns_credentials_decode_cbor(
                                 (pbns_view){record, record_len}, &credentials)
                           : PBNS_ERR_FORMAT;
  if (status == PBNS_OK) {
    const pbns_credentials_storage storage = credential_storage();
    status = pbns_credentials_store(&storage, &credentials);
  }
  if (status == PBNS_OK && !send_record_fingerprint(record, record_len)) {
    status = PBNS_ERR_IO;
  }
  if (status != PBNS_OK) {
    (void)send_text("ERROR invalid record\n");
  }
  secure_zero(&credentials, sizeof(credentials));
  secure_zero(record, sizeof(record));
  return status == PBNS_OK;
}

static pbns_status data_usb_read(void *context, pbns_buffer destination,
                                 size_t *received) {
  (void)context;
  if (received == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *received = 0U;
  if (destination.len != 0U ||
      (destination.ptr == NULL && destination.cap > 0U) ||
      destination.cap > UINT32_MAX) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!tud_cdc_n_connected(DATA_CDC_INSTANCE)) {
    return PBNS_OK;
  }
  const uint32_t available = tud_cdc_n_available(DATA_CDC_INSTANCE);
  if (available == 0U || destination.cap == 0U) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  const size_t amount =
      destination.cap < (size_t)available ? destination.cap : (size_t)available;
  const uint32_t actual =
      tud_cdc_n_read(DATA_CDC_INSTANCE, destination.ptr, (uint32_t)amount);
  if (actual == 0U) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  if (actual > amount) {
    return PBNS_ERR_IO;
  }
  *received = actual;
  return PBNS_OK;
}

static pbns_status data_usb_write(void *context, pbns_view source,
                                  size_t *written) {
  (void)context;
  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (source.ptr == NULL || source.len == 0U || source.len > UINT32_MAX) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!tud_cdc_n_connected(DATA_CDC_INSTANCE)) {
    return PBNS_ERR_TRANSPORT;
  }
  const uint32_t available = tud_cdc_n_write_available(DATA_CDC_INSTANCE);
  if (available == 0U) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  const size_t amount =
      source.len < (size_t)available ? source.len : (size_t)available;
  const uint32_t actual =
      tud_cdc_n_write(DATA_CDC_INSTANCE, source.ptr, (uint32_t)amount);
  if (actual == 0U) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  data_usb_bytes_queued = true;
  if (actual > amount) {
    return PBNS_ERR_IO;
  }
  *written = actual;
  return PBNS_OK;
}

static void tunnel_init(void) {
  static pbns_credentials credentials;
  secure_zero(&credentials, sizeof(credentials));
  const pbns_credentials_storage storage = credential_storage();
  pbns_status status = pbns_credentials_load(&storage, &credentials);
  if (status == PBNS_OK) {
    status = pbns_pico_network_init(&pico_network, &credentials);
  }
  secure_zero(&credentials, sizeof(credentials));
  if (status != PBNS_OK) {
    return;
  }
  pbns_network_init(&network_controller);
  pbns_byte_pump_init(
      &tunnel_pump,
      (pbns_buffer){usb_to_tcp_storage, 0U, sizeof(usb_to_tcp_storage)},
      (pbns_buffer){tcp_to_usb_storage, 0U, sizeof(tcp_to_usb_storage)});
  pbns_pump_session_init(&tunnel_session);
  pbns_tail_deadline_init(&usb_to_tcp_tail,
                          tunnel_pump.usb_to_tls_read_generation);
  tunnel_available = true;
}

static void tunnel_deinit(void) {
  tunnel_available = false;
  tunnel_was_ready = false;
  pbns_tail_deadline_reset(&usb_to_tcp_tail,
                           tunnel_pump.usb_to_tls_read_generation);
  pbns_pico_network_deinit(&pico_network);
  pbns_byte_pump_cancel(&tunnel_pump);
  secure_zero(usb_to_tcp_storage, sizeof(usb_to_tcp_storage));
  secure_zero(tcp_to_usb_storage, sizeof(tcp_to_usb_storage));
  secure_zero(&tunnel_pump, sizeof(tunnel_pump));
  secure_zero(&tunnel_session, sizeof(tunnel_session));
  secure_zero(&network_controller, sizeof(network_controller));
}

static bool tunnel_task(void) {
  if (!tunnel_available) {
    return true;
  }
  const bool usb_connected = tud_cdc_n_connected(DATA_CDC_INSTANCE);
  bool disconnected = false;
  if (pbns_pump_session_observe(&tunnel_session, usb_connected,
                                &disconnected) != PBNS_OK) {
    return true;
  }
  if (disconnected) {
    tud_cdc_n_read_flush(DATA_CDC_INSTANCE);
    (void)tud_cdc_n_write_clear(DATA_CDC_INSTANCE);
    pbns_byte_pump_reset(&tunnel_pump);
    pbns_tail_deadline_reset(&usb_to_tcp_tail,
                             tunnel_pump.usb_to_tls_read_generation);
  }
  const pbns_network_ops network_ops =
      pbns_pico_network_operations(&pico_network);
  bool network_progress = false;
  (void)pbns_network_step(&network_controller, &network_ops,
                          to_ms_64_since_boot(get_absolute_time()),
                          usb_connected, &network_progress);
  const bool ready = network_controller.state == PBNS_NETWORK_READY;
  if (ready != tunnel_was_ready) {
    pbns_byte_pump_reset(&tunnel_pump);
    pbns_tail_deadline_reset(&usb_to_tcp_tail,
                             tunnel_pump.usb_to_tls_read_generation);
    tunnel_was_ready = ready;
  }
  if (!ready || !usb_connected) {
    pbns_tail_deadline_reset(&usb_to_tcp_tail,
                             tunnel_pump.usb_to_tls_read_generation);
    return !network_progress;
  }
  const pbns_pump_endpoint usb = {
      .read = data_usb_read,
      .write = data_usb_write,
      .context = NULL,
  };
  const pbns_pump_endpoint tcp = pbns_pico_network_tcp_endpoint(&pico_network);
  const uint64_t now_us = time_us_64();
  const bool force_usb_to_tcp_write = pbns_tail_deadline_should_force(
      &usb_to_tcp_tail, now_us, TUNNEL_AGGREGATION_DEADLINE_US);
  const pbns_byte_pump_policy policy = {
      .usb_to_tls_minimum_write = TUNNEL_AGGREGATION_THRESHOLD,
      .tls_to_usb_minimum_writable = TUNNEL_AGGREGATION_THRESHOLD,
      .force_usb_to_tls_write = force_usb_to_tcp_write,
  };
  size_t pump_steps = 0U;
  bool pump_progress = false;
  data_usb_bytes_queued = false;
  const pbns_status status = pbns_byte_pump_batch_with_policy(
      &tunnel_pump, usb, tcp, &policy, &pump_steps, &pump_progress);
  (void)pump_steps;
  if (data_usb_bytes_queued) {
    tud_cdc_n_write_flush(DATA_CDC_INSTANCE);
  }
  if (status != PBNS_OK || pbns_byte_pump_is_complete(&tunnel_pump)) {
    if (status != PBNS_OK) {
      pbns_pico_network_fail(&pico_network, status);
    }
    pbns_byte_pump_cancel(&tunnel_pump);
    pbns_tail_deadline_reset(&usb_to_tcp_tail,
                             tunnel_pump.usb_to_tls_read_generation);
  } else {
    pbns_tail_deadline_observe_input(
        &usb_to_tcp_tail, tunnel_pump.usb_to_tls_read_generation, time_us_64());
    const size_t pending = pbns_byte_ring_size(&tunnel_pump.usb_to_tls);
    pbns_tail_deadline_set_pending(&usb_to_tcp_tail,
                                   pending != 0U &&
                                       pending < TUNNEL_AGGREGATION_THRESHOLD &&
                                       !tunnel_pump.usb_source_closed);
  }
  const bool rings_pending =
      pbns_byte_ring_size(&tunnel_pump.usb_to_tls) != 0U ||
      pbns_byte_ring_size(&tunnel_pump.tls_to_usb) != 0U;
  return !network_progress && !pump_progress && !rings_pending &&
         !usb_to_tcp_tail.pending;
}

static void provisioning_parser_reset(void) {
  secure_zero(&provision_parser, sizeof(provision_parser));
}

static void activate_provisioning(void) {
  tunnel_deinit();
  tud_cdc_n_read_flush(PROVISION_CDC_INSTANCE);
  provisioning_parser_reset();
  const pbns_status status = pbns_provision_session_activate(
      &provision_session, tud_cdc_n_connected(PROVISION_CDC_INSTANCE));
  if (status == PBNS_OK) {
    provisioning_mode = true;
  }
}

static void physical_gate_task(void) {
  const uint64_t now_ms = to_ms_64_since_boot(get_absolute_time());
  if (!pbns_provision_gate_sample_due(&provision_gate, now_ms)) {
    return;
  }
  bool activated = false;
  const pbns_status status = pbns_provision_gate_observe(
      &provision_gate, now_ms, bootsel_is_pressed(), &activated);
  if (status == PBNS_OK && activated) {
    activate_provisioning();
  }
}

static void provisioning_task(void) {
  const bool connected = tud_cdc_n_connected(PROVISION_CDC_INSTANCE);
  bool opened = false;
  if (pbns_provision_session_observe(&provision_session, connected, &opened) !=
      PBNS_OK) {
    provisioning_parser_reset();
    return;
  }
  if (!connected) {
    provisioning_parser_reset();
    return;
  }
  if (opened) {
    tud_cdc_n_read_flush(PROVISION_CDC_INSTANCE);
    provisioning_parser_reset();
  }
  if (!pbns_provision_session_is_ready(&provision_session)) {
    provisioning_parser_reset();
    return;
  }
  if (!provision_parser.ready_sent) {
    provision_parser.ready_sent = send_text("PBNS-PROVISION-v1 READY\n");
  }
  while (tud_cdc_n_available(PROVISION_CDC_INSTANCE) > 0U) {
    const int32_t value = tud_cdc_n_read_char(PROVISION_CDC_INSTANCE);
    if (value < 0) {
      return;
    }
    const uint8_t octet = (uint8_t)value;
    if (octet == '\n') {
      if (provision_parser.discarding) {
        (void)send_text("ERROR invalid command\n");
      } else {
        if (provision_parser.line_len > 0U &&
            provision_parser.line[provision_parser.line_len - 1U] == '\r') {
          --provision_parser.line_len;
        }
        if (provision_parser.line_len == sizeof("REBOOT") - 1U &&
            memcmp(provision_parser.line, "REBOOT", sizeof("REBOOT") - 1U) ==
                0 &&
            provision_parser.provisioned) {
          provisioning_parser_reset();
          watchdog_reboot(0U, 0U, 0U);
        } else {
          provision_parser.provisioned = process_set_command(
              provision_parser.line, provision_parser.line_len);
        }
      }
      secure_zero(provision_parser.line, sizeof(provision_parser.line));
      provision_parser.line_len = 0U;
      provision_parser.discarding = false;
    } else if (provision_parser.discarding) {
      continue;
    } else if (provision_parser.line_len >= sizeof(provision_parser.line)) {
      secure_zero(provision_parser.line, sizeof(provision_parser.line));
      provision_parser.line_len = 0U;
      provision_parser.discarding = true;
    } else {
      provision_parser.line[provision_parser.line_len] = octet;
      ++provision_parser.line_len;
    }
  }
}

int main(void) {
  board_init();
  if (!tusb_init()) {
    while (true) {
      tight_loop_contents();
    }
  }
  pbns_provision_gate_init(&provision_gate);
  pbns_provision_session_init(&provision_session);
  tunnel_init();
  while (true) {
    tud_task_ext(0U, false);
    if (!provisioning_mode) {
      physical_gate_task();
    }
    if (provisioning_mode) {
      provisioning_task();
    } else if (tunnel_task()) {
      sleep_us(TUNNEL_IDLE_PACING_US);
    }
  }
}
