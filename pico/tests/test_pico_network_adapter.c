#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "lwip/err.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "pbns_proxy/network.h"
#include "pico/cyw43_arch.h"

typedef enum test_event {
  TEST_EVENT_LOCK = 1,
  TEST_EVENT_WRITE,
  TEST_EVENT_OUTPUT,
  TEST_EVENT_UNLOCK
} test_event;

#define TEST_EVENT_CAPACITY 8U

static test_event events[TEST_EVENT_CAPACITY];
static size_t event_count;
static bool unlocked;
static err_t write_result;
static err_t output_result;
static uint16_t send_capacity;
static size_t write_calls;
static size_t output_calls;
static const void *last_source;
static uint16_t last_length;
static uint8_t last_flags;
static struct tcp_pcb *last_pcb;
static pbns_pico_network *observed_network;
static pbns_status status_at_unlock;
static struct tcp_pcb fake_pcb;
static uint8_t fake_pbuf_data[16];
static size_t pbuf_free_calls;
static size_t tcp_abort_calls;
#if defined(PBNS_RAW_TUNNEL_DIAGNOSTIC)
static pbns_raw_diagnostic_state diagnostic;
#endif
struct cyw43_t cyw43_state;

static void record_event(test_event event) {
  assert(!unlocked);
  assert(event_count < TEST_EVENT_CAPACITY);
  events[event_count] = event;
  ++event_count;
}

void cyw43_arch_lwip_begin(void) { record_event(TEST_EVENT_LOCK); }

void cyw43_arch_lwip_end(void) {
  record_event(TEST_EVENT_UNLOCK);
  status_at_unlock = observed_network == NULL
                         ? PBNS_ERR_STATE
                         : observed_network->asynchronous_status;
  unlocked = true;
}

uint16_t tcp_sndbuf(const struct tcp_pcb *pcb) {
  assert(!unlocked);
  assert(pcb == &fake_pcb);
  return send_capacity;
}

err_t tcp_write(struct tcp_pcb *pcb, const void *source, uint16_t length,
                uint8_t flags) {
  record_event(TEST_EVENT_WRITE);
  ++write_calls;
  last_pcb = pcb;
  last_source = source;
  last_length = length;
  last_flags = flags;
  return write_result;
}

err_t tcp_output(struct tcp_pcb *pcb) {
  record_event(TEST_EVENT_OUTPUT);
  ++output_calls;
  last_pcb = pcb;
  return output_result;
}

void tcp_recved(struct tcp_pcb *pcb, uint16_t length) {
  (void)pcb;
  (void)length;
}

uint8_t pbuf_free(struct pbuf *packet) {
  assert(packet != NULL);
  ++pbuf_free_calls;
  return 1U;
}

uint16_t pbuf_copy_partial(const struct pbuf *packet, void *destination,
                           uint16_t length, uint16_t offset) {
  assert(packet != NULL);
  assert(destination != NULL);
  assert((size_t)offset + (size_t)length <= packet->tot_len);
  memcpy(destination, &fake_pbuf_data[offset], length);
  return length;
}

void tcp_abort(struct tcp_pcb *pcb) {
  assert(pcb == &fake_pcb);
  ++tcp_abort_calls;
}

static void reset_case(pbns_pico_network *network) {
  *network = (pbns_pico_network){0};
  network->initialized = true;
  network->tcp_connected = true;
  network->connection = &fake_pcb;
  network->asynchronous_status = PBNS_OK;
#if defined(PBNS_RAW_TUNNEL_DIAGNOSTIC)
  pbns_raw_diagnostic_init(&diagnostic);
  network->diagnostic = &diagnostic;
#endif
  observed_network = network;
  event_count = 0U;
  unlocked = false;
  write_result = ERR_OK;
  output_result = ERR_OK;
  send_capacity = UINT16_MAX;
  write_calls = 0U;
  output_calls = 0U;
  last_source = NULL;
  last_length = 0U;
  last_flags = 0U;
  last_pcb = NULL;
  status_at_unlock = PBNS_ERR_STATE;
  pbuf_free_calls = 0U;
  tcp_abort_calls = 0U;
}

static void expect_events(const test_event *expected, size_t count) {
  assert(event_count == count);
  for (size_t index = 0U; index < count; ++index) {
    assert(events[index] == expected[index]);
  }
}

static pbns_status write_bytes(pbns_pico_network *network, const uint8_t *bytes,
                               size_t length, size_t *written) {
  const pbns_pump_endpoint endpoint = pbns_pico_network_tcp_endpoint(network);
  assert(endpoint.write != NULL);
  assert(endpoint.context == network);
  return endpoint.write(endpoint.context, (pbns_view){bytes, length}, written);
}

static void test_tcp_write_err_ok_output_err_rte_is_terminal(void) {
  static const test_event expected[] = {TEST_EVENT_LOCK, TEST_EVENT_WRITE,
                                        TEST_EVENT_OUTPUT, TEST_EVENT_UNLOCK};
  const uint8_t bytes[] = {1U, 2U, 3U, 4U, 5U, 6U};
  pbns_pico_network network = {0};
  reset_case(&network);
  send_capacity = 4U;
  output_result = ERR_RTE;
  size_t written = SIZE_MAX;

  assert(write_bytes(&network, bytes, sizeof(bytes), &written) ==
         PBNS_ERR_TRANSPORT);
  assert(written == 0U);
  assert(network.asynchronous_status == PBNS_ERR_TRANSPORT);
  assert(status_at_unlock == PBNS_ERR_TRANSPORT);
  assert(write_calls == 1U);
  assert(output_calls == 1U);
  assert(last_pcb == &fake_pcb);
  assert(last_source == bytes);
  assert(last_length == 4U);
  assert(last_flags == TCP_WRITE_FLAG_COPY);
  expect_events(expected, sizeof(expected) / sizeof(expected[0]));
#if defined(PBNS_RAW_TUNNEL_DIAGNOSTIC)
  assert(diagnostic.tcp_write_result == PBNS_TCP_IO_OK);
  assert(diagnostic.tcp_output_result == PBNS_TCP_IO_FAILED);
#endif
}

static void test_tcp_write_err_mem_is_retry(void) {
  static const test_event expected[] = {TEST_EVENT_LOCK, TEST_EVENT_WRITE,
                                        TEST_EVENT_UNLOCK};
  const uint8_t byte = 7U;
  pbns_pico_network network = {0};
  reset_case(&network);
  write_result = ERR_MEM;
  size_t written = SIZE_MAX;

  assert(write_bytes(&network, &byte, 1U, &written) == PBNS_ERR_WOULD_BLOCK);
  assert(written == 0U);
  assert(network.asynchronous_status == PBNS_OK);
  assert(status_at_unlock == PBNS_OK);
  assert(write_calls == 1U);
  assert(output_calls == 0U);
  expect_events(expected, sizeof(expected) / sizeof(expected[0]));
#if defined(PBNS_RAW_TUNNEL_DIAGNOSTIC)
  assert(diagnostic.tcp_write_result == PBNS_TCP_IO_RETRY);
  assert(diagnostic.tcp_output_result == PBNS_TCP_IO_NOT_RUN);
#endif
}

static void test_tcp_write_err_rte_is_terminal(void) {
  static const test_event expected[] = {TEST_EVENT_LOCK, TEST_EVENT_WRITE,
                                        TEST_EVENT_UNLOCK};
  const uint8_t byte = 8U;
  pbns_pico_network network = {0};
  reset_case(&network);
  write_result = ERR_RTE;
  size_t written = SIZE_MAX;

  assert(write_bytes(&network, &byte, 1U, &written) == PBNS_ERR_TRANSPORT);
  assert(written == 0U);
  assert(network.asynchronous_status == PBNS_ERR_TRANSPORT);
  assert(status_at_unlock == PBNS_ERR_TRANSPORT);
  assert(write_calls == 1U);
  assert(output_calls == 0U);
  expect_events(expected, sizeof(expected) / sizeof(expected[0]));
#if defined(PBNS_RAW_TUNNEL_DIAGNOSTIC)
  assert(diagnostic.tcp_write_result == PBNS_TCP_IO_FAILED);
  assert(diagnostic.tcp_output_result == PBNS_TCP_IO_NOT_RUN);
#endif
}

static void test_tcp_write_and_output_success(void) {
  static const test_event expected[] = {TEST_EVENT_LOCK, TEST_EVENT_WRITE,
                                        TEST_EVENT_OUTPUT, TEST_EVENT_UNLOCK};
  const uint8_t bytes[] = {9U, 10U, 11U};
  pbns_pico_network network = {0};
  reset_case(&network);
  size_t written = 0U;

  assert(write_bytes(&network, bytes, sizeof(bytes), &written) == PBNS_OK);
  assert(written == sizeof(bytes));
  assert(network.asynchronous_status == PBNS_OK);
  assert(status_at_unlock == PBNS_OK);
  assert(write_calls == 1U);
  assert(output_calls == 1U);
  assert(last_source == bytes);
  assert(last_length == sizeof(bytes));
  assert(last_flags == TCP_WRITE_FLAG_COPY);
  expect_events(expected, sizeof(expected) / sizeof(expected[0]));
#if defined(PBNS_RAW_TUNNEL_DIAGNOSTIC)
  assert(diagnostic.tcp_write_result == PBNS_TCP_IO_OK);
  assert(diagnostic.tcp_output_result == PBNS_TCP_IO_OK);
#endif
}

static void test_zero_send_capacity_is_retry(void) {
  static const test_event expected[] = {TEST_EVENT_LOCK, TEST_EVENT_UNLOCK};
  const uint8_t byte = 12U;
  pbns_pico_network network = {0};
  reset_case(&network);
  send_capacity = 0U;
  size_t written = SIZE_MAX;

  assert(write_bytes(&network, &byte, 1U, &written) == PBNS_ERR_WOULD_BLOCK);
  assert(written == 0U);
  assert(network.asynchronous_status == PBNS_OK);
  assert(status_at_unlock == PBNS_OK);
  assert(write_calls == 0U);
  assert(output_calls == 0U);
  expect_events(expected, sizeof(expected) / sizeof(expected[0]));
#if defined(PBNS_RAW_TUNNEL_DIAGNOSTIC)
  assert(diagnostic.tcp_write_result == PBNS_TCP_IO_NOT_RUN);
  assert(diagnostic.tcp_output_result == PBNS_TCP_IO_NOT_RUN);
#endif
}

#if defined(PBNS_RAW_TUNNEL_DIAGNOSTIC)
static void test_diagnostic_attachment_is_locked_and_fail_closed(void) {
  static const test_event expected[] = {TEST_EVENT_LOCK, TEST_EVENT_UNLOCK};
  pbns_pico_network network = {0};
  reset_case(&network);
  network.diagnostic = NULL;
  event_count = 0U;
  unlocked = false;
  assert(pbns_pico_network_attach_diagnostic(&network, &diagnostic) == PBNS_OK);
  assert(network.diagnostic == &diagnostic);
  expect_events(expected, sizeof(expected) / sizeof(expected[0]));
  event_count = 0U;
  unlocked = false;
  assert(pbns_pico_network_observe_diagnostic(
             &network, PBNS_RAW_OBSERVE_CDC_RX) == PBNS_OK);
  assert(diagnostic.cdc_rx_callbacks == 1U);
  expect_events(expected, sizeof(expected) / sizeof(expected[0]));
  assert(pbns_pico_network_attach_diagnostic(NULL, &diagnostic) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_pico_network_attach_diagnostic(&network, NULL) ==
         PBNS_ERR_ARGUMENT);
}

#if defined(PBNS_PICO_NETWORK_TEST)
static void test_orderly_tcp_eof_drains_before_source_close(void) {
  uint8_t ring_storage[32] = {0};
  uint8_t destination_storage[8] = {0};
  pbns_pico_network network = {0};
  reset_case(&network);
  pbns_byte_ring_init(&network.tcp_rx,
                      (pbns_buffer){ring_storage, 0U, sizeof(ring_storage)});
  fake_pbuf_data[0] = 0x17U;
  fake_pbuf_data[1] = 0x03U;
  fake_pbuf_data[2] = 0x03U;
  struct pbuf packet = {.tot_len = 3U};

  assert(pbns_pico_network_test_receive(&network, &fake_pcb, &packet, ERR_OK) ==
         ERR_OK);
  assert(pbns_pico_network_test_receive(&network, &fake_pcb, NULL, ERR_OK) ==
         ERR_OK);
  assert(network.remote_closed);
  assert(network.asynchronous_status == PBNS_OK);

  const pbns_pump_endpoint endpoint = pbns_pico_network_tcp_endpoint(&network);
  size_t received = SIZE_MAX;
  unlocked = false;
  assert(endpoint.read(endpoint.context,
                       (pbns_buffer){destination_storage, 0U,
                                     sizeof(destination_storage)},
                       &received) == PBNS_OK);
  assert(received == 3U);
  assert(memcmp(destination_storage, fake_pbuf_data, received) == 0);

  unlocked = false;
  received = SIZE_MAX;
  assert(endpoint.read(endpoint.context,
                       (pbns_buffer){destination_storage, 0U,
                                     sizeof(destination_storage)},
                       &received) == PBNS_OK);
  assert(received == 0U);
}

static void test_tcp_receive_callback_observes_before_pump(void) {
  uint8_t ring_storage[32] = {0};
  pbns_pico_network network = {0};
  reset_case(&network);
  pbns_byte_ring_init(&network.tcp_rx,
                      (pbns_buffer){ring_storage, 0U, sizeof(ring_storage)});
  fake_pbuf_data[0] = 0x16U;
  fake_pbuf_data[1] = 0x03U;
  fake_pbuf_data[2] = 0x03U;
  struct pbuf packet = {.tot_len = 3U};

  assert(pbns_pico_network_test_receive(&network, &fake_pcb, &packet, ERR_OK) ==
         ERR_OK);
  assert(diagnostic.tcp_rx_callbacks == 1U);
  assert((diagnostic.milestones & PBNS_RAW_MILESTONE_TCP_RX) != 0U);
  assert(pbns_byte_ring_size(&network.tcp_rx) == 3U);
  assert(pbuf_free_calls == 1U);
  assert(tcp_abort_calls == 0U);
  assert(event_count == 0U);
}
#endif
#endif

static void test_arguments_and_open_state_fail_closed(void) {
  static const test_event locked_only[] = {TEST_EVENT_LOCK, TEST_EVENT_UNLOCK};
  const uint8_t byte = 13U;
  pbns_pico_network network = {0};
  reset_case(&network);
  pbns_pump_endpoint endpoint = pbns_pico_network_tcp_endpoint(&network);
  size_t written = SIZE_MAX;

  assert(endpoint.write(endpoint.context, (pbns_view){&byte, 1U}, NULL) ==
         PBNS_ERR_ARGUMENT);
  assert(event_count == 0U);
  assert(endpoint.write(endpoint.context, (pbns_view){NULL, 1U}, &written) ==
         PBNS_ERR_ARGUMENT);
  assert(written == 0U);
  assert(event_count == 0U);
  written = SIZE_MAX;
  assert(endpoint.write(endpoint.context, (pbns_view){&byte, 0U}, &written) ==
         PBNS_ERR_ARGUMENT);
  assert(written == 0U);
  assert(event_count == 0U);

  endpoint.context = NULL;
  written = SIZE_MAX;
  assert(endpoint.write(endpoint.context, (pbns_view){&byte, 1U}, &written) ==
         PBNS_ERR_ARGUMENT);
  assert(written == 0U);
  assert(event_count == 0U);

  reset_case(&network);
  network.tcp_connected = false;
  written = SIZE_MAX;
  assert(write_bytes(&network, &byte, 1U, &written) == PBNS_ERR_WOULD_BLOCK);
  assert(written == 0U);
  assert(write_calls == 0U);
  assert(output_calls == 0U);
  expect_events(locked_only, sizeof(locked_only) / sizeof(locked_only[0]));

  reset_case(&network);
  network.connection = NULL;
  written = SIZE_MAX;
  assert(write_bytes(&network, &byte, 1U, &written) == PBNS_ERR_WOULD_BLOCK);
  assert(written == 0U);
  assert(write_calls == 0U);
  assert(output_calls == 0U);
  expect_events(locked_only, sizeof(locked_only) / sizeof(locked_only[0]));

  network.initialized = false;
  endpoint = pbns_pico_network_tcp_endpoint(&network);
  assert(endpoint.read == NULL);
  assert(endpoint.write == NULL);
  assert(endpoint.context == NULL);
  endpoint = pbns_pico_network_tcp_endpoint(NULL);
  assert(endpoint.read == NULL);
  assert(endpoint.write == NULL);
  assert(endpoint.context == NULL);
}

int main(void) {
  test_tcp_write_err_ok_output_err_rte_is_terminal();
  test_tcp_write_err_mem_is_retry();
  test_tcp_write_err_rte_is_terminal();
  test_tcp_write_and_output_success();
  test_zero_send_capacity_is_retry();
#if defined(PBNS_RAW_TUNNEL_DIAGNOSTIC)
  test_diagnostic_attachment_is_locked_and_fail_closed();
#if defined(PBNS_PICO_NETWORK_TEST)
  test_orderly_tcp_eof_drains_before_source_close();
  test_tcp_receive_callback_observes_before_pump();
#endif
#endif
  test_arguments_and_open_state_fail_closed();
  return 0;
}
