#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns_proxy/byte_pump.h"
#include "pbns_proxy/byte_ring.h"
#include "pbns_proxy/tail_deadline.h"
#include "pbns_proxy/tcp_write_outcome.h"

#define ENDPOINT_CAPACITY 97U
#define RANDOM_SCHEDULES 100000U
#define STEP_LIMIT 2048U

typedef struct fake_endpoint {
  uint8_t input[ENDPOINT_CAPACITY];
  size_t input_len;
  size_t read_offset;
  uint8_t output[ENDPOINT_CAPACITY];
  size_t output_len;
  size_t max_read;
  size_t max_write;
  size_t read_calls;
  size_t write_calls;
  size_t read_block_period;
  size_t write_block_period;
  size_t fail_read_call;
  size_t fail_write_call;
  pbns_status read_failure;
  pbns_status write_failure;
  size_t internally_queued_bytes;
  bool fail_after_internal_queue;
  bool zero_write;
} fake_endpoint;

static uint32_t random_state = UINT32_C(0x6d2b79f5);

static uint32_t next_random(void) {
  uint32_t value = random_state;
  value ^= value << 13U;
  value ^= value >> 17U;
  value ^= value << 5U;
  random_state = value;
  return value;
}

static size_t minimum_size(size_t left, size_t right) {
  return left < right ? left : right;
}

static pbns_status fake_read(void *context, pbns_buffer destination,
                             size_t *received) {
  fake_endpoint *const endpoint = context;
  assert(endpoint != NULL);
  assert(received != NULL);
  assert(destination.len == 0U);
  *received = 0U;
  ++endpoint->read_calls;
  if (endpoint->fail_read_call != 0U &&
      endpoint->read_calls == endpoint->fail_read_call) {
    return endpoint->read_failure;
  }
  if (endpoint->read_block_period != 0U &&
      endpoint->read_calls % endpoint->read_block_period == 0U) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  if (endpoint->read_offset == endpoint->input_len) {
    return PBNS_OK;
  }
  const size_t remaining = endpoint->input_len - endpoint->read_offset;
  const size_t limit = minimum_size(destination.cap, endpoint->max_read);
  const size_t amount = minimum_size(remaining, limit);
  assert(amount > 0U);
  memcpy(destination.ptr, endpoint->input + endpoint->read_offset, amount);
  endpoint->read_offset += amount;
  *received = amount;
  return PBNS_OK;
}

static pbns_status fake_write(void *context, pbns_view source,
                              size_t *written) {
  fake_endpoint *const endpoint = context;
  assert(endpoint != NULL);
  assert(written != NULL);
  *written = 0U;
  ++endpoint->write_calls;
  if (endpoint->fail_write_call != 0U &&
      endpoint->write_calls == endpoint->fail_write_call) {
    if (endpoint->fail_after_internal_queue) {
      endpoint->internally_queued_bytes = source.len;
      return pbns_tcp_write_outcome(PBNS_TCP_IO_OK, PBNS_TCP_IO_FAILED,
                                    source.len, written);
    }
    return endpoint->write_failure;
  }
  if (endpoint->write_block_period != 0U &&
      endpoint->write_calls % endpoint->write_block_period == 0U) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  if (endpoint->zero_write) {
    return PBNS_OK;
  }
  const size_t remaining = sizeof(endpoint->output) - endpoint->output_len;
  const size_t limit = minimum_size(source.len, endpoint->max_write);
  const size_t amount = minimum_size(remaining, limit);
  assert(amount > 0U);
  memcpy(endpoint->output + endpoint->output_len, source.ptr, amount);
  endpoint->output_len += amount;
  *written = amount;
  return PBNS_OK;
}

static pbns_pump_endpoint pump_endpoint(fake_endpoint *endpoint) {
  return (pbns_pump_endpoint){
      .read = fake_read,
      .write = fake_write,
      .context = endpoint,
  };
}

static void fill_random(uint8_t *output, size_t size) {
  for (size_t index = 0U; index < size; ++index) {
    output[index] = (uint8_t)next_random();
  }
}

static pbns_status run_to_completion(pbns_byte_pump *pump, fake_endpoint *usb,
                                     fake_endpoint *tls) {
  const pbns_pump_endpoint usb_endpoint = pump_endpoint(usb);
  const pbns_pump_endpoint tls_endpoint = pump_endpoint(tls);
  for (size_t step = 0U; step < STEP_LIMIT; ++step) {
    bool made_progress = false;
    const pbns_status status =
        pbns_byte_pump_step(pump, usb_endpoint, tls_endpoint, &made_progress);
    if (status != PBNS_OK) {
      return status;
    }
    if (pbns_byte_pump_is_complete(pump)) {
      return PBNS_OK;
    }
  }
  return PBNS_ERR_TIMEOUT;
}

static void test_ring_wraparound_and_bounds(void) {
  uint8_t storage[5] = {0};
  pbns_byte_ring ring = {0};
  pbns_byte_ring_init(&ring, (pbns_buffer){storage, 0U, sizeof(storage)});
  assert(pbns_byte_ring_capacity(&ring) == sizeof(storage));
  assert(pbns_byte_ring_size(&ring) == 0U);

  pbns_buffer writable = {0};
  assert(pbns_byte_ring_writable(&ring, &writable) == PBNS_OK);
  assert(writable.cap == sizeof(storage));
  memcpy(writable.ptr, "abc", 3U);
  assert(pbns_byte_ring_commit(&ring, 3U) == PBNS_OK);

  pbns_view readable = {0};
  assert(pbns_byte_ring_readable(&ring, &readable) == PBNS_OK);
  assert(readable.len == 3U);
  assert(memcmp(readable.ptr, "abc", 3U) == 0);
  assert(pbns_byte_ring_consume(&ring, 2U) == PBNS_OK);

  assert(pbns_byte_ring_writable(&ring, &writable) == PBNS_OK);
  assert(writable.cap == 2U);
  memcpy(writable.ptr, "de", 2U);
  assert(pbns_byte_ring_commit(&ring, 2U) == PBNS_OK);
  assert(pbns_byte_ring_writable(&ring, &writable) == PBNS_OK);
  assert(writable.cap == 2U);
  memcpy(writable.ptr, "fg", 2U);
  assert(pbns_byte_ring_commit(&ring, 2U) == PBNS_OK);
  assert(pbns_byte_ring_size(&ring) == sizeof(storage));

  assert(pbns_byte_ring_readable(&ring, &readable) == PBNS_OK);
  assert(readable.len == 3U);
  assert(memcmp(readable.ptr, "cde", 3U) == 0);
  assert(pbns_byte_ring_consume(&ring, 3U) == PBNS_OK);
  assert(pbns_byte_ring_readable(&ring, &readable) == PBNS_OK);
  assert(readable.len == 2U);
  assert(memcmp(readable.ptr, "fg", 2U) == 0);
  assert(pbns_byte_ring_commit(&ring, 4U) == PBNS_ERR_LIMIT);
  assert(pbns_byte_ring_consume(&ring, 3U) == PBNS_ERR_LIMIT);

  pbns_byte_ring_reset(&ring);
  assert(pbns_byte_ring_size(&ring) == 0U);
  assert(pbns_byte_ring_capacity(&ring) == sizeof(storage));
}

static void test_pump_preserves_simultaneous_short_io(void) {
  static const uint8_t usb_input[] = {0x00, 0x01, 0xff, 0x50, 0x42, 0x4e, 0x53};
  static const uint8_t tls_input[] = {0x91, 0x00, 0x7f, 0xaa, 0x55, 0x10};
  uint8_t usb_to_tls_storage[5] = {0};
  uint8_t tls_to_usb_storage[5] = {0};
  pbns_byte_pump pump = {0};
  pbns_byte_pump_init(
      &pump, (pbns_buffer){usb_to_tls_storage, 0U, sizeof(usb_to_tls_storage)},
      (pbns_buffer){tls_to_usb_storage, 0U, sizeof(tls_to_usb_storage)});

  fake_endpoint usb = {
      .input_len = sizeof(usb_input),
      .max_read = 2U,
      .max_write = 1U,
      .read_block_period = 3U,
      .write_block_period = 2U,
  };
  fake_endpoint tls = {
      .input_len = sizeof(tls_input),
      .max_read = 3U,
      .max_write = 2U,
      .read_block_period = 2U,
      .write_block_period = 4U,
  };
  memcpy(usb.input, usb_input, sizeof(usb_input));
  memcpy(tls.input, tls_input, sizeof(tls_input));

  assert(run_to_completion(&pump, &usb, &tls) == PBNS_OK);
  assert(tls.output_len == sizeof(usb_input));
  assert(memcmp(tls.output, usb_input, sizeof(usb_input)) == 0);
  assert(usb.output_len == sizeof(tls_input));
  assert(memcmp(usb.output, tls_input, sizeof(tls_input)) == 0);
}

static void test_source_close_drains_pending_bytes(void) {
  uint8_t first_storage[4] = {0};
  uint8_t second_storage[4] = {0};
  pbns_byte_pump pump = {0};
  pbns_byte_pump_init(
      &pump, (pbns_buffer){first_storage, 0U, sizeof(first_storage)},
      (pbns_buffer){second_storage, 0U, sizeof(second_storage)});
  fake_endpoint usb = {
      .input = {1U, 2U, 3U, 4U},
      .input_len = 4U,
      .max_read = 4U,
      .max_write = 1U,
  };
  fake_endpoint tls = {.max_read = 1U, .max_write = 1U};
  assert(run_to_completion(&pump, &usb, &tls) == PBNS_OK);
  assert(tls.output_len == 4U);
  assert(memcmp(tls.output, usb.input, 4U) == 0);
  assert(usb.read_calls >= 2U);
}

static void test_failure_and_cancellation_are_sticky_until_reset(void) {
  uint8_t first_storage[3] = {0};
  uint8_t second_storage[3] = {0};
  pbns_byte_pump pump = {0};
  pbns_byte_pump_init(
      &pump, (pbns_buffer){first_storage, 0U, sizeof(first_storage)},
      (pbns_buffer){second_storage, 0U, sizeof(second_storage)});
  fake_endpoint usb = {
      .input = {0xaaU},
      .input_len = 1U,
      .max_read = 1U,
      .max_write = 1U,
  };
  fake_endpoint tls = {
      .max_read = 1U,
      .max_write = 1U,
      .fail_write_call = 1U,
      .write_failure = PBNS_ERR_TRANSPORT,
  };
  const pbns_pump_endpoint usb_endpoint = pump_endpoint(&usb);
  const pbns_pump_endpoint tls_endpoint = pump_endpoint(&tls);
  bool progress = false;
  assert(pbns_byte_pump_step(&pump, usb_endpoint, tls_endpoint, &progress) ==
         PBNS_OK);
  assert(pbns_byte_pump_step(&pump, usb_endpoint, tls_endpoint, &progress) ==
         PBNS_ERR_TRANSPORT);
  assert(pbns_byte_pump_step(&pump, usb_endpoint, tls_endpoint, &progress) ==
         PBNS_ERR_STATE);

  pbns_byte_pump_reset(&pump);
  pbns_byte_pump_cancel(&pump);
  assert(pbns_byte_pump_step(&pump, usb_endpoint, tls_endpoint, &progress) ==
         PBNS_ERR_STATE);
  pbns_byte_pump_reset(&pump);
  assert(!pbns_byte_pump_is_complete(&pump));
}

static void
test_queued_sink_failure_is_not_replayed_and_cancel_clears_ring(void) {
  uint8_t first_storage[3] = {0};
  uint8_t second_storage[3] = {0};
  pbns_byte_pump pump = {0};
  pbns_byte_pump_init(
      &pump, (pbns_buffer){first_storage, 0U, sizeof(first_storage)},
      (pbns_buffer){second_storage, 0U, sizeof(second_storage)});
  fake_endpoint usb = {
      .input = {0x16U},
      .input_len = 1U,
      .max_read = 1U,
      .max_write = 1U,
  };
  fake_endpoint tls = {
      .max_read = 1U,
      .max_write = 1U,
      .fail_write_call = 1U,
      .fail_after_internal_queue = true,
  };
  const pbns_pump_endpoint usb_endpoint = pump_endpoint(&usb);
  const pbns_pump_endpoint tls_endpoint = pump_endpoint(&tls);
  bool progress = false;

  assert(pbns_byte_pump_step(&pump, usb_endpoint, tls_endpoint, &progress) ==
         PBNS_OK);
  assert(progress);
  assert(pbns_byte_ring_size(&pump.usb_to_tls) == 1U);
  assert(pbns_byte_pump_step(&pump, usb_endpoint, tls_endpoint, &progress) ==
         PBNS_ERR_TRANSPORT);
  assert(!progress);
  assert(pump.failed);
  assert(tls.write_calls == 1U);
  assert(tls.internally_queued_bytes == 1U);
  assert(pbns_byte_ring_size(&pump.usb_to_tls) == 1U);
  assert(pbns_byte_pump_step(&pump, usb_endpoint, tls_endpoint, &progress) ==
         PBNS_ERR_STATE);
  assert(tls.write_calls == 1U);
  assert(pbns_byte_ring_size(&pump.usb_to_tls) == 1U);

  pbns_byte_pump_cancel(&pump);
  assert(pump.cancelled);
  assert(pbns_byte_ring_size(&pump.usb_to_tls) == 0U);
  assert(pbns_byte_ring_size(&pump.tls_to_usb) == 0U);
  assert(tls.write_calls == 1U);
}

static void test_zero_length_successful_write_fails_closed(void) {
  uint8_t first_storage[2] = {0};
  uint8_t second_storage[2] = {0};
  pbns_byte_pump pump = {0};
  pbns_byte_pump_init(
      &pump, (pbns_buffer){first_storage, 0U, sizeof(first_storage)},
      (pbns_buffer){second_storage, 0U, sizeof(second_storage)});
  fake_endpoint usb = {
      .input = {0x5aU},
      .input_len = 1U,
      .max_read = 1U,
      .max_write = 1U,
  };
  fake_endpoint tls = {
      .max_read = 1U,
      .max_write = 1U,
      .zero_write = true,
  };
  assert(run_to_completion(&pump, &usb, &tls) == PBNS_ERR_IO);
}

static void test_step_is_fair_and_rejects_overlapping_storage(void) {
  uint8_t first_storage[4] = {0};
  uint8_t second_storage[4] = {0};
  pbns_byte_pump pump = {0};
  pbns_byte_pump_init(
      &pump, (pbns_buffer){first_storage, 0U, sizeof(first_storage)},
      (pbns_buffer){second_storage, 0U, sizeof(second_storage)});
  fake_endpoint usb = {
      .input = {0x01U, 0x02U},
      .input_len = 2U,
      .max_read = 1U,
      .max_write = 1U,
  };
  fake_endpoint tls = {
      .input = {0x03U, 0x04U},
      .input_len = 2U,
      .max_read = 1U,
      .max_write = 1U,
  };
  const pbns_pump_endpoint usb_endpoint = pump_endpoint(&usb);
  const pbns_pump_endpoint tls_endpoint = pump_endpoint(&tls);
  bool progress = false;
  assert(pbns_byte_pump_step(&pump, usb_endpoint, tls_endpoint, &progress) ==
         PBNS_OK);
  assert(progress);
  assert(usb.read_calls == 1U && tls.read_calls == 1U);
  assert(usb.write_calls == 0U && tls.write_calls == 0U);
  assert(pbns_byte_pump_step(&pump, usb_endpoint, tls_endpoint, &progress) ==
         PBNS_OK);
  assert(usb.read_calls == 2U && tls.read_calls == 2U);
  assert(usb.write_calls == 1U && tls.write_calls == 1U);

  pbns_byte_pump_init(
      &pump, (pbns_buffer){first_storage, 0U, sizeof(first_storage)},
      (pbns_buffer){first_storage + 1U, 0U, sizeof(first_storage) - 1U});
  progress = true;
  assert(pbns_byte_pump_step(&pump, usb_endpoint, tls_endpoint, &progress) ==
         PBNS_ERR_STATE);
  assert(!progress);
}

static void test_source_failure_is_sticky(void) {
  uint8_t first_storage[2] = {0};
  uint8_t second_storage[2] = {0};
  pbns_byte_pump pump = {0};
  pbns_byte_pump_init(
      &pump, (pbns_buffer){first_storage, 0U, sizeof(first_storage)},
      (pbns_buffer){second_storage, 0U, sizeof(second_storage)});
  fake_endpoint usb = {
      .max_read = 1U,
      .max_write = 1U,
      .fail_read_call = 1U,
      .read_failure = PBNS_ERR_TIMEOUT,
  };
  fake_endpoint tls = {.max_read = 1U, .max_write = 1U};
  const pbns_pump_endpoint usb_endpoint = pump_endpoint(&usb);
  const pbns_pump_endpoint tls_endpoint = pump_endpoint(&tls);
  bool progress = true;
  assert(pbns_byte_pump_step(&pump, usb_endpoint, tls_endpoint, &progress) ==
         PBNS_ERR_TIMEOUT);
  assert(pbns_byte_pump_step(&pump, usb_endpoint, tls_endpoint, &progress) ==
         PBNS_ERR_STATE);
}

static void test_batch_is_bounded_and_stops_on_terminal_conditions(void) {
  uint8_t first_storage[16] = {0};
  uint8_t second_storage[16] = {0};
  pbns_byte_pump pump = {0};
  fake_endpoint usb = {
      .max_read = 1U,
      .max_write = 1U,
  };
  fake_endpoint tls = {
      .max_read = 1U,
      .max_write = 1U,
  };
  const pbns_pump_endpoint usb_endpoint = pump_endpoint(&usb);
  const pbns_pump_endpoint tls_endpoint = pump_endpoint(&tls);
  size_t steps = 99U;
  bool progress = true;

  assert(pbns_byte_pump_batch(NULL, usb_endpoint, tls_endpoint, &steps,
                              &progress) == PBNS_ERR_ARGUMENT);
  assert(steps == 0U && !progress);
  steps = 99U;
  progress = true;
  assert(pbns_byte_pump_batch(&pump, usb_endpoint, tls_endpoint, NULL,
                              &progress) == PBNS_ERR_ARGUMENT);
  assert(!progress);
  assert(pbns_byte_pump_batch(&pump, usb_endpoint, tls_endpoint, &steps,
                              NULL) == PBNS_ERR_ARGUMENT);
  assert(steps == 0U);
  assert(pbns_byte_pump_batch(&pump, usb_endpoint, tls_endpoint, &steps,
                              &progress) == PBNS_ERR_STATE);
  assert(steps == 0U && !progress);

  pbns_byte_pump_init(
      &pump, (pbns_buffer){first_storage, 0U, sizeof(first_storage)},
      (pbns_buffer){second_storage, 0U, sizeof(second_storage)});
  usb.read_block_period = 1U;
  tls.read_block_period = 1U;
  assert(pbns_byte_pump_batch(&pump, usb_endpoint, tls_endpoint, &steps,
                              &progress) == PBNS_OK);
  assert(steps == 1U && !progress);
  assert(usb.read_calls == 1U && tls.read_calls == 1U);

  pbns_byte_pump_reset(&pump);
  usb = (fake_endpoint){
      .input_len = ENDPOINT_CAPACITY,
      .max_read = 1U,
      .max_write = 1U,
  };
  tls = (fake_endpoint){
      .input_len = ENDPOINT_CAPACITY,
      .max_read = 1U,
      .max_write = 1U,
  };
  fill_random(usb.input, usb.input_len);
  fill_random(tls.input, tls.input_len);
  assert(pbns_byte_pump_batch(&pump, usb_endpoint, tls_endpoint, &steps,
                              &progress) == PBNS_OK);
  assert(steps == PBNS_BYTE_PUMP_BATCH_MAX_STEPS && progress);
  assert(usb.read_calls == PBNS_BYTE_PUMP_BATCH_MAX_STEPS);
  assert(tls.read_calls == PBNS_BYTE_PUMP_BATCH_MAX_STEPS);
  assert(usb.write_calls == PBNS_BYTE_PUMP_BATCH_MAX_STEPS - 1U);
  assert(tls.write_calls == PBNS_BYTE_PUMP_BATCH_MAX_STEPS - 1U);

  pbns_byte_pump_reset(&pump);
  usb = (fake_endpoint){
      .input = {0x42U},
      .input_len = 1U,
      .max_read = 1U,
      .max_write = 1U,
  };
  tls = (fake_endpoint){
      .max_read = 1U,
      .max_write = 1U,
      .fail_write_call = 1U,
      .write_failure = PBNS_ERR_TRANSPORT,
  };
  assert(pbns_byte_pump_batch(&pump, usb_endpoint, tls_endpoint, &steps,
                              &progress) == PBNS_ERR_TRANSPORT);
  assert(steps == 2U && progress);
  assert(pump.failed);

  pbns_byte_pump_reset(&pump);
  usb = (fake_endpoint){.max_read = 1U, .max_write = 1U};
  tls = (fake_endpoint){.max_read = 1U, .max_write = 1U};
  assert(pbns_byte_pump_batch(&pump, usb_endpoint, tls_endpoint, &steps,
                              &progress) == PBNS_OK);
  assert(steps == 1U && progress);
  assert(pbns_byte_pump_is_complete(&pump));
}

static void test_policy_holds_short_usb_tail_until_forced_or_closed(void) {
  uint8_t first_storage[16] = {0};
  uint8_t second_storage[16] = {0};
  pbns_byte_pump pump = {0};
  pbns_byte_pump_init(
      &pump, (pbns_buffer){first_storage, 0U, sizeof(first_storage)},
      (pbns_buffer){second_storage, 0U, sizeof(second_storage)});
  fake_endpoint usb = {
      .input = {1U, 2U, 3U, 4U},
      .input_len = 4U,
      .max_read = 4U,
      .max_write = sizeof(usb.output),
  };
  fake_endpoint tls = {
      .max_read = 1U,
      .max_write = sizeof(tls.output),
  };
  const pbns_pump_endpoint usb_endpoint = pump_endpoint(&usb);
  const pbns_pump_endpoint tls_endpoint = pump_endpoint(&tls);
  const pbns_byte_pump_policy hold = {
      .usb_to_tls_minimum_write = 8U,
  };
  const pbns_byte_pump_policy force = {
      .usb_to_tls_minimum_write = 8U,
      .force_usb_to_tls_write = true,
  };
  bool progress = false;

  assert(pbns_byte_pump_step_with_policy(&pump, usb_endpoint, tls_endpoint,
                                         &hold, &progress) == PBNS_OK);
  assert(progress && tls.output_len == 0U);
  assert(pbns_byte_pump_step_with_policy(&pump, usb_endpoint, tls_endpoint,
                                         &force, &progress) == PBNS_OK);
  assert(progress && tls.output_len == usb.input_len);

  pbns_byte_pump_reset(&pump);
  usb.output_len = 0U;
  usb.read_offset = 0U;
  tls.output_len = 0U;
  tls.read_offset = 0U;
  assert(pbns_byte_pump_step_with_policy(&pump, usb_endpoint, tls_endpoint,
                                         &hold, &progress) == PBNS_OK);
  assert(pbns_byte_pump_step_with_policy(&pump, usb_endpoint, tls_endpoint,
                                         &hold, &progress) == PBNS_OK);
  assert(pump.usb_source_closed && tls.output_len == 0U);
  assert(pbns_byte_pump_step_with_policy(&pump, usb_endpoint, tls_endpoint,
                                         &hold, &progress) == PBNS_OK);
  assert(tls.output_len == usb.input_len);
}

static void test_forced_batch_does_not_force_new_usb_input(void) {
  uint8_t first_storage[16] = {0};
  uint8_t second_storage[16] = {0};
  pbns_byte_pump pump = {0};
  pbns_byte_pump_init(
      &pump, (pbns_buffer){first_storage, 0U, sizeof(first_storage)},
      (pbns_buffer){second_storage, 0U, sizeof(second_storage)});
  fake_endpoint usb = {
      .input = {1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U},
      .input_len = 4U,
      .max_read = 4U,
      .max_write = sizeof(usb.output),
      .read_block_period = 3U,
  };
  fake_endpoint tls = {.max_read = 1U, .max_write = sizeof(tls.output)};
  const pbns_pump_endpoint usb_endpoint = pump_endpoint(&usb);
  const pbns_pump_endpoint tls_endpoint = pump_endpoint(&tls);
  const pbns_byte_pump_policy hold = {.usb_to_tls_minimum_write = 8U};
  const pbns_byte_pump_policy force = {
      .usb_to_tls_minimum_write = 8U,
      .force_usb_to_tls_write = true,
  };
  size_t steps = 0U;
  bool progress = false;

  assert(pbns_byte_pump_step_with_policy(&pump, usb_endpoint, tls_endpoint,
                                         &hold, &progress) == PBNS_OK);
  assert(pbns_byte_ring_size(&pump.usb_to_tls) == 4U);
  usb.input_len = 8U;
  assert(pbns_byte_pump_batch_with_policy(&pump, usb_endpoint, tls_endpoint,
                                          &force, &steps,
                                          &progress) == PBNS_OK);
  assert(steps == 2U && progress);
  assert(tls.output_len == 4U);
  assert(pbns_byte_ring_size(&pump.usb_to_tls) == 4U);
  assert(pump.usb_to_tls_read_generation == 2U);
  assert(pump.usb_to_tls_write_generation == 1U);
}

static void test_tail_deadline_tracks_fresh_input_and_resets(void) {
  pbns_tail_deadline deadline = {0};
  pbns_tail_deadline_init(&deadline, 0U);
  pbns_tail_deadline_observe_input(&deadline, 1U, UINT64_C(100));
  pbns_tail_deadline_set_pending(&deadline, true);
  assert(!pbns_tail_deadline_should_force(&deadline, UINT64_C(1099),
                                          UINT64_C(1000)));
  assert(pbns_tail_deadline_should_force(&deadline, UINT64_C(1100),
                                         UINT64_C(1000)));

  /* An expired tail drains, then fresh USB input must get a new deadline. */
  pbns_tail_deadline_observe_input(&deadline, 2U, UINT64_C(1100));
  assert(!pbns_tail_deadline_should_force(&deadline, UINT64_C(2099),
                                          UINT64_C(1000)));
  assert(pbns_tail_deadline_should_force(&deadline, UINT64_C(2100),
                                         UINT64_C(1000)));
  /* A blocked retry has no new read generation and remains forced. */
  pbns_tail_deadline_observe_input(&deadline, 2U, UINT64_C(3000));
  assert(pbns_tail_deadline_should_force(&deadline, UINT64_C(3000),
                                         UINT64_C(1000)));

  pbns_tail_deadline_observe_input(&deadline, 3U, UINT64_MAX - UINT64_C(500));
  assert(!pbns_tail_deadline_should_force(&deadline, UINT64_C(498),
                                          UINT64_C(1000)));
  assert(pbns_tail_deadline_should_force(&deadline, UINT64_C(499),
                                         UINT64_C(1000)));
  pbns_tail_deadline_reset(&deadline, 3U);
  assert(!pbns_tail_deadline_should_force(&deadline, UINT64_C(499),
                                          UINT64_C(1000)));
}

static void test_policy_forces_full_ring_and_watermarks_inbound_reads(void) {
  uint8_t first_storage[4] = {0};
  uint8_t second_storage[8] = {0};
  pbns_byte_pump pump = {0};
  pbns_byte_pump_init(
      &pump, (pbns_buffer){first_storage, 0U, sizeof(first_storage)},
      (pbns_buffer){second_storage, 0U, sizeof(second_storage)});
  fake_endpoint usb = {
      .input = {1U, 2U, 3U, 4U},
      .input_len = 4U,
      .max_read = 4U,
      .max_write = 1U,
  };
  fake_endpoint tls = {
      .input = {5U, 6U, 7U, 8U},
      .input_len = 4U,
      .max_read = 4U,
      .max_write = sizeof(tls.output),
  };
  const pbns_pump_endpoint usb_endpoint = pump_endpoint(&usb);
  const pbns_pump_endpoint tls_endpoint = pump_endpoint(&tls);
  const pbns_byte_pump_policy policy = {
      .usb_to_tls_minimum_write = 8U,
      .tls_to_usb_minimum_writable = 8U,
  };
  bool progress = false;

  assert(pbns_byte_pump_step_with_policy(&pump, usb_endpoint, tls_endpoint,
                                         &policy, &progress) == PBNS_OK);
  assert(pbns_byte_ring_size(&pump.usb_to_tls) == sizeof(first_storage));
  assert(pbns_byte_pump_step_with_policy(&pump, usb_endpoint, tls_endpoint,
                                         &policy, &progress) == PBNS_OK);
  assert(tls.output_len == usb.input_len);

  pbns_byte_pump_reset(&pump);
  usb.read_offset = 0U;
  usb.input_len = 0U;
  usb.output_len = 0U;
  usb.max_write = 1U;
  tls.read_offset = 0U;
  tls.input_len = 4U;
  tls.max_read = 4U;
  assert(pbns_byte_pump_step_with_policy(&pump, usb_endpoint, tls_endpoint,
                                         &policy, &progress) == PBNS_OK);
  assert(tls.read_calls >= 1U);
  const size_t reads_after_fill = tls.read_calls;
  assert(pbns_byte_pump_step_with_policy(&pump, usb_endpoint, tls_endpoint,
                                         &policy, &progress) == PBNS_OK);
  assert(tls.read_calls == reads_after_fill);
}

static void test_policy_argument_errors_and_default_compatibility(void) {
  uint8_t first_storage[4] = {0};
  uint8_t second_storage[4] = {0};
  pbns_byte_pump pump = {0};
  pbns_byte_pump_init(
      &pump, (pbns_buffer){first_storage, 0U, sizeof(first_storage)},
      (pbns_buffer){second_storage, 0U, sizeof(second_storage)});
  fake_endpoint usb = {.max_read = 1U, .max_write = 1U};
  fake_endpoint tls = {.max_read = 1U, .max_write = 1U};
  const pbns_pump_endpoint usb_endpoint = pump_endpoint(&usb);
  const pbns_pump_endpoint tls_endpoint = pump_endpoint(&tls);
  bool progress = true;
  size_t steps = 99U;
  assert(pbns_byte_pump_step_with_policy(&pump, usb_endpoint, tls_endpoint,
                                         NULL, &progress) == PBNS_ERR_ARGUMENT);
  assert(!progress);
  assert(pbns_byte_pump_batch_with_policy(&pump, usb_endpoint, tls_endpoint,
                                          NULL, &steps,
                                          &progress) == PBNS_ERR_ARGUMENT);
  assert(steps == 0U && !progress);
  assert(pbns_byte_pump_step(&pump, usb_endpoint, tls_endpoint, &progress) ==
         PBNS_OK);
  assert(pbns_byte_pump_is_complete(&pump));
}

static void test_pump_session_reports_only_disconnect_edges(void) {
  pbns_pump_session session = {0};
  bool disconnected = true;
  assert(pbns_pump_session_observe(&session, false, &disconnected) ==
         PBNS_ERR_ARGUMENT);
  assert(!disconnected);
  assert(pbns_pump_session_observe(NULL, false, &disconnected) ==
         PBNS_ERR_ARGUMENT);
  assert(!disconnected);
  assert(pbns_pump_session_observe(&session, false, NULL) == PBNS_ERR_ARGUMENT);

  pbns_pump_session_init(&session);
  disconnected = true;
  assert(pbns_pump_session_observe(&session, false, &disconnected) == PBNS_OK);
  assert(!disconnected);
  assert(pbns_pump_session_observe(&session, true, &disconnected) == PBNS_OK);
  assert(!disconnected);
  assert(pbns_pump_session_observe(&session, true, &disconnected) == PBNS_OK);
  assert(!disconnected);
  assert(pbns_pump_session_observe(&session, false, &disconnected) == PBNS_OK);
  assert(disconnected);
  assert(pbns_pump_session_observe(&session, false, &disconnected) == PBNS_OK);
  assert(!disconnected);
  assert(pbns_pump_session_observe(&session, true, &disconnected) == PBNS_OK);
  assert(!disconnected);
  assert(pbns_pump_session_observe(&session, false, &disconnected) == PBNS_OK);
  assert(disconnected);

  pbns_pump_session_init(NULL);
}

static void test_random_short_io_schedules(void) {
  for (size_t schedule = 0U; schedule < RANDOM_SCHEDULES; ++schedule) {
    uint8_t first_storage[16] = {0};
    uint8_t second_storage[16] = {0};
    const size_t first_capacity = 1U + (size_t)(next_random() % 16U);
    const size_t second_capacity = 1U + (size_t)(next_random() % 16U);
    pbns_byte_pump pump = {0};
    pbns_byte_pump_init(&pump, (pbns_buffer){first_storage, 0U, first_capacity},
                        (pbns_buffer){second_storage, 0U, second_capacity});

    fake_endpoint usb = {
        .input_len = (size_t)(next_random() % (ENDPOINT_CAPACITY + 1U)),
        .max_read = 1U + (size_t)(next_random() % 8U),
        .max_write = 1U + (size_t)(next_random() % 8U),
        .read_block_period = 2U + (size_t)(next_random() % 7U),
        .write_block_period = 2U + (size_t)(next_random() % 7U),
    };
    fake_endpoint tls = {
        .input_len = (size_t)(next_random() % (ENDPOINT_CAPACITY + 1U)),
        .max_read = 1U + (size_t)(next_random() % 8U),
        .max_write = 1U + (size_t)(next_random() % 8U),
        .read_block_period = 2U + (size_t)(next_random() % 7U),
        .write_block_period = 2U + (size_t)(next_random() % 7U),
    };
    fill_random(usb.input, usb.input_len);
    fill_random(tls.input, tls.input_len);
    assert(run_to_completion(&pump, &usb, &tls) == PBNS_OK);
    assert(tls.output_len == usb.input_len);
    assert(memcmp(tls.output, usb.input, usb.input_len) == 0);
    assert(usb.output_len == tls.input_len);
    assert(memcmp(usb.output, tls.input, tls.input_len) == 0);
  }
}

int main(void) {
  test_ring_wraparound_and_bounds();
  test_pump_preserves_simultaneous_short_io();
  test_source_close_drains_pending_bytes();
  test_failure_and_cancellation_are_sticky_until_reset();
  test_queued_sink_failure_is_not_replayed_and_cancel_clears_ring();
  test_zero_length_successful_write_fails_closed();
  test_step_is_fair_and_rejects_overlapping_storage();
  test_source_failure_is_sticky();
  test_batch_is_bounded_and_stops_on_terminal_conditions();
  test_policy_holds_short_usb_tail_until_forced_or_closed();
  test_forced_batch_does_not_force_new_usb_input();
  test_tail_deadline_tracks_fresh_input_and_resets();
  test_policy_forces_full_ring_and_watermarks_inbound_reads();
  test_policy_argument_errors_and_default_compatibility();
  test_pump_session_reports_only_disconnect_edges();
  test_random_short_io_schedules();
  return 0;
}
