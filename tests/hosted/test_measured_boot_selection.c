#include "pbns/measured_boot.h"

#include <assert.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_LOG_CAPACITY 512U
#define TEST_PATH_CAPACITY 4096U

typedef struct fake_capture {
  pbns_view base_log;
  pbns_view final_events;
  pbns_measured_boot_final_disposition final_disposition;
  bool truncated;
  pbns_measured_boot_pcr_snapshot snapshots[5];
  pbns_status snapshot_statuses[5];
  size_t snapshot_count;
  size_t read_count;
  size_t policy_calls;
  const pbns_measured_boot_selection_item *exact_policy_items;
  size_t exact_policy_count;
  bool disallow_seven;
} fake_capture;

static size_t load_vector(const char *directory, const char *name,
                          uint8_t *output, size_t capacity) {
  char path[TEST_PATH_CAPACITY] = {0};
  const int path_length = snprintf(path, sizeof(path), "%s/%s", directory, name);
  assert(path_length > 0 && (size_t)path_length < sizeof(path));
  FILE *file = fopen(path, "rb");
  assert(file != NULL);
  assert(fseek(file, 0L, SEEK_END) == 0);
  const long end = ftell(file);
  assert(end >= 0L && (unsigned long)end <= capacity);
  assert(fseek(file, 0L, SEEK_SET) == 0);
  const size_t length = (size_t)end;
  assert(fread(output, 1U, length, file) == length);
  assert(fclose(file) == 0);
  return length;
}

static pbns_status fake_event_log(void *context,
                                  pbns_measured_boot_event_source *source) {
  fake_capture *fake = context;
  *source = (pbns_measured_boot_event_source){
      .base_log = fake->base_log,
      .final_events_table = fake->final_events,
      .final_disposition = fake->final_disposition,
      .truncated = fake->truncated,
  };
  return PBNS_OK;
}

static pbns_status fake_pcr_read(void *context,
                                 pbns_measured_boot_selection selection,
                                 pbns_measured_boot_pcr_snapshot *snapshot) {
  fake_capture *fake = context;
  (void)selection;
  if (fake->read_count >= fake->snapshot_count) {
    return PBNS_ERR_SERVICE;
  }
  const size_t index = fake->read_count++;
  if (fake->snapshot_statuses[index] != PBNS_OK) {
    return fake->snapshot_statuses[index];
  }
  *snapshot = fake->snapshots[index];
  return PBNS_OK;
}

static pbns_status sha256(void *context, pbns_view input,
                          uint8_t digest[PBNS_MEASURED_BOOT_DIGEST_SIZE]) {
  (void)context;
  return SHA256(input.ptr, input.len, digest) != NULL ? PBNS_OK
                                                     : PBNS_ERR_CRYPTO;
}

static bool allowed(void *context, pbns_measured_boot_selection selection) {
  fake_capture *fake = context;
  ++fake->policy_calls;
  if (fake->exact_policy_items != NULL) {
    if (selection.count != fake->exact_policy_count) {
      return false;
    }
    for (size_t index = 0U; index < selection.count; ++index) {
      if (selection.items[index].hash_algorithm !=
              fake->exact_policy_items[index].hash_algorithm ||
          selection.items[index].pcr_index !=
              fake->exact_policy_items[index].pcr_index) {
        return false;
      }
    }
    return true;
  }
  for (size_t index = 0U; index < selection.count; ++index) {
    if (selection.items[index].hash_algorithm != PBNS_TPM_ALG_SHA256 ||
        (fake->disallow_seven && selection.items[index].pcr_index == 7U)) {
      return false;
    }
  }
  return true;
}

static void set_snapshot(pbns_measured_boot_pcr_snapshot *snapshot,
                         const pbns_measured_boot_selection_item *selection,
                         size_t count, uint32_t counter, uint8_t fill) {
  *snapshot = (pbns_measured_boot_pcr_snapshot){0};
  snapshot->count = count;
  snapshot->update_counter = counter;
  for (size_t index = 0U; index < count; ++index) {
    snapshot->values[index].selection = selection[index];
    snapshot->values[index].digest_size = PBNS_MEASURED_BOOT_DIGEST_SIZE;
    memset(snapshot->values[index].digest, (int)(fill + (uint8_t)index),
           PBNS_MEASURED_BOOT_DIGEST_SIZE);
  }
}

static pbns_measured_boot_capture_input make_input(
    fake_capture *fake, const pbns_measured_boot_selection_item *items,
    size_t count) {
  return (pbns_measured_boot_capture_input){
      .selection = {.items = items, .count = count},
      .event_log_read = fake_event_log,
      .pcr_read = fake_pcr_read,
      .sha256 = sha256,
      .policy_allows = allowed,
      .context = fake,
      .policy_context = fake,
  };
}

static void assert_zero(const void *value, size_t size) {
  const uint8_t *bytes = value;
  for (size_t index = 0U; index < size; ++index) {
    assert(bytes[index] == 0U);
  }
}

static void store_u32(uint8_t *output, uint32_t value) {
  for (size_t index = 0U; index < 4U; ++index) {
    output[index] = (uint8_t)(value >> (8U * index));
  }
}

static void store_u64(uint8_t *output, uint64_t value) {
  for (size_t index = 0U; index < 8U; ++index) {
    output[index] = (uint8_t)(value >> (8U * index));
  }
}

static size_t make_sha256_event(uint8_t *output, uint8_t pcr,
                                uint32_t event_size, uint8_t fill) {
  store_u32(output, pcr);
  store_u32(output + 4U, UINT32_C(0x80000003));
  store_u32(output + 8U, 1U);
  output[12U] = 0x0bU;
  output[13U] = 0U;
  memset(output + 14U, fill, PBNS_MEASURED_BOOT_DIGEST_SIZE);
  store_u32(output + 46U, event_size);
  memset(output + 50U, fill, event_size);
  return 50U + event_size;
}

static void test_exact_suffix_boundary(const char *directory) {
  uint8_t header[TEST_LOG_CAPACITY] = {0};
  const size_t header_and_event = load_vector(
      directory, "valid-sha256.bin", header, sizeof(header));
  const size_t header_size = 69U;
  assert(header_and_event > header_size);

  uint8_t true_log[TEST_LOG_CAPACITY] = {0};
  memcpy(true_log, header, header_size);
  const size_t first_size = make_sha256_event(
      true_log + header_size, 1U, 16U, 0x11U);
  uint8_t *true_table = true_log + header_size + first_size - 16U;
  store_u64(true_table, 1U);
  store_u64(true_table + 8U, 1U);
  const size_t second_size = make_sha256_event(
      true_log + header_size + first_size, 2U, 3U, 0x22U);
  const size_t true_size = header_size + first_size + second_size;
  bool exact_suffix = false;
  assert(pbns_measured_boot_final_events_exact_suffix(
             (pbns_view){true_log, true_size},
             (pbns_view){true_table, 16U + second_size}, &exact_suffix) ==
         PBNS_OK);
  assert(exact_suffix);

  uint8_t interior_log[TEST_LOG_CAPACITY] = {0};
  memcpy(interior_log, header, header_size);
  const size_t interior_first_size = make_sha256_event(
      interior_log + header_size, 1U, 66U, 0x33U);
  uint8_t *interior_table = interior_log + header_size + 50U;
  store_u64(interior_table, 1U);
  store_u64(interior_table + 8U, 1U);
  uint8_t *embedded_event = interior_table + 16U;
  const size_t trailing_size = make_sha256_event(
      interior_log + header_size + interior_first_size, 2U, 3U, 0x44U);
  store_u32(embedded_event, 3U);
  store_u32(embedded_event + 4U, UINT32_C(0x80000003));
  store_u32(embedded_event + 8U, 1U);
  embedded_event[12U] = 0x0bU;
  embedded_event[13U] = 0U;
  memset(embedded_event + 14U, 0x55, PBNS_MEASURED_BOOT_DIGEST_SIZE);
  store_u32(embedded_event + 46U, (uint32_t)trailing_size);
  const size_t interior_size = header_size + interior_first_size + trailing_size;
  exact_suffix = true;
  assert(pbns_measured_boot_final_events_exact_suffix(
             (pbns_view){interior_log, interior_size},
             (pbns_view){interior_table, 16U + 50U + trailing_size},
             &exact_suffix) == PBNS_OK);
  assert(!exact_suffix);
}

static void test_selection_validation(void) {
  static const pbns_measured_boot_selection_item valid[] = {
      {PBNS_TPM_ALG_SHA256, 0U}, {PBNS_TPM_ALG_SHA256, 2U},
      {PBNS_TPM_ALG_SHA256, 4U}, {PBNS_TPM_ALG_SHA256, 7U}};
  fake_capture fake = {0};
  assert(pbns_measured_boot_validate_selection(
             (pbns_measured_boot_selection){valid, 4U}, allowed, &fake) ==
         PBNS_OK);
  assert(fake.policy_calls == 1U);
  assert(pbns_measured_boot_validate_selection(
             (pbns_measured_boot_selection){
                 valid, PBNS_MEASURED_BOOT_SELECTION_MAX_COUNT + 1U},
             allowed, &fake) == PBNS_ERR_ARGUMENT);
  pbns_measured_boot_selection_item invalid[2] = {valid[0], valid[0]};
  assert(pbns_measured_boot_validate_selection(
             (pbns_measured_boot_selection){invalid, 2U}, allowed, &fake) ==
         PBNS_ERR_FORMAT);
  invalid[0] = valid[1];
  invalid[1] = valid[0];
  assert(pbns_measured_boot_validate_selection(
             (pbns_measured_boot_selection){invalid, 2U}, allowed, &fake) ==
         PBNS_ERR_FORMAT);
  invalid[0] = (pbns_measured_boot_selection_item){PBNS_TPM_ALG_SHA256, 24U};
  assert(pbns_measured_boot_validate_selection(
             (pbns_measured_boot_selection){invalid, 1U}, allowed, &fake) ==
         PBNS_ERR_ARGUMENT);
  invalid[0] = (pbns_measured_boot_selection_item){UINT16_C(0x000c), 0U};
  assert(pbns_measured_boot_validate_selection(
             (pbns_measured_boot_selection){invalid, 1U}, allowed, &fake) ==
         PBNS_ERR_UNSUPPORTED);
  assert(fake.policy_calls == 1U);
  fake.disallow_seven = true;
  assert(pbns_measured_boot_validate_selection(
             (pbns_measured_boot_selection){valid, 4U}, allowed, &fake) ==
         PBNS_ERR_AUTHENTICATION);
  static const pbns_measured_boot_selection_item exact[] = {
      {PBNS_TPM_ALG_SHA256, 0U}, {PBNS_TPM_ALG_SHA256, 2U}};
  fake = (fake_capture){.exact_policy_items = exact, .exact_policy_count = 2U};
  assert(pbns_measured_boot_validate_selection(
             (pbns_measured_boot_selection){exact, 2U}, allowed, &fake) ==
         PBNS_OK);
  assert(pbns_measured_boot_validate_selection(
             (pbns_measured_boot_selection){exact, 1U}, allowed, &fake) ==
         PBNS_ERR_AUTHENTICATION);
  assert(pbns_measured_boot_validate_selection(
             (pbns_measured_boot_selection){exact + 1U, 1U}, allowed, &fake) ==
         PBNS_ERR_AUTHENTICATION);
  assert(pbns_measured_boot_validate_selection(
             (pbns_measured_boot_selection){valid, 3U}, allowed, &fake) ==
         PBNS_ERR_AUTHENTICATION);

  uint8_t encoded[12] = {0};
  size_t written = 0U;
  assert(pbns_measured_boot_encode_canonical_selection(
             (pbns_measured_boot_selection){valid, 4U},
             (pbns_buffer){encoded, 0U, sizeof(encoded)}, &written) == PBNS_OK);
  static const uint8_t expected[] = {0x00U, 0x0bU, 0x00U, 0x00U, 0x0bU, 0x02U,
                                     0x00U, 0x0bU, 0x04U, 0x00U, 0x0bU, 0x07U};
  assert(written == sizeof(expected));
  assert(memcmp(encoded, expected, sizeof(expected)) == 0);
}

static void test_capture_and_final_events(const char *directory) {
  uint8_t base[TEST_LOG_CAPACITY] = {0};
  uint8_t final_events[TEST_LOG_CAPACITY] = {0};
  const size_t base_size = load_vector(directory, "valid-sha256.bin", base,
                                       sizeof(base));
  const size_t final_size = load_vector(directory, "valid-final-events.bin",
                                        final_events, sizeof(final_events));
  size_t located_final_size = 0U;
  assert(pbns_measured_boot_locate_final_events_end(
             (pbns_view){base, base_size},
             (pbns_view){final_events, sizeof(final_events)},
             &located_final_size) == PBNS_OK);
  assert(located_final_size == final_size);
  bool exact_suffix = true;
  assert(pbns_measured_boot_final_events_exact_suffix(
             (pbns_view){base, base_size},
             (pbns_view){final_events, final_size}, &exact_suffix) == PBNS_OK);
  assert(!exact_suffix);
  static const pbns_measured_boot_selection_item selection[] = {
      {PBNS_TPM_ALG_SHA256, 0U}, {PBNS_TPM_ALG_SHA256, 2U},
      {PBNS_TPM_ALG_SHA256, 4U}, {PBNS_TPM_ALG_SHA256, 7U}};
  fake_capture fake = {
      .base_log = {base, base_size},
      .final_events = {final_events, final_size},
      .final_disposition = PBNS_MEASURED_BOOT_FINAL_APPEND,
      .snapshot_count = 2U,
  };
  set_snapshot(&fake.snapshots[0], selection, 4U, 9U, 0x30U);
  set_snapshot(&fake.snapshots[1], selection, 4U, 9U, 0x30U);
  uint8_t arena[TEST_LOG_CAPACITY] = {0};
  pbns_measured_boot_evidence evidence = {0};
  const pbns_measured_boot_capture_input input = make_input(&fake, selection, 4U);
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &evidence) ==
         PBNS_OK);
  assert(evidence.event_log.ptr == arena);
  assert(evidence.event_log.len > base_size);
  assert(evidence.event_count == 3U);
  assert(evidence.pcr_count == 4U);
  assert(evidence.pcr_update_counter == 9U);
  static const uint8_t fixed_log_digest[32] = {
      0x8fU, 0x4aU, 0xfeU, 0xb3U, 0xc8U, 0x9dU, 0x44U, 0xe0U,
      0x9cU, 0x9aU, 0x7bU, 0xf4U, 0xabU, 0x75U, 0xe3U, 0x28U,
      0x6dU, 0x2cU, 0x3cU, 0x64U, 0xc8U, 0x7cU, 0x9eU, 0x51U,
      0xa4U, 0x5fU, 0x55U, 0x65U, 0x81U, 0x66U, 0x71U, 0x43U};
  uint8_t expected_selection_digest[32] = {0};
  assert(evidence.event_log.len == base_size + final_size - 16U);
  assert(memcmp(arena, base, base_size) == 0);
  assert(memcmp(arena + base_size, final_events + 16U, final_size - 16U) == 0);
  static const uint8_t canonical[] = {0x00U, 0x0bU, 0x00U, 0x00U, 0x0bU, 0x02U,
                                      0x00U, 0x0bU, 0x04U, 0x00U, 0x0bU, 0x07U};
  assert(SHA256(canonical, sizeof(canonical), expected_selection_digest) != NULL);
  assert(memcmp(evidence.event_log_digest, fixed_log_digest,
                sizeof(fixed_log_digest)) == 0);
  assert(memcmp(evidence.selection_digest, expected_selection_digest, 32U) == 0);

  pbns_measured_boot_evidence second = {0};
  uint8_t second_arena[TEST_LOG_CAPACITY] = {0};
  fake.read_count = 0U;
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){second_arena, 0U, evidence.event_log.len},
             &second) == PBNS_OK);
  assert(memcmp(&evidence.event_log_digest, &second.event_log_digest,
                sizeof(evidence.event_log_digest)) == 0);
  fake.read_count = 0U;
  memset(&second, 0x5a, sizeof(second));
  memset(second_arena, 0xa5, sizeof(second_arena));
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){second_arena, 0U, evidence.event_log.len - 1U},
             &second) == PBNS_ERR_LIMIT);
  assert_zero(&second, sizeof(second));
  assert_zero(second_arena, evidence.event_log.len - 1U);
}

static void test_final_disposition_and_alias(const char *directory) {
  uint8_t base[TEST_LOG_CAPACITY] = {0};
  uint8_t final_table[TEST_LOG_CAPACITY] = {0};
  const size_t base_size = load_vector(directory, "valid-sha256.bin", base,
                                       sizeof(base));
  const size_t vector_final_size = load_vector(
      directory, "valid-final-events.bin", final_table, sizeof(final_table));
  static const pbns_measured_boot_selection_item selection[] = {
      {PBNS_TPM_ALG_SHA256, 0U}};
  fake_capture fake = {
      .base_log = {base, base_size},
      .final_events = {final_table, vector_final_size},
      .final_disposition = PBNS_MEASURED_BOOT_FINAL_APPEND,
      .snapshot_count = 2U,
  };
  set_snapshot(&fake.snapshots[0], selection, 1U, 2U, 0x20U);
  set_snapshot(&fake.snapshots[1], selection, 1U, 2U, 0x20U);
  const pbns_measured_boot_capture_input input = make_input(&fake, selection, 1U);
  uint8_t arena[TEST_LOG_CAPACITY] = {0};
  pbns_measured_boot_evidence evidence = {0};

  memcpy(final_table + 16U, base + 69U, base_size - 69U);
  fake.final_events.len = 16U + base_size - 69U;
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &evidence) ==
         PBNS_OK);
  assert(evidence.event_count == 3U);
  assert(memcmp(arena + 69U, arena + base_size, base_size - 69U) == 0);

  fake.read_count = 0U;
  fake.final_events = (pbns_view){final_table, fake.final_events.len};
  fake.final_disposition = PBNS_MEASURED_BOOT_FINAL_ALREADY_INCLUDED_EXACT;
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &evidence) ==
         PBNS_OK);
  assert(evidence.event_log.len == base_size && evidence.event_count == 2U);

  fake.read_count = 0U;
  const uint32_t invalid_disposition = 99U;
  _Static_assert(sizeof(fake.final_disposition) == sizeof(invalid_disposition),
                 "final disposition representation");
  memcpy(&fake.final_disposition, &invalid_disposition,
         sizeof(invalid_disposition));
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &evidence) ==
         PBNS_ERR_FORMAT);
  assert_zero(&evidence, sizeof(evidence));

  memcpy(arena, base, base_size);
  fake.base_log = (pbns_view){arena, base_size};
  fake.final_events = (pbns_view){0};
  fake.final_disposition = PBNS_MEASURED_BOOT_FINAL_NONE;
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &evidence) ==
         PBNS_ERR_FORMAT);
  assert_zero(arena, sizeof(arena));

  fake.base_log = (pbns_view){base, base_size};
  memcpy(arena + 100U, final_table, vector_final_size);
  fake.final_events = (pbns_view){arena + 100U, vector_final_size};
  fake.final_disposition = PBNS_MEASURED_BOOT_FINAL_APPEND;
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &evidence) ==
         PBNS_ERR_FORMAT);
  assert_zero(arena, sizeof(arena));
}

static void test_log_rejections(const char *directory) {
  uint8_t base[TEST_LOG_CAPACITY] = {0};
  uint8_t unsupported[TEST_LOG_CAPACITY] = {0};
  uint8_t final_events[TEST_LOG_CAPACITY] = {0};
  const size_t base_size = load_vector(directory, "valid-sha256.bin", base,
                                       sizeof(base));
  const size_t unsupported_size = load_vector(directory, "unsupported-bank.bin",
                                              unsupported, sizeof(unsupported));
  const size_t final_size = load_vector(directory, "valid-final-events.bin",
                                        final_events, sizeof(final_events));
  static const pbns_measured_boot_selection_item selection[] = {
      {PBNS_TPM_ALG_SHA256, 0U}};
  fake_capture fake = {.base_log = {base, base_size}, .snapshot_count = 2U};
  set_snapshot(&fake.snapshots[0], selection, 1U, 1U, 1U);
  set_snapshot(&fake.snapshots[1], selection, 1U, 1U, 1U);
  pbns_measured_boot_capture_input input = make_input(&fake, selection, 1U);
  uint8_t arena[TEST_LOG_CAPACITY] = {0};
  pbns_measured_boot_evidence output = {0};

  for (size_t length = 1U; length < base_size; ++length) {
    fake.base_log.len = length;
    fake.read_count = 0U;
    memset(arena, 0xa5, sizeof(arena));
    memset(&output, 0x5a, sizeof(output));
    assert(pbns_measured_boot_capture_evidence(
               &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &output) ==
           PBNS_ERR_FORMAT);
    assert_zero(&output, sizeof(output));
  }
  fake.base_log = (pbns_view){base, base_size};
  for (size_t length = 1U; length < final_size; ++length) {
    fake.final_events = (pbns_view){final_events, length};
    fake.final_disposition = PBNS_MEASURED_BOOT_FINAL_APPEND;
    fake.read_count = 0U;
    assert(pbns_measured_boot_capture_evidence(
               &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &output) ==
           PBNS_ERR_FORMAT);
    assert_zero(&output, sizeof(output));
  }
  fake.final_events = (pbns_view){0};
  fake.final_disposition = PBNS_MEASURED_BOOT_FINAL_NONE;
  fake.base_log = (pbns_view){unsupported, unsupported_size};
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &output) ==
         PBNS_ERR_UNSUPPORTED);
  fake.base_log = (pbns_view){base, base_size};
  fake.truncated = true;
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &output) ==
         PBNS_ERR_LIMIT);

  const size_t large_size = PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE + 1U;
  uint8_t *large = malloc(2U * large_size);
  assert(large != NULL);
  fake.truncated = false;
  fake.base_log = (pbns_view){large, large_size};
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){large + large_size, 0U, large_size},
             &output) == PBNS_ERR_LIMIT);
  free(large);
}

static void test_pcr_failures_and_retry(const char *directory) {
  uint8_t base[TEST_LOG_CAPACITY] = {0};
  const size_t base_size = load_vector(directory, "valid-sha256.bin", base,
                                       sizeof(base));
  static const pbns_measured_boot_selection_item selection[] = {
      {PBNS_TPM_ALG_SHA256, 0U}, {PBNS_TPM_ALG_SHA256, 2U}};
  fake_capture fake = {.base_log = {base, base_size}, .snapshot_count = 3U};
  for (size_t index = 0U; index < 3U; ++index) {
    set_snapshot(&fake.snapshots[index], selection, 2U, 4U, 0x20U);
  }
  pbns_measured_boot_capture_input input = make_input(&fake, selection, 2U);
  uint8_t arena[TEST_LOG_CAPACITY] = {0};
  pbns_measured_boot_evidence output = {0};

  fake.snapshots[0].count = 1U;
  memset(arena, 0xa5, sizeof(arena));
  memset(&output, 0x5a, sizeof(output));
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &output) ==
         PBNS_ERR_FORMAT);
  assert_zero(&output, sizeof(output));
  assert_zero(arena, base_size);
  set_snapshot(&fake.snapshots[0], selection, 2U, 4U, 0x20U);
  fake.read_count = 0U;
  fake.snapshots[0].values[0].selection.pcr_index = 1U;
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &output) ==
         PBNS_ERR_FORMAT);
  set_snapshot(&fake.snapshots[0], selection, 2U, 4U, 0x20U);
  fake.read_count = 0U;
  fake.snapshots[0].values[0] = fake.snapshots[0].values[1];
  fake.snapshots[0].values[1].selection = selection[0];
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &output) ==
         PBNS_ERR_FORMAT);
  set_snapshot(&fake.snapshots[0], selection, 2U, 4U, 0x20U);
  fake.read_count = 0U;
  fake.snapshots[0].values[1].digest_size = 31U;
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &output) ==
         PBNS_ERR_FORMAT);

  fake.snapshot_statuses[0] = PBNS_ERR_BUSY;
  set_snapshot(&fake.snapshots[1], selection, 2U, 12U, 0x60U);
  set_snapshot(&fake.snapshots[2], selection, 2U, 12U, 0x60U);
  fake.read_count = 0U;
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &output) ==
         PBNS_OK);
  assert(fake.read_count == 3U && output.pcr_update_counter == 12U);

  fake.snapshot_count = 4U;
  memset(fake.snapshot_statuses, 0, sizeof(fake.snapshot_statuses));
  fake.snapshot_statuses[0] = PBNS_ERR_BUSY;
  fake.snapshot_statuses[2] = PBNS_ERR_BUSY;
  set_snapshot(&fake.snapshots[1], selection, 2U, 12U, 0x60U);
  set_snapshot(&fake.snapshots[3], selection, 2U, 12U, 0x60U);
  fake.read_count = 0U;
  memset(arena, 0xa5, sizeof(arena));
  memset(&output, 0x5a, sizeof(output));
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &output) ==
         PBNS_ERR_BUSY);
  assert(fake.read_count == 3U);
  assert_zero(&output, sizeof(output));
  assert_zero(arena, base_size);

  fake.snapshot_count = 3U;
  memset(fake.snapshot_statuses, 0, sizeof(fake.snapshot_statuses));
  fake.snapshot_statuses[1] = PBNS_ERR_BUSY;
  set_snapshot(&fake.snapshots[0], selection, 2U, 12U, 0x60U);
  set_snapshot(&fake.snapshots[2], selection, 2U, 12U, 0x60U);
  fake.read_count = 0U;
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &output) ==
         PBNS_OK);
  assert(fake.read_count == 3U && output.pcr_update_counter == 12U);

  fake.snapshot_count = 3U;
  memset(fake.snapshot_statuses, 0, sizeof(fake.snapshot_statuses));
  fake.snapshot_statuses[0] = PBNS_ERR_BUSY;
  fake.snapshot_statuses[1] = PBNS_ERR_BUSY;
  fake.read_count = 0U;
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &output) ==
         PBNS_ERR_BUSY);
  assert(fake.read_count == 2U);
  assert_zero(&output, sizeof(output));
  memset(fake.snapshot_statuses, 0, sizeof(fake.snapshot_statuses));

  for (size_t index = 0U; index < 3U; ++index) {
    set_snapshot(&fake.snapshots[index], selection, 2U,
                 (uint32_t)(10U + index), 0x40U);
  }
  fake.read_count = 0U;
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &output) ==
         PBNS_ERR_BUSY);
  assert(fake.read_count == 3U);
  assert_zero(&output, sizeof(output));
  assert_zero(arena, base_size);

  set_snapshot(&fake.snapshots[0], selection, 2U, 10U, 0x40U);
  set_snapshot(&fake.snapshots[1], selection, 2U, 11U, 0x50U);
  set_snapshot(&fake.snapshots[2], selection, 2U, 11U, 0x50U);
  fake.read_count = 0U;
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &output) == PBNS_OK);
  assert(fake.read_count == 3U);
  assert(output.pcr_update_counter == 11U);
  assert(output.pcrs[0].digest[0] == 0x50U);

  fake.snapshot_count = 4U;
  memset(fake.snapshot_statuses, 0, sizeof(fake.snapshot_statuses));
  fake.snapshot_statuses[2] = PBNS_ERR_BUSY;
  set_snapshot(&fake.snapshots[0], selection, 2U, 10U, 0x40U);
  set_snapshot(&fake.snapshots[1], selection, 2U, 11U, 0x50U);
  set_snapshot(&fake.snapshots[3], selection, 2U, 11U, 0x50U);
  fake.read_count = 0U;
  assert(pbns_measured_boot_capture_evidence(
             &input, (pbns_buffer){arena, 0U, sizeof(arena)}, &output) ==
         PBNS_OK);
  assert(fake.read_count == 4U && output.pcr_update_counter == 11U);
}

int main(int argc, char **argv) {
  assert(argc == 2);
  test_selection_validation();
  test_exact_suffix_boundary(argv[1]);
  test_capture_and_final_events(argv[1]);
  test_final_disposition_and_alias(argv[1]);
  test_log_rejections(argv[1]);
  test_pcr_failures_and_retry(argv[1]);
  return 0;
}
