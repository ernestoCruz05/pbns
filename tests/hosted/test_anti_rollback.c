#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/anti_rollback.h"
#include "pbns/crc32c.h"

static void test_write_u64_be(uint8_t *destination, uint64_t value) {
  for (size_t index = 0U; index < 8U; ++index) {
    destination[7U - index] = (uint8_t)(value & UINT64_C(0xff));
    value >>= 8U;
  }
}

static void test_write_u32_be(uint8_t *destination, uint32_t value) {
  destination[0] = (uint8_t)(value >> 24U);
  destination[1] = (uint8_t)(value >> 16U);
  destination[2] = (uint8_t)(value >> 8U);
  destination[3] = (uint8_t)value;
}

static void make_record(uint64_t generation, uint64_t version,
                        uint8_t output[PBNS_ANTI_ROLLBACK_RECORD_SIZE]) {
  static const uint8_t magic[] = {'P', 'B', 'R', '1'};
  memset(output, 0, PBNS_ANTI_ROLLBACK_RECORD_SIZE);
  memcpy(output, magic, sizeof(magic));
  test_write_u64_be(output + 4U, generation);
  test_write_u64_be(output + 12U, version);
  test_write_u32_be(output + 20U, pbns_crc32c((pbns_view){output, 20U}));
}

typedef struct fake_slots {
  uint8_t records[PBNS_ANTI_ROLLBACK_SLOT_COUNT]
                 [PBNS_ANTI_ROLLBACK_RECORD_SIZE];
  bool present[PBNS_ANTI_ROLLBACK_SLOT_COUNT];
  bool fail_write;
  bool corrupt_write;
  size_t writes;
} fake_slots;

static pbns_status slot_read(void *context, size_t slot, uint8_t record[24],
                             bool *present) {
  fake_slots *slots = context;
  if (slot >= PBNS_ANTI_ROLLBACK_SLOT_COUNT) {
    return PBNS_ERR_ARGUMENT;
  }
  *present = slots->present[slot];
  if (*present) {
    memcpy(record, slots->records[slot], PBNS_ANTI_ROLLBACK_RECORD_SIZE);
  } else {
    memset(record, 0, PBNS_ANTI_ROLLBACK_RECORD_SIZE);
  }
  return PBNS_OK;
}

static pbns_status slot_write(void *context, size_t slot, pbns_view record) {
  fake_slots *slots = context;
  ++slots->writes;
  if (slots->fail_write) {
    return PBNS_ERR_IO;
  }
  assert(slot < PBNS_ANTI_ROLLBACK_SLOT_COUNT);
  assert(record.len == PBNS_ANTI_ROLLBACK_RECORD_SIZE);
  memcpy(slots->records[slot], record.ptr, record.len);
  slots->present[slot] = true;
  if (slots->corrupt_write) {
    slots->records[slot][12] ^= 1U;
  }
  return PBNS_OK;
}

static void test_nvram_two_slot_transaction_and_replay(void) {
  fake_slots slots = {0};
  pbns_anti_rollback controller = {0};
  assert(pbns_anti_rollback_init_nvram(&controller, slot_read, slot_write,
                                       &slots) == PBNS_OK);
  pbns_anti_rollback_state state = {0};
  assert(pbns_anti_rollback_read(&controller, &state) == PBNS_OK);
  assert(state.version == 0U);
  assert(state.generation == 0U);
  assert(state.active_slot == SIZE_MAX);
  assert(state.assurance == PBNS_ANTI_ROLLBACK_ASSURANCE_NVRAM_REDUCED);

  assert(pbns_anti_rollback_advance(&controller, 4U, (pbns_view){NULL, 0U},
                                    &state) == PBNS_OK);
  assert(state.version == 4U);
  assert(state.generation == 1U);
  assert(state.active_slot == 0U);
  assert(slots.writes == 1U);
  assert(pbns_anti_rollback_advance(&controller, 5U, (pbns_view){NULL, 0U},
                                    &state) == PBNS_OK);
  assert(state.version == 5U);
  assert(state.generation == 2U);
  assert(state.active_slot == 1U);
  assert(slots.writes == 2U);

  assert(pbns_anti_rollback_advance(&controller, 5U, (pbns_view){NULL, 0U},
                                    &state) == PBNS_ERR_REPLAY);
  assert(pbns_anti_rollback_advance(&controller, 3U, (pbns_view){NULL, 0U},
                                    &state) == PBNS_ERR_REPLAY);
  assert(slots.writes == 2U);
}

static void test_nvram_interrupted_and_corrupt_write_preserve_current(void) {
  fake_slots slots = {0};
  pbns_anti_rollback controller = {0};
  assert(pbns_anti_rollback_init_nvram(&controller, slot_read, slot_write,
                                       &slots) == PBNS_OK);
  pbns_anti_rollback_state state = {0};
  assert(pbns_anti_rollback_advance(&controller, 4U, (pbns_view){NULL, 0U},
                                    &state) == PBNS_OK);

  slots.fail_write = true;
  assert(pbns_anti_rollback_advance(&controller, 5U, (pbns_view){NULL, 0U},
                                    &state) == PBNS_ERR_IO);
  assert(pbns_anti_rollback_read(&controller, &state) == PBNS_OK);
  assert(state.version == 4U);
  slots.fail_write = false;
  slots.corrupt_write = true;
  assert(pbns_anti_rollback_advance(&controller, 5U, (pbns_view){NULL, 0U},
                                    &state) == PBNS_ERR_STATE);
  assert(pbns_anti_rollback_read(&controller, &state) == PBNS_OK);
  assert(state.version == 4U);

  slots.records[0][0] ^= 1U;
  assert(pbns_anti_rollback_read(&controller, &state) == PBNS_OK);
  assert(state.version == 0U);
  assert(state.active_slot == SIZE_MAX);
}

static void test_nvram_ambiguous_generation_and_overflow(void) {
  fake_slots slots = {0};
  make_record(7U, 4U, slots.records[0]);
  make_record(7U, 5U, slots.records[1]);
  slots.present[0] = true;
  slots.present[1] = true;
  pbns_anti_rollback controller = {0};
  assert(pbns_anti_rollback_init_nvram(&controller, slot_read, slot_write,
                                       &slots) == PBNS_OK);
  pbns_anti_rollback_state state = {0};
  assert(pbns_anti_rollback_read(&controller, &state) == PBNS_ERR_AMBIGUOUS);
  assert(state.assurance == PBNS_ANTI_ROLLBACK_ASSURANCE_NVRAM_REDUCED);

  memset(&slots, 0, sizeof(slots));
  make_record(UINT64_MAX, 9U, slots.records[0]);
  slots.present[0] = true;
  assert(pbns_anti_rollback_read(&controller, &state) == PBNS_OK);
  assert(state.generation == UINT64_MAX);
  assert(state.version == 9U);
  assert(pbns_anti_rollback_advance(&controller, 10U, (pbns_view){NULL, 0U},
                                    &state) == PBNS_ERR_LIMIT);
  assert(slots.writes == 0U);
}

typedef struct fake_tpm {
  uint64_t version;
  bool fail_read;
  bool fail_advance;
  size_t advances;
} fake_tpm;

static pbns_status tpm_read(void *context, uint64_t *version) {
  fake_tpm *tpm = context;
  if (tpm->fail_read) {
    return PBNS_ERR_CRYPTO;
  }
  *version = tpm->version;
  return PBNS_OK;
}

static pbns_status tpm_advance(void *context, uint64_t current, uint64_t target,
                               pbns_view authorization) {
  static const uint8_t expected[] = {0xa1U, 0x01U, 0x05U};
  fake_tpm *tpm = context;
  ++tpm->advances;
  if (tpm->fail_advance || current != tpm->version ||
      authorization.len != sizeof(expected) ||
      memcmp(authorization.ptr, expected, sizeof(expected)) != 0) {
    return PBNS_ERR_AUTHENTICATION;
  }
  tpm->version = target;
  return PBNS_OK;
}

static void test_tpm_is_explicit_and_rereads_after_advance(void) {
  fake_tpm tpm = {.version = 4U};
  pbns_anti_rollback controller = {0};
  assert(pbns_anti_rollback_init_tpm(&controller, tpm_read, tpm_advance,
                                     &tpm) == PBNS_OK);
  pbns_anti_rollback_state state = {0};
  assert(pbns_anti_rollback_read(&controller, &state) == PBNS_OK);
  assert(state.version == 4U);
  assert(state.assurance == PBNS_ANTI_ROLLBACK_ASSURANCE_TPM);
  static const uint8_t authorization[] = {0xa1U, 0x01U, 0x05U};
  assert(pbns_anti_rollback_advance(
             &controller, 5U, (pbns_view){authorization, sizeof(authorization)},
             &state) == PBNS_OK);
  assert(state.version == 5U);
  assert(tpm.advances == 1U);
  assert(pbns_anti_rollback_advance(
             &controller, 5U, (pbns_view){authorization, sizeof(authorization)},
             &state) == PBNS_ERR_REPLAY);
  assert(tpm.advances == 1U);

  tpm.fail_read = true;
  assert(pbns_anti_rollback_read(&controller, &state) == PBNS_ERR_CRYPTO);
  assert(state.assurance == PBNS_ANTI_ROLLBACK_ASSURANCE_INVALID);
}

static void test_arguments_and_no_automatic_fallback(void) {
  fake_tpm tpm = {.version = 4U, .fail_advance = true};
  pbns_anti_rollback controller = {0};
  assert(pbns_anti_rollback_init_tpm(&controller, tpm_read, tpm_advance,
                                     &tpm) == PBNS_OK);
  pbns_anti_rollback_state state = {0};
  static const uint8_t authorization[] = {0xa1U};
  assert(pbns_anti_rollback_advance(
             &controller, 5U, (pbns_view){authorization, sizeof(authorization)},
             &state) == PBNS_ERR_AUTHENTICATION);
  assert(state.assurance == PBNS_ANTI_ROLLBACK_ASSURANCE_INVALID);
  assert(pbns_anti_rollback_init_tpm(NULL, tpm_read, tpm_advance, &tpm) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_anti_rollback_init_nvram(&controller, NULL, slot_write, NULL) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_anti_rollback_read(NULL, &state) == PBNS_ERR_ARGUMENT);
}

int main(void) {
  test_nvram_two_slot_transaction_and_replay();
  test_nvram_interrupted_and_corrupt_write_preserve_current();
  test_nvram_ambiguous_generation_and_overflow();
  test_tpm_is_explicit_and_rereads_after_advance();
  test_arguments_and_no_automatic_fallback();
  return 0;
}
