#include "pbns/anti_rollback.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/crc32c.h"

static const uint8_t record_magic[4] = {'P', 'B', 'R', '1'};

static bool view_valid(pbns_view value) {
  return value.ptr != NULL || value.len == 0U;
}

static uint64_t read_u64_be(const uint8_t *source) {
  uint64_t value = 0U;
  for (size_t index = 0U; index < 8U; ++index) {
    value = (value << 8U) | source[index];
  }
  return value;
}

static uint32_t read_u32_be(const uint8_t *source) {
  return ((uint32_t)source[0] << 24U) | ((uint32_t)source[1] << 16U) |
         ((uint32_t)source[2] << 8U) | (uint32_t)source[3];
}

static void write_u64_be(uint8_t *destination, uint64_t value) {
  for (size_t index = 0U; index < 8U; ++index) {
    destination[7U - index] = (uint8_t)(value & UINT64_C(0xff));
    value >>= 8U;
  }
}

static void write_u32_be(uint8_t *destination, uint32_t value) {
  destination[0] = (uint8_t)(value >> 24U);
  destination[1] = (uint8_t)(value >> 16U);
  destination[2] = (uint8_t)(value >> 8U);
  destination[3] = (uint8_t)value;
}

static void encode_record(uint64_t generation, uint64_t version,
                          uint8_t output[PBNS_ANTI_ROLLBACK_RECORD_SIZE]) {
  memset(output, 0, PBNS_ANTI_ROLLBACK_RECORD_SIZE);
  memcpy(output, record_magic, sizeof(record_magic));
  write_u64_be(output + 4U, generation);
  write_u64_be(output + 12U, version);
  write_u32_be(output + 20U, pbns_crc32c((pbns_view){output, 20U}));
}

static bool decode_record(const uint8_t record[PBNS_ANTI_ROLLBACK_RECORD_SIZE],
                          uint64_t *generation, uint64_t *version) {
  if (memcmp(record, record_magic, sizeof(record_magic)) != 0 ||
      read_u32_be(record + 20U) != pbns_crc32c((pbns_view){record, 20U})) {
    return false;
  }
  *generation = read_u64_be(record + 4U);
  *version = read_u64_be(record + 12U);
  return *generation > 0U && *version > 0U;
}

pbns_status pbns_anti_rollback_init_tpm(
    pbns_anti_rollback *controller, pbns_anti_rollback_tpm_read_fn read,
    pbns_anti_rollback_tpm_advance_fn advance, void *context) {
  if (controller != NULL) {
    *controller = (pbns_anti_rollback){0};
  }
  if (controller == NULL || read == NULL || advance == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  controller->assurance = PBNS_ANTI_ROLLBACK_ASSURANCE_TPM;
  controller->context = context;
  controller->tpm_read = read;
  controller->tpm_advance = advance;
  return PBNS_OK;
}

pbns_status pbns_anti_rollback_init_nvram(
    pbns_anti_rollback *controller, pbns_anti_rollback_slot_read_fn read,
    pbns_anti_rollback_slot_write_fn write, void *context) {
  if (controller != NULL) {
    *controller = (pbns_anti_rollback){0};
  }
  if (controller == NULL || read == NULL || write == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  controller->assurance = PBNS_ANTI_ROLLBACK_ASSURANCE_NVRAM_REDUCED;
  controller->context = context;
  controller->slot_read = read;
  controller->slot_write = write;
  return PBNS_OK;
}

static bool controller_valid(const pbns_anti_rollback *controller) {
  if (controller == NULL) {
    return false;
  }
  if (controller->assurance == PBNS_ANTI_ROLLBACK_ASSURANCE_TPM) {
    return controller->tpm_read != NULL && controller->tpm_advance != NULL &&
           controller->slot_read == NULL && controller->slot_write == NULL;
  }
  if (controller->assurance == PBNS_ANTI_ROLLBACK_ASSURANCE_NVRAM_REDUCED) {
    return controller->slot_read != NULL && controller->slot_write != NULL &&
           controller->tpm_read == NULL && controller->tpm_advance == NULL;
  }
  return false;
}

static pbns_status read_nvram(const pbns_anti_rollback *controller,
                              pbns_anti_rollback_state *state) {
  uint64_t generations[PBNS_ANTI_ROLLBACK_SLOT_COUNT] = {0};
  uint64_t versions[PBNS_ANTI_ROLLBACK_SLOT_COUNT] = {0};
  bool valid[PBNS_ANTI_ROLLBACK_SLOT_COUNT] = {false};
  for (size_t slot = 0U; slot < PBNS_ANTI_ROLLBACK_SLOT_COUNT; ++slot) {
    uint8_t record[PBNS_ANTI_ROLLBACK_RECORD_SIZE] = {0};
    bool present = false;
    const pbns_status status =
        controller->slot_read(controller->context, slot, record, &present);
    if (status != PBNS_OK) {
      memset(record, 0, sizeof(record));
      return status;
    }
    valid[slot] =
        present && decode_record(record, &generations[slot], &versions[slot]);
    memset(record, 0, sizeof(record));
  }
  state->assurance = PBNS_ANTI_ROLLBACK_ASSURANCE_NVRAM_REDUCED;
  state->active_slot = PBNS_ANTI_ROLLBACK_NO_SLOT;
  if (!valid[0] && !valid[1]) {
    return PBNS_OK;
  }
  size_t selected = valid[0] ? 0U : 1U;
  if (valid[0] && valid[1]) {
    if (generations[0] == generations[1]) {
      return PBNS_ERR_AMBIGUOUS;
    }
    selected = generations[1] > generations[0] ? 1U : 0U;
  }
  state->generation = generations[selected];
  state->version = versions[selected];
  state->active_slot = selected;
  return PBNS_OK;
}

pbns_status pbns_anti_rollback_read(const pbns_anti_rollback *controller,
                                    pbns_anti_rollback_state *state) {
  if (state != NULL) {
    *state = (pbns_anti_rollback_state){0};
  }
  if (!controller_valid(controller) || state == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (controller->assurance == PBNS_ANTI_ROLLBACK_ASSURANCE_TPM) {
    uint64_t version = 0U;
    const pbns_status status =
        controller->tpm_read(controller->context, &version);
    if (status != PBNS_OK) {
      return status;
    }
    state->version = version;
    state->active_slot = PBNS_ANTI_ROLLBACK_NO_SLOT;
    state->assurance = PBNS_ANTI_ROLLBACK_ASSURANCE_TPM;
    return PBNS_OK;
  }
  return read_nvram(controller, state);
}

pbns_status pbns_anti_rollback_advance(const pbns_anti_rollback *controller,
                                       uint64_t target_version,
                                       pbns_view authorization,
                                       pbns_anti_rollback_state *state) {
  if (state != NULL) {
    *state = (pbns_anti_rollback_state){0};
  }
  if (!controller_valid(controller) || !view_valid(authorization) ||
      state == NULL || target_version == 0U ||
      authorization.len > PBNS_ANTI_ROLLBACK_AUTHORIZATION_MAX_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_anti_rollback_state current = {0};
  pbns_status status = pbns_anti_rollback_read(controller, &current);
  if (status != PBNS_OK) {
    return status;
  }
  if (target_version <= current.version) {
    return PBNS_ERR_REPLAY;
  }
  if (controller->assurance == PBNS_ANTI_ROLLBACK_ASSURANCE_TPM) {
    if (authorization.len == 0U) {
      return PBNS_ERR_ARGUMENT;
    }
    status = controller->tpm_advance(controller->context, current.version,
                                     target_version, authorization);
    if (status != PBNS_OK) {
      return status;
    }
  } else {
    if (authorization.len != 0U || current.generation == UINT64_MAX) {
      return authorization.len != 0U ? PBNS_ERR_ARGUMENT : PBNS_ERR_LIMIT;
    }
    const size_t inactive = current.active_slot == PBNS_ANTI_ROLLBACK_NO_SLOT
                                ? 0U
                                : current.active_slot ^ 1U;
    uint8_t record[PBNS_ANTI_ROLLBACK_RECORD_SIZE] = {0};
    encode_record(current.generation + 1U, target_version, record);
    status = controller->slot_write(controller->context, inactive,
                                    (pbns_view){record, sizeof(record)});
    memset(record, 0, sizeof(record));
    if (status != PBNS_OK) {
      return status;
    }
  }
  pbns_anti_rollback_state verified = {0};
  status = pbns_anti_rollback_read(controller, &verified);
  if (status != PBNS_OK) {
    return status;
  }
  if (verified.version != target_version ||
      (controller->assurance == PBNS_ANTI_ROLLBACK_ASSURANCE_NVRAM_REDUCED &&
       verified.generation != current.generation + 1U)) {
    return PBNS_ERR_STATE;
  }
  *state = verified;
  return PBNS_OK;
}
