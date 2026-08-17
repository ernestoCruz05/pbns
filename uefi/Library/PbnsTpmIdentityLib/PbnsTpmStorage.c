#include "PbnsTpmStorage.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define PBNS_TPM_STORAGE_MAGIC UINT32_C(0x44495450)
#define PBNS_TPM_STORAGE_CRC_OFFSET 12U
#define PBNS_TPM_STORAGE_LENGTH_OFFSET 28U
#define PBNS_TPM_STORAGE_FIELD_COUNT 11U
#define PBNS_CRC32C_POLYNOMIAL UINT32_C(0x82f63b78)

static void store_u16(uint8_t *output, uint16_t value) {
  output[0] = (uint8_t)(value & UINT16_C(0xff));
  output[1] = (uint8_t)(value >> 8U);
}

static void store_u32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)(value & UINT32_C(0xff));
  output[1] = (uint8_t)((value >> 8U) & UINT32_C(0xff));
  output[2] = (uint8_t)((value >> 16U) & UINT32_C(0xff));
  output[3] = (uint8_t)(value >> 24U);
}

static uint16_t load_u16(const uint8_t *input) {
  return (uint16_t)((uint16_t)input[0] | ((uint16_t)input[1] << 8U));
}

static uint32_t load_u32(const uint8_t *input) {
  return (uint32_t)input[0] | ((uint32_t)input[1] << 8U) |
         ((uint32_t)input[2] << 16U) | ((uint32_t)input[3] << 24U);
}

static uint32_t record_crc(pbns_view encoded) {
  uint32_t crc = UINT32_MAX;
  for (size_t index = 0U; index < encoded.len; ++index) {
    uint8_t value = encoded.ptr[index];
    if (index >= PBNS_TPM_STORAGE_CRC_OFFSET &&
        index < PBNS_TPM_STORAGE_CRC_OFFSET + sizeof(uint32_t)) {
      value = 0U;
    }
    crc ^= value;
    for (unsigned int bit = 0U; bit < 8U; ++bit) {
      const uint32_t mask = (uint32_t)(0U - (crc & 1U));
      crc = (crc >> 1U) ^ (PBNS_CRC32C_POLYNOMIAL & mask);
    }
  }
  return ~crc;
}

static bool valid_required_view(pbns_view view, size_t maximum) {
  return view.ptr != NULL && view.len > 0U && view.len <= maximum;
}

static pbns_status validate_record(const pbns_tpm_storage_record *record) {
  if (record == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!valid_required_view(record->ek_public, PBNS_TPM_PUBLIC_MAX) ||
      record->ek_name.ptr == NULL ||
      record->ek_name.len != PBNS_TPM_NAME_SIZE ||
      !valid_required_view(record->srk_public, PBNS_TPM_PUBLIC_MAX) ||
      record->srk_name.ptr == NULL ||
      record->srk_name.len != PBNS_TPM_NAME_SIZE ||
      !valid_required_view(record->ak_public, PBNS_TPM_PUBLIC_MAX) ||
      !valid_required_view(record->ak_private, PBNS_TPM_PRIVATE_MAX) ||
      record->ak_name.ptr == NULL ||
      record->ak_name.len != PBNS_TPM_NAME_SIZE ||
      !valid_required_view(record->identity_public, PBNS_TPM_PUBLIC_MAX) ||
      !valid_required_view(record->identity_private, PBNS_TPM_PRIVATE_MAX) ||
      record->identity_name.ptr == NULL ||
      record->identity_name.len != PBNS_TPM_NAME_SIZE ||
      record->ek_chain_digest.ptr == NULL ||
      record->ek_chain_digest.len != PBNS_TPM_EK_CHAIN_DIGEST_SIZE) {
    return PBNS_ERR_LIMIT;
  }
  return PBNS_OK;
}

static void store_length(uint8_t *header, size_t field, size_t length) {
  store_u16(header + PBNS_TPM_STORAGE_LENGTH_OFFSET + field * 2U,
            (uint16_t)length);
}

pbns_status pbns_tpm_storage_encode(const pbns_tpm_storage_record *record,
                                    pbns_buffer output, size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  if (output.ptr == NULL || output.len != 0U || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  memset(output.ptr, 0, output.cap);
  const pbns_status validation = validate_record(record);
  if (validation != PBNS_OK) {
    return validation;
  }
  const pbns_view fields[PBNS_TPM_STORAGE_FIELD_COUNT] = {
      record->ek_public,     record->ek_name,         record->srk_public,
      record->srk_name,      record->ak_public,       record->ak_private,
      record->ak_name,       record->identity_public, record->identity_private,
      record->identity_name, record->ek_chain_digest,
  };
  size_t total = PBNS_TPM_STORAGE_HEADER_SIZE;
  for (size_t index = 0U; index < PBNS_TPM_STORAGE_FIELD_COUNT; ++index) {
    if (fields[index].len > PBNS_TPM_STORAGE_MAX_SIZE - total) {
      return PBNS_ERR_LIMIT;
    }
    total += fields[index].len;
  }
  if (total > output.cap || total > PBNS_TPM_STORAGE_MAX_SIZE) {
    return PBNS_ERR_LIMIT;
  }

  store_u32(output.ptr, PBNS_TPM_STORAGE_MAGIC);
  store_u16(output.ptr + 4U, PBNS_TPM_STORAGE_VERSION);
  store_u16(output.ptr + 6U, PBNS_TPM_STORAGE_HEADER_SIZE);
  store_u32(output.ptr + 8U, (uint32_t)total);
  store_u32(output.ptr + 16U, record->manufacturer);
  store_u32(output.ptr + 20U, record->firmware1);
  store_u32(output.ptr + 24U, record->firmware2);
  size_t offset = PBNS_TPM_STORAGE_HEADER_SIZE;
  for (size_t index = 0U; index < PBNS_TPM_STORAGE_FIELD_COUNT; ++index) {
    store_length(output.ptr, index, fields[index].len);
    memcpy(output.ptr + offset, fields[index].ptr, fields[index].len);
    offset += fields[index].len;
  }
  store_u32(output.ptr + PBNS_TPM_STORAGE_CRC_OFFSET,
            record_crc((pbns_view){output.ptr, total}));
  *written = total;
  return PBNS_OK;
}

pbns_status pbns_tpm_storage_decode(pbns_view encoded,
                                    pbns_tpm_storage_record *record) {
  if (record == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *record = (pbns_tpm_storage_record){0};
  if (encoded.ptr == NULL || encoded.len < PBNS_TPM_STORAGE_HEADER_SIZE ||
      encoded.len > PBNS_TPM_STORAGE_MAX_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  if (load_u32(encoded.ptr) != PBNS_TPM_STORAGE_MAGIC) {
    return PBNS_ERR_FORMAT;
  }
  if (load_u16(encoded.ptr + 4U) != PBNS_TPM_STORAGE_VERSION) {
    return PBNS_ERR_VERSION;
  }
  if (load_u16(encoded.ptr + 6U) != PBNS_TPM_STORAGE_HEADER_SIZE ||
      load_u32(encoded.ptr + 8U) != encoded.len) {
    return PBNS_ERR_FORMAT;
  }
  if (load_u32(encoded.ptr + PBNS_TPM_STORAGE_CRC_OFFSET) !=
      record_crc(encoded)) {
    return PBNS_ERR_CRC;
  }

  pbns_view fields[PBNS_TPM_STORAGE_FIELD_COUNT] = {{0}};
  size_t offset = PBNS_TPM_STORAGE_HEADER_SIZE;
  for (size_t index = 0U; index < PBNS_TPM_STORAGE_FIELD_COUNT; ++index) {
    const size_t length =
        load_u16(encoded.ptr + PBNS_TPM_STORAGE_LENGTH_OFFSET + index * 2U);
    if (length > encoded.len - offset) {
      return PBNS_ERR_FORMAT;
    }
    fields[index] = (pbns_view){encoded.ptr + offset, length};
    offset += length;
  }
  if (offset != encoded.len) {
    return PBNS_ERR_FORMAT;
  }
  *record = (pbns_tpm_storage_record){
      .manufacturer = load_u32(encoded.ptr + 16U),
      .firmware1 = load_u32(encoded.ptr + 20U),
      .firmware2 = load_u32(encoded.ptr + 24U),
      .ek_public = fields[0],
      .ek_name = fields[1],
      .srk_public = fields[2],
      .srk_name = fields[3],
      .ak_public = fields[4],
      .ak_private = fields[5],
      .ak_name = fields[6],
      .identity_public = fields[7],
      .identity_private = fields[8],
      .identity_name = fields[9],
      .ek_chain_digest = fields[10],
  };
  const pbns_status validation = validate_record(record);
  if (validation != PBNS_OK) {
    *record = (pbns_tpm_storage_record){0};
    return PBNS_ERR_FORMAT;
  }
  return PBNS_OK;
}

static bool constant_time_equal(const uint8_t *left, const uint8_t *right,
                                size_t length) {
  uint8_t difference = 0U;
  for (size_t index = 0U; index < length; ++index) {
    difference |= (uint8_t)(left[index] ^ right[index]);
  }
  return difference == 0U;
}

pbns_status
pbns_tpm_storage_validate_names(const pbns_tpm_storage_record *record,
                                pbns_tpm_storage_name compute_name,
                                void *compute_context) {
  if (compute_name == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status validation = validate_record(record);
  if (validation != PBNS_OK) {
    return validation;
  }
  const pbns_view public_values[] = {
      record->ek_public,
      record->srk_public,
      record->ak_public,
      record->identity_public,
  };
  const pbns_view expected_names[] = {
      record->ek_name,
      record->srk_name,
      record->ak_name,
      record->identity_name,
  };
  uint8_t computed[PBNS_TPM_NAME_SIZE] = {0};
  for (size_t index = 0U;
       index < sizeof(public_values) / sizeof(public_values[0]); ++index) {
    memset(computed, 0, sizeof(computed));
    const pbns_status status =
        compute_name(compute_context, public_values[index],
                     (pbns_buffer){computed, 0U, sizeof(computed)});
    if (status != PBNS_OK) {
      memset(computed, 0, sizeof(computed));
      return status;
    }
    if (!constant_time_equal(computed, expected_names[index].ptr,
                             sizeof(computed))) {
      memset(computed, 0, sizeof(computed));
      return PBNS_ERR_AUTHENTICATION;
    }
  }
  memset(computed, 0, sizeof(computed));
  return PBNS_OK;
}
