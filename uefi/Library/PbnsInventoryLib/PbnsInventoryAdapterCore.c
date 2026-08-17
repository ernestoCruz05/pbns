#include "PbnsInventoryAdapterCore.h"

#include <limits.h>
#include <string.h>

#define SMBIOS2_MIN_ENTRY_LENGTH 0x1eU
#define SMBIOS2_FULL_ENTRY_LENGTH 0x1fU
#define SMBIOS3_ENTRY_LENGTH 0x18U
#define SMBIOS2_INTERMEDIATE_OFFSET 0x10U

static pbns_inventory_adapter_result result(
    pbns_inventory_platform_result kind, uint64_t native_status) {
  return (pbns_inventory_adapter_result){kind, native_status};
}

static bool checksum_valid(pbns_view value) {
  uint8_t checksum = 0U;
  if (value.ptr == NULL || value.len == 0U) {
    return false;
  }
  for (size_t index = 0U; index < value.len; ++index) {
    checksum = (uint8_t)(checksum + value.ptr[index]);
  }
  return checksum == 0U;
}

static uint16_t load_u16(const uint8_t *value) {
  return (uint16_t)((uint16_t)value[0U] |
                    (uint16_t)((uint16_t)value[1U] << 8U));
}

static uint32_t load_u32(const uint8_t *value) {
  return (uint32_t)value[0U] | ((uint32_t)value[1U] << 8U) |
         ((uint32_t)value[2U] << 16U) | ((uint32_t)value[3U] << 24U);
}

static uint64_t load_u64(const uint8_t *value) {
  uint64_t result_value = 0U;
  for (size_t index = 0U; index < 8U; ++index) {
    result_value |= (uint64_t)value[index] << (index * 8U);
  }
  return result_value;
}

pbns_inventory_adapter_result pbns_inventory_adapter_smbios_entry(
    pbns_view entry, bool version3,
    pbns_inventory_adapter_smbios_table *table) {
  if (entry.ptr == NULL || table == NULL) {
    return result(PBNS_PLATFORM_ERROR, 0U);
  }
  *table = (pbns_inventory_adapter_smbios_table){0};
  size_t entry_length = 0U;
  if (version3) {
    static const uint8_t anchor[] = {'_', 'S', 'M', '3', '_'};
    if (entry.len < SMBIOS3_ENTRY_LENGTH ||
        memcmp(entry.ptr, anchor, sizeof(anchor)) != 0 || entry.ptr[7U] < 3U) {
      return result(PBNS_PLATFORM_MALFORMED, 0U);
    }
    entry_length = entry.ptr[6U];
    if (entry_length != SMBIOS3_ENTRY_LENGTH || entry_length > entry.len ||
        !checksum_valid((pbns_view){entry.ptr, entry_length})) {
      return result(PBNS_PLATFORM_MALFORMED, 0U);
    }
    table->length = load_u32(entry.ptr + 12U);
    table->address = load_u64(entry.ptr + 16U);
    table->require_exact_end = false;
  } else {
    static const uint8_t anchor[] = {'_', 'S', 'M', '_'};
    static const uint8_t intermediate[] = {'_', 'D', 'M', 'I', '_'};
    if (entry.len < 8U || memcmp(entry.ptr, anchor, sizeof(anchor)) != 0 ||
        entry.ptr[6U] < 2U) {
      return result(PBNS_PLATFORM_MALFORMED, 0U);
    }
    entry_length = entry.ptr[5U];
    if ((entry_length != SMBIOS2_MIN_ENTRY_LENGTH &&
         entry_length != SMBIOS2_FULL_ENTRY_LENGTH) ||
        entry_length > entry.len ||
        memcmp(entry.ptr + SMBIOS2_INTERMEDIATE_OFFSET, intermediate,
               sizeof(intermediate)) != 0 ||
        !checksum_valid((pbns_view){entry.ptr, entry_length}) ||
        !checksum_valid((pbns_view){entry.ptr + SMBIOS2_INTERMEDIATE_OFFSET,
                                   entry_length -
                                       SMBIOS2_INTERMEDIATE_OFFSET})) {
      return result(PBNS_PLATFORM_MALFORMED, 0U);
    }
    table->length = load_u16(entry.ptr + 22U);
    table->address = load_u32(entry.ptr + 24U);
    table->expected_record_count = load_u16(entry.ptr + 28U);
    table->require_exact_end = true;
  }
  if (table->address == 0U || table->length == 0U) {
    *table = (pbns_inventory_adapter_smbios_table){0};
    return result(PBNS_PLATFORM_MALFORMED, 0U);
  }
  if (table->length > PBNS_INVENTORY_SMBIOS_TABLE_MAX_SIZE) {
    *table = (pbns_inventory_adapter_smbios_table){0};
    return result(PBNS_PLATFORM_LIMIT, 0U);
  }
  if (table->address > UINTPTR_MAX || table->length > UINTPTR_MAX ||
      (uintptr_t)table->address > UINTPTR_MAX - (uintptr_t)table->length) {
    *table = (pbns_inventory_adapter_smbios_table){0};
    return result(PBNS_PLATFORM_MALFORMED, 0U);
  }
  return result(PBNS_PLATFORM_SUCCESS, 0U);
}

pbns_inventory_adapter_result pbns_inventory_adapter_smbios_collect(
    pbns_view entry, bool version3, pbns_view declared_table,
    pbns_inventory_smbios_collector *collector) {
  if (collector == NULL || declared_table.ptr == NULL) {
    return result(PBNS_PLATFORM_ERROR, 0U);
  }
  pbns_inventory_adapter_smbios_table table = {0};
  pbns_inventory_adapter_result status =
      pbns_inventory_adapter_smbios_entry(entry, version3, &table);
  if (status.kind != PBNS_PLATFORM_SUCCESS) {
    return status;
  }
  if (table.length != declared_table.len) {
    return result(PBNS_PLATFORM_MALFORMED, 0U);
  }
  const pbns_status consume_status = pbns_inventory_smbios_consume_table(
      collector, declared_table, table.require_exact_end);
  if (consume_status == PBNS_ERR_LIMIT) {
    return result(PBNS_PLATFORM_LIMIT, 0U);
  }
  if (consume_status != PBNS_OK ||
      (table.require_exact_end &&
       collector->record_count != table.expected_record_count)) {
    return result(PBNS_PLATFORM_MALFORMED, 0U);
  }
  return status;
}

static pbns_inventory_adapter_result read_boolean(
    pbns_inventory_adapter_get_variable get_variable, void *context,
    pbns_inventory_adapter_variable variable, bool *value) {
  uint8_t encoded = 0U;
  size_t size = sizeof(encoded);
  uint32_t attributes = 0U;
  pbns_inventory_adapter_result status =
      get_variable(context, variable, &encoded, &size, &attributes);
  if (status.kind != PBNS_PLATFORM_SUCCESS) {
    return status;
  }
  if (size != sizeof(encoded) || encoded > 1U) {
    return result(PBNS_PLATFORM_MALFORMED, 0U);
  }
  *value = encoded != 0U;
  return status;
}

static pbns_inventory_adapter_result hash_variable(
    pbns_inventory_adapter_get_variable get_variable, void *context,
    pbns_inventory_adapter_variable variable, pbns_buffer scratch,
    pbns_inventory_hash_parts_fn hash, void *hash_context, uint8_t digest[32]) {
  size_t size = 0U;
  uint32_t attributes = 0U;
  pbns_inventory_adapter_result status =
      get_variable(context, variable, NULL, &size, &attributes);
  if (status.kind == PBNS_PLATFORM_NOT_FOUND) {
    return pbns_inventory_hash_variable(hash, hash_context, false, 0U,
                                        (pbns_view){NULL, 0U}, digest) == PBNS_OK
               ? result(PBNS_PLATFORM_SUCCESS, 0U)
               : result(PBNS_PLATFORM_ERROR, 0U);
  }
  if (status.kind != PBNS_PLATFORM_LIMIT &&
      status.kind != PBNS_PLATFORM_SUCCESS) {
    return status;
  }
  if (size > scratch.cap || size > PBNS_INVENTORY_VARIABLE_MAX_SIZE) {
    return result(PBNS_PLATFORM_LIMIT, status.native_status);
  }
  status = get_variable(context, variable, scratch.ptr, &size, &attributes);
  if (status.kind != PBNS_PLATFORM_SUCCESS) {
    memset(scratch.ptr, 0, scratch.cap);
    return status;
  }
  if (size > scratch.cap) {
    memset(scratch.ptr, 0, scratch.cap);
    return result(PBNS_PLATFORM_LIMIT, 0U);
  }
  const pbns_status hash_status = pbns_inventory_hash_variable(
      hash, hash_context, true, attributes,
      (pbns_view){scratch.ptr, size}, digest);
  memset(scratch.ptr, 0, size);
  return hash_status == PBNS_OK ? result(PBNS_PLATFORM_SUCCESS, 0U)
                                : result(PBNS_PLATFORM_ERROR, 0U);
}

pbns_inventory_adapter_result pbns_inventory_adapter_secure_boot(
    pbns_inventory_adapter_get_variable get_variable, void *context,
    pbns_buffer scratch, pbns_inventory_hash_parts_fn hash, void *hash_context,
    pbns_inventory_secure_boot_input *output) {
  if (get_variable == NULL || scratch.ptr == NULL || scratch.len != 0U ||
      scratch.cap == 0U || scratch.cap > PBNS_INVENTORY_VARIABLE_MAX_SIZE ||
      hash == NULL || output == NULL) {
    return result(PBNS_PLATFORM_ERROR, 0U);
  }
  *output = (pbns_inventory_secure_boot_input){
      .status = PBNS_INVENTORY_UNSUPPORTED,
  };
  bool secure_boot = false;
  bool setup_mode = false;
  pbns_inventory_adapter_result status = read_boolean(
      get_variable, context, PBNS_ADAPTER_SECURE_BOOT, &secure_boot);
  if (status.kind == PBNS_PLATFORM_SUCCESS) {
    status = read_boolean(get_variable, context, PBNS_ADAPTER_SETUP_MODE,
                          &setup_mode);
  }
  uint8_t db_digest[32] = {0};
  uint8_t dbx_digest[32] = {0};
  if (status.kind == PBNS_PLATFORM_SUCCESS) {
    status = hash_variable(get_variable, context, PBNS_ADAPTER_DB, scratch,
                           hash, hash_context, db_digest);
  }
  if (status.kind == PBNS_PLATFORM_SUCCESS) {
    status = hash_variable(get_variable, context, PBNS_ADAPTER_DBX, scratch,
                           hash, hash_context, dbx_digest);
  }
  if (status.kind != PBNS_PLATFORM_SUCCESS) {
    output->status = pbns_inventory_classify_platform_result(status.kind);
    memset(db_digest, 0, sizeof(db_digest));
    memset(dbx_digest, 0, sizeof(dbx_digest));
    memset(scratch.ptr, 0, scratch.cap);
    return status;
  }
  output->status = PBNS_INVENTORY_OK;
  output->secure_boot = secure_boot;
  output->setup_mode = setup_mode;
  memcpy(output->db_digest, db_digest, sizeof(db_digest));
  memcpy(output->dbx_digest, dbx_digest, sizeof(dbx_digest));
  memset(db_digest, 0, sizeof(db_digest));
  memset(dbx_digest, 0, sizeof(dbx_digest));
  memset(scratch.ptr, 0, scratch.cap);
  return status;
}

pbns_inventory_capability pbns_inventory_adapter_tcg(
    const pbns_inventory_adapter_tcg_capability *capability, uint32_t *banks,
    size_t bank_capacity, pbns_inventory_tpm_input *output) {
  if (capability == NULL || banks == NULL || output == NULL) {
    return PBNS_INVENTORY_ERROR;
  }
  *output = (pbns_inventory_tpm_input){0};
  if (!capability->present) {
    output->status = PBNS_INVENTORY_ABSENT;
    return output->status;
  }
  size_t bank_count = 0U;
  const pbns_status status = pbns_inventory_tpm_active_banks(
      capability->active_bitmap, capability->supported_bank_count, banks,
      bank_capacity, &bank_count);
  if (status != PBNS_OK) {
    output->status = status == PBNS_ERR_UNSUPPORTED
                         ? PBNS_INVENTORY_UNSUPPORTED
                         : PBNS_INVENTORY_MALFORMED;
    return output->status;
  }
  output->status = PBNS_INVENTORY_OK;
  output->present = true;
  output->manufacturer = capability->manufacturer;
  output->firmware_version = capability->firmware_version;
  output->active_banks = banks;
  output->active_bank_count = bank_count;
  return output->status;
}
