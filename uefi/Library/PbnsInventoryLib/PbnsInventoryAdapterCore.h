#ifndef PBNS_INVENTORY_ADAPTER_CORE_H
#define PBNS_INVENTORY_ADAPTER_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/inventory.h"

typedef struct pbns_inventory_adapter_result {
  pbns_inventory_platform_result kind;
  uint64_t native_status;
} pbns_inventory_adapter_result;

typedef enum pbns_inventory_adapter_variable {
  PBNS_ADAPTER_SECURE_BOOT = 1,
  PBNS_ADAPTER_SETUP_MODE = 2,
  PBNS_ADAPTER_DB = 3,
  PBNS_ADAPTER_DBX = 4
} pbns_inventory_adapter_variable;

typedef pbns_inventory_adapter_result (*pbns_inventory_adapter_get_variable)(
    void *context, pbns_inventory_adapter_variable variable, uint8_t *data,
    size_t *size, uint32_t *attributes);

typedef struct pbns_inventory_adapter_smbios_table {
  uint64_t address;
  size_t length;
  size_t expected_record_count;
  bool require_exact_end;
} pbns_inventory_adapter_smbios_table;

typedef struct pbns_inventory_adapter_tcg_capability {
  bool present;
  uint32_t manufacturer;
  uint32_t firmware_version;
  uint32_t active_bitmap;
  size_t supported_bank_count;
} pbns_inventory_adapter_tcg_capability;

pbns_inventory_adapter_result pbns_inventory_adapter_secure_boot(
    pbns_inventory_adapter_get_variable get_variable, void *context,
    pbns_buffer scratch, pbns_inventory_hash_parts_fn hash, void *hash_context,
    pbns_inventory_secure_boot_input *output);
pbns_inventory_adapter_result pbns_inventory_adapter_smbios_entry(
    pbns_view entry, bool version3,
    pbns_inventory_adapter_smbios_table *table);
pbns_inventory_adapter_result pbns_inventory_adapter_smbios_collect(
    pbns_view entry, bool version3, pbns_view declared_table,
    pbns_inventory_smbios_collector *collector);
pbns_inventory_capability pbns_inventory_adapter_tcg(
    const pbns_inventory_adapter_tcg_capability *capability, uint32_t *banks,
    size_t bank_capacity, pbns_inventory_tpm_input *output);

#endif
