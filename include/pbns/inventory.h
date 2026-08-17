#ifndef PBNS_INVENTORY_H
#define PBNS_INVENTORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_INVENTORY_DIGEST_SIZE 32U
#define PBNS_INVENTORY_PCI_FUNCTION_MAX 256U
#define PBNS_INVENTORY_BLOCK_DEVICE_MAX 64U
#define PBNS_INVENTORY_ENCODED_MAX_SIZE ((size_t)64U * 1024U)
#define PBNS_INVENTORY_VARIABLE_MAX_SIZE ((size_t)64U * 1024U)
#define PBNS_INVENTORY_TEXT_MAX_SIZE 96U
#define PBNS_INVENTORY_TPM_BANK_MAX 8U
#define PBNS_INVENTORY_TIMING_MAX 8U
#define PBNS_INVENTORY_SMBIOS_RECORD_MAX 1024U
#define PBNS_INVENTORY_SMBIOS_TABLE_MAX_SIZE ((size_t)1024U * 1024U)
#define PBNS_INVENTORY_SMBIOS_COUNT_MAX 1024U
#define PBNS_INVENTORY_PCI_TUPLE_SIZE 12U

#define PBNS_INVENTORY_VARIABLE_ABSENT_DOMAIN "PBNS UEFI VARIABLE ABSENT V1"
#define PBNS_INVENTORY_VARIABLE_PRESENT_DOMAIN "PBNS UEFI VARIABLE PRESENT V1"

typedef enum pbns_inventory_capability {
  PBNS_INVENTORY_OK = 0,
  PBNS_INVENTORY_ABSENT = 1,
  PBNS_INVENTORY_UNSUPPORTED = 2,
  PBNS_INVENTORY_MALFORMED = 3,
  PBNS_INVENTORY_LIMIT = 4,
  PBNS_INVENTORY_ERROR = 5
} pbns_inventory_capability;

typedef enum pbns_inventory_outcome_key {
  PBNS_INVENTORY_OUTCOME_SMBIOS = 1,
  PBNS_INVENTORY_OUTCOME_PCI = 2,
  PBNS_INVENTORY_OUTCOME_STORAGE = 3,
  PBNS_INVENTORY_OUTCOME_SECURE_BOOT = 4,
  PBNS_INVENTORY_OUTCOME_TPM = 5
} pbns_inventory_outcome_key;

typedef enum pbns_inventory_platform_result {
  PBNS_PLATFORM_SUCCESS = 0,
  PBNS_PLATFORM_NOT_FOUND = 1,
  PBNS_PLATFORM_UNSUPPORTED = 2,
  PBNS_PLATFORM_MALFORMED = 3,
  PBNS_PLATFORM_LIMIT = 4,
  PBNS_PLATFORM_ERROR = 5
} pbns_inventory_platform_result;

typedef struct pbns_inventory_text {
  uint8_t bytes[PBNS_INVENTORY_TEXT_MAX_SIZE];
  size_t len;
} pbns_inventory_text;

typedef struct pbns_inventory_pci_function {
  uint16_t segment;
  uint8_t bus;
  uint8_t device;
  uint8_t function;
  uint16_t vendor_id;
  uint16_t device_id;
  uint8_t class_code;
  uint8_t subclass;
  uint8_t prog_if;
} pbns_inventory_pci_function;

typedef struct pbns_inventory_block_device {
  uint64_t last_block;
  uint32_t block_size;
  bool removable;
  bool logical_partition;
} pbns_inventory_block_device;

typedef struct pbns_inventory_secure_boot_input {
  pbns_inventory_capability status;
  bool secure_boot;
  bool setup_mode;
  uint8_t db_digest[PBNS_INVENTORY_DIGEST_SIZE];
  uint8_t dbx_digest[PBNS_INVENTORY_DIGEST_SIZE];
} pbns_inventory_secure_boot_input;

typedef struct pbns_inventory_tpm_input {
  pbns_inventory_capability status;
  bool present;
  uint32_t manufacturer;
  uint32_t firmware_version;
  const uint32_t *active_banks;
  size_t active_bank_count;
} pbns_inventory_tpm_input;

typedef struct pbns_inventory_timing {
  uint32_t key;
  uint64_t microseconds;
} pbns_inventory_timing;

typedef pbns_status (*pbns_inventory_hash_fn)(void *context, pbns_view input,
                                               uint8_t digest[32]);
typedef pbns_status (*pbns_inventory_hash_parts_fn)(
    void *context, const pbns_view *parts, size_t part_count,
    uint8_t digest[PBNS_INVENTORY_DIGEST_SIZE]);

/* O estado conserva apenas os campos SMBIOS aprovados e normalizados. */
typedef struct pbns_inventory_smbios_collector {
  pbns_inventory_text firmware_vendor;
  pbns_inventory_text firmware_version;
  pbns_inventory_text cpu_class;
  uint8_t board_material[3U * (PBNS_INVENTORY_TEXT_MAX_SIZE + 1U)];
  size_t board_material_len;
  uint64_t memory_mib;
  size_t record_count;
  bool end_seen;
} pbns_inventory_smbios_collector;

/* A inserção ordenada evita um temporário grande na pilha UEFI. */
typedef struct pbns_inventory_pci_collector {
  uint8_t tuples[PBNS_INVENTORY_PCI_FUNCTION_MAX]
                [PBNS_INVENTORY_PCI_TUPLE_SIZE];
  size_t function_count;
} pbns_inventory_pci_collector;

typedef struct pbns_inventory_storage_collector {
  uint64_t count;
  uint64_t total_bytes;
} pbns_inventory_storage_collector;

/* Esta fronteira impede que identificadores brutos entrem no relatório. */
typedef struct pbns_inventory_inputs {
  pbns_view host_fingerprint;
  pbns_inventory_capability smbios_status;
  pbns_inventory_text firmware_vendor;
  pbns_inventory_text firmware_version;
  pbns_inventory_text cpu_class;
  uint64_t memory_mib;
  uint8_t board_model_digest[PBNS_INVENTORY_DIGEST_SIZE];
  pbns_inventory_capability pci_status;
  uint8_t pci_digest[PBNS_INVENTORY_DIGEST_SIZE];
  pbns_inventory_capability storage_status;
  uint64_t block_device_count;
  uint64_t storage_capacity_gib;
  pbns_inventory_secure_boot_input secure_boot;
  pbns_inventory_tpm_input tpm;
  uint32_t pbns_version;
  uint32_t pico_version;
  uint32_t gateway_version;
  const pbns_inventory_timing *timings;
  size_t timing_count;
  uint64_t prior_loader_efi_status;
} pbns_inventory_inputs;

typedef struct pbns_inventory_report {
  uint8_t host_fingerprint[PBNS_INVENTORY_DIGEST_SIZE];
  uint8_t board_model_digest[PBNS_INVENTORY_DIGEST_SIZE];
  pbns_inventory_text firmware_vendor;
  pbns_inventory_text firmware_version;
  pbns_inventory_text cpu_class;
  uint64_t memory_mib;
  uint8_t pci_digest[PBNS_INVENTORY_DIGEST_SIZE];
  uint64_t block_device_count;
  uint64_t storage_capacity_gib;
  bool secure_boot;
  bool setup_mode;
  uint8_t db_digest[PBNS_INVENTORY_DIGEST_SIZE];
  uint8_t dbx_digest[PBNS_INVENTORY_DIGEST_SIZE];
  bool tpm_present;
  uint32_t tpm_manufacturer;
  uint32_t tpm_firmware_version;
  uint32_t tpm_active_banks[PBNS_INVENTORY_TPM_BANK_MAX];
  size_t tpm_active_bank_count;
  uint32_t pbns_version;
  uint32_t pico_version;
  uint32_t gateway_version;
  pbns_inventory_capability outcomes[5];
  pbns_inventory_timing timings[PBNS_INVENTORY_TIMING_MAX];
  size_t timing_count;
  uint64_t prior_loader_efi_status;
} pbns_inventory_report;

bool pbns_inventory_text_is_normalized(const pbns_inventory_text *text);
pbns_inventory_capability pbns_inventory_classify_platform_result(
    pbns_inventory_platform_result result);
pbns_status pbns_inventory_tpm_active_banks(
    uint32_t active_bitmap, size_t supported_bank_count, uint32_t *banks,
    size_t bank_capacity, size_t *bank_count);
pbns_status pbns_inventory_smbios_consume(
    pbns_inventory_smbios_collector *collector, pbns_view record);
pbns_status pbns_inventory_smbios_consume_table(
    pbns_inventory_smbios_collector *collector, pbns_view table,
    bool require_exact_end);
pbns_status pbns_inventory_smbios_finish(
    const pbns_inventory_smbios_collector *collector,
    pbns_inventory_hash_fn hash, void *context,
    uint8_t board_digest[PBNS_INVENTORY_DIGEST_SIZE]);
pbns_status pbns_inventory_pci_add(
    pbns_inventory_pci_collector *collector,
    const pbns_inventory_pci_function *function);
pbns_status pbns_inventory_pci_finish(
    const pbns_inventory_pci_collector *collector, pbns_inventory_hash_fn hash,
    void *context, uint8_t digest[PBNS_INVENTORY_DIGEST_SIZE]);
pbns_status pbns_inventory_storage_add(
    pbns_inventory_storage_collector *collector,
    const pbns_inventory_block_device *device);
pbns_status pbns_inventory_hash_variable(
    pbns_inventory_hash_parts_fn hash, void *context, bool present,
    uint32_t attributes, pbns_view variable,
    uint8_t digest[PBNS_INVENTORY_DIGEST_SIZE]);
pbns_status pbns_inventory_collect(const pbns_inventory_inputs *inputs,
                                   pbns_inventory_report *report);
pbns_status pbns_inventory_encode(const pbns_inventory_report *report,
                                  pbns_buffer output, size_t *written);

#endif
