#ifndef PBNS_MEASURED_BOOT_ADAPTER_CORE_H
#define PBNS_MEASURED_BOOT_ADAPTER_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/measured_boot.h"
#include "pbns/status.h"

#define PBNS_UEFI_MEMORY_DESCRIPTOR_VERSION UINT32_C(1)
#define PBNS_UEFI_MEMORY_PAGE_SIZE UINT64_C(4096)
#define PBNS_UEFI_MEMORY_RP UINT64_C(0x0000000000002000)
#define PBNS_UEFI_MEMORY_MAP_MAX_SIZE ((size_t)1024U * 1024U)
#define PBNS_UEFI_MEMORY_MAP_ATTEMPTS 3U
#define PBNS_TPM_PCR_READ_CHUNK_MAX 8U

typedef enum pbns_uefi_memory_type {
  PBNS_UEFI_RESERVED_MEMORY = 0,
  PBNS_UEFI_LOADER_CODE = 1,
  PBNS_UEFI_LOADER_DATA = 2,
  PBNS_UEFI_BOOT_SERVICES_CODE = 3,
  PBNS_UEFI_BOOT_SERVICES_DATA = 4,
  PBNS_UEFI_RUNTIME_SERVICES_CODE = 5,
  PBNS_UEFI_RUNTIME_SERVICES_DATA = 6,
  PBNS_UEFI_CONVENTIONAL_MEMORY = 7,
  PBNS_UEFI_UNUSABLE_MEMORY = 8,
  PBNS_UEFI_ACPI_RECLAIM_MEMORY = 9,
  PBNS_UEFI_ACPI_MEMORY_NVS = 10,
  PBNS_UEFI_MEMORY_MAPPED_IO = 11,
  PBNS_UEFI_MEMORY_MAPPED_IO_PORT_SPACE = 12,
  PBNS_UEFI_PAL_CODE = 13,
  PBNS_UEFI_PERSISTENT_MEMORY = 14
} pbns_uefi_memory_type;

typedef struct pbns_uefi_memory_descriptor {
  uint32_t type;
  uint32_t padding;
  uint64_t physical_start;
  uint64_t virtual_start;
  uint64_t number_of_pages;
  uint64_t attribute;
} pbns_uefi_memory_descriptor;

typedef enum pbns_uefi_map_result {
  PBNS_UEFI_MAP_OK = 0,
  PBNS_UEFI_MAP_BUFFER_TOO_SMALL = 1,
  PBNS_UEFI_MAP_ERROR = 2
} pbns_uefi_map_result;

typedef pbns_uefi_map_result (*pbns_uefi_get_memory_map_fn)(
    void *context, uint8_t *map, size_t *map_size, size_t *descriptor_size,
    uint32_t *descriptor_version);
typedef pbns_status (*pbns_uefi_allocate_fn)(void *context, size_t size,
                                             uint8_t **allocation);
typedef void (*pbns_uefi_free_fn)(void *context, uint8_t *allocation,
                                  size_t size);

typedef struct pbns_uefi_memory_ops {
  pbns_uefi_get_memory_map_fn get_memory_map;
  pbns_uefi_allocate_fn allocate;
  pbns_uefi_free_fn free;
  void *context;
} pbns_uefi_memory_ops;

typedef pbns_status (*pbns_tpm_pcr_read_chunk_fn)(
    void *context, pbns_measured_boot_selection selection,
    pbns_measured_boot_pcr_snapshot *snapshot);

pbns_status pbns_uefi_memory_readable_extent(
    const pbns_uefi_memory_ops *ops, uint64_t address, size_t maximum,
    size_t *extent);
pbns_status pbns_uefi_memory_range_readable(
    const pbns_uefi_memory_ops *ops, uint64_t address, size_t length);
pbns_status pbns_measured_boot_read_pcr_chunks(
    pbns_measured_boot_selection selection, size_t chunk_max,
    pbns_tpm_pcr_read_chunk_fn read_chunk, void *context,
    pbns_measured_boot_pcr_snapshot *snapshot);
#endif
