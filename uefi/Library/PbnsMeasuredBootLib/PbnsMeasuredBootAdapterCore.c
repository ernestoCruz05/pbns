#include "PbnsMeasuredBootAdapterCore.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void secure_zero(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  while (bytes != NULL && length > 0U) {
    *bytes++ = 0U;
    --length;
  }
}

static bool readable_type(uint32_t type) {
  return type <= PBNS_UEFI_CONVENTIONAL_MEMORY ||
         type == PBNS_UEFI_ACPI_RECLAIM_MEMORY ||
         type == PBNS_UEFI_ACPI_MEMORY_NVS;
}

static pbns_status release_map(const pbns_uefi_memory_ops *ops, uint8_t *map,
                               size_t allocation_size, pbns_status status) {
  if (map != NULL) {
    secure_zero(map, allocation_size);
    ops->free(ops->context, map, allocation_size);
  }
  return status;
}

static pbns_status validate_map(pbns_view map, size_t descriptor_size,
                                uint32_t descriptor_version, uint64_t address,
                                size_t maximum, size_t *extent) {
  if (descriptor_version != PBNS_UEFI_MEMORY_DESCRIPTOR_VERSION ||
      descriptor_size < sizeof(pbns_uefi_memory_descriptor) || map.len == 0U ||
      map.len % descriptor_size != 0U) {
    return PBNS_ERR_FORMAT;
  }
  bool found = false;
  size_t found_extent = 0U;
  for (size_t offset = 0U; offset < map.len; offset += descriptor_size) {
    pbns_uefi_memory_descriptor descriptor = {0};
    memcpy(&descriptor, map.ptr + offset, sizeof(descriptor));
    if (descriptor.number_of_pages == 0U ||
        descriptor.physical_start % PBNS_UEFI_MEMORY_PAGE_SIZE != 0U ||
        descriptor.number_of_pages >
            (UINT64_MAX - descriptor.physical_start) /
                PBNS_UEFI_MEMORY_PAGE_SIZE) {
      return PBNS_ERR_FORMAT;
    }
    const uint64_t end =
        descriptor.physical_start +
        descriptor.number_of_pages * PBNS_UEFI_MEMORY_PAGE_SIZE;
    if (address >= descriptor.physical_start && address < end) {
      if (!readable_type(descriptor.type) ||
          (descriptor.attribute & PBNS_UEFI_MEMORY_RP) != 0U) {
        return PBNS_ERR_FORMAT;
      }
      const uint64_t available = end - address;
      found_extent =
          available > (uint64_t)maximum ? maximum : (size_t)available;
      found = true;
    }
  }
  if (!found) {
    return PBNS_ERR_FORMAT;
  }
  *extent = found_extent;
  return PBNS_OK;
}

pbns_status pbns_uefi_memory_readable_extent(
    const pbns_uefi_memory_ops *ops, uint64_t address, size_t maximum,
    size_t *extent) {
  if (extent != NULL) {
    *extent = 0U;
  }
  if (ops == NULL || ops->get_memory_map == NULL || ops->allocate == NULL ||
      ops->free == NULL || maximum == 0U || extent == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  size_t required = 0U;
  size_t descriptor_size = 0U;
  uint32_t descriptor_version = 0U;
  if (ops->get_memory_map(ops->context, NULL, &required, &descriptor_size,
                          &descriptor_version) !=
          PBNS_UEFI_MAP_BUFFER_TOO_SMALL ||
      descriptor_size < sizeof(pbns_uefi_memory_descriptor) ||
      descriptor_version != PBNS_UEFI_MEMORY_DESCRIPTOR_VERSION ||
      required == 0U || required > PBNS_UEFI_MEMORY_MAP_MAX_SIZE) {
    return PBNS_ERR_FORMAT;
  }

  for (size_t attempt = 0U; attempt < PBNS_UEFI_MEMORY_MAP_ATTEMPTS;
       ++attempt) {
    if (descriptor_size > (SIZE_MAX - required) / 2U) {
      return PBNS_ERR_LIMIT;
    }
    const size_t allocation_size = required + 2U * descriptor_size;
    if (allocation_size > PBNS_UEFI_MEMORY_MAP_MAX_SIZE) {
      return PBNS_ERR_LIMIT;
    }
    uint8_t *map = NULL;
    pbns_status status =
        ops->allocate(ops->context, allocation_size, &map);
    if (status != PBNS_OK || map == NULL) {
      return status == PBNS_OK ? PBNS_ERR_RESOURCE : status;
    }
    size_t actual_size = allocation_size;
    size_t actual_descriptor_size = 0U;
    uint32_t actual_version = 0U;
    const pbns_uefi_map_result result = ops->get_memory_map(
        ops->context, map, &actual_size, &actual_descriptor_size,
        &actual_version);
    if (result == PBNS_UEFI_MAP_BUFFER_TOO_SMALL) {
      release_map(ops, map, allocation_size, PBNS_OK);
      if (actual_size == 0U || actual_size > PBNS_UEFI_MEMORY_MAP_MAX_SIZE ||
          actual_descriptor_size < sizeof(pbns_uefi_memory_descriptor) ||
          actual_version != PBNS_UEFI_MEMORY_DESCRIPTOR_VERSION) {
        return PBNS_ERR_FORMAT;
      }
      required = actual_size;
      descriptor_size = actual_descriptor_size;
      continue;
    }
    if (result != PBNS_UEFI_MAP_OK || actual_size > allocation_size) {
      return release_map(ops, map, allocation_size, PBNS_ERR_FORMAT);
    }
    status = validate_map((pbns_view){map, actual_size},
                          actual_descriptor_size, actual_version, address,
                          maximum, extent);
    return release_map(ops, map, allocation_size, status);
  }
  return PBNS_ERR_BUSY;
}

pbns_status pbns_uefi_memory_range_readable(
    const pbns_uefi_memory_ops *ops, uint64_t address, size_t length) {
  if (length == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  if ((uint64_t)length > UINT64_MAX - address) {
    return PBNS_ERR_LIMIT;
  }
  size_t extent = 0U;
  const pbns_status status =
      pbns_uefi_memory_readable_extent(ops, address, length, &extent);
  return status == PBNS_OK && extent != length
             ? PBNS_ERR_FORMAT
             : status;
}

static bool selection_item_equal(pbns_measured_boot_selection_item left,
                                 pbns_measured_boot_selection_item right) {
  return left.hash_algorithm == right.hash_algorithm &&
         left.pcr_index == right.pcr_index;
}

static pbns_status validate_selection(pbns_measured_boot_selection selection) {
  if (selection.items == NULL || selection.count == 0U ||
      selection.count > PBNS_MEASURED_BOOT_SELECTION_MAX_COUNT) {
    return PBNS_ERR_ARGUMENT;
  }
  for (size_t index = 0U; index < selection.count; ++index) {
    if (selection.items[index].hash_algorithm != PBNS_TPM_ALG_SHA256) {
      return PBNS_ERR_UNSUPPORTED;
    }
    if (selection.items[index].pcr_index >= 24U ||
        (index > 0U &&
         selection.items[index - 1U].pcr_index >=
             selection.items[index].pcr_index)) {
      return PBNS_ERR_FORMAT;
    }
  }
  return PBNS_OK;
}

static pbns_status validate_chunk(
    pbns_measured_boot_selection requested,
    const pbns_measured_boot_pcr_snapshot *returned) {
  if (returned->count != requested.count) {
    return PBNS_ERR_FORMAT;
  }
  for (size_t index = 0U; index < requested.count; ++index) {
    if (!selection_item_equal(returned->values[index].selection,
                              requested.items[index]) ||
        returned->values[index].digest_size !=
            PBNS_MEASURED_BOOT_DIGEST_SIZE) {
      return PBNS_ERR_FORMAT;
    }
  }
  return PBNS_OK;
}

pbns_status pbns_measured_boot_read_pcr_chunks(
    pbns_measured_boot_selection selection, size_t chunk_max,
    pbns_tpm_pcr_read_chunk_fn read_chunk, void *context,
    pbns_measured_boot_pcr_snapshot *snapshot) {
  if (snapshot != NULL) {
    *snapshot = (pbns_measured_boot_pcr_snapshot){0};
  }
  const pbns_status selection_status = validate_selection(selection);
  if (selection_status != PBNS_OK || chunk_max == 0U ||
      chunk_max > PBNS_TPM_PCR_READ_CHUNK_MAX || read_chunk == NULL ||
      snapshot == NULL) {
    return selection_status != PBNS_OK ? selection_status : PBNS_ERR_ARGUMENT;
  }
  pbns_measured_boot_pcr_snapshot chunk = {0};
  bool counter_set = false;
  uint32_t counter = 0U;
  for (size_t offset = 0U; offset < selection.count;) {
    const size_t remaining = selection.count - offset;
    const size_t count = remaining > chunk_max ? chunk_max : remaining;
    const pbns_measured_boot_selection requested = {
        selection.items + offset, count};
    chunk = (pbns_measured_boot_pcr_snapshot){0};
    pbns_status status = read_chunk(context, requested, &chunk);
    if (status == PBNS_OK) {
      status = validate_chunk(requested, &chunk);
    }
    if (status != PBNS_OK ||
        (counter_set && chunk.update_counter != counter)) {
      secure_zero(&chunk, sizeof(chunk));
      secure_zero(snapshot, sizeof(*snapshot));
      return status == PBNS_OK ? PBNS_ERR_BUSY : status;
    }
    if (!counter_set) {
      counter = chunk.update_counter;
      counter_set = true;
    }
    memcpy(snapshot->values + offset, chunk.values,
           count * sizeof(chunk.values[0]));
    offset += count;
  }
  snapshot->count = selection.count;
  snapshot->update_counter = counter;
  secure_zero(&chunk, sizeof(chunk));
  return PBNS_OK;
}
