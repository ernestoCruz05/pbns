#include "PbnsMeasuredBootAdapterCore.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct fake_map {
  pbns_uefi_memory_descriptor descriptors[3];
  size_t count;
  size_t descriptor_size;
  uint32_t version;
  size_t get_calls;
  size_t grow_on_call;
  size_t allocations;
  size_t frees;
  bool any_unwiped_free;
  bool force_error;
  size_t error_on_call;
  bool always_grow;
  bool nondivisible;
} fake_map;

typedef struct fake_pcr {
  size_t calls;
  size_t requested[3];
  uint32_t counters[3];
  size_t mismatch_call;
  bool saw_wiped;
} fake_pcr;

static pbns_uefi_map_result get_map(void *context, uint8_t *map,
                                    size_t *map_size, size_t *descriptor_size,
                                    uint32_t *version) {
  fake_map *fake = context;
  ++fake->get_calls;
  *descriptor_size = fake->descriptor_size;
  *version = fake->version;
  size_t required = fake->count * fake->descriptor_size;
  if (fake->nondivisible) {
    ++required;
  }
  if (fake->force_error || fake->get_calls == fake->error_on_call) {
    return PBNS_UEFI_MAP_ERROR;
  }
  if (map == NULL || *map_size < required || fake->always_grow ||
      fake->get_calls == fake->grow_on_call) {
    *map_size = required + (fake->get_calls == fake->grow_on_call ?
                                fake->descriptor_size : 0U);
    return PBNS_UEFI_MAP_BUFFER_TOO_SMALL;
  }
  memset(map, 0, *map_size);
  for (size_t index = 0U; index < fake->count; ++index) {
    memcpy(map + index * fake->descriptor_size, &fake->descriptors[index],
           sizeof(fake->descriptors[index]));
  }
  *map_size = required;
  return PBNS_UEFI_MAP_OK;
}

static pbns_status allocate_map(void *context, size_t size,
                                uint8_t **allocation) {
  fake_map *fake = context;
  *allocation = malloc(size);
  if (*allocation == NULL) {
    return PBNS_ERR_RESOURCE;
  }
  memset(*allocation, 0xa5, size);
  ++fake->allocations;
  return PBNS_OK;
}

static void free_map(void *context, uint8_t *allocation, size_t size) {
  fake_map *fake = context;
  for (size_t index = 0U; index < size; ++index) {
    fake->any_unwiped_free =
        fake->any_unwiped_free || allocation[index] != 0U;
  }
  ++fake->frees;
  free(allocation);
}

static pbns_uefi_memory_ops map_ops(fake_map *fake) {
  return (pbns_uefi_memory_ops){get_map, allocate_map, free_map, fake};
}

static fake_map readable_map(uint32_t type) {
  fake_map fake = {
      .count = 1U,
      .descriptor_size = sizeof(pbns_uefi_memory_descriptor),
      .version = PBNS_UEFI_MEMORY_DESCRIPTOR_VERSION,
  };
  fake.descriptors[0] = (pbns_uefi_memory_descriptor){
      .type = type, .physical_start = UINT64_C(0x1000), .number_of_pages = 2U};
  return fake;
}

static void test_memory_map_policy(void) {
  const uint32_t allowed[] = {
      PBNS_UEFI_RESERVED_MEMORY, PBNS_UEFI_LOADER_CODE,
      PBNS_UEFI_LOADER_DATA, PBNS_UEFI_BOOT_SERVICES_CODE,
      PBNS_UEFI_BOOT_SERVICES_DATA, PBNS_UEFI_RUNTIME_SERVICES_CODE,
      PBNS_UEFI_RUNTIME_SERVICES_DATA, PBNS_UEFI_CONVENTIONAL_MEMORY,
      PBNS_UEFI_ACPI_RECLAIM_MEMORY, PBNS_UEFI_ACPI_MEMORY_NVS};
  for (size_t index = 0U; index < sizeof(allowed) / sizeof(allowed[0]); ++index) {
    fake_map fake = readable_map(allowed[index]);
    const pbns_uefi_memory_ops ops = map_ops(&fake);
    size_t extent = 0U;
    assert(pbns_uefi_memory_readable_extent(&ops, UINT64_C(0x1800), 8192U,
                                            &extent) == PBNS_OK);
    assert(extent == 6144U);
    assert(fake.allocations == 1U && fake.frees == 1U &&
           !fake.any_unwiped_free);
  }
  const uint32_t rejected[] = {
      PBNS_UEFI_UNUSABLE_MEMORY, PBNS_UEFI_MEMORY_MAPPED_IO,
      PBNS_UEFI_MEMORY_MAPPED_IO_PORT_SPACE, PBNS_UEFI_PAL_CODE,
      PBNS_UEFI_PERSISTENT_MEMORY};
  for (size_t index = 0U; index < sizeof(rejected) / sizeof(rejected[0]); ++index) {
    fake_map fake = readable_map(rejected[index]);
    const pbns_uefi_memory_ops ops = map_ops(&fake);
    assert(pbns_uefi_memory_range_readable(&ops, UINT64_C(0x1000), 1U) ==
           PBNS_ERR_FORMAT);
    assert(!fake.any_unwiped_free);
  }
  fake_map fake = readable_map(PBNS_UEFI_BOOT_SERVICES_DATA);
  fake.descriptors[0].attribute = PBNS_UEFI_MEMORY_RP;
  pbns_uefi_memory_ops ops = map_ops(&fake);
  assert(pbns_uefi_memory_range_readable(&ops, UINT64_C(0x1000), 1U) ==
         PBNS_ERR_FORMAT);

  fake = readable_map(PBNS_UEFI_RESERVED_MEMORY);
  fake.grow_on_call = 2U;
  ops = map_ops(&fake);
  assert(pbns_uefi_memory_range_readable(&ops, UINT64_C(0x1000), 4096U) ==
         PBNS_OK);
  assert(fake.allocations == 2U && fake.frees == 2U &&
         !fake.any_unwiped_free);
  fake = readable_map(PBNS_UEFI_RESERVED_MEMORY);
  fake.error_on_call = 2U;
  ops = map_ops(&fake);
  assert(pbns_uefi_memory_range_readable(&ops, UINT64_C(0x1000), 1U) ==
         PBNS_ERR_FORMAT);
  assert(fake.allocations == 1U && fake.frees == 1U &&
         !fake.any_unwiped_free);
  fake = readable_map(PBNS_UEFI_RESERVED_MEMORY);
  fake.always_grow = true;
  ops = map_ops(&fake);
  assert(pbns_uefi_memory_range_readable(&ops, UINT64_C(0x1000), 1U) ==
         PBNS_ERR_BUSY);
  assert(fake.allocations == PBNS_UEFI_MEMORY_MAP_ATTEMPTS &&
         fake.frees == PBNS_UEFI_MEMORY_MAP_ATTEMPTS &&
         !fake.any_unwiped_free);

  fake = readable_map(PBNS_UEFI_RESERVED_MEMORY);
  fake.descriptor_size = sizeof(pbns_uefi_memory_descriptor) - 1U;
  ops = map_ops(&fake);
  assert(pbns_uefi_memory_range_readable(&ops, UINT64_C(0x1000), 1U) ==
         PBNS_ERR_FORMAT);
  fake = readable_map(PBNS_UEFI_RESERVED_MEMORY);
  fake.nondivisible = true;
  ops = map_ops(&fake);
  assert(pbns_uefi_memory_range_readable(&ops, UINT64_C(0x1000), 1U) ==
         PBNS_ERR_FORMAT);
  fake = readable_map(PBNS_UEFI_RESERVED_MEMORY);
  fake.version = 2U;
  ops = map_ops(&fake);
  assert(pbns_uefi_memory_range_readable(&ops, UINT64_C(0x1000), 1U) ==
         PBNS_ERR_FORMAT);
  fake = readable_map(PBNS_UEFI_RESERVED_MEMORY);
  fake.descriptors[0].number_of_pages = 0U;
  ops = map_ops(&fake);
  assert(pbns_uefi_memory_range_readable(&ops, UINT64_C(0x1000), 1U) ==
         PBNS_ERR_FORMAT);
  fake = readable_map(PBNS_UEFI_RESERVED_MEMORY);
  fake.descriptors[0].physical_start = UINT64_C(0x1001);
  ops = map_ops(&fake);
  assert(pbns_uefi_memory_range_readable(&ops, UINT64_C(0x1001), 1U) ==
         PBNS_ERR_FORMAT);
  fake = readable_map(PBNS_UEFI_RESERVED_MEMORY);
  fake.descriptors[0].physical_start = UINT64_MAX - 4095U;
  fake.descriptors[0].number_of_pages = 2U;
  ops = map_ops(&fake);
  assert(pbns_uefi_memory_range_readable(&ops, UINT64_MAX - 1U, 1U) ==
         PBNS_ERR_FORMAT);
  fake = readable_map(PBNS_UEFI_RESERVED_MEMORY);
  ops = map_ops(&fake);
  assert(pbns_uefi_memory_range_readable(&ops, UINT64_C(0x1fff), 2U) ==
         PBNS_OK);
  assert(pbns_uefi_memory_range_readable(&ops, UINT64_C(0x2fff), 2U) ==
         PBNS_ERR_FORMAT);
  assert(pbns_uefi_memory_range_readable(&ops, UINT64_MAX, 2U) ==
         PBNS_ERR_LIMIT);
}

static pbns_status read_chunk(void *context,
                              pbns_measured_boot_selection selection,
                              pbns_measured_boot_pcr_snapshot *snapshot) {
  fake_pcr *fake = context;
  const size_t call = fake->calls++;
  assert(call < 3U);
  fake->requested[call] = selection.count;
  *snapshot = (pbns_measured_boot_pcr_snapshot){0};
  snapshot->count = selection.count;
  snapshot->update_counter = fake->counters[call];
  for (size_t index = 0U; index < selection.count; ++index) {
    snapshot->values[index].selection = selection.items[index];
    snapshot->values[index].digest_size = PBNS_MEASURED_BOOT_DIGEST_SIZE;
    memset(snapshot->values[index].digest,
           (int)selection.items[index].pcr_index, PBNS_MEASURED_BOOT_DIGEST_SIZE);
  }
  if (fake->mismatch_call == call + 1U) {
    snapshot->values[0].selection.pcr_index ^= 1U;
  }
  return PBNS_OK;
}

static void make_selection(pbns_measured_boot_selection_item items[24],
                           size_t count) {
  for (size_t index = 0U; index < count; ++index) {
    items[index] = (pbns_measured_boot_selection_item){
        PBNS_TPM_ALG_SHA256, (uint8_t)index};
  }
}

static void test_pcr_chunks(void) {
  pbns_measured_boot_selection_item items[24] = {0};
  make_selection(items, 24U);
  fake_pcr fake = {.counters = {7U, 7U, 7U}};
  pbns_measured_boot_pcr_snapshot output = {0};
  assert(pbns_measured_boot_read_pcr_chunks(
             (pbns_measured_boot_selection){items, 9U},
             PBNS_TPM_PCR_READ_CHUNK_MAX, read_chunk, &fake, &output) == PBNS_OK);
  assert(fake.calls == 2U && fake.requested[0] == 8U && fake.requested[1] == 1U);
  assert(output.count == 9U && output.values[8].digest[0] == 8U);

  fake = (fake_pcr){.counters = {7U, 7U, 7U}};
  assert(pbns_measured_boot_read_pcr_chunks(
             (pbns_measured_boot_selection){items, 24U}, 8U, read_chunk, &fake,
             &output) == PBNS_OK);
  assert(fake.calls == 3U && fake.requested[0] == 8U &&
         fake.requested[1] == 8U && fake.requested[2] == 8U);

  fake = (fake_pcr){.counters = {7U, 8U, 8U}};
  memset(&output, 0xa5, sizeof(output));
  assert(pbns_measured_boot_read_pcr_chunks(
             (pbns_measured_boot_selection){items, 9U}, 8U, read_chunk, &fake,
             &output) == PBNS_ERR_BUSY);
  for (size_t index = 0U; index < sizeof(output); ++index) {
    assert(((const uint8_t *)&output)[index] == 0U);
  }
  fake = (fake_pcr){.counters = {7U, 7U}, .mismatch_call = 2U};
  assert(pbns_measured_boot_read_pcr_chunks(
             (pbns_measured_boot_selection){items, 9U}, 8U, read_chunk, &fake,
             &output) == PBNS_ERR_FORMAT);
  for (size_t index = 0U; index < sizeof(output); ++index) {
    assert(((const uint8_t *)&output)[index] == 0U);
  }
}

int main(void) {
  test_memory_map_policy();
  test_pcr_chunks();
  return 0;
}
