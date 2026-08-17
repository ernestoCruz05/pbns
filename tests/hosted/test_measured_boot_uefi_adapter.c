#include "PbnsMeasuredBootUefiAdapter.h"

#include <IndustryStandard/Tpm20.h>
#include <Library/BaseMemoryLib.h>
#include <Library/Tpm2CommandLib.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

EFI_GUID gEfiTcg2ProtocolGuid = {0};
EFI_GUID gEfiTcg2FinalEventsTableGuid = {
    UINT32_C(0x1e2ed096), UINT16_C(0x30e2), UINT16_C(0x4254),
    {0xbdU, 0x89U, 0x86U, 0x3bU, 0xbeU, 0xf8U, 0x23U, 0x25U}};

VOID *SetMem(VOID *buffer, UINTN size, UINT8 value) {
  return memset(buffer, value, size);
}

VOID *ZeroMem(VOID *buffer, UINTN size) { return memset(buffer, 0, size); }

VOID *CopyMem(VOID *destination, const VOID *source, UINTN size) {
  return memcpy(destination, source, size);
}

INTN CompareMem(const VOID *first, const VOID *second, UINTN size) {
  return (INTN)memcmp(first, second, size);
}

BOOLEAN CompareGuid(const EFI_GUID *first, const EFI_GUID *second) {
  return (BOOLEAN)(memcmp(first, second, sizeof(*first)) == 0);
}

typedef struct fake_tpm {
  UINT8 masks[3][3];
  size_t calls;
  size_t mismatch_call;
  UINT32 counters[3];
} fake_tpm;

static fake_tpm tpm;

EFI_STATUS Tpm2PcrRead(TPML_PCR_SELECTION *input, UINT32 *counter,
                       TPML_PCR_SELECTION *output, TPML_DIGEST *values) {
  const size_t call = tpm.calls++;
  assert(call < 3U);
  assert(input->count == 1U);
  assert(input->pcrSelections[0].hash == TPM_ALG_SHA256);
  assert(input->pcrSelections[0].sizeofSelect == 3U);
  memcpy(tpm.masks[call], input->pcrSelections[0].pcrSelect, 3U);
  *output = *input;
  if (tpm.mismatch_call == call + 1U) {
    output->pcrSelections[0].pcrSelect[0] ^= 1U;
  }
  *counter = tpm.counters[call];
  values->count = 0U;
  for (UINT8 pcr = 0U; pcr < 24U; ++pcr) {
    if ((input->pcrSelections[0].pcrSelect[pcr / 8U] &
         (UINT8)(1U << (pcr % 8U))) != 0U) {
      TPM2B_DIGEST *digest = &values->digests[values->count++];
      digest->size = PBNS_MEASURED_BOOT_DIGEST_SIZE;
      memset(digest->buffer, pcr, PBNS_MEASURED_BOOT_DIGEST_SIZE);
    }
  }
  return EFI_SUCCESS;
}

static void make_selection(pbns_measured_boot_selection_item items[24]) {
  for (size_t index = 0U; index < 24U; ++index) {
    items[index] = (pbns_measured_boot_selection_item){
        PBNS_TPM_ALG_SHA256, (uint8_t)index};
  }
}

static void assert_zero(const void *value, size_t size) {
  const uint8_t *bytes = value;
  for (size_t index = 0U; index < size; ++index) {
    assert(bytes[index] == 0U);
  }
}

static void test_actual_pcr_masks(void) {
  pbns_measured_boot_selection_item items[24] = {0};
  make_selection(items);
  pbns_measured_boot_pcr_snapshot snapshot = {0};
  EFI_STATUS last_status = EFI_SUCCESS;
  tpm = (fake_tpm){.counters = {9U, 9U, 9U}};
  assert(pbns_measured_boot_read_pcr_chunks(
             (pbns_measured_boot_selection){items, 9U}, 8U,
             PbnsMeasuredBootUefiPcrReadChunk, &last_status, &snapshot) ==
         PBNS_OK);
  assert(tpm.calls == 2U);
  static const UINT8 first_mask[3] = {0xffU, 0U, 0U};
  static const UINT8 second_mask[3] = {0U, 0x01U, 0U};
  assert(memcmp(tpm.masks[0], first_mask, sizeof(first_mask)) == 0);
  assert(memcmp(tpm.masks[1], second_mask, sizeof(second_mask)) == 0);
  assert(snapshot.count == 9U);
  for (size_t index = 0U; index < snapshot.count; ++index) {
    assert(snapshot.values[index].selection.pcr_index == index);
    assert(snapshot.values[index].digest[0] == index);
  }

  tpm = (fake_tpm){.counters = {11U, 11U, 11U}};
  assert(pbns_measured_boot_read_pcr_chunks(
             (pbns_measured_boot_selection){items, 24U}, 8U,
             PbnsMeasuredBootUefiPcrReadChunk, &last_status, &snapshot) ==
         PBNS_OK);
  assert(tpm.calls == 3U);
  static const UINT8 masks[3][3] = {
      {0xffU, 0U, 0U}, {0U, 0xffU, 0U}, {0U, 0U, 0xffU}};
  assert(memcmp(tpm.masks, masks, sizeof(masks)) == 0);
  for (size_t index = 0U; index < snapshot.count; ++index) {
    assert(snapshot.values[index].selection.pcr_index == index);
    assert(snapshot.values[index].digest[0] == index);
  }

  tpm = (fake_tpm){.counters = {7U, 7U}, .mismatch_call = 2U};
  memset(&snapshot, 0xa5, sizeof(snapshot));
  assert(pbns_measured_boot_read_pcr_chunks(
             (pbns_measured_boot_selection){items, 9U}, 8U,
             PbnsMeasuredBootUefiPcrReadChunk, &last_status, &snapshot) ==
         PBNS_ERR_FORMAT);
  assert_zero(&snapshot, sizeof(snapshot));
}

typedef struct mutating_map {
  EFI_SYSTEM_TABLE *system_table;
  EFI_CONFIGURATION_TABLE *replacement_entries;
  UINTN replacement_count;
  pbns_uefi_memory_descriptor descriptor;
  size_t calls;
  size_t frees;
  bool unwiped;
} mutating_map;

static pbns_uefi_map_result get_mutating_map(
    void *context, uint8_t *map, size_t *map_size, size_t *descriptor_size,
    uint32_t *version) {
  mutating_map *fake = context;
  ++fake->calls;
  fake->system_table->ConfigurationTable = fake->replacement_entries;
  fake->system_table->NumberOfTableEntries = fake->replacement_count;
  *descriptor_size = sizeof(fake->descriptor);
  *version = PBNS_UEFI_MEMORY_DESCRIPTOR_VERSION;
  if (map == NULL || *map_size < sizeof(fake->descriptor)) {
    *map_size = sizeof(fake->descriptor);
    return PBNS_UEFI_MAP_BUFFER_TOO_SMALL;
  }
  memcpy(map, &fake->descriptor, sizeof(fake->descriptor));
  *map_size = sizeof(fake->descriptor);
  return PBNS_UEFI_MAP_OK;
}

static pbns_status allocate_map(void *context, size_t size,
                                uint8_t **allocation) {
  (void)context;
  *allocation = malloc(size);
  return *allocation == NULL ? PBNS_ERR_RESOURCE : PBNS_OK;
}

static void free_map(void *context, uint8_t *allocation, size_t size) {
  mutating_map *fake = context;
  for (size_t index = 0U; index < size; ++index) {
    fake->unwiped = fake->unwiped || allocation[index] != 0U;
  }
  ++fake->frees;
  free(allocation);
}

static pbns_uefi_memory_descriptor descriptor_for_entries(
    const EFI_CONFIGURATION_TABLE *entries, size_t count) {
  const uintptr_t start = (uintptr_t)entries & ~(uintptr_t)0xfffU;
  const uintptr_t end =
      (uintptr_t)entries + count * sizeof(EFI_CONFIGURATION_TABLE);
  return (pbns_uefi_memory_descriptor){
      .type = PBNS_UEFI_BOOT_SERVICES_DATA,
      .physical_start = (uint64_t)start,
      .number_of_pages = (uint64_t)((end - start + 4095U) / 4096U),
  };
}

static void test_configuration_table_snapshot_shrinks_live_count(void) {
  int expected_table = 7;
  EFI_CONFIGURATION_TABLE entries[2] = {
      {.VendorGuid = {0}, .VendorTable = NULL},
      {.VendorGuid = gEfiTcg2FinalEventsTableGuid,
       .VendorTable = &expected_table},
  };
  EFI_CONFIGURATION_TABLE replacement_entries[2] = {
      {.VendorGuid = {0}, .VendorTable = NULL},
      {.VendorGuid = {0}, .VendorTable = NULL},
  };
  EFI_SYSTEM_TABLE system_table = {
      .NumberOfTableEntries = 2U,
      .ConfigurationTable = entries,
  };
  mutating_map fake = {
      .system_table = &system_table,
      .replacement_entries = replacement_entries,
      .replacement_count = 1U,
      .descriptor = descriptor_for_entries(entries, 2U),
  };
  const pbns_uefi_memory_ops ops = {
      get_mutating_map, allocate_map, free_map, &fake};
  VOID *found = NULL;
  assert(PbnsMeasuredBootFindFinalEventsTable(&system_table, &ops, &found) ==
         EFI_SUCCESS);
  assert(found == &expected_table);
  assert(fake.calls == 2U && fake.frees == 1U && !fake.unwiped);
  assert(system_table.ConfigurationTable == replacement_entries);
  assert(system_table.NumberOfTableEntries == 1U);
}

static void test_configuration_table_snapshot_ignores_live_expansion(void) {
  int original_table = 8;
  int replacement_table = 9;
  EFI_CONFIGURATION_TABLE entries[2] = {
      {.VendorGuid = {0}, .VendorTable = NULL},
      {.VendorGuid = gEfiTcg2FinalEventsTableGuid,
       .VendorTable = &original_table},
  };
  EFI_CONFIGURATION_TABLE replacement_entries[2] = {
      {.VendorGuid = gEfiTcg2FinalEventsTableGuid,
       .VendorTable = &replacement_table},
      {.VendorGuid = {0}, .VendorTable = NULL},
  };
  EFI_SYSTEM_TABLE system_table = {
      .NumberOfTableEntries = 1U,
      .ConfigurationTable = entries,
  };
  mutating_map fake = {
      .system_table = &system_table,
      .replacement_entries = replacement_entries,
      .replacement_count = 2U,
      .descriptor = descriptor_for_entries(entries, 1U),
  };
  const pbns_uefi_memory_ops ops = {
      get_mutating_map, allocate_map, free_map, &fake};
  VOID *found = &replacement_table;
  assert(PbnsMeasuredBootFindFinalEventsTable(&system_table, &ops, &found) ==
         EFI_NOT_FOUND);
  assert(found == NULL);
  assert(fake.calls == 2U && fake.frees == 1U && !fake.unwiped);
  assert(system_table.ConfigurationTable == replacement_entries);
  assert(system_table.NumberOfTableEntries == 2U);
}

int main(void) {
  test_actual_pcr_masks();
  test_configuration_table_snapshot_shrinks_live_count();
  test_configuration_table_snapshot_ignores_live_expansion();
  return 0;
}
