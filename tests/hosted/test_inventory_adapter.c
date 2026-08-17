#include "PbnsInventoryAdapterCore.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#define ARRAY_COUNT(values) (sizeof(values) / sizeof((values)[0]))

typedef struct fake_variable {
  pbns_inventory_adapter_result query;
  pbns_inventory_adapter_result read;
  const uint8_t *data;
  size_t size;
  uint32_t attributes;
} fake_variable;

typedef struct fake_variables {
  fake_variable values[4];
} fake_variables;

static pbns_status hash_parts(void *context, const pbns_view *parts,
                              size_t part_count, uint8_t digest[32]) {
  (void)context;
  EVP_MD_CTX *hash = EVP_MD_CTX_new();
  if (hash == NULL || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) {
    EVP_MD_CTX_free(hash);
    return PBNS_ERR_CRYPTO;
  }
  for (size_t index = 0U; index < part_count; ++index) {
    if (EVP_DigestUpdate(hash, parts[index].ptr, parts[index].len) != 1) {
      EVP_MD_CTX_free(hash);
      return PBNS_ERR_CRYPTO;
    }
  }
  unsigned int size = 0U;
  const int status = EVP_DigestFinal_ex(hash, digest, &size);
  EVP_MD_CTX_free(hash);
  return status == 1 && size == 32U ? PBNS_OK : PBNS_ERR_CRYPTO;
}

static pbns_inventory_adapter_result fake_get_variable(
    void *context, pbns_inventory_adapter_variable variable, uint8_t *data,
    size_t *size, uint32_t *attributes) {
  fake_variables *fake = context;
  assert(variable >= PBNS_ADAPTER_SECURE_BOOT && variable <= PBNS_ADAPTER_DBX);
  fake_variable *value = &fake->values[(size_t)variable - 1U];
  if (data == NULL) {
    *size = value->size;
    *attributes = value->attributes;
    return value->query;
  }
  if (value->read.kind != PBNS_PLATFORM_SUCCESS) {
    return value->read;
  }
  assert(*size >= value->size);
  memcpy(data, value->data, value->size);
  *size = value->size;
  *attributes = value->attributes;
  return value->read;
}

static fake_variables valid_variables(void) {
  static const uint8_t enabled = 1U;
  static const uint8_t disabled = 0U;
  static const uint8_t db[] = "db bytes";
  static const uint8_t dbx[] = "dbx bytes";
  fake_variables fake = {0};
  fake.values[0] = (fake_variable){
      .query = {PBNS_PLATFORM_SUCCESS, 0U},
      .read = {PBNS_PLATFORM_SUCCESS, 0U},
      .data = &enabled,
      .size = 1U,
  };
  fake.values[1] = (fake_variable){
      .query = {PBNS_PLATFORM_SUCCESS, 0U},
      .read = {PBNS_PLATFORM_SUCCESS, 0U},
      .data = &disabled,
      .size = 1U,
  };
  fake.values[2] = (fake_variable){
      .query = {PBNS_PLATFORM_LIMIT, 10U},
      .read = {PBNS_PLATFORM_SUCCESS, 0U},
      .data = db,
      .size = sizeof(db) - 1U,
      .attributes = 0x27U,
  };
  fake.values[3] = (fake_variable){
      .query = {PBNS_PLATFORM_LIMIT, 10U},
      .read = {PBNS_PLATFORM_SUCCESS, 0U},
      .data = dbx,
      .size = sizeof(dbx) - 1U,
      .attributes = 0x27U,
  };
  return fake;
}

static void test_secure_boot_adapter_statuses_and_wipe(void) {
  static const struct {
    pbns_inventory_platform_result result;
    uint64_t native;
    pbns_inventory_capability expected;
  } cases[] = {
      {PBNS_PLATFORM_NOT_FOUND, 14U, PBNS_INVENTORY_ABSENT},
      {PBNS_PLATFORM_UNSUPPORTED, 3U, PBNS_INVENTORY_UNSUPPORTED},
      {PBNS_PLATFORM_ERROR, 7U, PBNS_INVENTORY_ERROR},
  };
  for (size_t index = 0U; index < ARRAY_COUNT(cases); ++index) {
    fake_variables fake = valid_variables();
    fake.values[0].read =
        (pbns_inventory_adapter_result){cases[index].result, cases[index].native};
    uint8_t scratch[64] = {0};
    pbns_inventory_secure_boot_input output;
    memset(&output, 0xa5, sizeof(output));
    const pbns_inventory_adapter_result status =
        pbns_inventory_adapter_secure_boot(
            fake_get_variable, &fake,
            (pbns_buffer){scratch, 0U, sizeof(scratch)}, hash_parts, NULL,
            &output);
    assert(status.kind == cases[index].result &&
           status.native_status == cases[index].native);
    assert(output.status == cases[index].expected);
  }

  fake_variables malformed = valid_variables();
  static const uint8_t invalid = 2U;
  malformed.values[0].data = &invalid;
  uint8_t scratch[64] = {0};
  pbns_inventory_secure_boot_input output = {0};
  assert(pbns_inventory_adapter_secure_boot(
             fake_get_variable, &malformed,
             (pbns_buffer){scratch, 0U, sizeof(scratch)}, hash_parts, NULL,
             &output)
             .kind == PBNS_PLATFORM_MALFORMED);
  assert(output.status == PBNS_INVENTORY_MALFORMED);

  fake_variables second_read_failure = valid_variables();
  second_read_failure.values[3].read =
      (pbns_inventory_adapter_result){PBNS_PLATFORM_ERROR, 7U};
  memset(scratch, 0xa5, sizeof(scratch));
  memset(&output, 0xa5, sizeof(output));
  const pbns_inventory_adapter_result failed =
      pbns_inventory_adapter_secure_boot(
          fake_get_variable, &second_read_failure,
          (pbns_buffer){scratch, 0U, sizeof(scratch)}, hash_parts, NULL,
          &output);
  assert(failed.kind == PBNS_PLATFORM_ERROR && failed.native_status == 7U);
  assert(output.status == PBNS_INVENTORY_ERROR);
  for (size_t index = 0U; index < sizeof(scratch); ++index) {
    assert(scratch[index] == 0U);
  }
  for (size_t index = 0U; index < sizeof(output.db_digest); ++index) {
    assert(output.db_digest[index] == 0U && output.dbx_digest[index] == 0U);
  }
}

static void checksum(uint8_t *bytes, size_t start, size_t length,
                     size_t checksum_offset) {
  bytes[checksum_offset] = 0U;
  uint8_t sum = 0U;
  for (size_t index = start; index < start + length; ++index) {
    sum = (uint8_t)(sum + bytes[index]);
  }
  bytes[checksum_offset] = (uint8_t)(0U - sum);
}

static void store_u16(uint8_t *output, uint16_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8U);
}

static void store_u32(uint8_t *output, uint32_t value) {
  for (size_t index = 0U; index < 4U; ++index) {
    output[index] = (uint8_t)(value >> (index * 8U));
  }
}

static void store_u64(uint8_t *output, uint64_t value) {
  for (size_t index = 0U; index < 8U; ++index) {
    output[index] = (uint8_t)(value >> (index * 8U));
  }
}

static size_t make_smbios2(uint8_t entry[31], uint8_t length,
                           uintptr_t table_address) {
  memset(entry, 0, 31U);
  static const uint8_t anchor[] = {'_', 'S', 'M', '_'};
  static const uint8_t intermediate[] = {'_', 'D', 'M', 'I', '_'};
  for (size_t index = 0U; index < sizeof(anchor); ++index) {
    entry[index] = anchor[index];
  }
  entry[5U] = length;
  entry[6U] = 2U;
  entry[7U] = 8U;
  for (size_t index = 0U; index < sizeof(intermediate); ++index) {
    entry[16U + index] = intermediate[index];
  }
  store_u16(entry + 22U, 6U);
  store_u32(entry + 24U, (uint32_t)table_address);
  store_u16(entry + 28U, 1U);
  checksum(entry, 16U, (size_t)length - 16U, 21U);
  checksum(entry, 0U, length, 4U);
  return length;
}

static size_t make_smbios3(uint8_t entry[24], uintptr_t table_address) {
  static const uint8_t anchor[] = {'_', 'S', 'M', '3', '_'};
  memset(entry, 0, 24U);
  for (size_t index = 0U; index < sizeof(anchor); ++index) {
    entry[index] = anchor[index];
  }
  entry[6U] = 24U;
  entry[7U] = 3U;
  entry[8U] = 2U;
  store_u32(entry + 12U, 6U);
  store_u64(entry + 16U, table_address);
  checksum(entry, 0U, 24U, 5U);
  return 24U;
}

static void test_smbios_entry_policy_and_table_integration(void) {
  uint8_t table[] = {127U, 4U, 0U, 0U, 0U, 0U};
  uint8_t entry2[31] = {0};
  pbns_inventory_adapter_smbios_table parsed = {0};
  (void)make_smbios2(entry2, 0x1eU, (uintptr_t)table);
  size_t length = 0x1eU;
  assert(pbns_inventory_adapter_smbios_entry(
             (pbns_view){entry2, sizeof(entry2)}, false, &parsed)
             .kind == PBNS_PLATFORM_SUCCESS);
  pbns_inventory_smbios_collector collector = {0};
  assert(pbns_inventory_adapter_smbios_collect(
             (pbns_view){entry2, sizeof(entry2)}, false,
             (pbns_view){table, parsed.length}, &collector)
             .kind == PBNS_PLATFORM_SUCCESS);
  assert(collector.record_count == parsed.expected_record_count);

  length = make_smbios2(entry2, 0x1fU, (uintptr_t)table);
  assert(pbns_inventory_adapter_smbios_entry(
             (pbns_view){entry2, sizeof(entry2)}, false, &parsed)
             .kind == PBNS_PLATFORM_SUCCESS);
  entry2[6U] = 1U;
  checksum(entry2, 16U, length - 16U, 21U);
  checksum(entry2, 0U, length, 4U);
  assert(pbns_inventory_adapter_smbios_entry(
             (pbns_view){entry2, sizeof(entry2)}, false, &parsed)
             .kind == PBNS_PLATFORM_MALFORMED);

  uint8_t entry3[24] = {0};
  length = make_smbios3(entry3, (uintptr_t)table);
  assert(pbns_inventory_adapter_smbios_entry(
             (pbns_view){entry3, length}, true, &parsed)
             .kind == PBNS_PLATFORM_SUCCESS);
  entry3[7U] = 2U;
  checksum(entry3, 0U, length, 5U);
  assert(pbns_inventory_adapter_smbios_entry(
             (pbns_view){entry3, length}, true, &parsed)
             .kind == PBNS_PLATFORM_MALFORMED);

  length = make_smbios3(entry3, (uintptr_t)table);
  const size_t corruptions[] = {0U, 5U, 6U};
  for (size_t index = 0U; index < ARRAY_COUNT(corruptions); ++index) {
    uint8_t bad[24] = {0};
    memcpy(bad, entry3, sizeof(bad));
    bad[corruptions[index]] ^= 1U;
    assert(pbns_inventory_adapter_smbios_entry(
               (pbns_view){bad, sizeof(bad)}, true, &parsed)
               .kind == PBNS_PLATFORM_MALFORMED);
  }
  store_u32(entry3 + 12U,
            (uint32_t)(PBNS_INVENTORY_SMBIOS_TABLE_MAX_SIZE + 1U));
  checksum(entry3, 0U, length, 5U);
  assert(pbns_inventory_adapter_smbios_entry(
             (pbns_view){entry3, length}, true, &parsed)
             .kind == PBNS_PLATFORM_LIMIT);
  length = make_smbios3(entry3, (uintptr_t)table);
  store_u64(entry3 + 16U, UINT64_MAX - 2U);
  checksum(entry3, 0U, length, 5U);
  assert(pbns_inventory_adapter_smbios_entry(
             (pbns_view){entry3, length}, true, &parsed)
             .kind == PBNS_PLATFORM_MALFORMED);

  length = make_smbios2(entry2, 0x1fU, (uintptr_t)table);
  store_u16(entry2 + 28U, 2U);
  checksum(entry2, 16U, length - 16U, 21U);
  checksum(entry2, 0U, length, 4U);
  assert(pbns_inventory_adapter_smbios_entry(
             (pbns_view){entry2, sizeof(entry2)}, false, &parsed)
             .kind == PBNS_PLATFORM_SUCCESS);
  collector = (pbns_inventory_smbios_collector){0};
  assert(pbns_inventory_adapter_smbios_collect(
             (pbns_view){entry2, sizeof(entry2)}, false,
             (pbns_view){table, parsed.length}, &collector)
             .kind == PBNS_PLATFORM_MALFORMED);
  (void)make_smbios2(entry2, 0x1fU, (uintptr_t)table);
  collector = (pbns_inventory_smbios_collector){0};
  assert(pbns_inventory_adapter_smbios_collect(
             (pbns_view){entry2, sizeof(entry2)}, false,
             (pbns_view){table, sizeof(table) - 1U}, &collector)
             .kind == PBNS_PLATFORM_MALFORMED);
}

static void test_tcg_policy(void) {
  uint32_t banks[PBNS_INVENTORY_TPM_BANK_MAX] = {0};
  pbns_inventory_tpm_input tpm = {0};
  const pbns_inventory_adapter_tcg_capability capability = {
      .present = true,
      .manufacturer = UINT32_C(0x49465800),
      .active_bitmap = 0x02U,
      .supported_bank_count = 2U,
  };
  assert(pbns_inventory_adapter_tcg(&capability, banks, ARRAY_COUNT(banks),
                                    &tpm) == PBNS_INVENTORY_OK);
  assert(tpm.manufacturer == UINT32_C(0x49465800) &&
         tpm.active_bank_count == 1U && tpm.active_banks[0] == 0x000bU);
}

int main(void) {
  test_secure_boot_adapter_statuses_and_wipe();
  test_smbios_entry_policy_and_table_integration();
  test_tcg_policy();
  return EXIT_SUCCESS;
}
