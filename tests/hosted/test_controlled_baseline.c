#include "pbns/controlled_baseline.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../vectors/controlled-baseline-v1/controlled_baseline.inc"

static bool all_zero(const uint8_t *value, size_t length) {
  for (size_t index = 0U; index < length; ++index) {
    if (value[index] != 0U) {
      return false;
    }
  }
  return true;
}

static pbns_status firmware_hash(void *context, const pbns_view *parts,
                                 size_t part_count, uint8_t digest[32]) {
  static const uint8_t domain[] = "PBNS-FIRMWARE-IDENTITY-v1";
  static const uint8_t vendor[] = "vendor";
  static const uint8_t version[] = "1";
  (void)context;
  assert(parts != NULL && part_count == 4U && digest != NULL);
  assert(parts[0].len == sizeof(domain) - 1U &&
         memcmp(parts[0].ptr, domain, parts[0].len) == 0);
  assert(parts[1].len == sizeof(vendor) - 1U &&
         memcmp(parts[1].ptr, vendor, parts[1].len) == 0);
  assert(parts[2].len == 1U && parts[2].ptr[0] == 0U);
  assert(parts[3].len == sizeof(version) - 1U &&
         memcmp(parts[3].ptr, version, parts[3].len) == 0);
  memcpy(digest, controlled_baseline_firmware_digest, 32U);
  return PBNS_OK;
}

static pbns_controlled_baseline fixture(void) {
  pbns_controlled_baseline value = {
      .secure_boot = true,
      .setup_mode = false,
      .memory_mib = 4096U,
      .storage_gib = 64U,
      .block_devices = 1U,
      .memory_mib_delta = 128U,
      .storage_gib_delta = 4U,
      .block_device_delta = 1U,
  };
  memcpy(value.measurement_digest, controlled_baseline_measurement_digest,
         sizeof(value.measurement_digest));
  memcpy(value.db_digest, controlled_baseline_db_digest,
         sizeof(value.db_digest));
  memcpy(value.dbx_digest, controlled_baseline_dbx_digest,
         sizeof(value.dbx_digest));
  memcpy(value.firmware_digest, controlled_baseline_firmware_digest,
         sizeof(value.firmware_digest));
  return value;
}

static void test_firmware_identity_matches_go_domain(void) {
  static const uint8_t vendor[] = "vendor";
  static const uint8_t version[] = "1";
  uint8_t digest[32] = {0};
  assert(pbns_controlled_baseline_firmware_identity(
             (pbns_view){vendor, sizeof(vendor) - 1U},
             (pbns_view){version, sizeof(version) - 1U}, firmware_hash, NULL,
             digest) == PBNS_OK);
  assert(memcmp(digest, controlled_baseline_firmware_digest, sizeof(digest)) ==
         0);
  assert(pbns_controlled_baseline_firmware_identity(
             (pbns_view){0}, (pbns_view){version, sizeof(version) - 1U},
             firmware_hash, NULL, digest) == PBNS_ERR_FORMAT);
}

static void test_inventory_projection_has_zero_initial_deltas(void) {
  pbns_inventory_report inventory = {0};
  static const uint8_t vendor[] = "vendor";
  static const uint8_t version[] = "1";
  memcpy(inventory.firmware_vendor.bytes, vendor, sizeof(vendor) - 1U);
  inventory.firmware_vendor.len = sizeof(vendor) - 1U;
  memcpy(inventory.firmware_version.bytes, version, sizeof(version) - 1U);
  inventory.firmware_version.len = sizeof(version) - 1U;
  inventory.outcomes[0] = PBNS_INVENTORY_OK;
  inventory.outcomes[2] = PBNS_INVENTORY_OK;
  inventory.outcomes[3] = PBNS_INVENTORY_OK;
  inventory.secure_boot = true;
  inventory.setup_mode = false;
  memcpy(inventory.db_digest, controlled_baseline_db_digest, 32U);
  memcpy(inventory.dbx_digest, controlled_baseline_dbx_digest, 32U);
  inventory.memory_mib = 4096U;
  inventory.storage_capacity_gib = 64U;
  inventory.block_device_count = 1U;

  pbns_controlled_baseline value = {0};
  assert(pbns_controlled_baseline_from_inventory(
             controlled_baseline_measurement_digest, &inventory, firmware_hash,
             NULL, &value) == PBNS_OK);
  assert(memcmp(value.measurement_digest,
                controlled_baseline_measurement_digest, 32U) == 0);
  assert(memcmp(value.firmware_digest, controlled_baseline_firmware_digest,
                32U) == 0);
  assert(value.secure_boot && !value.setup_mode);
  assert(value.memory_mib == 4096U && value.storage_gib == 64U &&
         value.block_devices == 1U);
  assert(value.memory_mib_delta == 0U && value.storage_gib_delta == 0U &&
         value.block_device_delta == 0U);

  inventory.firmware_vendor.len = 0U;
  assert(pbns_controlled_baseline_from_inventory(
             controlled_baseline_measurement_digest, &inventory, firmware_hash,
             NULL, &value) == PBNS_ERR_FORMAT);
  inventory.firmware_vendor.bytes[0] = (uint8_t)' ';
  inventory.firmware_vendor.len = sizeof(vendor);
  assert(pbns_controlled_baseline_from_inventory(
             controlled_baseline_measurement_digest, &inventory, firmware_hash,
             NULL, &value) == PBNS_ERR_FORMAT);
  assert(all_zero(value.measurement_digest, sizeof(value.measurement_digest)) &&
         all_zero(value.db_digest, sizeof(value.db_digest)) &&
         all_zero(value.dbx_digest, sizeof(value.dbx_digest)) &&
         all_zero(value.firmware_digest, sizeof(value.firmware_digest)) &&
         !value.secure_boot && !value.setup_mode && value.memory_mib == 0U &&
         value.storage_gib == 0U && value.block_devices == 0U &&
         value.memory_mib_delta == 0U && value.storage_gib_delta == 0U &&
         value.block_device_delta == 0U);
}

static void test_controlled_baseline_matches_go_vector(void) {
  const pbns_controlled_baseline value = fixture();
  uint8_t encoded[512] = {0};
  size_t written = 0U;
  assert(pbns_controlled_baseline_encode(
             &value, (pbns_buffer){encoded, 0U, sizeof(encoded)}, &written) ==
         PBNS_OK);
  assert(written == sizeof(controlled_baseline_vector));
  assert(memcmp(encoded, controlled_baseline_vector, written) == 0);

  uint8_t second[512] = {0};
  size_t second_size = 0U;
  assert(pbns_controlled_baseline_encode(
             &value, (pbns_buffer){second, 0U, sizeof(second)}, &second_size) ==
         PBNS_OK);
  assert(second_size == written && memcmp(second, encoded, written) == 0);
  assert(pbns_controlled_baseline_encode(
             &value, (pbns_buffer){second, 0U, written - 1U}, &second_size) ==
         PBNS_ERR_LIMIT);
}

static void test_controlled_baseline_rejects_insecure_or_empty_security(void) {
  pbns_controlled_baseline value = fixture();
  uint8_t encoded[512] = {0};
  size_t written = 0U;

  value.secure_boot = false;
  assert(pbns_controlled_baseline_encode(
             &value, (pbns_buffer){encoded, 0U, sizeof(encoded)}, &written) ==
         PBNS_ERR_FORMAT);
  value = fixture();
  value.setup_mode = true;
  assert(pbns_controlled_baseline_encode(
             &value, (pbns_buffer){encoded, 0U, sizeof(encoded)}, &written) ==
         PBNS_ERR_FORMAT);
  value = fixture();
  memset(value.measurement_digest, 0, sizeof(value.measurement_digest));
  assert(pbns_controlled_baseline_encode(
             &value, (pbns_buffer){encoded, 0U, sizeof(encoded)}, &written) ==
         PBNS_ERR_FORMAT);
}

int main(void) {
  test_firmware_identity_matches_go_domain();
  test_inventory_projection_has_zero_initial_deltas();
  test_controlled_baseline_matches_go_vector();
  test_controlled_baseline_rejects_insecure_or_empty_security();
  return 0;
}
