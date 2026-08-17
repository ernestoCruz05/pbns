#include "pbns/boot_config.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static const uint8_t test_path[] = {
    0x04U, 0x04U, 0x14U, 0x00U, 0x5cU, 0x00U, 0x45U, 0x00U, 0x46U,
    0x00U, 0x49U, 0x00U, 0x00U, 0x00U, 0x7fU, 0xffU, 0x04U, 0x00U,
};

static void test_round_trip(void) {
  uint8_t encoded[PBNS_BOOT_CONFIG_ENCODED_CAP] = {0};
  uint8_t path[PBNS_BOOT_CONFIG_PATH_CAP] = {0};
  size_t written = 0U;
  pbns_boot_config decoded = {0};
  const pbns_boot_config input = {
      .normal_boot_option = UINT16_C(0x1234),
      .recovery_device_path = {test_path, sizeof(test_path)},
  };

  assert(pbns_boot_config_encode(&input,
                                 (pbns_buffer){encoded, 0U, sizeof(encoded)},
                                 &written) == PBNS_OK);
  assert(written == PBNS_BOOT_CONFIG_HEADER_SIZE + sizeof(test_path));
  assert(memcmp(encoded, "PBC1", 4U) == 0);
  assert(pbns_boot_config_decode((pbns_view){encoded, written},
                                 (pbns_buffer){path, 0U, sizeof(path)},
                                 &decoded) == PBNS_OK);
  assert(decoded.normal_boot_option == input.normal_boot_option);
  assert(decoded.recovery_device_path.len == sizeof(test_path));
  assert(memcmp(decoded.recovery_device_path.ptr, test_path,
                sizeof(test_path)) == 0);
}

static void test_encode_bounds(void) {
  uint8_t encoded[PBNS_BOOT_CONFIG_ENCODED_CAP] = {0};
  uint8_t oversized[PBNS_BOOT_CONFIG_PATH_CAP + 1U] = {0};
  size_t written = 99U;
  pbns_boot_config input = {
      .normal_boot_option = 1U,
      .recovery_device_path = {test_path, sizeof(test_path)},
  };

  assert(pbns_boot_config_encode(&input,
                                 (pbns_buffer){encoded, 0U,
                                               PBNS_BOOT_CONFIG_HEADER_SIZE +
                                                   sizeof(test_path) - 1U},
                                 &written) == PBNS_ERR_LIMIT);
  assert(written == 0U);
  input.recovery_device_path = (pbns_view){NULL, 0U};
  assert(pbns_boot_config_encode(&input,
                                 (pbns_buffer){encoded, 0U, sizeof(encoded)},
                                 &written) == PBNS_ERR_ARGUMENT);
  input.recovery_device_path = (pbns_view){oversized, sizeof(oversized)};
  assert(pbns_boot_config_encode(&input,
                                 (pbns_buffer){encoded, 0U, sizeof(encoded)},
                                 &written) == PBNS_ERR_LIMIT);
  assert(pbns_boot_config_encode(NULL,
                                 (pbns_buffer){encoded, 0U, sizeof(encoded)},
                                 &written) == PBNS_ERR_ARGUMENT);
}

static void test_decode_rejects_corruption_and_structure_errors(void) {
  uint8_t encoded[PBNS_BOOT_CONFIG_ENCODED_CAP] = {0};
  uint8_t changed[PBNS_BOOT_CONFIG_ENCODED_CAP] = {0};
  uint8_t path[PBNS_BOOT_CONFIG_PATH_CAP] = {0};
  size_t written = 0U;
  pbns_boot_config decoded = {0};
  const pbns_boot_config input = {
      .normal_boot_option = 7U,
      .recovery_device_path = {test_path, sizeof(test_path)},
  };

  assert(pbns_boot_config_encode(&input,
                                 (pbns_buffer){encoded, 0U, sizeof(encoded)},
                                 &written) == PBNS_OK);
  memcpy(changed, encoded, written);
  changed[written - 1U] ^= 0x80U;
  assert(pbns_boot_config_decode((pbns_view){changed, written},
                                 (pbns_buffer){path, 0U, sizeof(path)},
                                 &decoded) == PBNS_ERR_CRC);

  memcpy(changed, encoded, written);
  changed[4] = 2U;
  assert(pbns_boot_config_decode((pbns_view){changed, written},
                                 (pbns_buffer){path, 0U, sizeof(path)},
                                 &decoded) == PBNS_ERR_VERSION);
  memcpy(changed, encoded, written);
  changed[5] = 1U;
  assert(pbns_boot_config_decode((pbns_view){changed, written},
                                 (pbns_buffer){path, 0U, sizeof(path)},
                                 &decoded) == PBNS_ERR_FORMAT);
  assert(pbns_boot_config_decode((pbns_view){encoded, written - 1U},
                                 (pbns_buffer){path, 0U, sizeof(path)},
                                 &decoded) == PBNS_ERR_FORMAT);
  assert(
      pbns_boot_config_decode((pbns_view){encoded, written},
                              (pbns_buffer){path, 0U, sizeof(test_path) - 1U},
                              &decoded) == PBNS_ERR_LIMIT);
}

static void test_failure_record_is_deterministic_and_bounded(void) {
  uint8_t first[PBNS_BOOT_FAILURE_ENCODED_SIZE] = {0};
  uint8_t second[PBNS_BOOT_FAILURE_ENCODED_SIZE] = {0};
  size_t first_written = 0U;
  size_t second_written = 0U;
  const pbns_boot_failure valid = {
      .stage = UINT8_C(3),
      .platform_status = UINT64_C(0x8000000000000001),
  };
  const pbns_boot_failure invalid = {
      .stage = 0U,
      .platform_status = 1U,
  };
  pbns_boot_failure decoded = {0};

  assert(pbns_boot_failure_encode(&valid,
                                  (pbns_buffer){first, 0U, sizeof(first)},
                                  &first_written) == PBNS_OK);
  assert(pbns_boot_failure_encode(&valid,
                                  (pbns_buffer){second, 0U, sizeof(second)},
                                  &second_written) == PBNS_OK);
  assert(first_written == PBNS_BOOT_FAILURE_ENCODED_SIZE);
  assert(second_written == first_written);
  assert(memcmp(first, second, first_written) == 0);
  assert(memcmp(first, "PBF1", 4U) == 0);
  assert(pbns_boot_failure_decode((pbns_view){first, first_written},
                                  &decoded) == PBNS_OK);
  assert(decoded.stage == valid.stage);
  assert(decoded.platform_status == valid.platform_status);
  assert(pbns_boot_failure_decode((pbns_view){first, first_written - 1U},
                                  &decoded) == PBNS_ERR_FORMAT);
  first[6] ^= UINT8_C(1);
  assert(pbns_boot_failure_decode((pbns_view){first, first_written},
                                  &decoded) == PBNS_ERR_FORMAT);
  first[6] ^= UINT8_C(1);
  first[16] ^= UINT8_C(1);
  assert(pbns_boot_failure_decode((pbns_view){first, first_written},
                                  &decoded) == PBNS_ERR_CRC);
  first[16] ^= UINT8_C(1);
  assert(pbns_boot_failure_encode(&invalid,
                                  (pbns_buffer){first, 0U, sizeof(first)},
                                  &first_written) == PBNS_ERR_ARGUMENT);
  assert(pbns_boot_failure_encode(&valid,
                                  (pbns_buffer){first, 0U, sizeof(first) - 1U},
                                  &first_written) == PBNS_ERR_LIMIT);
}

int main(void) {
  test_round_trip();
  test_encode_bounds();
  test_decode_rejects_corruption_and_structure_errors();
  test_failure_record_is_deterministic_and_bounded();
  return 0;
}
