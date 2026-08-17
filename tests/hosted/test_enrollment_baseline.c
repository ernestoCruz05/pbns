#include "pbns/enrollment_baseline.h"
#include "pbns/measured_boot.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "qcbor/qcbor_spiffy_decode.h"

#define TEST_LOG_CAPACITY 256U
#define TEST_BASELINE_CAPACITY 2048U
#define TEST_PATH_CAPACITY 4096U

static void store_u16(uint8_t *output, uint16_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8U);
}

static void store_u32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8U);
  output[2] = (uint8_t)(value >> 16U);
  output[3] = (uint8_t)(value >> 24U);
}

static size_t make_valid_log(uint8_t output[TEST_LOG_CAPACITY]) {
  static const uint8_t signature[16] = "Spec ID Event03";
  size_t offset = 0U;
  store_u32(output + offset, 0U);
  offset += 4U;
  store_u32(output + offset, 3U);
  offset += 4U;
  memset(output + offset, 0, 20U);
  offset += 20U;
  store_u32(output + offset, 37U);
  offset += 4U;
  memcpy(output + offset, signature, sizeof(signature));
  offset += sizeof(signature);
  store_u32(output + offset, 0U);
  offset += 4U;
  output[offset++] = 0U;
  output[offset++] = 2U;
  output[offset++] = 0U;
  output[offset++] = 2U;
  store_u32(output + offset, 2U);
  offset += 4U;
  store_u16(output + offset, UINT16_C(0x0004));
  store_u16(output + offset + 2U, 20U);
  offset += 4U;
  store_u16(output + offset, UINT16_C(0x000b));
  store_u16(output + offset + 2U, 32U);
  offset += 4U;
  output[offset++] = 0U;

  store_u32(output + offset, 7U);
  offset += 4U;
  store_u32(output + offset, UINT32_C(0x80000001));
  offset += 4U;
  store_u32(output + offset, 1U);
  offset += 4U;
  store_u16(output + offset, UINT16_C(0x000b));
  offset += 2U;
  memset(output + offset, 0x5a, 32U);
  offset += 32U;
  store_u32(output + offset, 3U);
  offset += 4U;
  memcpy(output + offset, "evt", 3U);
  offset += 3U;
  return offset;
}

static pbns_enrollment_baseline make_baseline(pbns_view event_log) {
  pbns_enrollment_baseline baseline = {0};
  memset(baseline.firmware_vendor_digest, 0x11,
         sizeof(baseline.firmware_vendor_digest));
  memset(baseline.firmware_version_digest, 0x22,
         sizeof(baseline.firmware_version_digest));
  baseline.secure_boot = true;
  baseline.setup_mode = false;
  memset(baseline.db_digest, 0x33, sizeof(baseline.db_digest));
  memset(baseline.dbx_digest, 0x44, sizeof(baseline.dbx_digest));
  baseline.pcrs[0].index = 0U;
  baseline.pcrs[1].index = 2U;
  baseline.pcrs[2].index = 4U;
  baseline.pcrs[3].index = 7U;
  for (size_t index = 0U; index < PBNS_BASELINE_PCR_COUNT; ++index) {
    memset(baseline.pcrs[index].digest, (int)(0x50U + index),
           sizeof(baseline.pcrs[index].digest));
  }
  baseline.event_log = event_log;
  memset(baseline.event_log_digest, 0x66, sizeof(baseline.event_log_digest));
  return baseline;
}

static size_t load_vector(const char *directory, const char *name,
                          uint8_t *output, size_t capacity) {
  char path[TEST_PATH_CAPACITY] = {0};
  const int path_length =
      snprintf(path, sizeof(path), "%s/%s", directory, name);
  assert(path_length > 0 && (size_t)path_length < sizeof(path));
  FILE *file = fopen(path, "rb");
  assert(file != NULL);
  assert(fseek(file, 0L, SEEK_END) == 0);
  const long end = ftell(file);
  assert(end >= 0L && (unsigned long)end <= capacity);
  assert(fseek(file, 0L, SEEK_SET) == 0);
  const size_t length = (size_t)end;
  assert(fread(output, 1U, length, file) == length);
  assert(!ferror(file));
  assert(fclose(file) == 0);
  return length;
}

static void test_fixture_vectors(const char *vector_directory) {
  uint8_t valid[TEST_LOG_CAPACITY] = {0};
  uint8_t truncated[TEST_LOG_CAPACITY] = {0};
  const size_t valid_length =
      load_vector(vector_directory, "valid-sha256.bin", valid, sizeof(valid));
  const size_t truncated_length = load_vector(vector_directory, "truncated.bin",
                                              truncated, sizeof(truncated));
  pbns_measured_boot_summary summary = {0};
  assert(pbns_measured_boot_validate_event_log((pbns_view){valid, valid_length},
                                               &summary) == PBNS_OK);
  assert(summary.sha256_bank);
  assert(pbns_measured_boot_validate_event_log(
             (pbns_view){truncated, truncated_length}, &summary) ==
         PBNS_ERR_FORMAT);
}

static void test_event_log_validation(void) {
  uint8_t log[TEST_LOG_CAPACITY] = {0};
  const size_t length = make_valid_log(log);
  pbns_measured_boot_summary summary = {0};
  assert(pbns_measured_boot_validate_event_log((pbns_view){log, length},
                                               &summary) == PBNS_OK);
  assert(summary.event_count == 2U);
  assert(summary.sha256_bank);
  assert(summary.last_entry_offset == 69U);
  size_t located_size = 0U;
  assert(pbns_measured_boot_locate_event_log_end((pbns_view){log, sizeof(log)},
                                                 summary.last_entry_offset,
                                                 &located_size) == PBNS_OK);
  assert(located_size == length);
  assert(pbns_measured_boot_locate_event_log_end(
             (pbns_view){log, sizeof(log)}, summary.last_entry_offset + 1U,
             &located_size) == PBNS_ERR_FORMAT);

  for (size_t truncated = 0U; truncated < length; ++truncated) {
    assert(pbns_measured_boot_validate_event_log((pbns_view){log, truncated},
                                                 &summary) != PBNS_OK);
  }
  uint8_t changed[TEST_LOG_CAPACITY] = {0};
  memcpy(changed, log, length);
  changed[53U] = 1U;
  assert(pbns_measured_boot_validate_event_log((pbns_view){changed, length},
                                               &summary) == PBNS_ERR_FORMAT);
  memcpy(changed, log, length);
  store_u32(changed + 69U, 24U);
  assert(pbns_measured_boot_validate_event_log((pbns_view){changed, length},
                                               &summary) == PBNS_ERR_FORMAT);
  memcpy(changed, log, length);
  store_u16(changed + 64U, UINT16_C(0x000c));
  assert(pbns_measured_boot_validate_event_log((pbns_view){changed, length},
                                               &summary) == PBNS_ERR_FORMAT);
  memcpy(changed, log, length);
  store_u16(changed + 81U, UINT16_C(0x0004));
  memmove(changed + 103U, changed + 115U, 7U);
  assert(pbns_measured_boot_validate_event_log((pbns_view){changed, 110U},
                                               &summary) == PBNS_ERR_FORMAT);
  memcpy(changed, log, length);
  store_u16(changed + 81U, UINT16_C(0xffff));
  assert(pbns_measured_boot_validate_event_log((pbns_view){changed, length},
                                               &summary) == PBNS_ERR_FORMAT);
  assert(pbns_measured_boot_validate_event_log(
             (pbns_view){log, PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE + 1U},
             &summary) == PBNS_ERR_LIMIT);
}

static void test_pcr_stability(void) {
  uint8_t first[PBNS_BASELINE_PCR_COUNT * PBNS_BASELINE_DIGEST_SIZE] = {0};
  uint8_t second[sizeof(first)] = {0};
  memset(first, 0x5a, sizeof(first));
  memcpy(second, first, sizeof(second));
  assert(pbns_measured_boot_check_pcr_stability(
             (pbns_view){first, sizeof(first)}, 7U,
             (pbns_view){second, sizeof(second)}, 7U) == PBNS_OK);
  assert(pbns_measured_boot_check_pcr_stability(
             (pbns_view){first, sizeof(first)}, 7U,
             (pbns_view){second, sizeof(second)}, 8U) == PBNS_ERR_BUSY);
  second[sizeof(second) - 1U] ^= 1U;
  assert(pbns_measured_boot_check_pcr_stability(
             (pbns_view){first, sizeof(first)}, 7U,
             (pbns_view){second, sizeof(second)}, 7U) == PBNS_ERR_BUSY);
  assert(pbns_measured_boot_check_pcr_stability(
             (pbns_view){first, sizeof(first) - 1U}, 7U,
             (pbns_view){second, sizeof(second)}, 7U) == PBNS_ERR_ARGUMENT);
}

static void test_baseline_encoding(void) {
  uint8_t log[TEST_LOG_CAPACITY] = {0};
  const size_t log_length = make_valid_log(log);
  const pbns_enrollment_baseline baseline =
      make_baseline((pbns_view){log, log_length});
  uint8_t first[TEST_BASELINE_CAPACITY] = {0};
  uint8_t second[TEST_BASELINE_CAPACITY] = {0};
  size_t first_length = 0U;
  size_t second_length = 0U;
  assert(pbns_enrollment_baseline_encode(
             &baseline, (pbns_buffer){first, 0U, sizeof(first)},
             &first_length) == PBNS_OK);
  assert(first_length > log_length);
  assert(pbns_enrollment_baseline_encode(
             &baseline, (pbns_buffer){second, 0U, sizeof(second)},
             &second_length) == PBNS_OK);
  assert(first_length == second_length);
  assert(memcmp(first, second, first_length) == 0);
  assert(pbns_enrollment_baseline_encode(
             &baseline, (pbns_buffer){second, 0U, first_length - 1U},
             &second_length) == PBNS_ERR_LIMIT);
  assert(pbns_enrollment_baseline_encode(
             &baseline, (pbns_buffer){second, 1U, sizeof(second)},
             &second_length) == PBNS_ERR_ARGUMENT);

  QCBORDecodeContext decoder;
  UsefulBufC item = NULLUsefulBufC;
  QCBORDecode_Init(&decoder, (UsefulBufC){first, first_length},
                   QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterMap(&decoder, NULL);
  QCBORDecode_GetTextStringInMapN(&decoder, 1, &item);
  assert(item.len == sizeof(PBNS_BASELINE_DOMAIN) - 1U);
  assert(memcmp(item.ptr, PBNS_BASELINE_DOMAIN, item.len) == 0);
  QCBORDecode_GetByteStringInMapN(&decoder, 9, &item);
  assert(item.len == log_length);
  assert(memcmp(item.ptr, log, log_length) == 0);
  QCBORDecode_ExitMap(&decoder);
  assert(QCBORDecode_Finish(&decoder) == QCBOR_SUCCESS);
}

static bool contains_bytes(pbns_view haystack, pbns_view needle) {
  if (needle.len == 0U || needle.len > haystack.len) {
    return false;
  }
  for (size_t offset = 0U; offset <= haystack.len - needle.len; ++offset) {
    if (memcmp(haystack.ptr + offset, needle.ptr, needle.len) == 0) {
      return true;
    }
  }
  return false;
}

static void test_baseline_rejects_context_and_privacy_inputs(void) {
  uint8_t log[TEST_LOG_CAPACITY] = {0};
  const size_t log_length = make_valid_log(log);
  pbns_enrollment_baseline baseline =
      make_baseline((pbns_view){log, log_length});
  uint8_t output[TEST_BASELINE_CAPACITY] = {0};
  size_t written = 0U;

  baseline.pcrs[2].index = 3U;
  assert(pbns_enrollment_baseline_encode(
             &baseline, (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
         PBNS_ERR_ARGUMENT);
  baseline = make_baseline((pbns_view){log, log_length});
  baseline.event_log_digest[0] = 0U;
  assert(pbns_enrollment_baseline_encode(
             &baseline, (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
         PBNS_OK);
  static const uint8_t sentinel[] = "SERIAL-UUID-MAC-SSID";
  assert(!contains_bytes((pbns_view){output, written},
                         (pbns_view){sentinel, sizeof(sentinel) - 1U}));
}

int main(int argc, char **argv) {
  assert(argc == 2);
  test_fixture_vectors(argv[1]);
  test_event_log_validation();
  test_pcr_stability();
  test_baseline_encoding();
  test_baseline_rejects_context_and_privacy_inputs();
  return 0;
}
