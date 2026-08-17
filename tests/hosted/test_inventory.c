#include "pbns/inventory.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "qcbor/qcbor_spiffy_decode.h"

#define ARRAY_COUNT(values) (sizeof(values) / sizeof((values)[0]))
#define TEST_OUTPUT_SIZE 4096U
#define GIB_BYTES (UINT64_C(1024) * 1024U * 1024U)

typedef struct fake_pci_descriptor {
  pbns_inventory_pci_function approved;
  const char *mac;
} fake_pci_descriptor;

typedef struct fake_block_descriptor {
  pbns_inventory_block_device approved;
  const char *partition_label;
  const char *path;
} fake_block_descriptor;

static pbns_status hash_sha256(void *context, pbns_view value,
                               uint8_t digest[32]) {
  (void)context;
  return SHA256(value.ptr, value.len, digest) != NULL ? PBNS_OK
                                                       : PBNS_ERR_CRYPTO;
}

static pbns_status hash_sha256_parts(void *context, const pbns_view *parts,
                                     size_t part_count, uint8_t digest[32]) {
  (void)context;
  EVP_MD_CTX *hash = EVP_MD_CTX_new();
  if (hash == NULL || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) {
    EVP_MD_CTX_free(hash);
    return PBNS_ERR_CRYPTO;
  }
  for (size_t index = 0U; index < part_count; ++index) {
    if ((parts[index].ptr == NULL && parts[index].len != 0U) ||
        EVP_DigestUpdate(hash, parts[index].ptr, parts[index].len) != 1) {
      EVP_MD_CTX_free(hash);
      return PBNS_ERR_CRYPTO;
    }
  }
  unsigned int length = 0U;
  const int result = EVP_DigestFinal_ex(hash, digest, &length);
  EVP_MD_CTX_free(hash);
  return result == 1 && length == PBNS_INVENTORY_DIGEST_SIZE
             ? PBNS_OK
             : PBNS_ERR_CRYPTO;
}

static bool contains(pbns_view haystack, const char *needle) {
  const size_t length = strlen(needle);
  if (length == 0U || length > haystack.len) {
    return false;
  }
  for (size_t offset = 0U; offset <= haystack.len - length; ++offset) {
    if (memcmp(haystack.ptr + offset, needle, length) == 0) {
      return true;
    }
  }
  return false;
}

static size_t make_smbios_record(uint8_t *output, size_t capacity, uint8_t type,
                                 const uint8_t *formatted,
                                 size_t formatted_length,
                                 const char *const *strings,
                                 size_t string_count) {
  assert(output != NULL && formatted != NULL && formatted_length >= 4U);
  assert(formatted_length + 2U <= capacity && formatted_length <= UINT8_MAX);
  memcpy(output, formatted, formatted_length);
  output[0] = type;
  output[1] = (uint8_t)formatted_length;
  size_t length = formatted_length;
  for (size_t index = 0U; index < string_count; ++index) {
    const size_t string_length = strlen(strings[index]);
    assert(length + string_length + 2U <= capacity);
    memcpy(output + length, strings[index], string_length);
    length += string_length;
    output[length++] = 0U;
  }
  output[length++] = 0U;
  if (string_count == 0U) {
    output[length++] = 0U;
  }
  return length;
}

static void set_text(pbns_inventory_text *text, const char *value) {
  const size_t length = strlen(value);
  assert(length <= sizeof(text->bytes));
  memset(text, 0, sizeof(*text));
  memcpy(text->bytes, value, length);
  text->len = length;
}

static pbns_inventory_inputs complete_inputs(uint8_t fingerprint[32]) {
  static const uint32_t banks[] = {11U, 4U};
  static const pbns_inventory_timing timings[] = {
      {.key = 7U, .microseconds = 700U},
      {.key = 2U, .microseconds = 200U},
  };
  pbns_inventory_inputs inputs = {
      .host_fingerprint = {fingerprint, PBNS_INVENTORY_DIGEST_SIZE},
      .smbios_status = PBNS_INVENTORY_OK,
      .memory_mib = 32768U,
      .pci_status = PBNS_INVENTORY_OK,
      .storage_status = PBNS_INVENTORY_OK,
      .block_device_count = 2U,
      .storage_capacity_gib = 96U,
      .secure_boot = {
          .status = PBNS_INVENTORY_OK,
          .secure_boot = true,
          .setup_mode = false,
      },
      .tpm = {
          .status = PBNS_INVENTORY_OK,
          .present = true,
          .manufacturer = UINT32_C(0x49465800),
          .firmware_version = 42U,
          .active_banks = banks,
          .active_bank_count = ARRAY_COUNT(banks),
      },
      .pbns_version = 1U,
      .pico_version = 2U,
      .gateway_version = 3U,
      .timings = timings,
      .timing_count = ARRAY_COUNT(timings),
      .prior_loader_efi_status = UINT64_C(0x8000000000000007),
  };
  set_text(&inputs.firmware_vendor, "Acme Firmware");
  set_text(&inputs.firmware_version, "1.2.3");
  set_text(&inputs.cpu_class, "Example CPU");
  memset(inputs.board_model_digest, 0x22,
         sizeof(inputs.board_model_digest));
  memset(inputs.pci_digest, 0x77, sizeof(inputs.pci_digest));
  memset(inputs.secure_boot.db_digest, 0xdb,
         sizeof(inputs.secure_boot.db_digest));
  memset(inputs.secure_boot.dbx_digest, 0xdc,
         sizeof(inputs.secure_boot.dbx_digest));
  return inputs;
}

static void decode_complete_report(pbns_view encoded) {
  QCBORDecodeContext decoder;
  UsefulBufC bytes = NULLUsefulBufC;
  UsefulBufC text = NULLUsefulBufC;
  uint64_t number = 0U;
  bool flag = false;
  QCBORDecode_Init(&decoder, (UsefulBufC){encoded.ptr, encoded.len},
                   QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterMap(&decoder, NULL);
  QCBORDecode_GetByteStringInMapN(&decoder, 1, &bytes);
  assert(bytes.len == 32U);
  QCBORDecode_GetByteStringInMapN(&decoder, 2, &bytes);
  assert(bytes.len == 32U);
  QCBORDecode_GetTextStringInMapN(&decoder, 3, &text);
  assert(text.len == strlen("Acme Firmware"));
  QCBORDecode_GetTextStringInMapN(&decoder, 4, &text);
  assert(text.len == strlen("1.2.3"));
  QCBORDecode_GetTextStringInMapN(&decoder, 5, &text);
  assert(text.len == strlen("Example CPU"));
  QCBORDecode_GetUInt64InMapN(&decoder, 6, &number);
  assert(number == 32768U);
  QCBORDecode_GetByteStringInMapN(&decoder, 7, &bytes);
  assert(bytes.len == 32U);
  QCBORDecode_EnterMapFromMapN(&decoder, 8);
  QCBORDecode_GetUInt64InMapN(&decoder, 1, &number);
  assert(number == 2U);
  QCBORDecode_GetUInt64InMapN(&decoder, 2, &number);
  assert(number == 96U);
  QCBORDecode_ExitMap(&decoder);
  QCBORDecode_GetBoolInMapN(&decoder, 9, &flag);
  assert(flag);
  QCBORDecode_GetBoolInMapN(&decoder, 10, &flag);
  assert(!flag);
  QCBORDecode_GetByteStringInMapN(&decoder, 11, &bytes);
  assert(bytes.len == 32U);
  QCBORDecode_GetByteStringInMapN(&decoder, 12, &bytes);
  assert(bytes.len == 32U);
  QCBORDecode_EnterMapFromMapN(&decoder, 13);
  QCBORDecode_GetBoolInMapN(&decoder, 1, &flag);
  assert(flag);
  QCBORDecode_GetUInt64InMapN(&decoder, 2, &number);
  assert(number == UINT32_C(0x49465800));
  QCBORDecode_GetUInt64InMapN(&decoder, 3, &number);
  assert(number == 42U);
  QCBORDecode_EnterArrayFromMapN(&decoder, 4);
  QCBORDecode_GetUInt64(&decoder, &number);
  assert(number == 4U);
  QCBORDecode_GetUInt64(&decoder, &number);
  assert(number == 11U);
  QCBORDecode_ExitArray(&decoder);
  QCBORDecode_ExitMap(&decoder);
  QCBORDecode_EnterMapFromMapN(&decoder, 14);
  for (int64_t key = 1; key <= 3; ++key) {
    QCBORDecode_GetUInt64InMapN(&decoder, key, &number);
    assert(number == (uint64_t)key);
  }
  QCBORDecode_ExitMap(&decoder);
  QCBORDecode_EnterMapFromMapN(&decoder, 15);
  for (int64_t key = 1; key <= 5; ++key) {
    QCBORDecode_GetUInt64InMapN(&decoder, key, &number);
    assert(number == 0U);
  }
  QCBORDecode_ExitMap(&decoder);
  QCBORDecode_EnterMapFromMapN(&decoder, 16);
  QCBORDecode_GetUInt64InMapN(&decoder, 2, &number);
  assert(number == 200U);
  QCBORDecode_GetUInt64InMapN(&decoder, 7, &number);
  assert(number == 700U);
  QCBORDecode_ExitMap(&decoder);
  QCBORDecode_GetUInt64InMapN(&decoder, 17, &number);
  assert(number == UINT64_C(0x8000000000000007));
  QCBORDecode_ExitMap(&decoder);
  assert(QCBORDecode_Finish(&decoder) == QCBOR_SUCCESS);
}

static void test_all_17_fields_and_canonical_encoding(void) {
  uint8_t fingerprint[32] = {0};
  fingerprint[0] = 0xf1U;
  pbns_inventory_inputs first_inputs = complete_inputs(fingerprint);
  pbns_inventory_report first_report = {0};
  assert(pbns_inventory_collect(&first_inputs, &first_report) == PBNS_OK);
  assert(first_report.timings[0].key == 2U);
  assert(first_report.tpm_active_banks[0] == 4U);

  pbns_inventory_timing reverse_timings[] = {
      {.key = 2U, .microseconds = 200U},
      {.key = 7U, .microseconds = 700U},
  };
  uint32_t reverse_banks[] = {4U, 11U};
  pbns_inventory_inputs second_inputs = complete_inputs(fingerprint);
  second_inputs.timings = reverse_timings;
  second_inputs.tpm.active_banks = reverse_banks;
  pbns_inventory_report second_report = {0};
  assert(pbns_inventory_collect(&second_inputs, &second_report) == PBNS_OK);

  uint8_t first[TEST_OUTPUT_SIZE] = {0};
  uint8_t second[TEST_OUTPUT_SIZE] = {0};
  size_t first_size = 0U;
  size_t second_size = 0U;
  assert(pbns_inventory_encode(&first_report,
                               (pbns_buffer){first, 0U, sizeof(first)},
                               &first_size) == PBNS_OK);
  assert(pbns_inventory_encode(&second_report,
                               (pbns_buffer){second, 0U, sizeof(second)},
                               &second_size) == PBNS_OK);
  assert(first_size == second_size);
  assert(memcmp(first, second, first_size) == 0);
  assert(first[0] == 0xb1U); /* Mapa definido com exactamente 17 entradas. */
  decode_complete_report((pbns_view){first, first_size});

  assert(pbns_inventory_encode(
             &first_report, (pbns_buffer){second, 0U, first_size - 1U},
             &second_size) == PBNS_ERR_LIMIT);
}

static void test_smbios_extraction_bounds_and_privacy(void) {
  pbns_inventory_smbios_collector collector = {0};
  uint8_t record[512] = {0};

  uint8_t bios[6] = {0U, 6U, 0U, 0U, 1U, 2U};
  const char *bios_strings[] = {"  Acme\tFirmware  ", "  1.2.3  "};
  size_t length = make_smbios_record(record, sizeof(record), 0U, bios,
                                     sizeof(bios), bios_strings,
                                     ARRAY_COUNT(bios_strings));
  assert(pbns_inventory_smbios_consume(
             &collector, (pbns_view){record, length}) == PBNS_OK);

  uint8_t system[25] = {0};
  static const uint8_t uuid_sentinel[] = "UUID-SENTINEL";
  for (size_t index = 0U; index + 1U < sizeof(uuid_sentinel); ++index) {
    system[8U + index] = uuid_sentinel[index];
  }
  const char *system_strings[] = {"System", "Product", "Version",
                                  "SERIAL-SENTINEL"};
  system[4] = 1U;
  system[5] = 2U;
  system[6] = 3U;
  system[7] = 4U;
  length = make_smbios_record(record, sizeof(record), 1U, system,
                              sizeof(system), system_strings,
                              ARRAY_COUNT(system_strings));
  assert(pbns_inventory_smbios_consume(
             &collector, (pbns_view){record, length}) == PBNS_OK);

  uint8_t board[9] = {0U, 9U, 0U, 0U, 1U, 2U, 3U, 4U, 5U};
  const char *board_strings[] = {" Board Vendor ", " Board Model ",
                                 " Rev A ", "SERIAL-SENTINEL",
                                 "ASSET-SENTINEL"};
  length = make_smbios_record(record, sizeof(record), 2U, board,
                              sizeof(board), board_strings,
                              ARRAY_COUNT(board_strings));
  assert(pbns_inventory_smbios_consume(
             &collector, (pbns_view){record, length}) == PBNS_OK);

  uint8_t cpu[17] = {0};
  cpu[16] = 1U;
  const char *cpu_strings[] = {"  Example\tCPU  "};
  length = make_smbios_record(record, sizeof(record), 4U, cpu, sizeof(cpu),
                              cpu_strings, ARRAY_COUNT(cpu_strings));
  assert(pbns_inventory_smbios_consume(
             &collector, (pbns_view){record, length}) == PBNS_OK);

  uint8_t memory[32] = {0};
  memory[12] = 0xffU;
  memory[13] = 0x7fU;
  memory[28] = 0x00U;
  memory[29] = 0x80U;
  length = make_smbios_record(record, sizeof(record), 17U, memory,
                              sizeof(memory), NULL, 0U);
  assert(pbns_inventory_smbios_consume(
             &collector, (pbns_view){record, length}) == PBNS_OK);

  uint8_t end[4] = {127U, 4U, 0U, 0U};
  length = make_smbios_record(record, sizeof(record), 127U, end, sizeof(end),
                              NULL, 0U);
  assert(pbns_inventory_smbios_consume(
             &collector, (pbns_view){record, length}) == PBNS_OK);
  assert(collector.memory_mib == 32768U);
  assert(collector.firmware_vendor.len == strlen("Acme Firmware"));
  assert(memcmp(collector.firmware_vendor.bytes, "Acme Firmware",
                collector.firmware_vendor.len) == 0);
  assert(collector.cpu_class.len == strlen("Example CPU"));

  uint8_t board_digest[32] = {0};
  assert(pbns_inventory_smbios_finish(&collector, hash_sha256, NULL,
                                      board_digest) == PBNS_OK);
  const pbns_view sanitized = {collector.board_material,
                               collector.board_material_len};
  assert(!contains(sanitized, "SERIAL-SENTINEL"));
  assert(!contains(sanitized, "UUID-SENTINEL"));
  assert(!contains(sanitized, "ASSET-SENTINEL"));
  assert(pbns_inventory_smbios_consume(
             &collector, (pbns_view){record, length}) == PBNS_ERR_ARGUMENT);

  pbns_inventory_smbios_collector malformed_collector = {0};
  uint8_t short_header[] = {0U, 3U, 0U, 0U, 0U, 0U};
  uint8_t no_double_nul[] = {0U, 4U, 0U, 0U, 'x', 0U};
  uint8_t trailing_after_end[] = {0U, 4U, 0U, 0U, 0U, 0U, 'x'};
  assert(pbns_inventory_smbios_consume(
             &malformed_collector,
             (pbns_view){short_header, sizeof(short_header)}) ==
         PBNS_ERR_FORMAT);
  assert(pbns_inventory_smbios_consume(
             &malformed_collector,
             (pbns_view){no_double_nul, sizeof(no_double_nul)}) ==
         PBNS_ERR_FORMAT);
  assert(pbns_inventory_smbios_consume(
             &malformed_collector,
             (pbns_view){trailing_after_end, sizeof(trailing_after_end)}) ==
         PBNS_ERR_FORMAT);
  assert(pbns_inventory_smbios_finish(&malformed_collector, hash_sha256, NULL,
                                      board_digest) == PBNS_ERR_FORMAT);
  malformed_collector.record_count = PBNS_INVENTORY_SMBIOS_COUNT_MAX;
  assert(pbns_inventory_smbios_consume(
             &malformed_collector,
             (pbns_view){short_header, sizeof(short_header)}) == PBNS_ERR_LIMIT);
}

static void test_pci_canonical_order_and_limits(void) {
  const fake_pci_descriptor descriptors[] = {
      {.approved = {.segment = 0U,
                    .bus = 2U,
                    .device = 1U,
                    .function = 0U,
                    .vendor_id = UINT16_C(0x8086),
                    .device_id = UINT16_C(0x1234),
                    .class_code = 2U,
                    .subclass = 0U,
                    .prog_if = 1U},
       .mac = "MAC-SENTINEL"},
      {.approved = {.segment = 0U,
                    .bus = 1U,
                    .device = 31U,
                    .function = 7U,
                    .vendor_id = UINT16_C(0x10ec),
                    .device_id = UINT16_C(0xabcd),
                    .class_code = 1U,
                    .subclass = 6U,
                    .prog_if = 1U},
       .mac = "OTHER-MAC"},
  };
  assert(strcmp(descriptors[0].mac, "MAC-SENTINEL") == 0);
  pbns_inventory_pci_collector first = {0};
  pbns_inventory_pci_collector second = {0};
  assert(pbns_inventory_pci_add(&first, &descriptors[0].approved) == PBNS_OK);
  assert(pbns_inventory_pci_add(&first, &descriptors[1].approved) == PBNS_OK);
  assert(pbns_inventory_pci_add(&second, &descriptors[1].approved) == PBNS_OK);
  assert(pbns_inventory_pci_add(&second, &descriptors[0].approved) == PBNS_OK);
  uint8_t first_digest[32] = {0};
  uint8_t second_digest[32] = {0};
  assert(pbns_inventory_pci_finish(&first, hash_sha256, NULL, first_digest) ==
         PBNS_OK);
  assert(pbns_inventory_pci_finish(&second, hash_sha256, NULL, second_digest) ==
         PBNS_OK);
  assert(memcmp(first_digest, second_digest, sizeof(first_digest)) == 0);
  assert(memcmp(first.tuples, second.tuples,
                first.function_count * PBNS_INVENTORY_PCI_TUPLE_SIZE) == 0);
  assert(!contains((pbns_view){&first.tuples[0][0], sizeof(first.tuples)},
                   "MAC-SENTINEL"));

  pbns_inventory_pci_function invalid = descriptors[0].approved;
  invalid.device = 32U;
  assert(pbns_inventory_pci_add(&first, &invalid) == PBNS_ERR_FORMAT);
  invalid = descriptors[0].approved;
  invalid.function = 8U;
  assert(pbns_inventory_pci_add(&first, &invalid) == PBNS_ERR_FORMAT);
  first.function_count = PBNS_INVENTORY_PCI_FUNCTION_MAX;
  assert(pbns_inventory_pci_add(&first, &descriptors[0].approved) ==
         PBNS_ERR_LIMIT);
}

static void test_storage_numeric_summary_and_overflow(void) {
  const fake_block_descriptor descriptors[] = {
      {.approved = {.last_block = GIB_BYTES / 512U - 1U,
                    .block_size = 512U,
                    .removable = false,
                    .logical_partition = false},
       .partition_label = "PARTITION-SENTINEL",
       .path = "PATH-SENTINEL"},
      {.approved = {.last_block = 999U,
                    .block_size = 512U,
                    .removable = true,
                    .logical_partition = false},
       .partition_label = "removable",
       .path = "removable-path"},
      {.approved = {.last_block = 999U,
                    .block_size = 512U,
                    .removable = false,
                    .logical_partition = true},
       .partition_label = "logical",
       .path = "logical-path"},
  };
  assert(strcmp(descriptors[0].partition_label, "PARTITION-SENTINEL") == 0);
  assert(strcmp(descriptors[0].path, "PATH-SENTINEL") == 0);
  pbns_inventory_storage_collector storage = {0};
  for (size_t index = 0U; index < ARRAY_COUNT(descriptors); ++index) {
    assert(pbns_inventory_storage_add(&storage, &descriptors[index].approved) ==
           PBNS_OK);
  }
  assert(storage.count == 1U && storage.total_bytes / GIB_BYTES == 1U);

  pbns_inventory_block_device zero_block = {.last_block = 1U,
                                             .block_size = 0U};
  pbns_inventory_block_device count_overflow = {.last_block = UINT64_MAX,
                                                 .block_size = 512U};
  assert(pbns_inventory_storage_add(&storage, &zero_block) == PBNS_ERR_LIMIT);
  assert(pbns_inventory_storage_add(&storage, &count_overflow) ==
         PBNS_ERR_LIMIT);
  pbns_inventory_storage_collector maximum = {0};
  const pbns_inventory_block_device tiny = {.last_block = 0U,
                                             .block_size = 1U};
  for (size_t index = 0U; index < PBNS_INVENTORY_BLOCK_DEVICE_MAX; ++index) {
    assert(pbns_inventory_storage_add(&maximum, &tiny) == PBNS_OK);
  }
  assert(pbns_inventory_storage_add(&maximum, &tiny) == PBNS_ERR_LIMIT);
  storage.count = 1U;
  storage.total_bytes = UINT64_MAX;
  assert(pbns_inventory_storage_add(&storage, &descriptors[0].approved) ==
         PBNS_ERR_LIMIT);
}

static void test_secure_variable_domains_and_bounds(void) {
  static const uint8_t expected_absent[32] = {
      0x6dU, 0xaeU, 0x8aU, 0x38U, 0x93U, 0x93U, 0xb0U, 0x0dU,
      0x33U, 0xeaU, 0x8fU, 0xb0U, 0xe8U, 0x3cU, 0xd8U, 0x9cU,
      0xb6U, 0xa9U, 0x93U, 0x52U, 0x72U, 0x79U, 0x15U, 0xa7U,
      0xb7U, 0xa7U, 0xe1U, 0xcbU, 0xdbU, 0x0aU, 0xa7U, 0x15U,
  };
  static const uint8_t expected_present[32] = {
      0x95U, 0xccU, 0x06U, 0xeaU, 0x6dU, 0xa4U, 0xa2U, 0x34U,
      0x9dU, 0x45U, 0xa4U, 0x12U, 0x8dU, 0x8bU, 0x62U, 0x58U,
      0xfdU, 0x01U, 0x48U, 0xaeU, 0x6dU, 0x7eU, 0xe3U, 0xc4U,
      0xc9U, 0x71U, 0xacU, 0x65U, 0xb7U, 0x4cU, 0xc5U, 0x53U,
  };
  const uint8_t variable[] = "SSID-SENTINEL USERNAME-SENTINEL";
  uint8_t present_digest[32] = {0};
  uint8_t absent_digest[32] = {0};
  uint8_t changed_digest[32] = {0};
  assert(pbns_inventory_hash_variable(
             hash_sha256_parts, NULL, true, UINT32_C(0x27),
             (pbns_view){variable, sizeof(variable) - 1U}, present_digest) ==
         PBNS_OK);
  assert(pbns_inventory_hash_variable(hash_sha256_parts, NULL, false, 0U,
                                      (pbns_view){NULL, 0U}, absent_digest) ==
         PBNS_OK);
  assert(memcmp(absent_digest, expected_absent, sizeof(absent_digest)) == 0);
  assert(memcmp(present_digest, expected_present, sizeof(present_digest)) == 0);
  assert(pbns_inventory_hash_variable(
             hash_sha256_parts, NULL, true, UINT32_C(0x26),
             (pbns_view){variable, sizeof(variable) - 1U}, changed_digest) ==
         PBNS_OK);
  assert(memcmp(present_digest, changed_digest, sizeof(present_digest)) != 0);
  assert(pbns_inventory_hash_variable(
             hash_sha256_parts, NULL, true, UINT32_C(0x27),
             (pbns_view){variable, sizeof(variable) - 2U}, changed_digest) ==
         PBNS_OK);
  assert(memcmp(present_digest, changed_digest, sizeof(present_digest)) != 0);
  uint8_t changed_variable[sizeof(variable)] = {0};
  memcpy(changed_variable, variable, sizeof(variable));
  changed_variable[0] ^= 1U;
  assert(pbns_inventory_hash_variable(
             hash_sha256_parts, NULL, true, UINT32_C(0x27),
             (pbns_view){changed_variable, sizeof(changed_variable) - 1U},
             changed_digest) == PBNS_OK);
  assert(memcmp(present_digest, changed_digest, sizeof(present_digest)) != 0);
  assert(pbns_inventory_hash_variable(
             hash_sha256_parts, NULL, true, 0U,
             (pbns_view){variable, PBNS_INVENTORY_VARIABLE_MAX_SIZE + 1U},
             present_digest) == PBNS_ERR_ARGUMENT);
  assert(pbns_inventory_hash_variable(hash_sha256_parts, NULL, false, 1U,
                                      (pbns_view){NULL, 0U}, absent_digest) ==
         PBNS_ERR_ARGUMENT);
}

static void test_tpm_active_bank_policy(void) {
  uint32_t banks[PBNS_INVENTORY_TPM_BANK_MAX] = {0};
  size_t count = 0U;
  assert(pbns_inventory_tpm_active_banks(0x02U, 2U, banks,
                                         ARRAY_COUNT(banks), &count) ==
         PBNS_OK);
  assert(count == 1U && banks[0] == UINT32_C(0x000b));
  assert(pbns_inventory_tpm_active_banks(0x03U, 2U, banks,
                                         ARRAY_COUNT(banks), &count) ==
         PBNS_OK);
  assert(count == 2U && banks[0] == UINT32_C(0x0004) &&
         banks[1] == UINT32_C(0x000b));
  assert(pbns_inventory_tpm_active_banks(0x20U, 2U, banks,
                                         ARRAY_COUNT(banks), &count) ==
         PBNS_ERR_UNSUPPORTED);
  assert(pbns_inventory_tpm_active_banks(0U, 2U, banks, ARRAY_COUNT(banks),
                                         &count) == PBNS_ERR_UNSUPPORTED);
  assert(pbns_inventory_tpm_active_banks(0x03U, 1U, banks,
                                         ARRAY_COUNT(banks), &count) ==
         PBNS_ERR_FORMAT);
  assert(count == 0U);
  assert(pbns_inventory_tpm_active_banks(0x03U, 2U, banks, 1U, &count) ==
         PBNS_ERR_LIMIT);
  assert(count == 0U);
}

static void test_platform_result_classifier(void) {
  assert(pbns_inventory_classify_platform_result(PBNS_PLATFORM_SUCCESS) ==
         PBNS_INVENTORY_OK);
  assert(pbns_inventory_classify_platform_result(PBNS_PLATFORM_NOT_FOUND) ==
         PBNS_INVENTORY_ABSENT);
  assert(pbns_inventory_classify_platform_result(PBNS_PLATFORM_UNSUPPORTED) ==
         PBNS_INVENTORY_UNSUPPORTED);
  assert(pbns_inventory_classify_platform_result(PBNS_PLATFORM_MALFORMED) ==
         PBNS_INVENTORY_MALFORMED);
  assert(pbns_inventory_classify_platform_result(PBNS_PLATFORM_LIMIT) ==
         PBNS_INVENTORY_LIMIT);
  assert(pbns_inventory_classify_platform_result(PBNS_PLATFORM_ERROR) ==
         PBNS_INVENTORY_ERROR);
}

static void test_bounded_smbios_table_traversal(void) {
  uint8_t table[128] = {0};
  size_t offset = 0U;
  uint8_t bios[6] = {0U, 6U, 0U, 0U, 1U, 2U};
  const char *bios_strings[] = {"Table Vendor", "3.0"};
  offset += make_smbios_record(table + offset, sizeof(table) - offset, 0U,
                               bios, sizeof(bios), bios_strings,
                               ARRAY_COUNT(bios_strings));
  uint8_t end[4] = {127U, 4U, 0U, 0U};
  offset += make_smbios_record(table + offset, sizeof(table) - offset, 127U,
                               end, sizeof(end), NULL, 0U);

  pbns_inventory_smbios_collector collector = {0};
  assert(pbns_inventory_smbios_consume_table(
             &collector, (pbns_view){table, offset}, true) == PBNS_OK);
  assert(collector.end_seen && collector.record_count == 2U);

  collector = (pbns_inventory_smbios_collector){0};
  table[offset] = 0xa5U;
  assert(pbns_inventory_smbios_consume_table(
             &collector, (pbns_view){table, offset + 1U}, true) ==
         PBNS_ERR_FORMAT);
  collector = (pbns_inventory_smbios_collector){0};
  assert(pbns_inventory_smbios_consume_table(
             &collector, (pbns_view){table, offset + 1U}, false) == PBNS_OK);

  collector = (pbns_inventory_smbios_collector){0};
  assert(pbns_inventory_smbios_consume_table(
             &collector, (pbns_view){table, offset - 1U}, true) ==
         PBNS_ERR_FORMAT);
  collector = (pbns_inventory_smbios_collector){0};
  assert(pbns_inventory_smbios_consume_table(
             &collector, (pbns_view){table, offset - 6U}, true) ==
         PBNS_ERR_FORMAT);

  collector = (pbns_inventory_smbios_collector){0};
  collector.record_count = PBNS_INVENTORY_SMBIOS_COUNT_MAX;
  assert(pbns_inventory_smbios_consume_table(
             &collector, (pbns_view){table, offset}, true) == PBNS_ERR_LIMIT);

  uint8_t oversized[PBNS_INVENTORY_SMBIOS_RECORD_MAX] = {0};
  oversized[0] = 10U;
  oversized[1] = 4U;
  memset(oversized + 4U, 1, sizeof(oversized) - 4U);
  collector = (pbns_inventory_smbios_collector){0};
  assert(pbns_inventory_smbios_consume_table(
             &collector, (pbns_view){oversized, sizeof(oversized)}, false) ==
         PBNS_ERR_LIMIT);
}

static void test_privacy_from_valid_raw_inputs(void) {
  static const char *const forbidden[] = {
      "SERIAL-SENTINEL",    "UUID-SENTINEL", "ASSET-SENTINEL",
      "MAC-SENTINEL",       "SSID-SENTINEL", "USERNAME-SENTINEL",
      "PARTITION-SENTINEL", "PATH-SENTINEL",
  };
  uint8_t fingerprint[32] = {0};
  pbns_inventory_inputs inputs = complete_inputs(fingerprint);

  pbns_inventory_smbios_collector smbios = {0};
  uint8_t record[512] = {0};
  uint8_t bios[6] = {0U, 6U, 0U, 0U, 1U, 2U};
  const char *bios_strings[] = {"Privacy Firmware", "2.0"};
  size_t length = make_smbios_record(record, sizeof(record), 0U, bios,
                                     sizeof(bios), bios_strings,
                                     ARRAY_COUNT(bios_strings));
  assert(pbns_inventory_smbios_consume(
             &smbios, (pbns_view){record, length}) == PBNS_OK);
  uint8_t system[25] = {0};
  static const uint8_t uuid_sentinel[] = "UUID-SENTINEL";
  for (size_t index = 0U; index + 1U < sizeof(uuid_sentinel); ++index) {
    system[8U + index] = uuid_sentinel[index];
  }
  system[4] = 1U;
  system[5] = 2U;
  system[6] = 3U;
  system[7] = 4U;
  const char *system_strings[] = {"System", "Model", "Revision",
                                  "SERIAL-SENTINEL"};
  length = make_smbios_record(record, sizeof(record), 1U, system,
                              sizeof(system), system_strings,
                              ARRAY_COUNT(system_strings));
  assert(pbns_inventory_smbios_consume(
             &smbios, (pbns_view){record, length}) == PBNS_OK);
  uint8_t board[9] = {0U, 9U, 0U, 0U, 1U, 2U, 3U, 4U, 5U};
  const char *board_strings[] = {"Board Vendor", "Board Model", "Rev B",
                                 "SERIAL-SENTINEL", "ASSET-SENTINEL"};
  length = make_smbios_record(record, sizeof(record), 2U, board,
                              sizeof(board), board_strings,
                              ARRAY_COUNT(board_strings));
  assert(pbns_inventory_smbios_consume(
             &smbios, (pbns_view){record, length}) == PBNS_OK);
  uint8_t cpu[17] = {0};
  cpu[16] = 1U;
  const char *cpu_strings[] = {"Privacy CPU"};
  length = make_smbios_record(record, sizeof(record), 4U, cpu, sizeof(cpu),
                              cpu_strings, ARRAY_COUNT(cpu_strings));
  assert(pbns_inventory_smbios_consume(
             &smbios, (pbns_view){record, length}) == PBNS_OK);
  uint8_t memory[32] = {0};
  memory[12] = 0x00U;
  memory[13] = 0x20U;
  length = make_smbios_record(record, sizeof(record), 17U, memory,
                              sizeof(memory), NULL, 0U);
  assert(pbns_inventory_smbios_consume(
             &smbios, (pbns_view){record, length}) == PBNS_OK);
  uint8_t end[4] = {127U, 4U, 0U, 0U};
  length = make_smbios_record(record, sizeof(record), 127U, end, sizeof(end),
                              NULL, 0U);
  assert(pbns_inventory_smbios_consume(
             &smbios, (pbns_view){record, length}) == PBNS_OK);
  assert(pbns_inventory_smbios_finish(&smbios, hash_sha256, NULL,
                                      inputs.board_model_digest) == PBNS_OK);
  inputs.firmware_vendor = smbios.firmware_vendor;
  inputs.firmware_version = smbios.firmware_version;
  inputs.cpu_class = smbios.cpu_class;
  inputs.memory_mib = smbios.memory_mib;

  const fake_pci_descriptor pci_raw = {
      .approved = {.segment = 0U,
                   .bus = 1U,
                   .device = 2U,
                   .function = 0U,
                   .vendor_id = UINT16_C(0x1234),
                   .device_id = UINT16_C(0x5678),
                   .class_code = 2U},
      .mac = "MAC-SENTINEL",
  };
  assert(strcmp(pci_raw.mac, "MAC-SENTINEL") == 0);
  pbns_inventory_pci_collector pci = {0};
  assert(pbns_inventory_pci_add(&pci, &pci_raw.approved) == PBNS_OK);
  assert(pbns_inventory_pci_finish(&pci, hash_sha256, NULL,
                                   inputs.pci_digest) == PBNS_OK);

  const fake_block_descriptor block_raw = {
      .approved = {.last_block = (GIB_BYTES + GIB_BYTES / 2U) / 512U - 1U,
                   .block_size = 512U},
      .partition_label = "PARTITION-SENTINEL",
      .path = "PATH-SENTINEL",
  };
  assert(strcmp(block_raw.partition_label, "PARTITION-SENTINEL") == 0);
  assert(strcmp(block_raw.path, "PATH-SENTINEL") == 0);
  pbns_inventory_storage_collector storage = {0};
  assert(pbns_inventory_storage_add(&storage, &block_raw.approved) == PBNS_OK);
  inputs.block_device_count = storage.count;
  inputs.storage_capacity_gib = storage.total_bytes / GIB_BYTES;
  assert(inputs.storage_capacity_gib == 1U);

  const uint8_t variable_raw[] = "SSID-SENTINEL USERNAME-SENTINEL";
  assert(pbns_inventory_hash_variable(
             hash_sha256_parts, NULL, true, UINT32_C(0x27),
             (pbns_view){variable_raw, sizeof(variable_raw) - 1U},
             inputs.secure_boot.db_digest) == PBNS_OK);
  assert(pbns_inventory_hash_variable(
             hash_sha256_parts, NULL, false, 0U, (pbns_view){NULL, 0U},
             inputs.secure_boot.dbx_digest) == PBNS_OK);

  pbns_inventory_report report = {0};
  uint8_t encoded[TEST_OUTPUT_SIZE] = {0};
  size_t encoded_size = 0U;
  assert(pbns_inventory_collect(&inputs, &report) == PBNS_OK);
  assert(pbns_inventory_encode(&report,
                               (pbns_buffer){encoded, 0U, sizeof(encoded)},
                               &encoded_size) == PBNS_OK);
  for (size_t index = 0U; index < ARRAY_COUNT(forbidden); ++index) {
    assert(!contains((pbns_view){encoded, encoded_size}, forbidden[index]));
  }
}

static void test_partial_outcomes_and_invalid_inputs(void) {
  uint8_t fingerprint[32] = {0};
  pbns_inventory_inputs inputs = {
      .host_fingerprint = {fingerprint, sizeof(fingerprint)},
      .smbios_status = PBNS_INVENTORY_MALFORMED,
      .pci_status = PBNS_INVENTORY_ERROR,
      .storage_status = PBNS_INVENTORY_LIMIT,
      .secure_boot = {.status = PBNS_INVENTORY_ABSENT},
      .tpm = {.status = PBNS_INVENTORY_UNSUPPORTED},
  };
  pbns_inventory_report report;
  memset(&report, 0xa5, sizeof(report));
  assert(pbns_inventory_collect(&inputs, &report) == PBNS_OK);
  assert(report.outcomes[0] == PBNS_INVENTORY_MALFORMED);
  assert(report.outcomes[1] == PBNS_INVENTORY_ERROR);
  assert(report.outcomes[2] == PBNS_INVENTORY_LIMIT);
  assert(report.outcomes[3] == PBNS_INVENTORY_ABSENT);
  assert(report.outcomes[4] == PBNS_INVENTORY_UNSUPPORTED);
  assert(report.memory_mib == 0U && report.firmware_vendor.len == 0U);
  assert(report.tpm_active_bank_count == 0U &&
         report.prior_loader_efi_status == 0U);

  pbns_inventory_timing duplicate[] = {
      {.key = 1U, .microseconds = 1U},
      {.key = 1U, .microseconds = 2U},
  };
  inputs.timings = duplicate;
  inputs.timing_count = ARRAY_COUNT(duplicate);
  memset(&report, 0xa5, sizeof(report));
  assert(pbns_inventory_collect(&inputs, &report) == PBNS_ERR_ARGUMENT);
  for (size_t index = 0U; index < sizeof(report.host_fingerprint); ++index) {
    assert(report.host_fingerprint[index] == 0U);
  }
  assert(report.firmware_vendor.len == 0U && report.memory_mib == 0U &&
         report.tpm_active_bank_count == 0U && report.timing_count == 0U);

  inputs.timings = NULL;
  inputs.timing_count = 0U;
  inputs.firmware_vendor.len = PBNS_INVENTORY_TEXT_MAX_SIZE + 1U;
  assert(pbns_inventory_collect(&inputs, &report) == PBNS_ERR_ARGUMENT);
}

int main(void) {
  test_all_17_fields_and_canonical_encoding();
  test_smbios_extraction_bounds_and_privacy();
  test_pci_canonical_order_and_limits();
  test_storage_numeric_summary_and_overflow();
  test_secure_variable_domains_and_bounds();
  test_tpm_active_bank_policy();
  test_platform_result_classifier();
  test_bounded_smbios_table_traversal();
  test_privacy_from_valid_raw_inputs();
  test_partial_outcomes_and_invalid_inputs();
  return EXIT_SUCCESS;
}
