#include "pbns/inventory.h"

#include <limits.h>
#include <string.h>

#include "qcbor/qcbor_encode.h"

#define PBNS_GIB_BYTES (UINT64_C(1024) * 1024U * 1024U)

static bool capability_valid(pbns_inventory_capability value) {
  return value >= PBNS_INVENTORY_OK && value <= PBNS_INVENTORY_ERROR;
}

pbns_inventory_capability pbns_inventory_classify_platform_result(
    pbns_inventory_platform_result result) {
  switch (result) {
    case PBNS_PLATFORM_SUCCESS:
      return PBNS_INVENTORY_OK;
    case PBNS_PLATFORM_NOT_FOUND:
      return PBNS_INVENTORY_ABSENT;
    case PBNS_PLATFORM_UNSUPPORTED:
      return PBNS_INVENTORY_UNSUPPORTED;
    case PBNS_PLATFORM_MALFORMED:
      return PBNS_INVENTORY_MALFORMED;
    case PBNS_PLATFORM_LIMIT:
      return PBNS_INVENTORY_LIMIT;
    case PBNS_PLATFORM_ERROR:
    default:
      return PBNS_INVENTORY_ERROR;
  }
}

pbns_status pbns_inventory_tpm_active_banks(
    uint32_t active_bitmap, size_t supported_bank_count, uint32_t *banks,
    size_t bank_capacity, size_t *bank_count) {
  static const struct {
    uint32_t bitmap;
    uint32_t algorithm;
  } known_banks[] = {
      {UINT32_C(0x01), UINT32_C(0x0004)},
      {UINT32_C(0x02), UINT32_C(0x000b)},
      {UINT32_C(0x04), UINT32_C(0x000c)},
      {UINT32_C(0x08), UINT32_C(0x000d)},
      {UINT32_C(0x10), UINT32_C(0x0012)},
  };
  const uint32_t known_bitmap = UINT32_C(0x1f);
  if (banks == NULL || bank_count == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *bank_count = 0U;
  if ((active_bitmap & ~known_bitmap) != 0U || active_bitmap == 0U) {
    return PBNS_ERR_UNSUPPORTED;
  }
  size_t active_count = 0U;
  for (size_t index = 0U;
       index < sizeof(known_banks) / sizeof(known_banks[0]); ++index) {
    if ((active_bitmap & known_banks[index].bitmap) != 0U) {
      ++active_count;
    }
  }
  if (supported_bank_count == 0U || active_count > supported_bank_count) {
    return PBNS_ERR_FORMAT;
  }
  if (bank_capacity < active_count) {
    return PBNS_ERR_LIMIT;
  }
  for (size_t index = 0U;
       index < sizeof(known_banks) / sizeof(known_banks[0]); ++index) {
    if ((active_bitmap & known_banks[index].bitmap) != 0U) {
      banks[*bank_count] = known_banks[index].algorithm;
      ++(*bank_count);
    }
  }
  return PBNS_OK;
}

bool pbns_inventory_text_is_normalized(const pbns_inventory_text *text) {
  if (text == NULL || text->len > PBNS_INVENTORY_TEXT_MAX_SIZE) {
    return false;
  }
  for (size_t index = 0U; index < text->len; ++index) {
    const uint8_t character = text->bytes[index];
    if (character < 0x20U || character > 0x7eU ||
        (character == (uint8_t)' ' &&
         (index == 0U || index + 1U == text->len ||
          text->bytes[index - 1U] == (uint8_t)' '))) {
      return false;
    }
  }
  return true;
}

static pbns_status normalize_text(pbns_view input, pbns_inventory_text *output) {
  if (output == NULL || (input.ptr == NULL && input.len != 0U)) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_inventory_text normalized = {0};
  bool pending_space = false;
  for (size_t index = 0U; index < input.len; ++index) {
    const uint8_t character = input.ptr[index];
    if (character == (uint8_t)' ' || character == (uint8_t)'\t') {
      pending_space = normalized.len != 0U;
      continue;
    }
    if (character < 0x21U || character > 0x7eU) {
      return PBNS_ERR_FORMAT;
    }
    if (pending_space) {
      if (normalized.len == PBNS_INVENTORY_TEXT_MAX_SIZE) {
        return PBNS_ERR_LIMIT;
      }
      normalized.bytes[normalized.len++] = (uint8_t)' ';
      pending_space = false;
    }
    if (normalized.len == PBNS_INVENTORY_TEXT_MAX_SIZE) {
      return PBNS_ERR_LIMIT;
    }
    normalized.bytes[normalized.len++] = character;
  }
  *output = normalized;
  return PBNS_OK;
}

static pbns_status smbios_string(pbns_view record, size_t formatted_length,
                                 uint8_t string_index, pbns_view *result) {
  if (result == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *result = (pbns_view){NULL, 0U};
  if (string_index == 0U) {
    return PBNS_OK;
  }
  size_t position = formatted_length;
  uint8_t current_index = 1U;
  while (position + 1U < record.len && record.ptr[position] != 0U) {
    size_t end = position;
    while (end < record.len && record.ptr[end] != 0U) {
      ++end;
    }
    if (end >= record.len) {
      return PBNS_ERR_FORMAT;
    }
    if (current_index == string_index) {
      *result = (pbns_view){record.ptr + position, end - position};
      return PBNS_OK;
    }
    if (current_index == UINT8_MAX) {
      return PBNS_ERR_LIMIT;
    }
    ++current_index;
    position = end + 1U;
  }
  return PBNS_ERR_FORMAT;
}

static pbns_status extract_text(pbns_view record, size_t formatted_length,
                                size_t index_offset,
                                pbns_inventory_text *destination) {
  pbns_view raw = {0};
  const pbns_status status =
      smbios_string(record, formatted_length, record.ptr[index_offset], &raw);
  if (status != PBNS_OK) {
    return status;
  }
  return normalize_text(raw, destination);
}

static pbns_status append_board_text(
    pbns_inventory_smbios_collector *collector,
    const pbns_inventory_text *text) {
  if (text->len > UINT8_MAX ||
      collector->board_material_len + 1U + text->len >
          sizeof(collector->board_material)) {
    return PBNS_ERR_LIMIT;
  }
  collector->board_material[collector->board_material_len++] =
      (uint8_t)text->len;
  if (text->len != 0U) {
    memcpy(collector->board_material + collector->board_material_len,
           text->bytes, text->len);
    collector->board_material_len += text->len;
  }
  return PBNS_OK;
}

static pbns_status consume_board(pbns_inventory_smbios_collector *collector,
                                 pbns_view record, size_t formatted_length) {
  if (formatted_length < 7U || collector->board_material_len != 0U) {
    return formatted_length < 7U ? PBNS_ERR_FORMAT : PBNS_OK;
  }
  pbns_inventory_text fields[3] = {0};
  for (size_t index = 0U; index < 3U; ++index) {
    const pbns_status status =
        extract_text(record, formatted_length, 4U + index, &fields[index]);
    if (status != PBNS_OK) {
      return status;
    }
  }
  for (size_t index = 0U; index < 3U; ++index) {
    const pbns_status status = append_board_text(collector, &fields[index]);
    if (status != PBNS_OK) {
      return status;
    }
  }
  return PBNS_OK;
}

static pbns_status consume_memory(pbns_inventory_smbios_collector *collector,
                                  pbns_view record,
                                  size_t formatted_length) {
  if (formatted_length < 14U) {
    return PBNS_ERR_FORMAT;
  }
  const uint16_t encoded =
      (uint16_t)((uint16_t)record.ptr[12U] |
                 (uint16_t)((uint16_t)record.ptr[13U] << 8U));
  uint64_t memory_mib = 0U;
  if (encoded == UINT16_C(0x7fff)) {
    if (formatted_length < 32U) {
      return PBNS_ERR_FORMAT;
    }
    memory_mib = (uint64_t)record.ptr[28U] |
                 ((uint64_t)record.ptr[29U] << 8U) |
                 ((uint64_t)record.ptr[30U] << 16U) |
                 ((uint64_t)record.ptr[31U] << 24U);
  } else if (encoded != 0U && encoded != UINT16_MAX) {
    memory_mib = (encoded & UINT16_C(0x8000)) != 0U
                     ? (uint64_t)(encoded & UINT16_C(0x7fff)) / 1024U
                     : encoded;
  }
  if (memory_mib > UINT64_MAX - collector->memory_mib) {
    return PBNS_ERR_LIMIT;
  }
  collector->memory_mib += memory_mib;
  return PBNS_OK;
}

pbns_status pbns_inventory_smbios_consume(
    pbns_inventory_smbios_collector *collector, pbns_view record) {
  if (collector == NULL || record.ptr == NULL || collector->end_seen) {
    return PBNS_ERR_ARGUMENT;
  }
  if (record.len < 6U || record.len > PBNS_INVENTORY_SMBIOS_RECORD_MAX) {
    return PBNS_ERR_FORMAT;
  }
  if (collector->record_count >= PBNS_INVENTORY_SMBIOS_COUNT_MAX) {
    return PBNS_ERR_LIMIT;
  }
  const size_t formatted_length = record.ptr[1U];
  if (formatted_length < 4U || formatted_length + 2U > record.len) {
    return PBNS_ERR_FORMAT;
  }
  bool terminator_seen = false;
  for (size_t index = formatted_length; index + 1U < record.len; ++index) {
    if (record.ptr[index] == 0U && record.ptr[index + 1U] == 0U) {
      terminator_seen = index + 2U == record.len;
      break;
    }
  }
  if (!terminator_seen) {
    return PBNS_ERR_FORMAT;
  }

  pbns_status status = PBNS_OK;
  switch (record.ptr[0U]) {
    case 0U:
      if (formatted_length < 6U) {
        status = PBNS_ERR_FORMAT;
      } else {
        status = extract_text(record, formatted_length, 4U,
                              &collector->firmware_vendor);
        if (status == PBNS_OK) {
          status = extract_text(record, formatted_length, 5U,
                                &collector->firmware_version);
        }
      }
      break;
    case 2U:
      status = consume_board(collector, record, formatted_length);
      break;
    case 4U:
      if (formatted_length < 17U) {
        status = PBNS_ERR_FORMAT;
      } else if (collector->cpu_class.len == 0U) {
        status = extract_text(record, formatted_length, 16U,
                              &collector->cpu_class);
      }
      break;
    case 17U:
      status = consume_memory(collector, record, formatted_length);
      break;
    case 127U:
      collector->end_seen = true;
      break;
    default:
      break;
  }
  if (status == PBNS_OK) {
    ++collector->record_count;
  }
  return status;
}

pbns_status pbns_inventory_smbios_consume_table(
    pbns_inventory_smbios_collector *collector, pbns_view table,
    bool require_exact_end) {
  if (collector == NULL || table.ptr == NULL || table.len == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  size_t offset = 0U;
  while (offset < table.len && !collector->end_seen) {
    const size_t remaining = table.len - offset;
    if (remaining < 4U) {
      return PBNS_ERR_FORMAT;
    }
    const size_t formatted_length = table.ptr[offset + 1U];
    if (formatted_length < 4U || formatted_length + 2U > remaining) {
      return PBNS_ERR_FORMAT;
    }
    const size_t scan_limit =
        remaining < PBNS_INVENTORY_SMBIOS_RECORD_MAX
            ? remaining
            : PBNS_INVENTORY_SMBIOS_RECORD_MAX;
    size_t extent = 0U;
    for (size_t index = formatted_length; index + 1U < scan_limit; ++index) {
      if (table.ptr[offset + index] == 0U &&
          table.ptr[offset + index + 1U] == 0U) {
        extent = index + 2U;
        break;
      }
    }
    if (extent == 0U) {
      return remaining >= PBNS_INVENTORY_SMBIOS_RECORD_MAX ? PBNS_ERR_LIMIT
                                                           : PBNS_ERR_FORMAT;
    }
    const pbns_status status = pbns_inventory_smbios_consume(
        collector, (pbns_view){table.ptr + offset, extent});
    if (status != PBNS_OK) {
      return status;
    }
    offset += extent;
  }
  if (!collector->end_seen || (require_exact_end && offset != table.len)) {
    return PBNS_ERR_FORMAT;
  }
  return PBNS_OK;
}

pbns_status pbns_inventory_smbios_finish(
    const pbns_inventory_smbios_collector *collector,
    pbns_inventory_hash_fn hash, void *context,
    uint8_t board_digest[PBNS_INVENTORY_DIGEST_SIZE]) {
  if (collector == NULL || hash == NULL || board_digest == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!collector->end_seen ||
      collector->record_count > PBNS_INVENTORY_SMBIOS_COUNT_MAX ||
      collector->board_material_len > sizeof(collector->board_material) ||
      !pbns_inventory_text_is_normalized(&collector->firmware_vendor) ||
      !pbns_inventory_text_is_normalized(&collector->firmware_version) ||
      !pbns_inventory_text_is_normalized(&collector->cpu_class)) {
    return PBNS_ERR_FORMAT;
  }
  return hash(context,
              (pbns_view){collector->board_material,
                          collector->board_material_len},
              board_digest);
}

static void encode_pci_tuple(const pbns_inventory_pci_function *function,
                             uint8_t tuple[PBNS_INVENTORY_PCI_TUPLE_SIZE]) {
  tuple[0] = (uint8_t)(function->segment >> 8U);
  tuple[1] = (uint8_t)function->segment;
  tuple[2] = function->bus;
  tuple[3] = function->device;
  tuple[4] = function->function;
  tuple[5] = (uint8_t)(function->vendor_id >> 8U);
  tuple[6] = (uint8_t)function->vendor_id;
  tuple[7] = (uint8_t)(function->device_id >> 8U);
  tuple[8] = (uint8_t)function->device_id;
  tuple[9] = function->class_code;
  tuple[10] = function->subclass;
  tuple[11] = function->prog_if;
}

pbns_status pbns_inventory_pci_add(
    pbns_inventory_pci_collector *collector,
    const pbns_inventory_pci_function *function) {
  if (collector == NULL || function == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (function->device > 31U || function->function > 7U) {
    return PBNS_ERR_FORMAT;
  }
  if (collector->function_count >= PBNS_INVENTORY_PCI_FUNCTION_MAX) {
    return PBNS_ERR_LIMIT;
  }
  uint8_t tuple[PBNS_INVENTORY_PCI_TUPLE_SIZE] = {0};
  encode_pci_tuple(function, tuple);
  size_t position = collector->function_count;
  while (position != 0U &&
         memcmp(tuple, collector->tuples[position - 1U], sizeof(tuple)) < 0) {
    memcpy(collector->tuples[position], collector->tuples[position - 1U],
           sizeof(tuple));
    --position;
  }
  memcpy(collector->tuples[position], tuple, sizeof(tuple));
  ++collector->function_count;
  return PBNS_OK;
}

pbns_status pbns_inventory_pci_finish(
    const pbns_inventory_pci_collector *collector, pbns_inventory_hash_fn hash,
    void *context, uint8_t digest[PBNS_INVENTORY_DIGEST_SIZE]) {
  if (collector == NULL || hash == NULL || digest == NULL ||
      collector->function_count > PBNS_INVENTORY_PCI_FUNCTION_MAX) {
    return PBNS_ERR_ARGUMENT;
  }
  return hash(context,
              (pbns_view){&collector->tuples[0U][0U],
                          collector->function_count *
                              PBNS_INVENTORY_PCI_TUPLE_SIZE},
              digest);
}

pbns_status pbns_inventory_storage_add(
    pbns_inventory_storage_collector *collector,
    const pbns_inventory_block_device *device) {
  if (collector == NULL || device == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (device->removable || device->logical_partition) {
    return PBNS_OK;
  }
  if (collector->count >= PBNS_INVENTORY_BLOCK_DEVICE_MAX) {
    return PBNS_ERR_LIMIT;
  }
  if (device->block_size == 0U || device->last_block == UINT64_MAX) {
    return PBNS_ERR_LIMIT;
  }
  const uint64_t block_count = device->last_block + 1U;
  if (block_count > UINT64_MAX / device->block_size) {
    return PBNS_ERR_LIMIT;
  }
  const uint64_t bytes = block_count * (uint64_t)device->block_size;
  if (bytes > UINT64_MAX - collector->total_bytes) {
    return PBNS_ERR_LIMIT;
  }
  collector->total_bytes += bytes;
  ++collector->count;
  return PBNS_OK;
}

pbns_status pbns_inventory_hash_variable(
    pbns_inventory_hash_parts_fn hash, void *context, bool present,
    uint32_t attributes, pbns_view variable,
    uint8_t digest[PBNS_INVENTORY_DIGEST_SIZE]) {
  static const uint8_t absent_domain[] =
      PBNS_INVENTORY_VARIABLE_ABSENT_DOMAIN;
  static const uint8_t present_domain[] =
      PBNS_INVENTORY_VARIABLE_PRESENT_DOMAIN;
  if (hash == NULL || digest == NULL || variable.len >
                                           PBNS_INVENTORY_VARIABLE_MAX_SIZE ||
      (variable.ptr == NULL && variable.len != 0U)) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!present) {
    if (attributes != 0U || variable.ptr != NULL || variable.len != 0U) {
      return PBNS_ERR_ARGUMENT;
    }
    const pbns_view parts[] = {
        {absent_domain, sizeof(absent_domain) - 1U},
    };
    return hash(context, parts, sizeof(parts) / sizeof(parts[0]), digest);
  }
  const uint64_t length = variable.len;
  const uint8_t metadata[12] = {
      (uint8_t)(attributes >> 24U), (uint8_t)(attributes >> 16U),
      (uint8_t)(attributes >> 8U),  (uint8_t)attributes,
      (uint8_t)(length >> 56U),     (uint8_t)(length >> 48U),
      (uint8_t)(length >> 40U),     (uint8_t)(length >> 32U),
      (uint8_t)(length >> 24U),     (uint8_t)(length >> 16U),
      (uint8_t)(length >> 8U),      (uint8_t)length,
  };
  const pbns_view parts[] = {
      {present_domain, sizeof(present_domain) - 1U},
      {metadata, sizeof(metadata)},
      variable,
  };
  return hash(context, parts, sizeof(parts) / sizeof(parts[0]), digest);
}

static void sort_u32(uint32_t *values, size_t count) {
  for (size_t index = 1U; index < count; ++index) {
    const uint32_t value = values[index];
    size_t position = index;
    while (position != 0U && values[position - 1U] > value) {
      values[position] = values[position - 1U];
      --position;
    }
    values[position] = value;
  }
}

static void sort_timings(pbns_inventory_timing *values, size_t count) {
  for (size_t index = 1U; index < count; ++index) {
    const pbns_inventory_timing value = values[index];
    size_t position = index;
    while (position != 0U && values[position - 1U].key > value.key) {
      values[position] = values[position - 1U];
      --position;
    }
    values[position] = value;
  }
}

pbns_status pbns_inventory_collect(const pbns_inventory_inputs *inputs,
                                   pbns_inventory_report *report) {
  if (inputs == NULL || report == NULL ||
      inputs->host_fingerprint.ptr == NULL ||
      inputs->host_fingerprint.len != PBNS_INVENTORY_DIGEST_SIZE ||
      !capability_valid(inputs->smbios_status) ||
      !capability_valid(inputs->pci_status) ||
      !capability_valid(inputs->storage_status) ||
      !capability_valid(inputs->secure_boot.status) ||
      !capability_valid(inputs->tpm.status) ||
      !pbns_inventory_text_is_normalized(&inputs->firmware_vendor) ||
      !pbns_inventory_text_is_normalized(&inputs->firmware_version) ||
      !pbns_inventory_text_is_normalized(&inputs->cpu_class) ||
      inputs->block_device_count > PBNS_INVENTORY_BLOCK_DEVICE_MAX ||
      inputs->timing_count > PBNS_INVENTORY_TIMING_MAX ||
      inputs->tpm.active_bank_count > PBNS_INVENTORY_TPM_BANK_MAX ||
      (inputs->timing_count != 0U && inputs->timings == NULL) ||
      (inputs->tpm.active_bank_count != 0U &&
       inputs->tpm.active_banks == NULL)) {
    return PBNS_ERR_ARGUMENT;
  }

  *report = (pbns_inventory_report){0};
  memcpy(report->host_fingerprint, inputs->host_fingerprint.ptr,
         PBNS_INVENTORY_DIGEST_SIZE);
  memcpy(report->board_model_digest, inputs->board_model_digest,
         PBNS_INVENTORY_DIGEST_SIZE);
  report->firmware_vendor = inputs->firmware_vendor;
  report->firmware_version = inputs->firmware_version;
  report->cpu_class = inputs->cpu_class;
  report->memory_mib = inputs->memory_mib;
  memcpy(report->pci_digest, inputs->pci_digest, PBNS_INVENTORY_DIGEST_SIZE);
  report->block_device_count = inputs->block_device_count;
  report->storage_capacity_gib = inputs->storage_capacity_gib;
  report->secure_boot = inputs->secure_boot.secure_boot;
  report->setup_mode = inputs->secure_boot.setup_mode;
  memcpy(report->db_digest, inputs->secure_boot.db_digest,
         PBNS_INVENTORY_DIGEST_SIZE);
  memcpy(report->dbx_digest, inputs->secure_boot.dbx_digest,
         PBNS_INVENTORY_DIGEST_SIZE);
  report->tpm_present = inputs->tpm.present;
  report->tpm_manufacturer = inputs->tpm.manufacturer;
  report->tpm_firmware_version = inputs->tpm.firmware_version;
  report->tpm_active_bank_count = inputs->tpm.active_bank_count;
  if (inputs->tpm.active_bank_count != 0U) {
    memcpy(report->tpm_active_banks, inputs->tpm.active_banks,
           inputs->tpm.active_bank_count * sizeof(inputs->tpm.active_banks[0]));
    sort_u32(report->tpm_active_banks, report->tpm_active_bank_count);
  }
  report->pbns_version = inputs->pbns_version;
  report->pico_version = inputs->pico_version;
  report->gateway_version = inputs->gateway_version;
  report->outcomes[0] = inputs->smbios_status;
  report->outcomes[1] = inputs->pci_status;
  report->outcomes[2] = inputs->storage_status;
  report->outcomes[3] = inputs->secure_boot.status;
  report->outcomes[4] = inputs->tpm.status;
  report->timing_count = inputs->timing_count;
  if (inputs->timing_count != 0U) {
    memcpy(report->timings, inputs->timings,
           inputs->timing_count * sizeof(inputs->timings[0]));
    sort_timings(report->timings, report->timing_count);
    for (size_t index = 0U; index < report->timing_count; ++index) {
      if (report->timings[index].key == 0U ||
          (index != 0U && report->timings[index - 1U].key ==
                              report->timings[index].key)) {
        *report = (pbns_inventory_report){0};
        return PBNS_ERR_ARGUMENT;
      }
    }
  }
  report->prior_loader_efi_status = inputs->prior_loader_efi_status;
  return PBNS_OK;
}

static bool report_valid(const pbns_inventory_report *report) {
  if (report == NULL ||
      !pbns_inventory_text_is_normalized(&report->firmware_vendor) ||
      !pbns_inventory_text_is_normalized(&report->firmware_version) ||
      !pbns_inventory_text_is_normalized(&report->cpu_class) ||
      report->block_device_count > PBNS_INVENTORY_BLOCK_DEVICE_MAX ||
      report->tpm_active_bank_count > PBNS_INVENTORY_TPM_BANK_MAX ||
      report->timing_count > PBNS_INVENTORY_TIMING_MAX) {
    return false;
  }
  for (size_t index = 0U; index < 5U; ++index) {
    if (!capability_valid(report->outcomes[index])) {
      return false;
    }
  }
  for (size_t index = 1U; index < report->tpm_active_bank_count; ++index) {
    if (report->tpm_active_banks[index - 1U] >
        report->tpm_active_banks[index]) {
      return false;
    }
  }
  for (size_t index = 0U; index < report->timing_count; ++index) {
    if (report->timings[index].key == 0U ||
        (index != 0U && report->timings[index - 1U].key >=
                            report->timings[index].key)) {
      return false;
    }
  }
  return true;
}

pbns_status pbns_inventory_encode(const pbns_inventory_report *report,
                                  pbns_buffer output, size_t *written) {
  if (!report_valid(report) || output.ptr == NULL || output.len != 0U ||
      output.cap == 0U || output.cap > PBNS_INVENTORY_ENCODED_MAX_SIZE ||
      written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  QCBOREncodeContext encoder;
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddBytesToMapN(
      &encoder, 1,
      (UsefulBufC){report->host_fingerprint, PBNS_INVENTORY_DIGEST_SIZE});
  QCBOREncode_AddBytesToMapN(
      &encoder, 2,
      (UsefulBufC){report->board_model_digest, PBNS_INVENTORY_DIGEST_SIZE});
  QCBOREncode_AddTextToMapN(
      &encoder, 3,
      (UsefulBufC){report->firmware_vendor.bytes, report->firmware_vendor.len});
  QCBOREncode_AddTextToMapN(
      &encoder, 4,
      (UsefulBufC){report->firmware_version.bytes,
                   report->firmware_version.len});
  QCBOREncode_AddTextToMapN(
      &encoder, 5,
      (UsefulBufC){report->cpu_class.bytes, report->cpu_class.len});
  QCBOREncode_AddUInt64ToMapN(&encoder, 6, report->memory_mib);
  QCBOREncode_AddBytesToMapN(
      &encoder, 7,
      (UsefulBufC){report->pci_digest, PBNS_INVENTORY_DIGEST_SIZE});
  QCBOREncode_OpenMapInMapN(&encoder, 8);
  QCBOREncode_AddUInt64ToMapN(&encoder, 1, report->block_device_count);
  QCBOREncode_AddUInt64ToMapN(&encoder, 2, report->storage_capacity_gib);
  QCBOREncode_CloseMap(&encoder);
  QCBOREncode_AddBoolToMapN(&encoder, 9, report->secure_boot);
  QCBOREncode_AddBoolToMapN(&encoder, 10, report->setup_mode);
  QCBOREncode_AddBytesToMapN(
      &encoder, 11,
      (UsefulBufC){report->db_digest, PBNS_INVENTORY_DIGEST_SIZE});
  QCBOREncode_AddBytesToMapN(
      &encoder, 12,
      (UsefulBufC){report->dbx_digest, PBNS_INVENTORY_DIGEST_SIZE});
  QCBOREncode_OpenMapInMapN(&encoder, 13);
  QCBOREncode_AddBoolToMapN(&encoder, 1, report->tpm_present);
  QCBOREncode_AddUInt64ToMapN(&encoder, 2, report->tpm_manufacturer);
  QCBOREncode_AddUInt64ToMapN(&encoder, 3, report->tpm_firmware_version);
  QCBOREncode_OpenArrayInMapN(&encoder, 4);
  for (size_t index = 0U; index < report->tpm_active_bank_count; ++index) {
    QCBOREncode_AddUInt64(&encoder, report->tpm_active_banks[index]);
  }
  QCBOREncode_CloseArray(&encoder);
  QCBOREncode_CloseMap(&encoder);
  QCBOREncode_OpenMapInMapN(&encoder, 14);
  QCBOREncode_AddUInt64ToMapN(&encoder, 1, report->pbns_version);
  QCBOREncode_AddUInt64ToMapN(&encoder, 2, report->pico_version);
  QCBOREncode_AddUInt64ToMapN(&encoder, 3, report->gateway_version);
  QCBOREncode_CloseMap(&encoder);
  QCBOREncode_OpenMapInMapN(&encoder, 15);
  for (size_t index = 0U; index < 5U; ++index) {
    QCBOREncode_AddUInt64ToMapN(&encoder, (int64_t)(index + 1U),
                                (uint64_t)report->outcomes[index]);
  }
  QCBOREncode_CloseMap(&encoder);
  QCBOREncode_OpenMapInMapN(&encoder, 16);
  for (size_t index = 0U; index < report->timing_count; ++index) {
    QCBOREncode_AddUInt64ToMapN(&encoder, report->timings[index].key,
                                report->timings[index].microseconds);
  }
  QCBOREncode_CloseMap(&encoder);
  QCBOREncode_AddUInt64ToMapN(&encoder, 17,
                              report->prior_loader_efi_status);
  QCBOREncode_CloseMap(&encoder);

  UsefulBufC encoded = NULLUsefulBufC;
  const QCBORError error = QCBOREncode_Finish(&encoder, &encoded);
  if (error == QCBOR_ERR_BUFFER_TOO_SMALL) {
    return PBNS_ERR_LIMIT;
  }
  if (error != QCBOR_SUCCESS || encoded.ptr != output.ptr ||
      encoded.len == 0U || encoded.len > output.cap ||
      encoded.len > PBNS_INVENTORY_ENCODED_MAX_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  *written = encoded.len;
  return PBNS_OK;
}
