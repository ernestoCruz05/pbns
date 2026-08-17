#include "pbns/measured_boot.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define PBNS_TCG_LEGACY_HEADER_SIZE 32U
#define PBNS_TCG_SPEC_FIXED_SIZE 29U
#define PBNS_TCG_EVENT2_FIXED_SIZE 12U
#define PBNS_TCG_DIGEST_SIZE_MAX 64U
#define PBNS_TCG_EV_NO_ACTION UINT32_C(3)
#define PBNS_TCG_FINAL_EVENTS_HEADER_SIZE 16U
#define PBNS_TCG_FINAL_EVENTS_VERSION UINT64_C(1)
#define PBNS_BASELINE_PCR_SNAPSHOT_SIZE ((size_t)4U * (size_t)32U)

typedef struct pbns_log_cursor {
  pbns_view input;
  size_t offset;
} pbns_log_cursor;

typedef struct pbns_log_algorithm {
  uint16_t identifier;
  uint16_t digest_size;
} pbns_log_algorithm;

typedef struct pbns_parsed_log {
  pbns_log_algorithm algorithms[PBNS_MEASURED_BOOT_ALGORITHM_MAX_COUNT];
  size_t algorithm_count;
  size_t event_count;
  size_t last_entry_offset;
  bool sha256_bank;
} pbns_parsed_log;

static void secure_zero(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  while (bytes != NULL && length > 0U) {
    *bytes++ = 0U;
    --length;
  }
}

static void move_bytes(uint8_t *destination, const uint8_t *source,
                       size_t length) {
  const uintptr_t destination_address = (uintptr_t)destination;
  const uintptr_t source_address = (uintptr_t)source;
  if (destination_address > source_address &&
      destination_address - source_address < length) {
    while (length > 0U) {
      --length;
      destination[length] = source[length];
    }
    return;
  }
  for (size_t index = 0U; index < length; ++index) {
    destination[index] = source[index];
  }
}

static bool take(pbns_log_cursor *cursor, size_t length,
                 const uint8_t **value) {
  if (cursor == NULL || value == NULL || length > cursor->input.len ||
      cursor->offset > cursor->input.len - length) {
    return false;
  }
  *value = cursor->input.ptr + cursor->offset;
  cursor->offset += length;
  return true;
}

static uint16_t load_u16(const uint8_t *input) {
  return (uint16_t)((uint16_t)input[0] | ((uint16_t)input[1] << 8U));
}

static uint32_t load_u32(const uint8_t *input) {
  return (uint32_t)input[0] | ((uint32_t)input[1] << 8U) |
         ((uint32_t)input[2] << 16U) | ((uint32_t)input[3] << 24U);
}

static uint64_t load_u64(const uint8_t *input) {
  return (uint64_t)load_u32(input) | ((uint64_t)load_u32(input + 4U) << 32U);
}

static bool read_u16(pbns_log_cursor *cursor, uint16_t *value) {
  const uint8_t *encoded = NULL;
  if (value == NULL || !take(cursor, 2U, &encoded)) {
    return false;
  }
  *value = load_u16(encoded);
  return true;
}

static bool read_u32(pbns_log_cursor *cursor, uint32_t *value) {
  const uint8_t *encoded = NULL;
  if (value == NULL || !take(cursor, 4U, &encoded)) {
    return false;
  }
  *value = load_u32(encoded);
  return true;
}

static bool identifier_seen(size_t count, const uint16_t *identifiers,
                            uint16_t identifier) {
  for (size_t index = 0U; index < count; ++index) {
    if (identifiers[index] == identifier) {
      return true;
    }
  }
  return false;
}

static bool algorithm_size(size_t count, const pbns_log_algorithm *algorithms,
                           uint16_t identifier, uint16_t *digest_size) {
  for (size_t index = 0U; index < count; ++index) {
    if (algorithms[index].identifier == identifier) {
      *digest_size = algorithms[index].digest_size;
      return true;
    }
  }
  return false;
}

static bool parse_spec_id(pbns_view event, pbns_log_algorithm *algorithms,
                          size_t *algorithm_count, bool *sha256_bank) {
  static const uint8_t signature[16] = "Spec ID Event03";
  if (event.ptr == NULL || event.len < PBNS_TCG_SPEC_FIXED_SIZE ||
      algorithms == NULL || algorithm_count == NULL || sha256_bank == NULL ||
      memcmp(event.ptr, signature, sizeof(signature)) != 0) {
    return false;
  }
  pbns_log_cursor cursor = {.input = event, .offset = 16U};
  const uint8_t *fixed = NULL;
  if (!take(&cursor, 8U, &fixed) || fixed[5] != 2U ||
      (fixed[7] != 1U && fixed[7] != 2U)) {
    return false;
  }
  uint32_t count = 0U;
  if (!read_u32(&cursor, &count) || count == 0U ||
      count > PBNS_MEASURED_BOOT_ALGORITHM_MAX_COUNT) {
    return false;
  }
  bool found_sha256 = false;
  for (uint32_t index = 0U; index < count; ++index) {
    uint16_t identifier = 0U;
    uint16_t digest_size = 0U;
    uint16_t ignored_size = 0U;
    if (!read_u16(&cursor, &identifier) || !read_u16(&cursor, &digest_size) ||
        digest_size == 0U || digest_size > PBNS_TCG_DIGEST_SIZE_MAX ||
        (identifier == UINT16_C(0x0004) && digest_size != 20U) ||
        (identifier == PBNS_TPM_ALG_SHA256 && digest_size != 32U) ||
        (identifier == UINT16_C(0x000c) && digest_size != 48U) ||
        (identifier == UINT16_C(0x000d) && digest_size != 64U) ||
        algorithm_size((size_t)index, algorithms, identifier, &ignored_size)) {
      return false;
    }
    algorithms[index] = (pbns_log_algorithm){identifier, digest_size};
    found_sha256 = found_sha256 ||
                   (identifier == PBNS_TPM_ALG_SHA256 && digest_size == 32U);
  }
  const uint8_t *vendor_size = NULL;
  const uint8_t *ignored = NULL;
  if (!take(&cursor, 1U, &vendor_size) ||
      !take(&cursor, vendor_size[0], &ignored) || cursor.offset != event.len) {
    return false;
  }
  *algorithm_count = (size_t)count;
  *sha256_bank = found_sha256;
  return true;
}

static bool parse_event2(pbns_log_cursor *cursor,
                         const pbns_log_algorithm *algorithms,
                         size_t algorithm_count) {
  const uint8_t *event_header = NULL;
  if (!take(cursor, PBNS_TCG_EVENT2_FIXED_SIZE, &event_header)) {
    return false;
  }
  const uint32_t digest_count = load_u32(event_header + 8U);
  if (load_u32(event_header) >= 24U || digest_count == 0U ||
      digest_count > PBNS_MEASURED_BOOT_ALGORITHM_MAX_COUNT) {
    return false;
  }
  uint16_t seen[PBNS_MEASURED_BOOT_ALGORITHM_MAX_COUNT] = {0};
  bool found_sha256 = false;
  for (uint32_t index = 0U; index < digest_count; ++index) {
    uint16_t identifier = 0U;
    uint16_t digest_size = 0U;
    const uint8_t *digest = NULL;
    if (!read_u16(cursor, &identifier) ||
        identifier_seen((size_t)index, seen, identifier) ||
        !algorithm_size(algorithm_count, algorithms, identifier,
                        &digest_size) ||
        !take(cursor, digest_size, &digest)) {
      return false;
    }
    seen[index] = identifier;
    found_sha256 = found_sha256 ||
                   (identifier == PBNS_TPM_ALG_SHA256 && digest_size == 32U);
  }
  uint32_t event_size = 0U;
  const uint8_t *event = NULL;
  return found_sha256 && read_u32(cursor, &event_size) &&
         take(cursor, event_size, &event);
}

static pbns_status parse_header(pbns_view event_log, pbns_log_cursor *cursor,
                                pbns_parsed_log *parsed) {
  const uint8_t *legacy = NULL;
  if (!take(cursor, PBNS_TCG_LEGACY_HEADER_SIZE, &legacy) ||
      load_u32(legacy) != 0U ||
      load_u32(legacy + 4U) != PBNS_TCG_EV_NO_ACTION) {
    return PBNS_ERR_FORMAT;
  }
  const uint32_t spec_size = load_u32(legacy + 28U);
  const uint8_t *spec = NULL;
  if (!take(cursor, spec_size, &spec) ||
      !parse_spec_id((pbns_view){spec, spec_size}, parsed->algorithms,
                     &parsed->algorithm_count, &parsed->sha256_bank) ||
      cursor->offset > event_log.len) {
    return PBNS_ERR_FORMAT;
  }
  return parsed->sha256_bank ? PBNS_OK : PBNS_ERR_UNSUPPORTED;
}

static pbns_status parse_log(pbns_view event_log, pbns_parsed_log *parsed) {
  *parsed = (pbns_parsed_log){0};
  if (event_log.ptr == NULL || event_log.len == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  if (event_log.len > PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE) {
    return PBNS_ERR_LIMIT;
  }
  pbns_log_cursor cursor = {.input = event_log, .offset = 0U};
  pbns_status status = parse_header(event_log, &cursor, parsed);
  if (status != PBNS_OK) {
    return status;
  }
  parsed->event_count = 1U;
  while (cursor.offset < event_log.len) {
    const size_t entry_offset = cursor.offset;
    if (!parse_event2(&cursor, parsed->algorithms, parsed->algorithm_count)) {
      return PBNS_ERR_FORMAT;
    }
    parsed->last_entry_offset = entry_offset;
    ++parsed->event_count;
  }
  return parsed->event_count >= 2U ? PBNS_OK : PBNS_ERR_FORMAT;
}

pbns_status
pbns_measured_boot_validate_event_log(pbns_view event_log,
                                      pbns_measured_boot_summary *summary) {
  if (summary == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *summary = (pbns_measured_boot_summary){0};
  pbns_parsed_log parsed = {0};
  const pbns_status status = parse_log(event_log, &parsed);
  if (status != PBNS_OK) {
    return status;
  }
  *summary = (pbns_measured_boot_summary){
      .event_count = parsed.event_count,
      .last_entry_offset = parsed.last_entry_offset,
      .sha256_bank = parsed.sha256_bank,
  };
  return PBNS_OK;
}

pbns_status pbns_measured_boot_check_pcr_stability(
    pbns_view first, uint32_t first_update_counter, pbns_view second,
    uint32_t second_update_counter) {
  if (first.ptr == NULL || second.ptr == NULL ||
      first.len != PBNS_BASELINE_PCR_SNAPSHOT_SIZE ||
      second.len != PBNS_BASELINE_PCR_SNAPSHOT_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  return first_update_counter == second_update_counter &&
                 memcmp(first.ptr, second.ptr, first.len) == 0
             ? PBNS_OK
             : PBNS_ERR_BUSY;
}

pbns_status pbns_measured_boot_locate_event_log_end(pbns_view bounded_log,
                                                    size_t last_entry_offset,
                                                    size_t *event_log_size) {
  if (bounded_log.ptr == NULL || bounded_log.len == 0U ||
      bounded_log.len > PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE ||
      event_log_size == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *event_log_size = 0U;
  pbns_parsed_log parsed = {0};
  pbns_log_cursor cursor = {.input = bounded_log, .offset = 0U};
  const pbns_status header_status = parse_header(bounded_log, &cursor, &parsed);
  if (header_status != PBNS_OK || last_entry_offset < cursor.offset) {
    return header_status == PBNS_ERR_UNSUPPORTED ? header_status
                                                 : PBNS_ERR_FORMAT;
  }
  while (cursor.offset <= last_entry_offset) {
    const size_t entry_offset = cursor.offset;
    if (!parse_event2(&cursor, parsed.algorithms, parsed.algorithm_count)) {
      return PBNS_ERR_FORMAT;
    }
    if (entry_offset == last_entry_offset) {
      *event_log_size = cursor.offset;
      return PBNS_OK;
    }
    if (entry_offset > last_entry_offset) {
      return PBNS_ERR_FORMAT;
    }
  }
  return PBNS_ERR_FORMAT;
}

static pbns_status selection_structure(pbns_measured_boot_selection selection) {
  if (selection.items == NULL || selection.count == 0U ||
      selection.count > PBNS_MEASURED_BOOT_SELECTION_MAX_COUNT) {
    return PBNS_ERR_ARGUMENT;
  }
  for (size_t index = 0U; index < selection.count; ++index) {
    const pbns_measured_boot_selection_item item = selection.items[index];
    if (item.hash_algorithm != PBNS_TPM_ALG_SHA256) {
      return PBNS_ERR_UNSUPPORTED;
    }
    if (item.pcr_index >= 24U) {
      return PBNS_ERR_ARGUMENT;
    }
    if (index > 0U) {
      const pbns_measured_boot_selection_item previous =
          selection.items[index - 1U];
      if (previous.hash_algorithm > item.hash_algorithm ||
          (previous.hash_algorithm == item.hash_algorithm &&
           previous.pcr_index >= item.pcr_index)) {
        return PBNS_ERR_FORMAT;
      }
    }
  }
  return PBNS_OK;
}

pbns_status pbns_measured_boot_validate_selection(
    pbns_measured_boot_selection selection,
    pbns_measured_boot_policy_fn policy_allows, void *policy_context) {
  if (policy_allows == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status status = selection_structure(selection);
  if (status != PBNS_OK) {
    return status;
  }
  return policy_allows(policy_context, selection) ? PBNS_OK
                                                   : PBNS_ERR_AUTHENTICATION;
}

pbns_status pbns_measured_boot_encode_canonical_selection(
    pbns_measured_boot_selection selection, pbns_buffer output,
    size_t *written) {
  if (written == NULL || output.ptr == NULL || output.len != 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  const pbns_status status = selection_structure(selection);
  if (status != PBNS_OK) {
    return status;
  }
  const size_t required =
      selection.count * PBNS_MEASURED_BOOT_CANONICAL_ITEM_SIZE;
  if (output.cap < required) {
    return PBNS_ERR_LIMIT;
  }
  for (size_t index = 0U; index < selection.count; ++index) {
    const size_t offset = index * PBNS_MEASURED_BOOT_CANONICAL_ITEM_SIZE;
    output.ptr[offset] =
        (uint8_t)(selection.items[index].hash_algorithm >> 8U);
    output.ptr[offset + 1U] =
        (uint8_t)selection.items[index].hash_algorithm;
    output.ptr[offset + 2U] = selection.items[index].pcr_index;
  }
  *written = required;
  return PBNS_OK;
}

static pbns_status parse_final_events_bounded(
    pbns_view table, const pbns_parsed_log *base, bool require_exact,
    pbns_view *events, size_t *event_count, size_t *table_size) {
  *events = (pbns_view){0};
  *event_count = 0U;
  *table_size = 0U;
  if (table.len == 0U) {
    return table.ptr == NULL ? PBNS_OK : PBNS_ERR_ARGUMENT;
  }
  if (table.ptr == NULL || table.len < PBNS_TCG_FINAL_EVENTS_HEADER_SIZE ||
      table.len > PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE +
                      PBNS_TCG_FINAL_EVENTS_HEADER_SIZE ||
      load_u64(table.ptr) != PBNS_TCG_FINAL_EVENTS_VERSION) {
    return PBNS_ERR_FORMAT;
  }
  const uint64_t count = load_u64(table.ptr + 8U);
  if (count > (uint64_t)PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE) {
    return PBNS_ERR_LIMIT;
  }
  pbns_log_cursor cursor = {
      .input = {table.ptr + PBNS_TCG_FINAL_EVENTS_HEADER_SIZE,
                table.len - PBNS_TCG_FINAL_EVENTS_HEADER_SIZE},
      .offset = 0U,
  };
  for (uint64_t index = 0U; index < count; ++index) {
    if (!parse_event2(&cursor, base->algorithms, base->algorithm_count)) {
      return PBNS_ERR_FORMAT;
    }
  }
  if (require_exact && cursor.offset != cursor.input.len) {
    return PBNS_ERR_FORMAT;
  }
  *events = (pbns_view){cursor.input.ptr, cursor.offset};
  *event_count = (size_t)count;
  *table_size = PBNS_TCG_FINAL_EVENTS_HEADER_SIZE + cursor.offset;
  return PBNS_OK;
}

pbns_status pbns_measured_boot_final_events_exact_suffix(
    pbns_view base_log, pbns_view final_events_table, bool *exact_suffix) {
  if (exact_suffix == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *exact_suffix = false;
  pbns_parsed_log base = {0};
  pbns_status status = parse_log(base_log, &base);
  if (status != PBNS_OK) {
    return status;
  }
  pbns_view final_events = {0};
  size_t final_count = 0U;
  size_t table_size = 0U;
  status = parse_final_events_bounded(final_events_table, &base, true,
                                      &final_events, &final_count, &table_size);
  if (status != PBNS_OK) {
    return status;
  }
  if (final_count == 0U || final_events.len > base_log.len) {
    return PBNS_OK;
  }
  const uintptr_t base_start = (uintptr_t)base_log.ptr;
  const uintptr_t final_start = (uintptr_t)final_events.ptr;
  if (base_log.len > UINTPTR_MAX - base_start ||
      final_events.len > UINTPTR_MAX - final_start ||
      final_start != base_start + base_log.len - final_events.len) {
    return PBNS_OK;
  }
  pbns_log_cursor cursor = {.input = base_log, .offset = 0U};
  status = parse_header(base_log, &cursor, &base);
  if (status != PBNS_OK) {
    return status;
  }
  const size_t suffix_start = base_log.len - final_events.len;
  bool boundary_seen = false;
  size_t suffix_count = 0U;
  while (cursor.offset < base_log.len) {
    const size_t event_offset = cursor.offset;
    if (!boundary_seen && event_offset == suffix_start) {
      boundary_seen = true;
    } else if (!boundary_seen && event_offset > suffix_start) {
      return PBNS_OK;
    }
    if (!parse_event2(&cursor, base.algorithms, base.algorithm_count)) {
      return PBNS_ERR_FORMAT;
    }
    if (boundary_seen) {
      ++suffix_count;
    }
  }
  *exact_suffix = boundary_seen && suffix_count == final_count;
  (void)table_size;
  return PBNS_OK;
}

pbns_status pbns_measured_boot_locate_final_events_end(
    pbns_view base_log, pbns_view bounded_final_events_table,
    size_t *final_events_table_size) {
  if (final_events_table_size == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *final_events_table_size = 0U;
  pbns_parsed_log base = {0};
  pbns_status status = parse_log(base_log, &base);
  if (status != PBNS_OK) {
    return status;
  }
  pbns_view events = {0};
  size_t event_count = 0U;
  return parse_final_events_bounded(bounded_final_events_table, &base, false,
                                    &events, &event_count,
                                    final_events_table_size);
}

static bool same_selection(pbns_measured_boot_selection_item left,
                           pbns_measured_boot_selection_item right) {
  return left.hash_algorithm == right.hash_algorithm &&
         left.pcr_index == right.pcr_index;
}

static pbns_status validate_snapshot(
    const pbns_measured_boot_pcr_snapshot *snapshot,
    pbns_measured_boot_selection selection) {
  if (snapshot->count != selection.count) {
    return PBNS_ERR_FORMAT;
  }
  for (size_t index = 0U; index < selection.count; ++index) {
    if (!same_selection(snapshot->values[index].selection,
                        selection.items[index]) ||
        snapshot->values[index].digest_size !=
            PBNS_MEASURED_BOOT_DIGEST_SIZE) {
      return PBNS_ERR_FORMAT;
    }
  }
  return PBNS_OK;
}

static pbns_status read_snapshot(
    const pbns_measured_boot_capture_input *input,
    pbns_measured_boot_pcr_snapshot *snapshot, bool *retry_used) {
  pbns_status status =
      input->pcr_read(input->context, input->selection, snapshot);
  if (status == PBNS_ERR_BUSY && !*retry_used) {
    *retry_used = true;
    secure_zero(snapshot, sizeof(*snapshot));
    status = input->pcr_read(input->context, input->selection, snapshot);
  }
  if (status != PBNS_OK) {
    secure_zero(snapshot, sizeof(*snapshot));
    return status;
  }
  return validate_snapshot(snapshot, input->selection);
}

static bool snapshots_equal(const pbns_measured_boot_pcr_snapshot *left,
                            const pbns_measured_boot_pcr_snapshot *right) {
  if (left->count != right->count ||
      left->update_counter != right->update_counter) {
    return false;
  }
  for (size_t index = 0U; index < left->count; ++index) {
    if (!same_selection(left->values[index].selection,
                        right->values[index].selection) ||
        left->values[index].digest_size != right->values[index].digest_size ||
        memcmp(left->values[index].digest, right->values[index].digest,
               PBNS_MEASURED_BOOT_DIGEST_SIZE) != 0) {
      return false;
    }
  }
  return true;
}

static bool range_valid(const uint8_t *pointer, size_t length) {
  return pointer != NULL && length <= UINTPTR_MAX - (uintptr_t)pointer;
}

static bool ranges_overlap(const uint8_t *left, size_t left_length,
                           const uint8_t *right, size_t right_length) {
  if (left_length == 0U || right_length == 0U) {
    return false;
  }
  const uintptr_t left_start = (uintptr_t)left;
  const uintptr_t right_start = (uintptr_t)right;
  return left_start < right_start + right_length &&
         right_start < left_start + left_length;
}

static pbns_status capture_fail(pbns_buffer arena, size_t copied,
                                pbns_measured_boot_evidence *evidence,
                                pbns_measured_boot_pcr_snapshot *first,
                                pbns_measured_boot_pcr_snapshot *second,
                                pbns_status status) {
  if (arena.ptr != NULL && copied <= arena.cap) {
    secure_zero(arena.ptr, copied);
  }
  if (first != NULL) {
    secure_zero(first, sizeof(*first));
  }
  if (second != NULL) {
    secure_zero(second, sizeof(*second));
  }
  if (evidence != NULL) {
    *evidence = (pbns_measured_boot_evidence){0};
  }
  return status;
}

pbns_status pbns_measured_boot_capture_evidence(
    const pbns_measured_boot_capture_input *input, pbns_buffer arena,
    pbns_measured_boot_evidence *evidence) {
  if (evidence != NULL) {
    *evidence = (pbns_measured_boot_evidence){0};
  }
  if (input == NULL || evidence == NULL || arena.ptr == NULL ||
      arena.len != 0U || arena.cap == 0U || !range_valid(arena.ptr, arena.cap) ||
      input->event_log_read == NULL || input->pcr_read == NULL ||
      input->sha256 == NULL || input->policy_allows == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_status status = pbns_measured_boot_validate_selection(
      input->selection, input->policy_allows, input->policy_context);
  if (status != PBNS_OK) {
    return capture_fail(arena, arena.cap, evidence, NULL, NULL, status);
  }
  pbns_measured_boot_event_source source = {0};
  status = input->event_log_read(input->context, &source);
  if (status != PBNS_OK) {
    return capture_fail(arena, arena.cap, evidence, NULL, NULL, status);
  }
  if (source.truncated) {
    return capture_fail(arena, arena.cap, evidence, NULL, NULL,
                        PBNS_ERR_LIMIT);
  }
  const bool no_final =
      source.final_disposition == PBNS_MEASURED_BOOT_FINAL_NONE;
  const bool has_final =
      source.final_disposition == PBNS_MEASURED_BOOT_FINAL_APPEND ||
      source.final_disposition ==
          PBNS_MEASURED_BOOT_FINAL_ALREADY_INCLUDED_EXACT;
  if ((!no_final && !has_final) ||
      (no_final &&
       (source.final_events_table.ptr != NULL ||
        source.final_events_table.len != 0U)) ||
      (has_final && (source.final_events_table.ptr == NULL ||
                     source.final_events_table.len == 0U)) ||
      !range_valid(source.base_log.ptr, source.base_log.len) ||
      (has_final && !range_valid(source.final_events_table.ptr,
                                 source.final_events_table.len)) ||
      ranges_overlap(arena.ptr, arena.cap, source.base_log.ptr,
                     source.base_log.len) ||
      (has_final &&
       ranges_overlap(arena.ptr, arena.cap, source.final_events_table.ptr,
                      source.final_events_table.len))) {
    return capture_fail(arena, arena.cap, evidence, NULL, NULL,
                        PBNS_ERR_FORMAT);
  }
  pbns_parsed_log base = {0};
  status = parse_log(source.base_log, &base);
  if (status != PBNS_OK) {
    return capture_fail(arena, arena.cap, evidence, NULL, NULL, status);
  }
  pbns_view final_events = {0};
  size_t final_count = 0U;
  size_t final_table_size = 0U;
  if (has_final) {
    status = parse_final_events_bounded(source.final_events_table, &base, true,
                                        &final_events, &final_count,
                                        &final_table_size);
  }
  if (status != PBNS_OK) {
    return capture_fail(arena, arena.cap, evidence, NULL, NULL, status);
  }
  const size_t append_size =
      source.final_disposition == PBNS_MEASURED_BOOT_FINAL_APPEND
          ? final_events.len
          : 0U;
  if (append_size > PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE -
                        source.base_log.len ||
      source.base_log.len + append_size > arena.cap) {
    return capture_fail(arena, arena.cap, evidence, NULL, NULL,
                        PBNS_ERR_LIMIT);
  }
  move_bytes(arena.ptr, source.base_log.ptr, source.base_log.len);
  if (append_size != 0U) {
    move_bytes(arena.ptr + source.base_log.len, final_events.ptr, append_size);
  }
  const size_t complete_size = source.base_log.len + append_size;
  pbns_measured_boot_summary complete = {0};
  status = pbns_measured_boot_validate_event_log(
      (pbns_view){arena.ptr, complete_size}, &complete);
  if (status != PBNS_OK) {
    return capture_fail(arena, complete_size, evidence, NULL, NULL, status);
  }

  uint8_t canonical[PBNS_MEASURED_BOOT_SELECTION_MAX_COUNT *
                    PBNS_MEASURED_BOOT_CANONICAL_ITEM_SIZE] = {0};
  size_t canonical_size = 0U;
  status = pbns_measured_boot_encode_canonical_selection(
      input->selection, (pbns_buffer){canonical, 0U, sizeof(canonical)},
      &canonical_size);
  if (status == PBNS_OK) {
    status = input->sha256(
        input->context, (pbns_view){arena.ptr, complete_size},
        evidence->event_log_digest);
  }
  if (status == PBNS_OK) {
    status = input->sha256(input->context,
                           (pbns_view){canonical, canonical_size},
                           evidence->selection_digest);
  }
  secure_zero(canonical, sizeof(canonical));
  if (status != PBNS_OK) {
    return capture_fail(arena, complete_size, evidence, NULL, NULL, status);
  }

  pbns_measured_boot_pcr_snapshot first = {0};
  pbns_measured_boot_pcr_snapshot second = {0};
  bool retry_used = false;
  status = read_snapshot(input, &first, &retry_used);
  if (status == PBNS_OK) {
    status = read_snapshot(input, &second, &retry_used);
  }
  if (status != PBNS_OK) {
    return capture_fail(arena, complete_size, evidence, &first, &second,
                        status);
  }
  if (!snapshots_equal(&first, &second)) {
    secure_zero(&first, sizeof(first));
    first = second;
    second = (pbns_measured_boot_pcr_snapshot){0};
    status = read_snapshot(input, &second, &retry_used);
    if (status != PBNS_OK || !snapshots_equal(&first, &second)) {
      return capture_fail(arena, complete_size, evidence, &first, &second,
                          status == PBNS_OK ? PBNS_ERR_BUSY : status);
    }
  }

  evidence->event_log = (pbns_view){arena.ptr, complete_size};
  evidence->event_count = complete.event_count;
  evidence->pcr_count = second.count;
  evidence->pcr_update_counter = second.update_counter;
  memcpy(evidence->pcrs, second.values,
         second.count * sizeof(second.values[0]));
  secure_zero(&first, sizeof(first));
  secure_zero(&second, sizeof(second));
  (void)final_count;
  (void)final_table_size;
  return PBNS_OK;
}
