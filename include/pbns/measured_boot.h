#ifndef PBNS_MEASURED_BOOT_H
#define PBNS_MEASURED_BOOT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE                                  \
  ((size_t)4U * (size_t)1024U * (size_t)1024U)
#define PBNS_MEASURED_BOOT_ALGORITHM_MAX_COUNT 16U
#define PBNS_MEASURED_BOOT_SELECTION_MAX_COUNT 24U
#define PBNS_MEASURED_BOOT_DIGEST_SIZE 32U
#define PBNS_MEASURED_BOOT_CANONICAL_ITEM_SIZE 3U
#define PBNS_TPM_ALG_SHA256 UINT16_C(0x000b)

typedef struct pbns_measured_boot_summary {
  size_t event_count;
  size_t last_entry_offset;
  bool sha256_bank;
} pbns_measured_boot_summary;

typedef struct pbns_measured_boot_selection_item {
  uint16_t hash_algorithm;
  uint8_t pcr_index;
} pbns_measured_boot_selection_item;

typedef struct pbns_measured_boot_selection {
  const pbns_measured_boot_selection_item *items;
  size_t count;
} pbns_measured_boot_selection;

typedef struct pbns_measured_boot_pcr_value {
  pbns_measured_boot_selection_item selection;
  uint8_t digest[PBNS_MEASURED_BOOT_DIGEST_SIZE];
  size_t digest_size;
} pbns_measured_boot_pcr_value;

typedef struct pbns_measured_boot_pcr_snapshot {
  pbns_measured_boot_pcr_value values[PBNS_MEASURED_BOOT_SELECTION_MAX_COUNT];
  size_t count;
  uint32_t update_counter;
} pbns_measured_boot_pcr_snapshot;

typedef enum pbns_measured_boot_final_disposition {
  PBNS_MEASURED_BOOT_FINAL_NONE = 0,
  PBNS_MEASURED_BOOT_FINAL_APPEND = 1,
  PBNS_MEASURED_BOOT_FINAL_ALREADY_INCLUDED_EXACT = 2
} pbns_measured_boot_final_disposition;

typedef struct pbns_measured_boot_event_source {
  pbns_view base_log;
  pbns_view final_events_table;
  pbns_measured_boot_final_disposition final_disposition;
  bool truncated;
} pbns_measured_boot_event_source;

typedef bool (*pbns_measured_boot_policy_fn)(
    void *context, pbns_measured_boot_selection selection);
typedef pbns_status (*pbns_measured_boot_event_log_fn)(
    void *context, pbns_measured_boot_event_source *source);
typedef pbns_status (*pbns_measured_boot_pcr_read_fn)(
    void *context, pbns_measured_boot_selection selection,
    pbns_measured_boot_pcr_snapshot *snapshot);
typedef pbns_status (*pbns_measured_boot_sha256_fn)(
    void *context, pbns_view input,
    uint8_t digest[PBNS_MEASURED_BOOT_DIGEST_SIZE]);

typedef struct pbns_measured_boot_capture_input {
  pbns_measured_boot_selection selection;
  pbns_measured_boot_event_log_fn event_log_read;
  pbns_measured_boot_pcr_read_fn pcr_read;
  pbns_measured_boot_sha256_fn sha256;
  pbns_measured_boot_policy_fn policy_allows;
  void *context;
  void *policy_context;
} pbns_measured_boot_capture_input;

typedef struct pbns_measured_boot_evidence {
  pbns_view event_log;
  uint8_t event_log_digest[PBNS_MEASURED_BOOT_DIGEST_SIZE];
  uint8_t selection_digest[PBNS_MEASURED_BOOT_DIGEST_SIZE];
  pbns_measured_boot_pcr_value pcrs[PBNS_MEASURED_BOOT_SELECTION_MAX_COUNT];
  size_t pcr_count;
  size_t event_count;
  uint32_t pcr_update_counter;
  uint64_t event_log_capture_ms;
  uint64_t pcr_read_ms;
} pbns_measured_boot_evidence;

pbns_status
pbns_measured_boot_validate_event_log(pbns_view event_log,
                                      pbns_measured_boot_summary *summary);
pbns_status pbns_measured_boot_locate_event_log_end(pbns_view bounded_log,
                                                    size_t last_entry_offset,
                                                    size_t *event_log_size);
pbns_status pbns_measured_boot_locate_final_events_end(
    pbns_view base_log, pbns_view bounded_final_events_table,
    size_t *final_events_table_size);
pbns_status pbns_measured_boot_final_events_exact_suffix(
    pbns_view base_log, pbns_view final_events_table, bool *exact_suffix);
pbns_status pbns_measured_boot_check_pcr_stability(
    pbns_view first, uint32_t first_update_counter, pbns_view second,
    uint32_t second_update_counter);
pbns_status pbns_measured_boot_validate_selection(
    pbns_measured_boot_selection selection,
    pbns_measured_boot_policy_fn policy_allows, void *policy_context);
pbns_status pbns_measured_boot_encode_canonical_selection(
    pbns_measured_boot_selection selection, pbns_buffer output,
    size_t *written);
pbns_status pbns_measured_boot_capture_evidence(
    const pbns_measured_boot_capture_input *input, pbns_buffer arena,
    pbns_measured_boot_evidence *evidence);

#endif
