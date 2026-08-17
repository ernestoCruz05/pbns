#ifndef PBNS_ENROLLMENT_BASELINE_H
#define PBNS_ENROLLMENT_BASELINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_BASELINE_DOMAIN "PBNS-ENROLLMENT-BASELINE-v1"
#define PBNS_BASELINE_DIGEST_SIZE 32U
#define PBNS_BASELINE_PCR_COUNT 4U

typedef struct pbns_baseline_pcr {
  uint8_t index;
  uint8_t digest[PBNS_BASELINE_DIGEST_SIZE];
} pbns_baseline_pcr;

typedef struct pbns_enrollment_baseline {
  uint8_t firmware_vendor_digest[PBNS_BASELINE_DIGEST_SIZE];
  uint8_t firmware_version_digest[PBNS_BASELINE_DIGEST_SIZE];
  bool secure_boot;
  bool setup_mode;
  uint8_t db_digest[PBNS_BASELINE_DIGEST_SIZE];
  uint8_t dbx_digest[PBNS_BASELINE_DIGEST_SIZE];
  pbns_baseline_pcr pcrs[PBNS_BASELINE_PCR_COUNT];
  pbns_view event_log;
  uint8_t event_log_digest[PBNS_BASELINE_DIGEST_SIZE];
} pbns_enrollment_baseline;

pbns_status
pbns_enrollment_baseline_encode(const pbns_enrollment_baseline *baseline,
                                pbns_buffer output, size_t *written);

#endif
