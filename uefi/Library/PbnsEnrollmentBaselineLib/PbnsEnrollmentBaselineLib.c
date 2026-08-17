#include <Uefi.h>

#include <Library/BaseMemoryLib.h>
#include <Library/PbnsEnrollmentBaselineLib.h>
#include <Library/PbnsMeasuredBootLib.h>
#include <Library/PbnsUefiPlatformLib.h>
#include <PbnsInventoryLib.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mbedtls/sha256.h"
#include "pbns/controlled_baseline.h"
#include "pbns/measured_boot.h"

static bool hash_all(const void *input, size_t length, uint8_t digest[32]) {
  return input != NULL && digest != NULL &&
         mbedtls_sha256(input, length, digest, 0) == 0;
}

static pbns_status hash_parts(void *context, const pbns_view *parts,
                              size_t part_count, uint8_t digest[32]) {
  (void)context;
  if (parts == NULL || part_count == 0U || digest == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  mbedtls_sha256_context hash;
  mbedtls_sha256_init(&hash);
  bool hash_ok = mbedtls_sha256_starts(&hash, 0) == 0;
  for (size_t index = 0U; hash_ok && index < part_count; ++index) {
    hash_ok =
        (parts[index].ptr != NULL || parts[index].len == 0U) &&
        (parts[index].len == 0U ||
         mbedtls_sha256_update(&hash, parts[index].ptr, parts[index].len) == 0);
  }
  hash_ok = hash_ok && mbedtls_sha256_finish(&hash, digest) == 0;
  mbedtls_sha256_free(&hash);
  if (!hash_ok) {
    ZeroMem(digest, 32U);
  }
  return hash_ok ? PBNS_OK : PBNS_ERR_CRYPTO;
}

EFI_STATUS EFIAPI PbnsEnrollmentBaselineCapture(
    EFI_SYSTEM_TABLE *SystemTable, pbns_view host_fingerprint,
    pbns_buffer event_log_buffer, pbns_buffer variable_scratch,
    pbns_buffer encoded_baseline, size_t *EncodedSize,
    uint8_t BaselineDigest[32], size_t *EventCount, uint32_t *PcrUpdateCounter,
    PBNS_ENROLLMENT_BASELINE_TIMINGS *Timings) {
  if (SystemTable == NULL || SystemTable->BootServices == NULL ||
      SystemTable->RuntimeServices == NULL || host_fingerprint.ptr == NULL ||
      host_fingerprint.len != PBNS_INVENTORY_DIGEST_SIZE ||
      event_log_buffer.ptr == NULL || event_log_buffer.len != 0U ||
      event_log_buffer.cap < PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE ||
      variable_scratch.ptr == NULL || variable_scratch.len != 0U ||
      variable_scratch.cap == 0U ||
      variable_scratch.cap > PBNS_BASELINE_VARIABLE_SCRATCH_MAX_SIZE ||
      encoded_baseline.ptr == NULL || encoded_baseline.len != 0U ||
      encoded_baseline.cap == 0U || EncodedSize == NULL ||
      BaselineDigest == NULL || EventCount == NULL ||
      PcrUpdateCounter == NULL || Timings == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *EncodedSize = 0U;
  *EventCount = 0U;
  *PcrUpdateCounter = 0U;
  *Timings = (PBNS_ENROLLMENT_BASELINE_TIMINGS){0};
  ZeroMem(BaselineDigest, 32U);

  pbns_measured_boot_capture measured = {0};
  EFI_STATUS status = PbnsMeasuredBootCapture(SystemTable->BootServices,
                                              event_log_buffer, &measured);
  if (EFI_ERROR(status)) {
    return status;
  }
  Timings->EventLogCaptureMs = measured.EventLogCaptureMs;
  Timings->PcrReadMs = measured.PcrReadMs;
  UINT64 hashing_start_ms = 0U;
  UINT64 hashing_end_ms = 0U;
  status = PbnsUefiMonotonicMs(SystemTable->BootServices, &hashing_start_ms);
  if (EFI_ERROR(status)) {
    ZeroMem(event_log_buffer.ptr, measured.event_log_size);
    return status;
  }
  pbns_inventory_report inventory = {0};
  const PBNS_INVENTORY_CONFIGURATION configuration = {
      .HostFingerprint = host_fingerprint,
      .VariableScratch = variable_scratch,
      .PbnsVersion = 1U,
      .PicoVersion = 1U,
      .GatewayVersion = 1U,
      .PriorLoaderEfiStatus = 0U,
  };
  status = PbnsInventoryCapture(SystemTable, &configuration, &inventory);
  uint8_t measurement_digest[32] = {0};
  if (!EFI_ERROR(status) &&
      !hash_all(event_log_buffer.ptr, measured.event_log_size,
                measurement_digest)) {
    status = EFI_COMPROMISED_DATA;
  }
  pbns_controlled_baseline baseline = {0};
  if (!EFI_ERROR(status) && pbns_controlled_baseline_from_inventory(
                                measurement_digest, &inventory, hash_parts,
                                NULL, &baseline) != PBNS_OK) {
    status = EFI_COMPROMISED_DATA;
  }
  if (EFI_ERROR(status)) {
    ZeroMem(event_log_buffer.ptr, measured.event_log_size);
    ZeroMem(measurement_digest, sizeof(measurement_digest));
    ZeroMem(&inventory, sizeof(inventory));
    ZeroMem(&baseline, sizeof(baseline));
    return status;
  }
  status = PbnsUefiMonotonicMs(SystemTable->BootServices, &hashing_end_ms);
  if (EFI_ERROR(status) || hashing_end_ms < hashing_start_ms) {
    ZeroMem(event_log_buffer.ptr, measured.event_log_size);
    ZeroMem(measurement_digest, sizeof(measurement_digest));
    ZeroMem(&inventory, sizeof(inventory));
    ZeroMem(&baseline, sizeof(baseline));
    return EFI_COMPROMISED_DATA;
  }
  Timings->HashingMs = hashing_end_ms - hashing_start_ms;
  UINT64 encoding_start_ms = 0U;
  UINT64 encoding_end_ms = 0U;
  status = PbnsUefiMonotonicMs(SystemTable->BootServices, &encoding_start_ms);
  if (EFI_ERROR(status)) {
    ZeroMem(event_log_buffer.ptr, measured.event_log_size);
    ZeroMem(measurement_digest, sizeof(measurement_digest));
    ZeroMem(&inventory, sizeof(inventory));
    ZeroMem(&baseline, sizeof(baseline));
    return status;
  }
  size_t encoded_size = 0U;
  const pbns_status encode_status = pbns_controlled_baseline_encode(
      &baseline, encoded_baseline, &encoded_size);
  status = PbnsUefiMonotonicMs(SystemTable->BootServices, &encoding_end_ms);
  if (EFI_ERROR(status) || encoding_end_ms < encoding_start_ms ||
      encode_status != PBNS_OK ||
      !hash_all(encoded_baseline.ptr, encoded_size, BaselineDigest)) {
    ZeroMem(event_log_buffer.ptr, measured.event_log_size);
    ZeroMem(encoded_baseline.ptr, encoded_baseline.cap);
    ZeroMem(BaselineDigest, 32U);
    ZeroMem(measurement_digest, sizeof(measurement_digest));
    ZeroMem(&inventory, sizeof(inventory));
    ZeroMem(&baseline, sizeof(baseline));
    return encode_status == PBNS_ERR_LIMIT ? EFI_BUFFER_TOO_SMALL
                                           : EFI_COMPROMISED_DATA;
  }
  Timings->EncodingMs = encoding_end_ms - encoding_start_ms;
  *EncodedSize = encoded_size;
  *EventCount = measured.event_count;
  *PcrUpdateCounter = measured.pcr_update_counter;
  ZeroMem(measurement_digest, sizeof(measurement_digest));
  ZeroMem(&inventory, sizeof(inventory));
  ZeroMem(&baseline, sizeof(baseline));
  return EFI_SUCCESS;
}
