#include "pbns/enrollment_baseline.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/measured_boot.h"
#include "qcbor/qcbor_encode.h"

static bool baseline_is_valid(const pbns_enrollment_baseline *baseline) {
  static const uint8_t required_pcrs[PBNS_BASELINE_PCR_COUNT] = {0U, 2U, 4U,
                                                                 7U};
  if (baseline == NULL || baseline->event_log.ptr == NULL ||
      baseline->event_log.len == 0U) {
    return false;
  }
  for (size_t index = 0U; index < PBNS_BASELINE_PCR_COUNT; ++index) {
    if (baseline->pcrs[index].index != required_pcrs[index]) {
      return false;
    }
  }
  pbns_measured_boot_summary summary = {0};
  return pbns_measured_boot_validate_event_log(baseline->event_log, &summary) ==
         PBNS_OK;
}

pbns_status
pbns_enrollment_baseline_encode(const pbns_enrollment_baseline *baseline,
                                pbns_buffer output, size_t *written) {
  if (!baseline_is_valid(baseline) || output.ptr == NULL || output.cap == 0U ||
      output.len != 0U || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  QCBOREncodeContext encoder;
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddTextToMapN(
      &encoder, 1,
      (UsefulBufC){PBNS_BASELINE_DOMAIN, sizeof(PBNS_BASELINE_DOMAIN) - 1U});
  QCBOREncode_AddBytesToMapN(
      &encoder, 2,
      (UsefulBufC){baseline->firmware_vendor_digest,
                   sizeof(baseline->firmware_vendor_digest)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 3,
      (UsefulBufC){baseline->firmware_version_digest,
                   sizeof(baseline->firmware_version_digest)});
  QCBOREncode_AddBoolToMapN(&encoder, 4, baseline->secure_boot);
  QCBOREncode_AddBoolToMapN(&encoder, 5, baseline->setup_mode);
  QCBOREncode_AddBytesToMapN(
      &encoder, 6,
      (UsefulBufC){baseline->db_digest, sizeof(baseline->db_digest)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 7,
      (UsefulBufC){baseline->dbx_digest, sizeof(baseline->dbx_digest)});
  QCBOREncode_OpenArrayInMapN(&encoder, 8);
  for (size_t index = 0U; index < PBNS_BASELINE_PCR_COUNT; ++index) {
    QCBOREncode_OpenMap(&encoder);
    QCBOREncode_AddUInt64ToMapN(&encoder, 1, baseline->pcrs[index].index);
    QCBOREncode_AddBytesToMapN(
        &encoder, 2,
        (UsefulBufC){baseline->pcrs[index].digest,
                     sizeof(baseline->pcrs[index].digest)});
    QCBOREncode_CloseMap(&encoder);
  }
  QCBOREncode_CloseArray(&encoder);
  QCBOREncode_AddBytesToMapN(
      &encoder, 9,
      (UsefulBufC){baseline->event_log.ptr, baseline->event_log.len});
  QCBOREncode_AddBytesToMapN(&encoder, 10,
                             (UsefulBufC){baseline->event_log_digest,
                                          sizeof(baseline->event_log_digest)});
  QCBOREncode_CloseMap(&encoder);
  UsefulBufC encoded = NULLUsefulBufC;
  const QCBORError error = QCBOREncode_Finish(&encoder, &encoded);
  if (error == QCBOR_ERR_BUFFER_TOO_SMALL) {
    return PBNS_ERR_LIMIT;
  }
  if (error != QCBOR_SUCCESS || encoded.ptr != output.ptr ||
      encoded.len == 0U || encoded.len > output.cap) {
    return PBNS_ERR_FORMAT;
  }
  *written = encoded.len;
  return PBNS_OK;
}
