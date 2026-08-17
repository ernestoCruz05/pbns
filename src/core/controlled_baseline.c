#include "pbns/controlled_baseline.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "qcbor/qcbor_encode.h"

static bool
nonzero_digest(const uint8_t value[PBNS_CONTROLLED_BASELINE_DIGEST_SIZE]) {
  uint8_t combined = 0U;
  for (size_t index = 0U; index < PBNS_CONTROLLED_BASELINE_DIGEST_SIZE;
       ++index) {
    combined |= value[index];
  }
  return combined != 0U;
}

static bool controlled_valid(const pbns_controlled_baseline *value) {
  return value != NULL && nonzero_digest(value->measurement_digest) &&
         value->secure_boot && !value->setup_mode &&
         nonzero_digest(value->db_digest) &&
         nonzero_digest(value->dbx_digest) &&
         nonzero_digest(value->firmware_digest);
}

pbns_status pbns_controlled_baseline_firmware_identity(
    pbns_view vendor, pbns_view version, pbns_controlled_baseline_hash_fn hash,
    void *hash_context, uint8_t digest[PBNS_CONTROLLED_BASELINE_DIGEST_SIZE]) {
  static const uint8_t domain[] = "PBNS-FIRMWARE-IDENTITY-v1";
  static const uint8_t separator = 0U;
  if (digest != NULL) {
    memset(digest, 0, PBNS_CONTROLLED_BASELINE_DIGEST_SIZE);
  }
  if (hash == NULL || digest == NULL || vendor.len > 96U || version.len > 96U ||
      (vendor.ptr == NULL && vendor.len != 0U) ||
      (version.ptr == NULL && version.len != 0U)) {
    return PBNS_ERR_ARGUMENT;
  }
  if (vendor.len == 0U || version.len == 0U) {
    return PBNS_ERR_FORMAT;
  }
  const pbns_view parts[] = {
      {domain, sizeof(domain) - 1U},
      vendor,
      {&separator, sizeof(separator)},
      version,
  };
  const pbns_status status =
      hash(hash_context, parts, sizeof(parts) / sizeof(parts[0]), digest);
  if (status != PBNS_OK) {
    memset(digest, 0, PBNS_CONTROLLED_BASELINE_DIGEST_SIZE);
  }
  return status;
}

pbns_status pbns_controlled_baseline_from_inventory(
    const uint8_t measurement_digest[PBNS_CONTROLLED_BASELINE_DIGEST_SIZE],
    const pbns_inventory_report *inventory,
    pbns_controlled_baseline_hash_fn hash, void *hash_context,
    pbns_controlled_baseline *value) {
  if (value != NULL) {
    *value = (pbns_controlled_baseline){0};
  }
  if (measurement_digest == NULL || inventory == NULL || hash == NULL ||
      value == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (inventory->outcomes[0] != PBNS_INVENTORY_OK ||
      inventory->outcomes[2] != PBNS_INVENTORY_OK ||
      inventory->outcomes[3] != PBNS_INVENTORY_OK ||
      inventory->firmware_vendor.len == 0U ||
      inventory->firmware_version.len == 0U ||
      !pbns_inventory_text_is_normalized(&inventory->firmware_vendor) ||
      !pbns_inventory_text_is_normalized(&inventory->firmware_version) ||
      inventory->block_device_count > PBNS_INVENTORY_BLOCK_DEVICE_MAX) {
    return PBNS_ERR_FORMAT;
  }

  memcpy(value->measurement_digest, measurement_digest,
         sizeof(value->measurement_digest));
  value->secure_boot = inventory->secure_boot;
  value->setup_mode = inventory->setup_mode;
  memcpy(value->db_digest, inventory->db_digest, sizeof(value->db_digest));
  memcpy(value->dbx_digest, inventory->dbx_digest, sizeof(value->dbx_digest));
  value->memory_mib = inventory->memory_mib;
  value->storage_gib = inventory->storage_capacity_gib;
  value->block_devices = inventory->block_device_count;
  const pbns_status status = pbns_controlled_baseline_firmware_identity(
      (pbns_view){inventory->firmware_vendor.bytes,
                  inventory->firmware_vendor.len},
      (pbns_view){inventory->firmware_version.bytes,
                  inventory->firmware_version.len},
      hash, hash_context, value->firmware_digest);
  if (status != PBNS_OK || !controlled_valid(value)) {
    *value = (pbns_controlled_baseline){0};
    return status == PBNS_OK ? PBNS_ERR_FORMAT : status;
  }
  return PBNS_OK;
}

pbns_status
pbns_controlled_baseline_encode(const pbns_controlled_baseline *value,
                                pbns_buffer output, size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  const bool output_valid =
      output.ptr != NULL && output.len == 0U && output.cap > 0U;
  if (output_valid) {
    memset(output.ptr, 0, output.cap);
  }
  if (!output_valid || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!controlled_valid(value)) {
    return PBNS_ERR_FORMAT;
  }

  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_OpenMapInMapN(&encoder, 1);
  QCBOREncode_AddUInt64ToMapN(&encoder, 1, 1U);
  QCBOREncode_AddBytesToMapN(&encoder, 2,
                             (UsefulBufC){value->measurement_digest,
                                          sizeof(value->measurement_digest)});
  QCBOREncode_AddBoolToMapN(&encoder, 3, value->secure_boot);
  QCBOREncode_AddBoolToMapN(&encoder, 4, value->setup_mode);
  QCBOREncode_AddBytesToMapN(
      &encoder, 5, (UsefulBufC){value->db_digest, sizeof(value->db_digest)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 6, (UsefulBufC){value->dbx_digest, sizeof(value->dbx_digest)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 7,
      (UsefulBufC){value->firmware_digest, sizeof(value->firmware_digest)});
  QCBOREncode_OpenMapInMapN(&encoder, 8);
  QCBOREncode_AddUInt64ToMapN(&encoder, 1, value->memory_mib_delta);
  QCBOREncode_AddUInt64ToMapN(&encoder, 2, value->storage_gib_delta);
  QCBOREncode_AddUInt64ToMapN(&encoder, 3, value->block_device_delta);
  QCBOREncode_CloseMap(&encoder);
  QCBOREncode_CloseMap(&encoder);
  QCBOREncode_AddUInt64ToMapN(&encoder, 2, value->memory_mib);
  QCBOREncode_AddUInt64ToMapN(&encoder, 3, value->storage_gib);
  QCBOREncode_AddUInt64ToMapN(&encoder, 4, value->block_devices);
  QCBOREncode_CloseMap(&encoder);

  UsefulBufC encoded = NULLUsefulBufC;
  const QCBORError error = QCBOREncode_Finish(&encoder, &encoded);
  if (error == QCBOR_ERR_BUFFER_TOO_SMALL) {
    memset(output.ptr, 0, output.cap);
    return PBNS_ERR_LIMIT;
  }
  if (error != QCBOR_SUCCESS || encoded.ptr != output.ptr ||
      encoded.len == 0U || encoded.len > output.cap) {
    memset(output.ptr, 0, output.cap);
    return PBNS_ERR_FORMAT;
  }
  *written = encoded.len;
  return PBNS_OK;
}
