#include "PbnsIdentityRecord.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/crc32c.h"

#define PBNS_IDENTITY_RECORD_CRC_OFFSET 20U

static const uint8_t record_magic[4] = {'P', 'B', 'I', '1'};

static void secure_zero(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  while (length > 0U) {
    *bytes = 0U;
    ++bytes;
    --length;
  }
}

static uint16_t load_u16(const uint8_t *bytes) {
  return (uint16_t)(((uint16_t)bytes[0] << 8U) | (uint16_t)bytes[1]);
}

static uint32_t load_u32(const uint8_t *bytes) {
  return ((uint32_t)bytes[0] << 24U) | ((uint32_t)bytes[1] << 16U) |
         ((uint32_t)bytes[2] << 8U) | (uint32_t)bytes[3];
}

static void store_u16(uint8_t *bytes, uint16_t value) {
  bytes[0] = (uint8_t)(value >> 8U);
  bytes[1] = (uint8_t)value;
}

static void store_u32(uint8_t *bytes, uint32_t value) {
  bytes[0] = (uint8_t)(value >> 24U);
  bytes[1] = (uint8_t)(value >> 16U);
  bytes[2] = (uint8_t)(value >> 8U);
  bytes[3] = (uint8_t)value;
}

static bool ranges_overlap(const uint8_t *first, size_t first_length,
                           const uint8_t *second, size_t second_length) {
  if (first_length == 0U || second_length == 0U) {
    return false;
  }
  const uintptr_t first_start = (uintptr_t)first;
  const uintptr_t second_start = (uintptr_t)second;
  if (first_length > UINTPTR_MAX - first_start ||
      second_length > UINTPTR_MAX - second_start) {
    return true;
  }
  const uintptr_t first_end = first_start + first_length;
  const uintptr_t second_end = second_start + second_length;
  return first_start < second_end && second_start < first_end;
}

static bool view_is_present(pbns_view view) {
  return view.ptr != NULL && view.len > 0U;
}

pbns_status pbns_identity_record_encode(pbns_view private_der,
                                        pbns_view public_cose_key,
                                        pbns_view fingerprint,
                                        pbns_buffer output, size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  if (written == NULL || !view_is_present(private_der) ||
      !view_is_present(public_cose_key) || fingerprint.ptr == NULL ||
      fingerprint.len != PBNS_IDENTITY_FINGERPRINT_SIZE || output.ptr == NULL ||
      output.len != 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  if (private_der.len > PBNS_IDENTITY_PRIVATE_DER_MAX ||
      public_cose_key.len > PBNS_IDENTITY_PUBLIC_COSE_MAX) {
    return PBNS_ERR_LIMIT;
  }
  const size_t total_length = PBNS_IDENTITY_RECORD_HEADER_SIZE +
                              private_der.len + public_cose_key.len +
                              fingerprint.len;
  if (output.cap < total_length) {
    return PBNS_ERR_LIMIT;
  }
  if (ranges_overlap(output.ptr, output.cap, private_der.ptr,
                     private_der.len) ||
      ranges_overlap(output.ptr, output.cap, public_cose_key.ptr,
                     public_cose_key.len) ||
      ranges_overlap(output.ptr, output.cap, fingerprint.ptr,
                     fingerprint.len)) {
    return PBNS_ERR_ARGUMENT;
  }

  memcpy(output.ptr, record_magic, sizeof(record_magic));
  store_u16(output.ptr + 4U, PBNS_IDENTITY_RECORD_VERSION);
  store_u16(output.ptr + 6U, PBNS_IDENTITY_CURVE_P256);
  store_u32(output.ptr + 8U, (uint32_t)private_der.len);
  store_u32(output.ptr + 12U, (uint32_t)public_cose_key.len);
  store_u16(output.ptr + 16U, PBNS_IDENTITY_FINGERPRINT_SIZE);
  store_u16(output.ptr + 18U, 0U);
  store_u32(output.ptr + PBNS_IDENTITY_RECORD_CRC_OFFSET, 0U);
  size_t cursor = PBNS_IDENTITY_RECORD_HEADER_SIZE;
  memcpy(output.ptr + cursor, private_der.ptr, private_der.len);
  cursor += private_der.len;
  memcpy(output.ptr + cursor, public_cose_key.ptr, public_cose_key.len);
  cursor += public_cose_key.len;
  memcpy(output.ptr + cursor, fingerprint.ptr, fingerprint.len);
  store_u32(output.ptr + PBNS_IDENTITY_RECORD_CRC_OFFSET,
            pbns_crc32c((pbns_view){output.ptr, total_length}));
  *written = total_length;
  return PBNS_OK;
}

pbns_status pbns_identity_record_decode(pbns_view encoded,
                                        pbns_identity_record *record) {
  if (record == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *record = (pbns_identity_record){0};
  if (encoded.ptr == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (encoded.len < PBNS_IDENTITY_RECORD_HEADER_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  if (encoded.len > PBNS_IDENTITY_RECORD_MAX_SIZE) {
    return PBNS_ERR_LIMIT;
  }
  if (memcmp(encoded.ptr, record_magic, sizeof(record_magic)) != 0) {
    return PBNS_ERR_FORMAT;
  }
  if (load_u16(encoded.ptr + 4U) != PBNS_IDENTITY_RECORD_VERSION) {
    return PBNS_ERR_VERSION;
  }
  if (load_u16(encoded.ptr + 6U) != PBNS_IDENTITY_CURVE_P256) {
    return PBNS_ERR_UNSUPPORTED;
  }
  const uint32_t private_length = load_u32(encoded.ptr + 8U);
  const uint32_t public_length = load_u32(encoded.ptr + 12U);
  const uint16_t fingerprint_length = load_u16(encoded.ptr + 16U);
  if (load_u16(encoded.ptr + 18U) != 0U) {
    return PBNS_ERR_FORMAT;
  }
  if (private_length == 0U || public_length == 0U ||
      fingerprint_length != PBNS_IDENTITY_FINGERPRINT_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  if (private_length > PBNS_IDENTITY_PRIVATE_DER_MAX ||
      public_length > PBNS_IDENTITY_PUBLIC_COSE_MAX) {
    return PBNS_ERR_LIMIT;
  }
  const size_t expected_length =
      PBNS_IDENTITY_RECORD_HEADER_SIZE + (size_t)private_length +
      (size_t)public_length + (size_t)fingerprint_length;
  if (encoded.len != expected_length) {
    return PBNS_ERR_FORMAT;
  }

  uint8_t crc_input[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
  memcpy(crc_input, encoded.ptr, encoded.len);
  const uint32_t stored_crc =
      load_u32(crc_input + PBNS_IDENTITY_RECORD_CRC_OFFSET);
  store_u32(crc_input + PBNS_IDENTITY_RECORD_CRC_OFFSET, 0U);
  const uint32_t computed_crc =
      pbns_crc32c((pbns_view){crc_input, encoded.len});
  secure_zero(crc_input, sizeof(crc_input));
  if (stored_crc != computed_crc) {
    return PBNS_ERR_CRC;
  }

  size_t cursor = PBNS_IDENTITY_RECORD_HEADER_SIZE;
  record->private_der = (pbns_view){encoded.ptr + cursor, private_length};
  cursor += private_length;
  record->public_cose_key = (pbns_view){encoded.ptr + cursor, public_length};
  cursor += public_length;
  record->fingerprint = (pbns_view){encoded.ptr + cursor, fingerprint_length};
  return PBNS_OK;
}
