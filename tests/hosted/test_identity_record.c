#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "PbnsIdentityRecord.h"
#include "pbns/crc32c.h"

#define CRC_OFFSET 20U

_Static_assert(PBNS_IDENTITY_RECORD_MAX_SIZE <= 1024U,
               "identity record exceeds its one-KiB bound");

static uint16_t load_u16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8U) | p[1]);
}

static uint32_t load_u32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24U) | ((uint32_t)p[1] << 16U) |
         ((uint32_t)p[2] << 8U) | p[3];
}

static void store_u16(uint8_t *p, uint16_t value) {
  p[0] = (uint8_t)(value >> 8U);
  p[1] = (uint8_t)value;
}

static void store_u32(uint8_t *p, uint32_t value) {
  p[0] = (uint8_t)(value >> 24U);
  p[1] = (uint8_t)(value >> 16U);
  p[2] = (uint8_t)(value >> 8U);
  p[3] = (uint8_t)value;
}

static void rewrite_crc(uint8_t *encoded, size_t length) {
  store_u32(encoded + CRC_OFFSET, 0U);
  store_u32(encoded + CRC_OFFSET, pbns_crc32c((pbns_view){encoded, length}));
}

static size_t make_record(uint8_t output[PBNS_IDENTITY_RECORD_MAX_SIZE]) {
  static const uint8_t private_der[] = {0x30, 0x06, 0x02, 0x01,
                                        0x01, 0x04, 0x01, 0x7f};
  static const uint8_t public_cose[] = {0xa4, 0x01, 0x02, 0x20,
                                        0x01, 0x21, 0x41, 0x01};
  uint8_t fingerprint[PBNS_IDENTITY_FINGERPRINT_SIZE] = {0};
  for (size_t i = 0U; i < sizeof(fingerprint); ++i) {
    fingerprint[i] = (uint8_t)(i + 1U);
  }
  size_t written = 0U;
  assert(pbns_identity_record_encode(
             (pbns_view){private_der, sizeof(private_der)},
             (pbns_view){public_cose, sizeof(public_cose)},
             (pbns_view){fingerprint, sizeof(fingerprint)},
             (pbns_buffer){output, 0U, PBNS_IDENTITY_RECORD_MAX_SIZE},
             &written) == PBNS_OK);
  return written;
}

static void test_exact_round_trip(void) {
  uint8_t encoded[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
  uint8_t repeated[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
  const size_t length = make_record(encoded);
  assert(length == PBNS_IDENTITY_RECORD_HEADER_SIZE + 8U + 8U +
                       PBNS_IDENTITY_FINGERPRINT_SIZE);
  assert(memcmp(encoded, "PBI1", 4U) == 0);
  assert(load_u16(encoded + 4U) == PBNS_IDENTITY_RECORD_VERSION);
  assert(load_u16(encoded + 6U) == PBNS_IDENTITY_CURVE_P256);
  assert(load_u32(encoded + 8U) == 8U);
  assert(load_u32(encoded + 12U) == 8U);
  assert(load_u16(encoded + 16U) == PBNS_IDENTITY_FINGERPRINT_SIZE);
  assert(load_u16(encoded + 18U) == 0U);
  uint8_t crc_input[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
  memcpy(crc_input, encoded, length);
  store_u32(crc_input + CRC_OFFSET, 0U);
  assert(load_u32(encoded + CRC_OFFSET) ==
         pbns_crc32c((pbns_view){crc_input, length}));

  pbns_identity_record record = {0};
  assert(pbns_identity_record_decode((pbns_view){encoded, length}, &record) ==
         PBNS_OK);
  assert(record.private_der.ptr == encoded + PBNS_IDENTITY_RECORD_HEADER_SIZE);
  assert(record.private_der.len == 8U);
  assert(record.public_cose_key.ptr == record.private_der.ptr + 8U);
  assert(record.public_cose_key.len == 8U);
  assert(record.fingerprint.ptr == record.public_cose_key.ptr + 8U);
  assert(record.fingerprint.len == PBNS_IDENTITY_FINGERPRINT_SIZE);

  size_t repeated_length = 0U;
  assert(pbns_identity_record_encode(
             record.private_der, record.public_cose_key, record.fingerprint,
             (pbns_buffer){repeated, 0U, sizeof(repeated)},
             &repeated_length) == PBNS_OK);
  assert(repeated_length == length);
  assert(memcmp(repeated, encoded, length) == 0);
}

static void test_maximum_lengths(void) {
  uint8_t private_der[PBNS_IDENTITY_PRIVATE_DER_MAX] = {1};
  uint8_t public_cose[PBNS_IDENTITY_PUBLIC_COSE_MAX] = {2};
  uint8_t fingerprint[PBNS_IDENTITY_FINGERPRINT_SIZE] = {3};
  uint8_t encoded[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
  size_t written = 0U;
  assert(pbns_identity_record_encode(
             (pbns_view){private_der, sizeof(private_der)},
             (pbns_view){public_cose, sizeof(public_cose)},
             (pbns_view){fingerprint, sizeof(fingerprint)},
             (pbns_buffer){encoded, 0U, sizeof(encoded)}, &written) == PBNS_OK);
  assert(written == sizeof(encoded));
  pbns_identity_record record = {0};
  assert(pbns_identity_record_decode((pbns_view){encoded, written}, &record) ==
         PBNS_OK);
}

static pbns_status encode_lengths(size_t private_length, size_t public_length,
                                  size_t fingerprint_length, size_t capacity) {
  uint8_t private_der[PBNS_IDENTITY_PRIVATE_DER_MAX + 1U] = {0};
  uint8_t public_cose[PBNS_IDENTITY_PUBLIC_COSE_MAX + 1U] = {0};
  uint8_t fingerprint[PBNS_IDENTITY_FINGERPRINT_SIZE + 1U] = {0};
  uint8_t output[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
  size_t written = 99U;
  const pbns_status status = pbns_identity_record_encode(
      (pbns_view){private_der, private_length},
      (pbns_view){public_cose, public_length},
      (pbns_view){fingerprint, fingerprint_length},
      (pbns_buffer){output, 0U, capacity}, &written);
  if (status != PBNS_OK) {
    assert(written == 0U);
  }
  return status;
}

static void test_encode_rejects_invalid_inputs(void) {
  assert(encode_lengths(1U, 1U, PBNS_IDENTITY_FINGERPRINT_SIZE,
                        PBNS_IDENTITY_RECORD_MAX_SIZE) == PBNS_OK);
  assert(encode_lengths(0U, 1U, PBNS_IDENTITY_FINGERPRINT_SIZE,
                        PBNS_IDENTITY_RECORD_MAX_SIZE) == PBNS_ERR_ARGUMENT);
  assert(encode_lengths(PBNS_IDENTITY_PRIVATE_DER_MAX + 1U, 1U,
                        PBNS_IDENTITY_FINGERPRINT_SIZE,
                        PBNS_IDENTITY_RECORD_MAX_SIZE) == PBNS_ERR_LIMIT);
  assert(encode_lengths(1U, PBNS_IDENTITY_PUBLIC_COSE_MAX + 1U,
                        PBNS_IDENTITY_FINGERPRINT_SIZE,
                        PBNS_IDENTITY_RECORD_MAX_SIZE) == PBNS_ERR_LIMIT);
  assert(encode_lengths(1U, 1U, PBNS_IDENTITY_FINGERPRINT_SIZE + 1U,
                        PBNS_IDENTITY_RECORD_MAX_SIZE) == PBNS_ERR_ARGUMENT);
  assert(encode_lengths(1U, 1U, PBNS_IDENTITY_FINGERPRINT_SIZE,
                        PBNS_IDENTITY_RECORD_HEADER_SIZE) == PBNS_ERR_LIMIT);

  uint8_t output[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
  uint8_t public_cose[1] = {0};
  uint8_t fingerprint[PBNS_IDENTITY_FINGERPRINT_SIZE] = {0};
  size_t written = 99U;
  assert(
      pbns_identity_record_encode((pbns_view){output + 100U, 8U},
                                  (pbns_view){public_cose, sizeof(public_cose)},
                                  (pbns_view){fingerprint, sizeof(fingerprint)},
                                  (pbns_buffer){output, 0U, sizeof(output)},
                                  &written) == PBNS_ERR_ARGUMENT);
  assert(written == 0U);
  assert(
      pbns_identity_record_encode((pbns_view){public_cose, sizeof(public_cose)},
                                  (pbns_view){output + 200U, 1U},
                                  (pbns_view){fingerprint, sizeof(fingerprint)},
                                  (pbns_buffer){output, 0U, sizeof(output)},
                                  &written) == PBNS_ERR_ARGUMENT);
  assert(pbns_identity_record_encode(
             (pbns_view){public_cose, sizeof(public_cose)},
             (pbns_view){public_cose, sizeof(public_cose)},
             (pbns_view){output + 300U, sizeof(fingerprint)},
             (pbns_buffer){output, 0U, sizeof(output)},
             &written) == PBNS_ERR_ARGUMENT);
  assert(
      pbns_identity_record_encode((pbns_view){NULL, 0U},
                                  (pbns_view){public_cose, sizeof(public_cose)},
                                  (pbns_view){fingerprint, sizeof(fingerprint)},
                                  (pbns_buffer){output, 0U, sizeof(output)},
                                  &written) == PBNS_ERR_ARGUMENT);
}

static void test_decode_rejects_damage(void) {
  uint8_t encoded[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
  const size_t length = make_record(encoded);
  pbns_identity_record record = {0};
  for (size_t truncated = 0U; truncated < length; ++truncated) {
    assert(pbns_identity_record_decode((pbns_view){encoded, truncated},
                                       &record) != PBNS_OK);
  }
  encoded[length] = 0xaa;
  assert(pbns_identity_record_decode((pbns_view){encoded, length + 1U},
                                     &record) != PBNS_OK);
  encoded[length] = 0U;

  const size_t offsets[] = {0U,
                            4U,
                            6U,
                            8U,
                            12U,
                            16U,
                            18U,
                            CRC_OFFSET,
                            PBNS_IDENTITY_RECORD_HEADER_SIZE,
                            PBNS_IDENTITY_RECORD_HEADER_SIZE + 8U,
                            PBNS_IDENTITY_RECORD_HEADER_SIZE + 16U};
  for (size_t i = 0U; i < sizeof(offsets) / sizeof(offsets[0]); ++i) {
    uint8_t damaged[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
    memcpy(damaged, encoded, length);
    damaged[offsets[i]] ^= 1U;
    assert(pbns_identity_record_decode((pbns_view){damaged, length}, &record) !=
           PBNS_OK);
  }
}

static void test_decode_rejects_forged_structure(void) {
  uint8_t encoded[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
  const size_t length = make_record(encoded);
  pbns_identity_record record = {0};

  uint8_t forged[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
  memcpy(forged, encoded, length);
  store_u16(forged + 4U, PBNS_IDENTITY_RECORD_VERSION + 1U);
  rewrite_crc(forged, length);
  assert(pbns_identity_record_decode((pbns_view){forged, length}, &record) ==
         PBNS_ERR_VERSION);

  memcpy(forged, encoded, length);
  store_u16(forged + 6U, PBNS_IDENTITY_CURVE_P256 + 1U);
  rewrite_crc(forged, length);
  assert(pbns_identity_record_decode((pbns_view){forged, length}, &record) ==
         PBNS_ERR_UNSUPPORTED);

  memcpy(forged, encoded, length);
  store_u16(forged + 18U, 1U);
  rewrite_crc(forged, length);
  assert(pbns_identity_record_decode((pbns_view){forged, length}, &record) ==
         PBNS_ERR_FORMAT);

  memcpy(forged, encoded, length);
  store_u32(forged + 8U, PBNS_IDENTITY_PRIVATE_DER_MAX + 1U);
  rewrite_crc(forged, length);
  assert(pbns_identity_record_decode((pbns_view){forged, length}, &record) ==
         PBNS_ERR_LIMIT);

  const size_t length_offsets[] = {8U, 12U, 16U};
  for (size_t i = 0U; i < sizeof(length_offsets) / sizeof(length_offsets[0]);
       ++i) {
    memcpy(forged, encoded, length);
    if (length_offsets[i] == 16U) {
      store_u16(forged + length_offsets[i], 31U);
    } else {
      store_u32(forged + length_offsets[i], 7U);
    }
    rewrite_crc(forged, length);
    assert(pbns_identity_record_decode((pbns_view){forged, length}, &record) ==
           PBNS_ERR_FORMAT);
  }

  uint8_t oversized[1025] = {0};
  assert(pbns_identity_record_decode((pbns_view){oversized, sizeof(oversized)},
                                     &record) == PBNS_ERR_LIMIT);
  assert(pbns_identity_record_decode((pbns_view){NULL, length}, &record) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_identity_record_decode((pbns_view){encoded, length}, NULL) ==
         PBNS_ERR_ARGUMENT);
}

int main(void) {
  test_exact_round_trip();
  test_maximum_lengths();
  test_encode_rejects_invalid_inputs();
  test_decode_rejects_damage();
  test_decode_rejects_forged_structure();
  return 0;
}
