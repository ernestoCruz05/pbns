#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "PbnsTpmStorage.h"

static const uint8_t ek_public[] = {1U, 2U, 3U};
static const uint8_t srk_public[] = {4U, 5U, 6U, 7U};
static const uint8_t ak_public[] = {8U, 9U, 10U};
static const uint8_t ak_private[] = {11U, 12U, 13U, 14U};
static const uint8_t identity_public[] = {15U, 16U, 17U};
static const uint8_t identity_private[] = {18U, 19U, 20U, 21U};

static void make_name(pbns_view public_blob,
                      uint8_t output[PBNS_TPM_NAME_SIZE]) {
  memset(output, 0, PBNS_TPM_NAME_SIZE);
  output[0] = 0U;
  output[1] = 0x0bU;
  for (size_t index = 0U; index < public_blob.len; ++index) {
    output[2U + (index % 32U)] ^= public_blob.ptr[index];
  }
}

static pbns_tpm_storage_record make_record(uint8_t names[4][34],
                                           uint8_t digest[32]) {
  make_name((pbns_view){ek_public, sizeof(ek_public)}, names[0]);
  make_name((pbns_view){srk_public, sizeof(srk_public)}, names[1]);
  make_name((pbns_view){ak_public, sizeof(ak_public)}, names[2]);
  make_name((pbns_view){identity_public, sizeof(identity_public)}, names[3]);
  memset(digest, 0xa5, 32U);
  return (pbns_tpm_storage_record){
      .manufacturer = UINT32_C(0x49465800),
      .firmware1 = 1U,
      .firmware2 = 2U,
      .ek_public = {ek_public, sizeof(ek_public)},
      .ek_name = {names[0], 34U},
      .srk_public = {srk_public, sizeof(srk_public)},
      .srk_name = {names[1], 34U},
      .ak_public = {ak_public, sizeof(ak_public)},
      .ak_private = {ak_private, sizeof(ak_private)},
      .ak_name = {names[2], 34U},
      .identity_public = {identity_public, sizeof(identity_public)},
      .identity_private = {identity_private, sizeof(identity_private)},
      .identity_name = {names[3], 34U},
      .ek_chain_digest = {digest, 32U},
  };
}

static pbns_status fake_name(void *context, pbns_view public_blob,
                             pbns_buffer name) {
  (void)context;
  if (name.ptr == NULL || name.len != 0U || name.cap < PBNS_TPM_NAME_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  make_name(public_blob, name.ptr);
  return PBNS_OK;
}

static void test_round_trip_and_metadata(void) {
  uint8_t names[4][34] = {{0}};
  uint8_t digest[32] = {0};
  const pbns_tpm_storage_record input = make_record(names, digest);
  uint8_t encoded[PBNS_TPM_STORAGE_MAX_SIZE] = {0};
  size_t written = 0U;
  assert(pbns_tpm_storage_encode(&input,
                                 (pbns_buffer){encoded, 0U, sizeof(encoded)},
                                 &written) == PBNS_OK);
  assert(written <= PBNS_TPM_STORAGE_MAX_SIZE);
  pbns_tpm_storage_record decoded = {0};
  assert(pbns_tpm_storage_decode((pbns_view){encoded, written}, &decoded) ==
         PBNS_OK);
  assert(decoded.manufacturer == input.manufacturer);
  assert(decoded.firmware1 == input.firmware1);
  assert(decoded.firmware2 == input.firmware2);
  assert(decoded.ak_private.len == sizeof(ak_private));
  assert(decoded.identity_private.len == sizeof(identity_private));
  assert(decoded.ak_private.ptr != decoded.identity_private.ptr);
  assert(memcmp(decoded.ak_private.ptr, ak_private, sizeof(ak_private)) == 0);
  assert(memcmp(decoded.identity_private.ptr, identity_private,
                sizeof(identity_private)) == 0);
  assert(pbns_tpm_storage_validate_names(&decoded, fake_name, NULL) == PBNS_OK);
}

static void assert_rejected_and_cleared(uint8_t *encoded, size_t length) {
  pbns_tpm_storage_record record;
  memset(&record, 0xa5, sizeof(record));
  assert(pbns_tpm_storage_decode((pbns_view){encoded, length}, &record) !=
         PBNS_OK);
  assert(record.manufacturer == 0U);
  assert(record.firmware1 == 0U);
  assert(record.firmware2 == 0U);
  const pbns_view views[] = {
      record.ek_public,     record.ek_name,         record.srk_public,
      record.srk_name,      record.ak_public,       record.ak_private,
      record.ak_name,       record.identity_public, record.identity_private,
      record.identity_name, record.ek_chain_digest,
  };
  for (size_t index = 0U; index < sizeof(views) / sizeof(views[0]); ++index) {
    assert(views[index].ptr == NULL);
    assert(views[index].len == 0U);
  }
}

static void test_corrupt_truncated_trailing_and_version_rejection(void) {
  uint8_t names[4][34] = {{0}};
  uint8_t digest[32] = {0};
  const pbns_tpm_storage_record input = make_record(names, digest);
  uint8_t encoded[PBNS_TPM_STORAGE_MAX_SIZE + 1U] = {0};
  size_t written = 0U;
  assert(pbns_tpm_storage_encode(&input,
                                 (pbns_buffer){encoded, 0U, sizeof(encoded)},
                                 &written) == PBNS_OK);

  encoded[written / 2U] ^= 1U;
  assert_rejected_and_cleared(encoded, written);
  encoded[written / 2U] ^= 1U;
  assert_rejected_and_cleared(encoded, written - 1U);
  encoded[written] = 0U;
  assert_rejected_and_cleared(encoded, written + 1U);
  encoded[4] = 2U;
  assert_rejected_and_cleared(encoded, written);
}

static void test_name_mismatch_and_bounds(void) {
  uint8_t names[4][34] = {{0}};
  uint8_t digest[32] = {0};
  pbns_tpm_storage_record input = make_record(names, digest);
  uint8_t encoded[PBNS_TPM_STORAGE_MAX_SIZE] = {0};
  size_t written = 0U;
  assert(pbns_tpm_storage_encode(&input,
                                 (pbns_buffer){encoded, 0U, sizeof(encoded)},
                                 &written) == PBNS_OK);
  pbns_tpm_storage_record decoded = {0};
  assert(pbns_tpm_storage_decode((pbns_view){encoded, written}, &decoded) ==
         PBNS_OK);
  names[2][3] ^= 1U;
  decoded.ak_name = (pbns_view){names[2], sizeof(names[2])};
  assert(pbns_tpm_storage_validate_names(&decoded, fake_name, NULL) ==
         PBNS_ERR_AUTHENTICATION);

  uint8_t oversized[PBNS_TPM_PRIVATE_MAX + 1U] = {0};
  input.ak_private = (pbns_view){oversized, sizeof(oversized)};
  memset(encoded, 0xa5, sizeof(encoded));
  written = 99U;
  assert(pbns_tpm_storage_encode(&input,
                                 (pbns_buffer){encoded, 0U, sizeof(encoded)},
                                 &written) == PBNS_ERR_LIMIT);
  assert(written == 0U);
  for (size_t index = 0U; index < sizeof(encoded); ++index) {
    assert(encoded[index] == 0U);
  }
}

_Static_assert(PBNS_TPM_STORAGE_VARIABLE_ATTRIBUTES ==
                   (PBNS_TPM_VARIABLE_NON_VOLATILE |
                    PBNS_TPM_VARIABLE_BOOTSERVICE),
               "storage variables must be nonvolatile and boot-service-only");
_Static_assert((PBNS_TPM_STORAGE_VARIABLE_ATTRIBUTES &
                PBNS_TPM_VARIABLE_RUNTIME) == 0U,
               "storage variables must not be runtime-visible");

int main(void) {
  test_round_trip_and_metadata();
  test_corrupt_truncated_trailing_and_version_rejection();
  test_name_mismatch_and_bounds();
  return 0;
}
