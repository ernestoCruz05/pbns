#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns_proxy/credentials.h"
#include "qcbor/qcbor_encode.h"

#define TEST_FLASH_SIZE                                                        \
  (PBNS_CREDENTIALS_SECTOR_SIZE * PBNS_CREDENTIALS_SLOT_COUNT)
#define ENCODED_CAPACITY 512U

typedef struct fake_flash {
  uint8_t bytes[TEST_FLASH_SIZE];
  size_t program_calls;
  size_t fail_program_call;
} fake_flash;

typedef struct credential_fields {
  uint64_t version;
  pbns_view ssid;
  pbns_view psk;
  pbns_view hostname;
  uint64_t port;
  pbns_view spki;
} credential_fields;

static pbns_status flash_read(void *context, size_t offset,
                              pbns_buffer destination) {
  fake_flash *const flash = context;
  if (flash == NULL || destination.ptr == NULL || destination.len != 0U ||
      offset > sizeof(flash->bytes) ||
      destination.cap > sizeof(flash->bytes) - offset) {
    return PBNS_ERR_ARGUMENT;
  }
  memcpy(destination.ptr, flash->bytes + offset, destination.cap);
  return PBNS_OK;
}

static pbns_status flash_erase(void *context, size_t offset, size_t length) {
  fake_flash *const flash = context;
  if (flash == NULL || offset % PBNS_CREDENTIALS_SECTOR_SIZE != 0U ||
      length != PBNS_CREDENTIALS_SECTOR_SIZE || offset > sizeof(flash->bytes) ||
      length > sizeof(flash->bytes) - offset) {
    return PBNS_ERR_ARGUMENT;
  }
  memset(flash->bytes + offset, 0xff, length);
  return PBNS_OK;
}

static pbns_status flash_program(void *context, size_t offset,
                                 pbns_view source) {
  fake_flash *const flash = context;
  if (flash == NULL || source.ptr == NULL || source.len == 0U ||
      offset % PBNS_CREDENTIALS_PAGE_SIZE != 0U ||
      source.len % PBNS_CREDENTIALS_PAGE_SIZE != 0U ||
      offset > sizeof(flash->bytes) ||
      source.len > sizeof(flash->bytes) - offset) {
    return PBNS_ERR_ARGUMENT;
  }
  ++flash->program_calls;
  const bool interrupted = flash->fail_program_call != 0U &&
                           flash->program_calls == flash->fail_program_call;
  const size_t programmed = interrupted ? source.len / 2U : source.len;
  for (size_t index = 0U; index < programmed; ++index) {
    if ((flash->bytes[offset + index] & source.ptr[index]) !=
        source.ptr[index]) {
      return PBNS_ERR_IO;
    }
    flash->bytes[offset + index] &= source.ptr[index];
  }
  return interrupted ? PBNS_ERR_IO : PBNS_OK;
}

static const pbns_credentials_storage_ops flash_ops = {
    .read = flash_read,
    .erase = flash_erase,
    .program = flash_program,
};

static pbns_credentials_storage storage_for(fake_flash *flash) {
  return (pbns_credentials_storage){
      .ops = &flash_ops,
      .context = flash,
      .slot_offsets = {0U, PBNS_CREDENTIALS_SECTOR_SIZE},
  };
}

static void flash_init(fake_flash *flash) {
  memset(flash, 0, sizeof(*flash));
  memset(flash->bytes, 0xff, sizeof(flash->bytes));
}

static credential_fields valid_fields(void) {
  static const uint8_t ssid[] = "PBNS-Lab";
  static const uint8_t psk[] = "prototype-password";
  static const uint8_t hostname[] = "gateway.pbns.test";
  static const uint8_t spki[PBNS_CREDENTIALS_SPKI_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  };
  return (credential_fields){
      .version = PBNS_CREDENTIALS_VERSION,
      .ssid = {ssid, sizeof(ssid) - 1U},
      .psk = {psk, sizeof(psk) - 1U},
      .hostname = {hostname, sizeof(hostname) - 1U},
      .port = UINT64_C(443),
      .spki = {spki, sizeof(spki)},
  };
}

static size_t encode_fields(const credential_fields *fields, uint8_t *output,
                            size_t capacity) {
  QCBOREncodeContext encoder = {0};
  UsefulBufC encoded = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output, capacity});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddUInt64ToMapN(&encoder, 1, fields->version);
  QCBOREncode_AddBytesToMapN(&encoder, 2,
                             (UsefulBufC){fields->ssid.ptr, fields->ssid.len});
  QCBOREncode_AddBytesToMapN(&encoder, 3,
                             (UsefulBufC){fields->psk.ptr, fields->psk.len});
  QCBOREncode_AddTextToMapN(
      &encoder, 4, (UsefulBufC){fields->hostname.ptr, fields->hostname.len});
  QCBOREncode_AddUInt64ToMapN(&encoder, 5, fields->port);
  QCBOREncode_AddBytesToMapN(&encoder, 6,
                             (UsefulBufC){fields->spki.ptr, fields->spki.len});
  QCBOREncode_CloseMap(&encoder);
  assert(QCBOREncode_Finish(&encoder, &encoded) == QCBOR_SUCCESS);
  assert(encoded.ptr == output);
  return encoded.len;
}

static pbns_credentials valid_credentials(void) {
  const credential_fields fields = valid_fields();
  uint8_t encoded[ENCODED_CAPACITY] = {0};
  const size_t encoded_len = encode_fields(&fields, encoded, sizeof(encoded));
  pbns_credentials credentials = {0};
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, encoded_len},
                                      &credentials) == PBNS_OK);
  return credentials;
}

static void assert_credentials_equal(const pbns_credentials *left,
                                     const pbns_credentials *right) {
  assert(left->ssid_len == right->ssid_len);
  assert(memcmp(left->ssid, right->ssid, left->ssid_len) == 0);
  assert(left->psk_len == right->psk_len);
  assert(memcmp(left->psk, right->psk, left->psk_len) == 0);
  assert(left->hostname_len == right->hostname_len);
  assert(memcmp(left->hostname, right->hostname, left->hostname_len) == 0);
  assert(left->port == right->port);
  assert(memcmp(left->spki_sha256, right->spki_sha256,
                sizeof(left->spki_sha256)) == 0);
}

static void test_canonical_round_trip(void) {
  const pbns_credentials expected = valid_credentials();
  uint8_t encoded[ENCODED_CAPACITY] = {0};
  size_t written = SIZE_MAX;
  assert(pbns_credentials_encode_cbor(
             &expected, (pbns_buffer){encoded, 0U, sizeof(encoded)},
             &written) == PBNS_OK);
  assert(written > 0U && written <= PBNS_CREDENTIALS_CBOR_MAX);
  pbns_credentials decoded = {0};
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &decoded) == PBNS_OK);
  assert_credentials_equal(&decoded, &expected);
}

static void test_spki_field_remains_decode_compatible(void) {
  static const uint8_t compatibility_spki[PBNS_CREDENTIALS_SPKI_SIZE] = {
      0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5,
      0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0xef, 0xee, 0xed, 0xec, 0xeb, 0xea,
      0xe9, 0xe8, 0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0,
  };
  credential_fields fields = valid_fields();
  fields.spki = (pbns_view){compatibility_spki, sizeof(compatibility_spki)};
  uint8_t encoded[ENCODED_CAPACITY] = {0};
  const size_t written = encode_fields(&fields, encoded, sizeof(encoded));
  pbns_credentials credentials = {0};
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_OK);
  assert(memcmp(credentials.spki_sha256, compatibility_spki,
                sizeof(compatibility_spki)) == 0);
}

static void test_accepts_maximum_lengths(void) {
  uint8_t ssid[PBNS_CREDENTIALS_SSID_MAX] = {0};
  uint8_t psk[PBNS_CREDENTIALS_PSK_MAX] = {0};
  uint8_t hostname[PBNS_CREDENTIALS_HOSTNAME_MAX] = {0};
  memset(ssid, 's', sizeof(ssid));
  memset(psk, 'p', sizeof(psk));
  memset(hostname, 'h', sizeof(hostname));
  credential_fields fields = valid_fields();
  fields.ssid = (pbns_view){ssid, sizeof(ssid)};
  fields.psk = (pbns_view){psk, sizeof(psk)};
  fields.hostname = (pbns_view){hostname, sizeof(hostname)};
  fields.port = UINT16_MAX;
  uint8_t encoded[ENCODED_CAPACITY] = {0};
  const size_t written = encode_fields(&fields, encoded, sizeof(encoded));
  assert(written <= PBNS_CREDENTIALS_CBOR_MAX);
  pbns_credentials credentials = {0};
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_OK);
  assert(credentials.ssid_len == sizeof(ssid));
  assert(credentials.psk_len == sizeof(psk));
  assert(credentials.hostname_len == sizeof(hostname));
  assert(credentials.port == UINT16_MAX);
}

static void test_rejects_invalid_cbor_profiles(void) {
  uint8_t encoded[ENCODED_CAPACITY] = {0};
  credential_fields fields = valid_fields();
  size_t written = encode_fields(&fields, encoded, sizeof(encoded));
  pbns_credentials credentials = {0};
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written - 1U},
                                      &credentials) == PBNS_ERR_FORMAT);

  memmove(encoded + 4U, encoded + 3U, written - 3U);
  encoded[2] = UINT8_C(0x18);
  encoded[3] = UINT8_C(0x01);
  ++written;
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_ERR_FORMAT);

  fields.version = PBNS_CREDENTIALS_VERSION + 1U;
  written = encode_fields(&fields, encoded, sizeof(encoded));
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_ERR_VERSION);

  static const uint8_t invalid_utf8[] = {0xc3, 0x28};
  fields = valid_fields();
  fields.ssid = (pbns_view){invalid_utf8, sizeof(invalid_utf8)};
  written = encode_fields(&fields, encoded, sizeof(encoded));
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_ERR_FORMAT);

  static const uint8_t nul_text[] = {'a', 0, 'b'};
  fields = valid_fields();
  fields.hostname = (pbns_view){nul_text, sizeof(nul_text)};
  written = encode_fields(&fields, encoded, sizeof(encoded));
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_ERR_FORMAT);

  fields = valid_fields();
  fields.ssid = (pbns_view){nul_text, sizeof(nul_text)};
  written = encode_fields(&fields, encoded, sizeof(encoded));
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_ERR_FORMAT);

  fields = valid_fields();
  fields.psk = (pbns_view){nul_text, sizeof(nul_text)};
  written = encode_fields(&fields, encoded, sizeof(encoded));
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_ERR_FORMAT);

  uint8_t oversized_ssid[PBNS_CREDENTIALS_SSID_MAX + 1U] = {0};
  memset(oversized_ssid, 's', sizeof(oversized_ssid));
  fields = valid_fields();
  fields.ssid = (pbns_view){oversized_ssid, sizeof(oversized_ssid)};
  written = encode_fields(&fields, encoded, sizeof(encoded));
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_ERR_LIMIT);

  uint8_t oversized_psk[PBNS_CREDENTIALS_PSK_MAX + 1U] = {0};
  memset(oversized_psk, 'p', sizeof(oversized_psk));
  fields = valid_fields();
  fields.psk = (pbns_view){oversized_psk, sizeof(oversized_psk)};
  written = encode_fields(&fields, encoded, sizeof(encoded));
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_ERR_LIMIT);

  uint8_t oversized_hostname[PBNS_CREDENTIALS_HOSTNAME_MAX + 1U] = {0};
  memset(oversized_hostname, 'h', sizeof(oversized_hostname));
  fields = valid_fields();
  fields.hostname = (pbns_view){oversized_hostname, sizeof(oversized_hostname)};
  written = encode_fields(&fields, encoded, sizeof(encoded));
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_ERR_LIMIT);

  fields = valid_fields();
  fields.spki.len = PBNS_CREDENTIALS_SPKI_SIZE - 1U;
  written = encode_fields(&fields, encoded, sizeof(encoded));
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_ERR_FORMAT);

  fields = valid_fields();
  fields.port = 0U;
  written = encode_fields(&fields, encoded, sizeof(encoded));
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_ERR_FORMAT);

  fields = valid_fields();
  fields.port = (uint64_t)UINT16_MAX + UINT64_C(1);
  written = encode_fields(&fields, encoded, sizeof(encoded));
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_ERR_FORMAT);

  fields = valid_fields();
  fields.ssid.len = 0U;
  written = encode_fields(&fields, encoded, sizeof(encoded));
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_ERR_FORMAT);

  fields = valid_fields();
  fields.psk.len = 0U;
  written = encode_fields(&fields, encoded, sizeof(encoded));
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_ERR_FORMAT);

  fields = valid_fields();
  fields.hostname.len = 0U;
  written = encode_fields(&fields, encoded, sizeof(encoded));
  assert(pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                      &credentials) == PBNS_ERR_FORMAT);
}

static void test_transactional_store_and_interrupted_update(void) {
  fake_flash flash = {0};
  flash_init(&flash);
  const pbns_credentials_storage storage = storage_for(&flash);
  pbns_credentials first = valid_credentials();
  assert(pbns_credentials_store(&storage, &first) == PBNS_OK);

  pbns_credentials loaded = {0};
  assert(pbns_credentials_load(&storage, &loaded) == PBNS_OK);
  assert_credentials_equal(&loaded, &first);

  pbns_credentials second = first;
  static const char second_hostname[] = "second.gateway.pbns.test";
  memcpy(second.hostname, second_hostname, sizeof(second_hostname));
  second.hostname_len = sizeof(second_hostname) - 1U;
  flash.fail_program_call = flash.program_calls + 1U;
  assert(pbns_credentials_store(&storage, &second) == PBNS_ERR_IO);
  assert(pbns_credentials_load(&storage, &loaded) == PBNS_OK);
  assert_credentials_equal(&loaded, &first);

  flash.fail_program_call = flash.program_calls + 2U;
  assert(pbns_credentials_store(&storage, &second) == PBNS_ERR_IO);
  assert(pbns_credentials_load(&storage, &loaded) == PBNS_OK);
  assert_credentials_equal(&loaded, &first);

  flash.fail_program_call = 0U;
  assert(pbns_credentials_store(&storage, &second) == PBNS_OK);
  assert(pbns_credentials_load(&storage, &loaded) == PBNS_OK);
  assert_credentials_equal(&loaded, &second);
}

static void test_transactional_clear_and_reprovision(void) {
  fake_flash flash = {0};
  flash_init(&flash);
  const pbns_credentials_storage storage = storage_for(&flash);
  pbns_credentials first = valid_credentials();
  assert(pbns_credentials_store(&storage, &first) == PBNS_OK);

  flash.fail_program_call = flash.program_calls + 2U;
  assert(pbns_credentials_clear(&storage) == PBNS_ERR_IO);
  pbns_credentials loaded = {0};
  assert(pbns_credentials_load(&storage, &loaded) == PBNS_OK);
  assert_credentials_equal(&loaded, &first);

  flash.fail_program_call = 0U;
  assert(pbns_credentials_clear(&storage) == PBNS_OK);
  assert(pbns_credentials_load(&storage, &loaded) == PBNS_ERR_STATE);

  pbns_credentials second = first;
  second.port = UINT16_C(8443);
  assert(pbns_credentials_store(&storage, &second) == PBNS_OK);
  assert(pbns_credentials_load(&storage, &loaded) == PBNS_OK);
  assert_credentials_equal(&loaded, &second);
}

static void test_corruption_falls_back_and_clear_is_transactional(void) {
  fake_flash flash = {0};
  flash_init(&flash);
  const pbns_credentials_storage storage = storage_for(&flash);
  pbns_credentials first = valid_credentials();
  pbns_credentials second = first;
  second.port = UINT16_C(8443);
  assert(pbns_credentials_store(&storage, &first) == PBNS_OK);
  assert(pbns_credentials_store(&storage, &second) == PBNS_OK);

  flash.bytes[PBNS_CREDENTIALS_SECTOR_SIZE + 24U] ^= UINT8_C(1);
  pbns_credentials loaded = {0};
  assert(pbns_credentials_load(&storage, &loaded) == PBNS_OK);
  assert_credentials_equal(&loaded, &first);

  assert(pbns_credentials_clear(&storage) == PBNS_OK);
  assert(pbns_credentials_load(&storage, &loaded) == PBNS_ERR_STATE);
}

int main(void) {
  test_canonical_round_trip();
  test_spki_field_remains_decode_compatible();
  test_accepts_maximum_lengths();
  test_rejects_invalid_cbor_profiles();
  test_transactional_store_and_interrupted_update();
  test_transactional_clear_and_reprovision();
  test_corruption_falls_back_and_clear_is_transactional();
  return 0;
}
