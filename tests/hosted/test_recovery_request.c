#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/recovery_request.h"

static const char manifest_hex[] =
    "a801781850424e532d5245434f564552592d524551554553542d763102010302"
    "04010550101112131415161718191a1b1c1d1e1f065820202122232425262728"
    "292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f075820404142434445"
    "464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f085820000000"
    "0000000000000000000000000000000000000000000000000000000000";
static const char artifact_hex[] =
    "a801781850424e532d5245434f564552592d524551554553542d763102010302"
    "04020550101112131415161718191a1b1c1d1e1f065820202122232425262728"
    "292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f075820404142434445"
    "464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f085820606162"
    "636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";

static uint8_t nibble(char value) {
  if (value >= '0' && value <= '9') {
    return (uint8_t)(value - '0');
  }
  assert(value >= 'a' && value <= 'f');
  return (uint8_t)(value - 'a' + 10);
}

static size_t decode_hex(const char *encoded, uint8_t *output,
                         size_t capacity) {
  const size_t length = strlen(encoded);
  assert((length % 2U) == 0U && length / 2U <= capacity);
  for (size_t index = 0U; index < length / 2U; ++index) {
    output[index] =
        (uint8_t)((uint8_t)(nibble(encoded[index * 2U]) << 4U) |
                  nibble(encoded[index * 2U + 1U]));
  }
  return length / 2U;
}

static void fill(uint8_t *output, size_t size, uint8_t first) {
  for (size_t index = 0U; index < size; ++index) {
    output[index] = (uint8_t)(first + (uint8_t)index);
  }
}

static pbns_recovery_request valid_request(pbns_recovery_operation operation) {
  pbns_recovery_request request = {.operation = operation};
  fill(request.request_id, sizeof(request.request_id), 0x10U);
  fill(request.host_fingerprint, sizeof(request.host_fingerprint), 0x20U);
  fill(request.nonce, sizeof(request.nonce), 0x40U);
  if (operation == PBNS_RECOVERY_OPERATION_ARTIFACT) {
    fill(request.artifact_digest, sizeof(request.artifact_digest), 0x60U);
  }
  return request;
}

static void assert_equal(const pbns_recovery_request *left,
                         const pbns_recovery_request *right) {
  assert(left->operation == right->operation);
  assert(memcmp(left->request_id, right->request_id,
                sizeof(left->request_id)) == 0);
  assert(memcmp(left->host_fingerprint, right->host_fingerprint,
                sizeof(left->host_fingerprint)) == 0);
  assert(memcmp(left->nonce, right->nonce, sizeof(left->nonce)) == 0);
  assert(memcmp(left->artifact_digest, right->artifact_digest,
                sizeof(left->artifact_digest)) == 0);
}

static void test_exact_vectors_and_round_trip(void) {
  const struct {
    pbns_recovery_operation operation;
    const char *hex;
  } cases[] = {
      {PBNS_RECOVERY_OPERATION_MANIFEST, manifest_hex},
      {PBNS_RECOVERY_OPERATION_ARTIFACT, artifact_hex},
  };
  for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
    const pbns_recovery_request request = valid_request(cases[index].operation);
    uint8_t expected[PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE] = {0};
    const size_t expected_size =
        decode_hex(cases[index].hex, expected, sizeof(expected));
    uint8_t encoded[PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE] = {0};
    size_t written = 0U;
    assert(pbns_recovery_request_encode(
               &request, (pbns_buffer){encoded, 0U, sizeof(encoded)},
               &written) == PBNS_OK);
    assert(written == expected_size);
    assert(memcmp(encoded, expected, written) == 0);

    uint8_t scratch[PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE] = {0};
    pbns_recovery_request decoded = {0};
    assert(pbns_recovery_request_decode(
               (pbns_view){encoded, written},
               (pbns_buffer){scratch, 0U, sizeof(scratch)},
               &decoded) == PBNS_OK);
    assert_equal(&request, &decoded);
  }
}

static void test_shape_rejection(void) {
  pbns_recovery_request request =
      valid_request(PBNS_RECOVERY_OPERATION_ARTIFACT);
  uint8_t output[PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE] = {0};
  size_t written = 99U;

  const pbns_recovery_request original = request;
  memset(request.request_id, 0, sizeof(request.request_id));
  assert(pbns_recovery_request_encode(
             &request, (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
         PBNS_ERR_ARGUMENT);
  assert(written == 0U);
  request = original;
  memset(request.host_fingerprint, 0, sizeof(request.host_fingerprint));
  assert(pbns_recovery_request_encode(
             &request, (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
         PBNS_ERR_ARGUMENT);
  request = original;
  memset(request.nonce, 0, sizeof(request.nonce));
  assert(pbns_recovery_request_encode(
             &request, (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
         PBNS_ERR_ARGUMENT);
  request = original;
  memset(request.artifact_digest, 0, sizeof(request.artifact_digest));
  assert(pbns_recovery_request_encode(
             &request, (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
         PBNS_ERR_ARGUMENT);
  request = original;
  request.operation = PBNS_RECOVERY_OPERATION_MANIFEST;
  assert(pbns_recovery_request_encode(
             &request, (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
         PBNS_ERR_ARGUMENT);
  request = valid_request(PBNS_RECOVERY_OPERATION_MANIFEST);
  request.artifact_digest[0] = 1U;
  assert(pbns_recovery_request_encode(
             &request, (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
         PBNS_ERR_ARGUMENT);
  request = original;
  request.operation = PBNS_RECOVERY_OPERATION_INVALID;
  assert(pbns_recovery_request_encode(
             &request, (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
         PBNS_ERR_ARGUMENT);
  request = original;
  assert(pbns_recovery_request_encode(
             &request, (pbns_buffer){output, 0U, 156U}, &written) ==
         PBNS_ERR_LIMIT);
}

static size_t locate_last_key(uint8_t *encoded, size_t length) {
  for (size_t index = length; index >= 3U; --index) {
    if (encoded[index - 3U] == 0x08U && encoded[index - 2U] == 0x58U &&
        encoded[index - 1U] == 0x20U) {
      return index - 3U;
    }
  }
  assert(false);
  return 0U;
}

static void expect_decode_failure(const uint8_t *encoded, size_t length) {
  uint8_t scratch[PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE] = {0};
  pbns_recovery_request decoded = {
      .operation = PBNS_RECOVERY_OPERATION_ARTIFACT,
  };
  assert(pbns_recovery_request_decode(
             (pbns_view){encoded, length},
             (pbns_buffer){scratch, 0U, sizeof(scratch)}, &decoded) != PBNS_OK);
  const pbns_recovery_request cleared = {0};
  assert_equal(&decoded, &cleared);
}

static void test_strict_decode_rejection(void) {
  uint8_t canonical[PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE] = {0};
  const size_t size = decode_hex(artifact_hex, canonical, sizeof(canonical));

  expect_decode_failure(canonical, size - 1U);

  uint8_t changed[PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE] = {0};
  memcpy(changed, canonical, size);
  changed[locate_last_key(changed, size)] = 0x09U;
  expect_decode_failure(changed, size);
  memcpy(changed, canonical, size);
  changed[locate_last_key(changed, size)] = 0x07U;
  expect_decode_failure(changed, size);

  uint8_t noncanonical[PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE] = {0};
  noncanonical[0] = 0xb8U;
  noncanonical[1] = 0x08U;
  memcpy(noncanonical + 2U, canonical + 1U, size - 1U);
  expect_decode_failure(noncanonical, size + 1U);

  memcpy(changed, canonical, size);
  changed[33U] = 0x03U;
  expect_decode_failure(changed, size);

  uint8_t short_scratch[156] = {0};
  pbns_recovery_request decoded = {0};
  assert(pbns_recovery_request_decode(
             (pbns_view){canonical, size},
             (pbns_buffer){short_scratch, 0U, sizeof(short_scratch)},
             &decoded) == PBNS_ERR_LIMIT);
}

static void test_arguments(void) {
  pbns_recovery_request request =
      valid_request(PBNS_RECOVERY_OPERATION_ARTIFACT);
  uint8_t output[PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE] = {0};
  size_t written = 1U;
  assert(pbns_recovery_request_encode(
             NULL, (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
         PBNS_ERR_ARGUMENT);
  assert(written == 0U);
  assert(pbns_recovery_request_encode(&request,
                                      (pbns_buffer){NULL, 0U, sizeof(output)},
                                      &written) == PBNS_ERR_ARGUMENT);
  assert(pbns_recovery_request_encode(
             &request, (pbns_buffer){output, 0U, sizeof(output)}, NULL) ==
         PBNS_ERR_ARGUMENT);

  pbns_recovery_request decoded = request;
  uint8_t scratch[PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE] = {0};
  assert(pbns_recovery_request_decode(
             (pbns_view){NULL, 1U},
             (pbns_buffer){scratch, 0U, sizeof(scratch)}, &decoded) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_recovery_request_decode(
             (pbns_view){output, 1U},
             (pbns_buffer){NULL, 0U, sizeof(scratch)}, &decoded) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_recovery_request_decode(
             (pbns_view){output, 1U},
             (pbns_buffer){scratch, 0U, sizeof(scratch)}, NULL) ==
         PBNS_ERR_ARGUMENT);
}

int main(void) {
  test_exact_vectors_and_round_trip();
  test_shape_rejection();
  test_strict_decode_rejection();
  test_arguments();
  return 0;
}
