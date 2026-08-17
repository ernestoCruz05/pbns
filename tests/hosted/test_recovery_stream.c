#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "pbns/recovery_stream.h"

typedef struct test_hash {
  EVP_MD_CTX *context;
  bool fail_begin;
  bool fail_update;
  bool fail_finish;
  size_t clear_count;
} test_hash;

static pbns_status hash_begin(void *context) {
  test_hash *hash = context;
  if (hash->fail_begin ||
      EVP_DigestInit_ex(hash->context, EVP_sha256(), NULL) != 1) {
    return PBNS_ERR_CRYPTO;
  }
  return PBNS_OK;
}

static pbns_status hash_update(void *context, pbns_view data) {
  test_hash *hash = context;
  if (hash->fail_update ||
      EVP_DigestUpdate(hash->context, data.ptr, data.len) != 1) {
    return PBNS_ERR_CRYPTO;
  }
  return PBNS_OK;
}

static pbns_status hash_finish(void *context, uint8_t digest[32]) {
  test_hash *hash = context;
  unsigned int written = 0U;
  if (hash->fail_finish ||
      EVP_DigestFinal_ex(hash->context, digest, &written) != 1 ||
      written != 32U) {
    return PBNS_ERR_CRYPTO;
  }
  return PBNS_OK;
}

static void hash_clear(void *context) {
  test_hash *hash = context;
  ++hash->clear_count;
  EVP_MD_CTX_reset(hash->context);
}

static const pbns_recovery_hash_ops hash_ops = {
    hash_begin,
    hash_update,
    hash_finish,
    hash_clear,
};

static pbns_request_id request_id(uint8_t first) {
  pbns_request_id request = {{0}};
  for (size_t index = 0U; index < sizeof(request.bytes); ++index) {
    request.bytes[index] = (uint8_t)(first + (uint8_t)index);
  }
  return request;
}

static pbns_frame frame(pbns_request_id request, pbns_message_type type,
                        uint32_t sequence) {
  return (pbns_frame){PBNS_SERVICE_RECOVERY_ARTIFACT, type, 0U, request,
                      sequence};
}

static void digest(const uint8_t *data, size_t size, uint8_t output[32]) {
  unsigned int written = 0U;
  assert(EVP_Digest(data, size, output, &written, EVP_sha256(), NULL) == 1);
  assert(written == 32U);
}

static void test_size(size_t image_size) {
  uint8_t *source = malloc(image_size);
  uint8_t *pages = calloc(image_size, 1U);
  assert(source != NULL);
  assert(pages != NULL);
  for (size_t index = 0U; index < image_size; ++index) {
    source[index] = (uint8_t)(index * 37U + 11U);
  }
  uint8_t expected[32] = {0};
  digest(source, image_size, expected);
  test_hash hash = {EVP_MD_CTX_new(), false, false, false, 0U};
  assert(hash.context != NULL);
  const pbns_request_id request = request_id(0x10U);
  pbns_recovery_stream stream = {0};
  assert(pbns_recovery_stream_init(&stream, request,
                                   (pbns_buffer){pages, 0U, image_size},
                                   expected, &hash_ops, &hash) == PBNS_OK);
  uint32_t sequence = 0U;
  size_t offset = 0U;
  size_t acknowledgements = 0U;
  while (offset < image_size) {
    const size_t remaining = image_size - offset;
    const size_t chunk = remaining > PBNS_RECOVERY_MANIFEST_CHUNK_SIZE
                             ? PBNS_RECOVERY_MANIFEST_CHUNK_SIZE
                             : remaining;
    const pbns_frame data = frame(request, PBNS_MESSAGE_DATA, sequence);
    pbns_recovery_ack ack = {0};
    assert(pbns_recovery_stream_accept(&stream, &data,
                                       (pbns_view){source + offset, chunk},
                                       &ack) == PBNS_OK);
    if (ack.required) {
      ++acknowledgements;
      assert(ack.next_sequence == sequence + 1U);
      assert(ack.window == 8U);
    }
    offset += chunk;
    ++sequence;
  }
  const pbns_frame complete = frame(request, PBNS_MESSAGE_COMPLETE, sequence);
  assert(pbns_recovery_stream_complete(&stream, &complete,
                                       (pbns_view){NULL, 0U}) == PBNS_OK);
  assert(stream.complete);
  assert(memcmp(source, pages, image_size) == 0);
  assert(acknowledgements == sequence / 8U);
  assert(hash.clear_count == 1U);
  pbns_recovery_stream_reset(&stream);
  for (size_t index = 0U; index < image_size; ++index) {
    assert(pages[index] == 0U);
  }
  assert(!stream.initialized);
  EVP_MD_CTX_free(hash.context);
  free(pages);
  free(source);
}

static void test_supported_sizes(void) {
  static const size_t sizes[] = {1U, 16383U, 16384U, 16385U, 1024U * 1024U};
  for (size_t index = 0U; index < sizeof(sizes) / sizeof(sizes[0]); ++index) {
    test_size(sizes[index]);
  }
}

static void test_shape_sequence_and_binding_failures(void) {
  uint8_t pages[16385] = {0};
  uint8_t source[16385] = {0};
  uint8_t expected[32] = {0};
  digest(source, sizeof(source), expected);
  const pbns_request_id request = request_id(0x20U);
  test_hash hash = {EVP_MD_CTX_new(), false, false, false, 0U};
  assert(hash.context != NULL);
  pbns_recovery_stream stream = {0};
  assert(pbns_recovery_stream_init(&stream, request,
                                   (pbns_buffer){pages, 0U, sizeof(pages)},
                                   expected, &hash_ops, &hash) == PBNS_OK);
  pbns_recovery_ack ack = {0};
  pbns_frame data = frame(request, PBNS_MESSAGE_DATA, 0U);
  assert(pbns_recovery_stream_accept(&stream, &data,
                                     (pbns_view){source, 16383U},
                                     &ack) == PBNS_ERR_FORMAT);
  assert(stream.failed);
  pbns_recovery_stream_reset(&stream);

  assert(pbns_recovery_stream_init(&stream, request,
                                   (pbns_buffer){pages, 0U, sizeof(pages)},
                                   expected, &hash_ops, &hash) == PBNS_OK);
  data.sequence = 1U;
  assert(pbns_recovery_stream_accept(
             &stream, &data,
             (pbns_view){source, PBNS_RECOVERY_MANIFEST_CHUNK_SIZE},
             &ack) == PBNS_ERR_SEQUENCE);
  pbns_recovery_stream_reset(&stream);

  assert(pbns_recovery_stream_init(&stream, request,
                                   (pbns_buffer){pages, 0U, sizeof(pages)},
                                   expected, &hash_ops, &hash) == PBNS_OK);
  data = frame(request_id(0x21U), PBNS_MESSAGE_DATA, 0U);
  assert(pbns_recovery_stream_accept(
             &stream, &data,
             (pbns_view){source, PBNS_RECOVERY_MANIFEST_CHUNK_SIZE},
             &ack) == PBNS_ERR_STATE);
  pbns_recovery_stream_reset(&stream);

  assert(pbns_recovery_stream_init(&stream, request,
                                   (pbns_buffer){pages, 0U, sizeof(pages)},
                                   expected, &hash_ops, &hash) == PBNS_OK);
  data = frame(request, PBNS_MESSAGE_DATA, 0U);
  data.service = PBNS_SERVICE_TRUSTED_TIME;
  assert(pbns_recovery_stream_accept(
             &stream, &data,
             (pbns_view){source, PBNS_RECOVERY_MANIFEST_CHUNK_SIZE},
             &ack) == PBNS_ERR_SERVICE);
  EVP_MD_CTX_free(hash.context);
}

static void test_early_complete_digest_and_hash_failures(void) {
  uint8_t pages[1] = {0};
  static const uint8_t source[] = {0x5aU};
  uint8_t expected[32] = {0};
  digest(source, sizeof(source), expected);
  const pbns_request_id request = request_id(0x30U);
  test_hash hash = {EVP_MD_CTX_new(), false, false, false, 0U};
  assert(hash.context != NULL);
  pbns_recovery_stream stream = {0};
  pbns_frame complete = frame(request, PBNS_MESSAGE_COMPLETE, 0U);
  assert(pbns_recovery_stream_init(&stream, request,
                                   (pbns_buffer){pages, 0U, sizeof(pages)},
                                   expected, &hash_ops, &hash) == PBNS_OK);
  assert(pbns_recovery_stream_complete(
             &stream, &complete, (pbns_view){NULL, 0U}) == PBNS_ERR_STATE);
  pbns_recovery_stream_reset(&stream);

  pbns_frame data = frame(request, PBNS_MESSAGE_DATA, 0U);
  pbns_recovery_ack ack = {0};
  assert(pbns_recovery_stream_init(&stream, request,
                                   (pbns_buffer){pages, 0U, sizeof(pages)},
                                   expected, &hash_ops, &hash) == PBNS_OK);
  assert(pbns_recovery_stream_accept(&stream, &data,
                                     (pbns_view){source, sizeof(source)},
                                     &ack) == PBNS_OK);
  data.sequence = 1U;
  assert(pbns_recovery_stream_accept(&stream, &data,
                                     (pbns_view){source, sizeof(source)},
                                     &ack) == PBNS_ERR_FORMAT);
  pbns_recovery_stream_reset(&stream);

  expected[0] ^= 1U;
  data.sequence = 0U;
  assert(pbns_recovery_stream_init(&stream, request,
                                   (pbns_buffer){pages, 0U, sizeof(pages)},
                                   expected, &hash_ops, &hash) == PBNS_OK);
  assert(pbns_recovery_stream_accept(&stream, &data,
                                     (pbns_view){source, sizeof(source)},
                                     &ack) == PBNS_OK);
  complete.sequence = 1U;
  assert(pbns_recovery_stream_complete(&stream, &complete,
                                       (pbns_view){NULL, 0U}) ==
         PBNS_ERR_AUTHENTICATION);
  pbns_recovery_stream_reset(&stream);

  expected[0] ^= 1U;
  hash.fail_finish = true;
  assert(pbns_recovery_stream_init(&stream, request,
                                   (pbns_buffer){pages, 0U, sizeof(pages)},
                                   expected, &hash_ops, &hash) == PBNS_OK);
  assert(pbns_recovery_stream_accept(&stream, &data,
                                     (pbns_view){source, sizeof(source)},
                                     &ack) == PBNS_OK);
  assert(pbns_recovery_stream_complete(
             &stream, &complete, (pbns_view){NULL, 0U}) == PBNS_ERR_CRYPTO);
  pbns_recovery_stream_reset(&stream);

  hash.fail_finish = false;
  hash.fail_update = true;
  assert(pbns_recovery_stream_init(&stream, request,
                                   (pbns_buffer){pages, 0U, sizeof(pages)},
                                   expected, &hash_ops, &hash) == PBNS_OK);
  assert(pbns_recovery_stream_accept(&stream, &data,
                                     (pbns_view){source, sizeof(source)},
                                     &ack) == PBNS_ERR_CRYPTO);
  assert(pages[0] == 0U);
  EVP_MD_CTX_free(hash.context);
}

static void test_cancellation_and_invalid_initialization(void) {
  uint8_t page = 0U;
  uint8_t expected[32] = {1U};
  const pbns_request_id request = request_id(0x40U);
  test_hash hash = {EVP_MD_CTX_new(), false, false, false, 0U};
  assert(hash.context != NULL);
  pbns_recovery_stream stream = {0};
  assert(pbns_recovery_stream_init(&stream, request,
                                   (pbns_buffer){&page, 0U, 1U}, expected,
                                   &hash_ops, &hash) == PBNS_OK);
  const pbns_frame cancel = frame(request, PBNS_MESSAGE_CANCEL, 0U);
  pbns_recovery_ack ack = {0};
  assert(pbns_recovery_stream_accept(&stream, &cancel, (pbns_view){NULL, 0U},
                                     &ack) == PBNS_ERR_TRANSPORT);
  const size_t clears_after_cancel = hash.clear_count;
  pbns_recovery_stream_reset(&stream);
  assert(hash.clear_count == clears_after_cancel);
  memset(expected, 0, sizeof(expected));
  assert(pbns_recovery_stream_init(&stream, request,
                                   (pbns_buffer){&page, 0U, 1U}, expected,
                                   &hash_ops, &hash) == PBNS_ERR_ARGUMENT);
  hash.fail_begin = true;
  expected[0] = 1U;
  assert(pbns_recovery_stream_init(&stream, request,
                                   (pbns_buffer){&page, 0U, 1U}, expected,
                                   &hash_ops, &hash) == PBNS_ERR_CRYPTO);
  EVP_MD_CTX_free(hash.context);
}

int main(void) {
  test_supported_sizes();
  test_shape_sequence_and_binding_failures();
  test_early_complete_digest_and_hash_failures();
  test_cancellation_and_invalid_initialization();
  return 0;
}
