#include "pbns/recovery_stream.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define PBNS_RECOVERY_ACK_WINDOW UINT32_C(8)

static bool view_valid(pbns_view value) {
  return value.ptr != NULL || value.len == 0U;
}

static bool request_equal(pbns_request_id left, pbns_request_id right) {
  uint8_t difference = 0U;
  for (size_t index = 0U; index < sizeof(left.bytes); ++index) {
    difference |= (uint8_t)(left.bytes[index] ^ right.bytes[index]);
  }
  return difference == 0U;
}

static bool digest_equal(const uint8_t *left, const uint8_t *right) {
  uint8_t difference = 0U;
  for (size_t index = 0U; index < PBNS_RECOVERY_MANIFEST_DIGEST_SIZE; ++index) {
    difference |= (uint8_t)(left[index] ^ right[index]);
  }
  return difference == 0U;
}

static bool digest_nonzero(const uint8_t *digest) {
  uint8_t combined = 0U;
  for (size_t index = 0U; index < PBNS_RECOVERY_MANIFEST_DIGEST_SIZE; ++index) {
    combined |= digest[index];
  }
  return combined != 0U;
}

static pbns_status fail(pbns_recovery_stream *stream, pbns_status status) {
  stream->failed = true;
  if (stream->hash_active && stream->hash_ops != NULL &&
      stream->hash_ops->clear != NULL) {
    stream->hash_ops->clear(stream->hash_context);
    stream->hash_active = false;
  }
  return status;
}

static pbns_status validate_frame(const pbns_recovery_stream *stream,
                                  const pbns_frame *frame) {
  if (frame->service != PBNS_SERVICE_RECOVERY_ARTIFACT) {
    return PBNS_ERR_SERVICE;
  }
  if (!request_equal(frame->request_id, stream->request_id)) {
    return PBNS_ERR_STATE;
  }
  if (frame->flags != 0U) {
    return PBNS_ERR_FORMAT;
  }
  if (frame->sequence != stream->next_sequence ||
      stream->next_sequence == UINT32_MAX) {
    return PBNS_ERR_SEQUENCE;
  }
  return PBNS_OK;
}

pbns_status pbns_recovery_stream_init(
    pbns_recovery_stream *stream, pbns_request_id request_id,
    pbns_buffer exact_pages,
    const uint8_t expected_digest[PBNS_RECOVERY_MANIFEST_DIGEST_SIZE],
    const pbns_recovery_hash_ops *hash_ops, void *hash_context) {
  if (stream != NULL) {
    *stream = (pbns_recovery_stream){0};
  }
  if (stream == NULL || exact_pages.ptr == NULL || exact_pages.len != 0U ||
      exact_pages.cap == 0U ||
      exact_pages.cap > (size_t)PBNS_RECOVERY_MANIFEST_IMAGE_MAX ||
      expected_digest == NULL || !digest_nonzero(expected_digest) ||
      hash_ops == NULL || hash_ops->begin == NULL || hash_ops->update == NULL ||
      hash_ops->finish == NULL || hash_ops->clear == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status status = hash_ops->begin(hash_context);
  if (status != PBNS_OK) {
    hash_ops->clear(hash_context);
    return status;
  }
  stream->request_id = request_id;
  stream->pages = exact_pages.ptr;
  stream->image_size = exact_pages.cap;
  memcpy(stream->expected_digest, expected_digest,
         sizeof(stream->expected_digest));
  stream->hash_ops = hash_ops;
  stream->hash_context = hash_context;
  stream->hash_active = true;
  stream->initialized = true;
  return PBNS_OK;
}

pbns_status pbns_recovery_stream_accept(pbns_recovery_stream *stream,
                                        const pbns_frame *frame,
                                        pbns_view payload,
                                        pbns_recovery_ack *ack) {
  if (ack != NULL) {
    *ack = (pbns_recovery_ack){0};
  }
  if (stream == NULL || frame == NULL || !view_valid(payload) || ack == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!stream->initialized || stream->complete || stream->failed) {
    return PBNS_ERR_STATE;
  }
  pbns_status status = validate_frame(stream, frame);
  if (status != PBNS_OK) {
    return fail(stream, status);
  }
  if (frame->type == PBNS_MESSAGE_CANCEL || frame->type == PBNS_MESSAGE_ERROR) {
    return fail(stream, PBNS_ERR_TRANSPORT);
  }
  if (frame->type != PBNS_MESSAGE_DATA) {
    return fail(stream, PBNS_ERR_MESSAGE_TYPE);
  }
  if (payload.len == 0U || payload.len > PBNS_RECOVERY_MANIFEST_CHUNK_SIZE ||
      stream->offset > stream->image_size) {
    return fail(stream, PBNS_ERR_FORMAT);
  }
  const size_t remaining = stream->image_size - stream->offset;
  const size_t expected = remaining > PBNS_RECOVERY_MANIFEST_CHUNK_SIZE
                              ? PBNS_RECOVERY_MANIFEST_CHUNK_SIZE
                              : remaining;
  if (expected == 0U || payload.len != expected) {
    return fail(stream, PBNS_ERR_FORMAT);
  }
  status = stream->hash_ops->update(stream->hash_context, payload);
  if (status != PBNS_OK) {
    return fail(stream, status);
  }
  memcpy(stream->pages + stream->offset, payload.ptr, payload.len);
  stream->offset += payload.len;
  ++stream->next_sequence;
  ++stream->records_since_ack;
  if (stream->records_since_ack == PBNS_RECOVERY_ACK_WINDOW) {
    ack->required = true;
    ack->next_sequence = stream->next_sequence;
    ack->window = PBNS_RECOVERY_ACK_WINDOW;
    stream->records_since_ack = 0U;
  }
  return PBNS_OK;
}

pbns_status pbns_recovery_stream_complete(pbns_recovery_stream *stream,
                                          const pbns_frame *frame,
                                          pbns_view payload) {
  if (stream == NULL || frame == NULL || !view_valid(payload)) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!stream->initialized || stream->complete || stream->failed) {
    return PBNS_ERR_STATE;
  }
  pbns_status status = validate_frame(stream, frame);
  if (status != PBNS_OK) {
    return fail(stream, status);
  }
  if (frame->type != PBNS_MESSAGE_COMPLETE || payload.len != 0U) {
    return fail(stream, PBNS_ERR_MESSAGE_TYPE);
  }
  if (stream->offset != stream->image_size) {
    return fail(stream, PBNS_ERR_STATE);
  }
  uint8_t digest[PBNS_RECOVERY_MANIFEST_DIGEST_SIZE] = {0};
  status = stream->hash_ops->finish(stream->hash_context, digest);
  if (status != PBNS_OK) {
    memset(digest, 0, sizeof(digest));
    return fail(stream, status);
  }
  if (!digest_equal(digest, stream->expected_digest)) {
    memset(digest, 0, sizeof(digest));
    return fail(stream, PBNS_ERR_AUTHENTICATION);
  }
  memset(digest, 0, sizeof(digest));
  stream->hash_ops->clear(stream->hash_context);
  stream->hash_active = false;
  ++stream->next_sequence;
  stream->complete = true;
  return PBNS_OK;
}

void pbns_recovery_stream_reset(pbns_recovery_stream *stream) {
  if (stream == NULL) {
    return;
  }
  if (stream->pages != NULL && stream->image_size > 0U) {
    memset(stream->pages, 0, stream->image_size);
  }
  if (stream->hash_active && stream->hash_ops != NULL &&
      stream->hash_ops->clear != NULL) {
    stream->hash_ops->clear(stream->hash_context);
  }
  *stream = (pbns_recovery_stream){0};
}
