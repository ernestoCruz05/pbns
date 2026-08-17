#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "recovery_service_adapter.h"

#define RECORDS 8U

typedef struct stream_fake {
  pbns_request_id request_id;
  uint8_t data[PBNS_RECOVERY_MANIFEST_CHUNK_SIZE];
  size_t record;
  size_t begin_calls;
  size_t cancel_calls;
  size_t finish_calls;
  size_t ack_calls;
  uint32_t ack_sequence;
  uint32_t ack_window;
  bool fail_receive;
} stream_fake;

typedef struct hash_fake {
  uint8_t digest[PBNS_RECOVERY_MANIFEST_DIGEST_SIZE];
  size_t clears;
} hash_fake;

typedef struct rollback_fake {
  uint64_t version;
  size_t reads;
  size_t advances;
  uint64_t mismatch_on_read;
  uint64_t post_write_mismatch;
  pbns_view authorization;
} rollback_fake;

typedef struct nvram_fake {
  uint8_t records[PBNS_ANTI_ROLLBACK_SLOT_COUNT]
                 [PBNS_ANTI_ROLLBACK_RECORD_SIZE];
  bool present[PBNS_ANTI_ROLLBACK_SLOT_COUNT];
} nvram_fake;

static pbns_status random_fill(void *context, pbns_buffer output) {
  (void)context;
  memset(output.ptr, 0x5a, output.cap);
  return PBNS_OK;
}

static pbns_status sign_request(void *context, pbns_view payload, pbns_view aad,
                                pbns_buffer output, size_t *written) {
  (void)context;
  (void)aad;
  if (payload.len > output.cap) {
    return PBNS_ERR_LIMIT;
  }
  memcpy(output.ptr, payload.ptr, payload.len);
  *written = payload.len;
  return PBNS_OK;
}

static pbns_status unused_exchange(void *context, const pbns_request_id *request_id,
                                   pbns_view request, pbns_buffer output,
                                   size_t *written) {
  (void)context;
  (void)request_id;
  (void)request;
  (void)output;
  (void)written;
  return PBNS_ERR_STATE;
}

static pbns_status unused_verify(void *context, pbns_view signed_manifest,
                                 pbns_view aad, pbns_view *payload) {
  (void)context;
  (void)signed_manifest;
  (void)aad;
  (void)payload;
  return PBNS_ERR_STATE;
}

static pbns_status bulk_begin(void *context, const pbns_request_id *request_id,
                              pbns_view signed_request, uint64_t exact_size) {
  stream_fake *fake = context;
  assert(signed_request.len > 0U);
  assert(exact_size == (uint64_t)RECORDS * PBNS_RECOVERY_MANIFEST_CHUNK_SIZE);
  fake->request_id = *request_id;
  fake->record = 0U;
  ++fake->begin_calls;
  return PBNS_OK;
}

static pbns_status bulk_receive(void *context, pbns_frame *frame,
                                pbns_view *payload) {
  stream_fake *fake = context;
  if (fake->fail_receive && fake->record == 1U) {
    return PBNS_ERR_IO;
  }
  *frame = (pbns_frame){
      .service = PBNS_SERVICE_RECOVERY_ARTIFACT,
      .request_id = fake->request_id,
      .sequence = (uint32_t)fake->record,
      .type = fake->record == RECORDS ? PBNS_MESSAGE_COMPLETE : PBNS_MESSAGE_DATA,
  };
  *payload = fake->record == RECORDS
                 ? (pbns_view){NULL, 0U}
                 : (pbns_view){fake->data, sizeof(fake->data)};
  ++fake->record;
  return PBNS_OK;
}

static pbns_status bulk_ack(void *context, uint32_t next_sequence,
                            uint32_t window) {
  stream_fake *fake = context;
  ++fake->ack_calls;
  fake->ack_sequence = next_sequence;
  fake->ack_window = window;
  return PBNS_OK;
}

static pbns_status bulk_finish(void *context) {
  stream_fake *fake = context;
  ++fake->finish_calls;
  return PBNS_OK;
}

static pbns_status bulk_cancel(void *context) {
  stream_fake *fake = context;
  ++fake->cancel_calls;
  return PBNS_OK;
}

static pbns_status hash_begin(void *context) {
  (void)context;
  return PBNS_OK;
}

static pbns_status hash_update(void *context, pbns_view data) {
  (void)context;
  return data.len == PBNS_RECOVERY_MANIFEST_CHUNK_SIZE ? PBNS_OK : PBNS_ERR_FORMAT;
}

static pbns_status hash_finish(void *context, uint8_t digest[32]) {
  const hash_fake *fake = context;
  memcpy(digest, fake->digest, sizeof(fake->digest));
  return PBNS_OK;
}

static void hash_clear(void *context) {
  hash_fake *fake = context;
  ++fake->clears;
}

static const pbns_recovery_hash_ops HASH_OPS = {
    .begin = hash_begin,
    .update = hash_update,
    .finish = hash_finish,
    .clear = hash_clear,
};

static pbns_recovery_manifest stream_manifest(const uint8_t digest[32]) {
  static const uint8_t authorization[] = {1U};
  static const uint8_t key_id[] = {'p'};
  pbns_recovery_manifest manifest = {
      .artifact_version = 2U,
      .minimum_version = 1U,
      .image_size = (uint64_t)RECORDS * PBNS_RECOVERY_MANIFEST_CHUNK_SIZE,
      .chunk_size = PBNS_RECOVERY_MANIFEST_CHUNK_SIZE,
      .not_before_ns = 1,
      .not_after_ns = 2,
      .policy_authorization = {authorization, sizeof(authorization)},
      .policy_key_id = {key_id, sizeof(key_id)},
  };
  memset(manifest.request_id, 1, sizeof(manifest.request_id));
  memset(manifest.host_binding, 2, sizeof(manifest.host_binding));
  memset(manifest.nonce, 3, sizeof(manifest.nonce));
  memcpy(manifest.artifact_digest, digest, sizeof(manifest.artifact_digest));
  return manifest;
}

static bool bytes_zero(const uint8_t *bytes, size_t length) {
  for (size_t index = 0U; index < length; ++index) {
    if (bytes[index] != 0U) {
      return false;
    }
  }
  return true;
}

static void test_stream(void) {
  uint8_t pages[RECORDS * PBNS_RECOVERY_MANIFEST_CHUNK_SIZE] = {0};
  stream_fake fake = {0};
  hash_fake hash = {.digest = {9U}};
  memset(fake.data, 0xa5, sizeof(fake.data));
  const pbns_recovery_live_client client = {
      .random_fill = random_fill,
      .sign_request = sign_request,
      .manifest_exchange = unused_exchange,
      .verify_manifest = unused_verify,
      .bulk_begin = bulk_begin,
      .bulk_receive = bulk_receive,
      .bulk_ack = bulk_ack,
      .bulk_finish = bulk_finish,
      .bulk_cancel = bulk_cancel,
      .hash_ops = &HASH_OPS,
      .context = &fake,
      .hash_context = &hash,
      .manifest_key_id = {(const uint8_t *)"m", 1U},
      .policy_key_id = {(const uint8_t *)"p", 1U},
  };
  const pbns_recovery_manifest manifest = stream_manifest(hash.digest);
  pbns_recovery_live_workspace workspace = {0};
  pbns_recovery_service_manifest_state state = {0};
  assert(pbns_recovery_service_manifest_set(&state, &manifest) == PBNS_OK);
  assert(pbns_recovery_service_stream(&client, &state,
                                      (pbns_buffer){pages, 0U, sizeof(pages)},
                                      &workspace) == PBNS_OK);
  assert(state.ready && state.manifest.artifact_version == manifest.artifact_version);
  assert(fake.begin_calls == 1U && fake.finish_calls == 1U &&
         fake.cancel_calls == 0U && fake.ack_calls == 1U &&
         fake.ack_sequence == RECORDS && fake.ack_window == RECORDS);
  for (size_t index = 0U; index < sizeof(pages); ++index) {
    assert(pages[index] == 0xa5U);
  }
  assert(pbns_recovery_service_stream(&client, &state,
                                      (pbns_buffer){pages, 0U, sizeof(pages) - 1U},
                                      &workspace) == PBNS_ERR_ARGUMENT);
  assert(!state.ready);
  assert(pbns_recovery_service_manifest_set(&state, &manifest) == PBNS_OK);
  fake.fail_receive = true;
  assert(pbns_recovery_service_stream(&client, &state,
                                      (pbns_buffer){pages, 0U, sizeof(pages)},
                                      &workspace) == PBNS_ERR_IO);
  assert(!state.ready && state.manifest.artifact_version == 0U &&
         state.manifest.policy_authorization.ptr == NULL &&
         bytes_zero((const uint8_t *)&workspace, sizeof(workspace)));
  assert(fake.cancel_calls == 1U && hash.clears > 0U);
  for (size_t index = 0U; index < sizeof(pages); ++index) {
    assert(pages[index] == 0U);
  }
  fake.fail_receive = false;
  assert(pbns_recovery_service_manifest_set(&state, &manifest) == PBNS_OK);
  assert(pbns_recovery_service_stream(&client, &state,
                                      (pbns_buffer){pages, 0U, sizeof(pages)},
                                      &workspace) == PBNS_OK);
  assert(fake.begin_calls == 3U && fake.request_id.bytes[0] != 0U);
}

static pbns_status rollback_read(void *context, uint64_t *version) {
  rollback_fake *fake = context;
  ++fake->reads;
  *version = fake->post_write_mismatch != 0U && fake->reads >= 5U
                 ? fake->post_write_mismatch
                 : (fake->mismatch_on_read != 0U && fake->reads > 1U
                        ? fake->mismatch_on_read
                        : fake->version);
  return PBNS_OK;
}

static pbns_status rollback_advance(void *context, uint64_t current,
                                    uint64_t target, pbns_view authorization) {
  rollback_fake *fake = context;
  assert(current == fake->version);
  fake->authorization = authorization;
  ++fake->advances;
  fake->version = target;
  return PBNS_OK;
}

static pbns_status nvram_read(void *context, size_t slot,
                                 uint8_t record[PBNS_ANTI_ROLLBACK_RECORD_SIZE],
                                 bool *present) {
  nvram_fake *fake = context;
  if (slot >= PBNS_ANTI_ROLLBACK_SLOT_COUNT) {
    return PBNS_ERR_ARGUMENT;
  }
  memcpy(record, fake->records[slot], PBNS_ANTI_ROLLBACK_RECORD_SIZE);
  *present = fake->present[slot];
  return PBNS_OK;
}

static pbns_status nvram_write(void *context, size_t slot, pbns_view record) {
  nvram_fake *fake = context;
  if (slot >= PBNS_ANTI_ROLLBACK_SLOT_COUNT ||
      record.len != PBNS_ANTI_ROLLBACK_RECORD_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  memcpy(fake->records[slot], record.ptr, record.len);
  fake->present[slot] = true;
  return PBNS_OK;
}

static void test_manifest_lifecycle(void) {
  pbns_recovery_service_manifest_state state = {0};
  pbns_recovery_live_workspace workspace;
  const uint8_t digest[32] = {9U};
  const pbns_recovery_manifest manifest = stream_manifest(digest);
  memset(&workspace, 0xa5, sizeof(workspace));
  assert(pbns_recovery_service_manifest_set(&state, &manifest) == PBNS_OK);
  pbns_recovery_service_manifest_invalidate(&state, &workspace);
  assert(!state.ready && state.manifest.artifact_version == 0U &&
         state.manifest.policy_authorization.ptr == NULL &&
         bytes_zero((const uint8_t *)&workspace, sizeof(workspace)));
  memset(&workspace, 0x5a, sizeof(workspace));
  assert(pbns_recovery_service_manifest_set(&state, &manifest) == PBNS_OK);
  pbns_recovery_service_manifest_invalidate(&state, &workspace);
  assert(!state.ready && bytes_zero((const uint8_t *)&workspace,
                                    sizeof(workspace)));
}

static void test_rollback(void) {
  static const uint8_t authorization[] = {7U, 8U};
  pbns_recovery_service_manifest_state state = {
      .manifest = {.artifact_version = 6U},
      .ready = true,
  };
  rollback_fake fake = {.version = 5U};
  pbns_anti_rollback controller = {0};
  assert(pbns_anti_rollback_init_tpm(&controller, rollback_read, rollback_advance,
                                     &fake) == PBNS_OK);
  pbns_recovery_service_rollback rollback = {
      .mode = PBNS_RECOVERY_ASSURANCE_T,
      .controller = &controller,
  };
  uint64_t current = 0U;
  assert(pbns_recovery_service_rollback_read(&rollback, &current) == PBNS_OK);
  assert(current == 5U);
  assert(pbns_recovery_service_rollback_advance(
             &rollback, &state, 5U, 6U,
             (pbns_view){authorization, sizeof(authorization)}) == PBNS_OK);
  assert(fake.advances == 1U && fake.authorization.ptr == authorization &&
         fake.authorization.len == sizeof(authorization));
  state.manifest.artifact_version = 7U;
  assert(pbns_recovery_service_rollback_advance(
             &rollback, &state, 5U, 7U,
             (pbns_view){authorization, sizeof(authorization)}) == PBNS_ERR_REPLAY);

  fake.version = 8U;
  fake.reads = 0U;
  fake.mismatch_on_read = 9U;
  rollback.retained_valid = false;
  assert(pbns_recovery_service_rollback_read(&rollback, &current) == PBNS_OK);
  state.manifest.artifact_version = 10U;
  assert(pbns_recovery_service_rollback_advance(
             &rollback, &state, 8U, 10U,
             (pbns_view){authorization, sizeof(authorization)}) == PBNS_ERR_REPLAY);
  assert(fake.advances == 1U);

  fake.version = 11U;
  fake.reads = 0U;
  fake.mismatch_on_read = 0U;
  fake.post_write_mismatch = 13U;
  fake.advances = 0U;
  rollback.retained_valid = false;
  state.manifest.artifact_version = 12U;
  assert(pbns_recovery_service_rollback_read(&rollback, &current) == PBNS_OK);
  assert(pbns_recovery_service_rollback_advance(
             &rollback, &state, 11U, 12U,
             (pbns_view){authorization, sizeof(authorization)}) == PBNS_ERR_STATE);
  assert(!rollback.retained_valid && fake.advances == 1U);

  nvram_fake nvram = {0};
  assert(pbns_anti_rollback_init_nvram(&controller, nvram_read, nvram_write,
                                       &nvram) == PBNS_OK);
  rollback = (pbns_recovery_service_rollback){
      .mode = PBNS_RECOVERY_ASSURANCE_S,
      .controller = &controller,
  };
  assert(pbns_recovery_service_rollback_read(&rollback, &current) == PBNS_OK);
  assert(current == 0U);
  state = (pbns_recovery_service_manifest_state){
      .manifest = {.artifact_version = 1U},
      .ready = true,
  };
  assert(pbns_recovery_service_rollback_advance(
             &rollback, &state, 0U, 2U,
             (pbns_view){authorization, sizeof(authorization)}) == PBNS_ERR_AUTHENTICATION);
  assert(pbns_recovery_service_rollback_advance(
             &rollback, &state, 0U, 1U,
             (pbns_view){authorization, sizeof(authorization)}) == PBNS_OK);
  assert(pbns_recovery_service_rollback_read(&rollback, &current) == PBNS_OK);
  assert(current == 1U);
}

int main(void) {
  test_stream();
  test_manifest_lifecycle();
  test_rollback();
  return 0;
}
