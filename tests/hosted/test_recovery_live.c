#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/recovery_live.h"

typedef enum fake_view_mode {
  FAKE_VIEW_VALID = 0,
  FAKE_VIEW_EXTERNAL,
  FAKE_VIEW_NULL_NONZERO,
  FAKE_VIEW_EMPTY,
  FAKE_VIEW_END_CROSSING,
  FAKE_VIEW_OVERSIZED
} fake_view_mode;

typedef enum fake_stream_mode {
  FAKE_STREAM_VALID = 0,
  FAKE_STREAM_INVALID_PAYLOAD,
  FAKE_STREAM_EARLY_COMPLETE,
  FAKE_STREAM_SHORT_DATA,
  FAKE_STREAM_OVERSIZE_DATA,
  FAKE_STREAM_WRONG_ID,
  FAKE_STREAM_WRONG_SERVICE,
  FAKE_STREAM_WRONG_TYPE,
  FAKE_STREAM_FLAGS,
  FAKE_STREAM_SEQUENCE,
  FAKE_STREAM_NONEMPTY_COMPLETE
} fake_stream_mode;

typedef struct fake_hash {
  uint8_t state[PBNS_RECOVERY_MANIFEST_DIGEST_SIZE];
  size_t offset;
  bool fail_begin;
  bool fail_update;
  bool fail_finish;
} fake_hash;

typedef struct fixture {
  uint8_t source[PBNS_RECOVERY_MANIFEST_CHUNK_SIZE * 8U + 5U];
  uint8_t manifest_encoded[PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE];
  size_t manifest_size;
  pbns_recovery_manifest response_manifest;
  uint8_t external_payload[PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE];
  uint8_t policy[3];
  uint8_t manifest_kid[3];
  uint8_t policy_kid[3];
  pbns_recovery_request requests[16];
  pbns_request_id exchange_id;
  pbns_request_id begin_id;
  uint8_t request_aad[sizeof(PBNS_RECOVERY_REQUEST_AAD) - 1U];
  size_t request_aad_size;
  uint8_t manifest_aad[PBNS_RECOVERY_MANIFEST_AAD_MAX_SIZE];
  size_t manifest_aad_size;
  size_t random_calls;
  size_t sign_calls;
  size_t exchange_calls;
  size_t verify_calls;
  size_t begin_calls;
  size_t receive_calls;
  size_t ack_calls;
  size_t finish_calls;
  size_t cancel_calls;
  uint32_t ack_sequence[4];
  uint32_t ack_window[4];
  size_t record;
  uint32_t first_data_sequence;
  bool have_first_data;
  pbns_status random_status;
  size_t random_fail_call;
  size_t random_zero_call;
  pbns_status sign_status;
  pbns_status exchange_status;
  pbns_status verify_status;
  pbns_status begin_status;
  pbns_status receive_status;
  pbns_status ack_status;
  pbns_status finish_status;
  bool short_sign;
  bool zero_sign;
  bool short_exchange;
  bool zero_exchange;
  fake_view_mode view_mode;
  fake_stream_mode stream_mode;
  pbns_status cancel_status;
  fake_hash hash;
} fixture;

static void fake_digest(const uint8_t *data, size_t size,
                        uint8_t output[PBNS_RECOVERY_MANIFEST_DIGEST_SIZE]) {
  memset(output, 0, PBNS_RECOVERY_MANIFEST_DIGEST_SIZE);
  for (size_t index = 0U; index < size; ++index) {
    output[index % PBNS_RECOVERY_MANIFEST_DIGEST_SIZE] =
        (uint8_t)(output[index % PBNS_RECOVERY_MANIFEST_DIGEST_SIZE] +
                  data[index] + (uint8_t)index);
  }
}

static pbns_status hash_begin(void *context) {
  fake_hash *hash = context;
  memset(hash->state, 0, sizeof(hash->state));
  hash->offset = 0U;
  return hash->fail_begin ? PBNS_ERR_CRYPTO : PBNS_OK;
}

static pbns_status hash_update(void *context, pbns_view data) {
  fake_hash *hash = context;
  if (hash->fail_update) {
    return PBNS_ERR_CRYPTO;
  }
  for (size_t index = 0U; index < data.len; ++index) {
    const size_t position = (hash->offset + index) % sizeof(hash->state);
    hash->state[position] =
        (uint8_t)(hash->state[position] + data.ptr[index] + (uint8_t)(hash->offset + index));
  }
  hash->offset += data.len;
  return PBNS_OK;
}

static pbns_status hash_finish(void *context,
                               uint8_t digest[PBNS_RECOVERY_MANIFEST_DIGEST_SIZE]) {
  fake_hash *hash = context;
  if (hash->fail_finish) {
    return PBNS_ERR_CRYPTO;
  }
  memcpy(digest, hash->state, sizeof(hash->state));
  return PBNS_OK;
}

static void hash_clear(void *context) {
  fake_hash *hash = context;
  memset(hash->state, 0, sizeof(hash->state));
  hash->offset = 0U;
}

static const pbns_recovery_hash_ops hash_ops = {
    hash_begin,
    hash_update,
    hash_finish,
    hash_clear,
};

static pbns_status fake_random(void *context, pbns_buffer output) {
  fixture *fake = context;
  ++fake->random_calls;
  if (fake->random_status != PBNS_OK ||
      (fake->random_fail_call != 0U &&
       fake->random_calls == fake->random_fail_call)) {
    return fake->random_status == PBNS_OK ? PBNS_ERR_ENTROPY : fake->random_status;
  }
  assert(output.len == 0U);
  assert(output.ptr != NULL);
  assert(output.cap == PBNS_RECOVERY_REQUEST_ID_SIZE ||
         output.cap == PBNS_RECOVERY_REQUEST_NONCE_SIZE);
  if (fake->random_zero_call != fake->random_calls) {
    for (size_t index = 0U; index < output.cap; ++index) {
      output.ptr[index] = (uint8_t)(fake->random_calls * 17U + index + 1U);
    }
  }
  return PBNS_OK;
}

static pbns_status fake_sign(void *context, pbns_view payload, pbns_view aad,
                             pbns_buffer output, size_t *written) {
  fixture *fake = context;
  ++fake->sign_calls;
  assert(fake->sign_calls <= sizeof(fake->requests) / sizeof(fake->requests[0]));
  assert(aad.len == sizeof(PBNS_RECOVERY_REQUEST_AAD) - 1U);
  assert(memcmp(aad.ptr, PBNS_RECOVERY_REQUEST_AAD, aad.len) == 0);
  memcpy(fake->request_aad, aad.ptr, aad.len);
  fake->request_aad_size = aad.len;
  uint8_t scratch[PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE] = {0};
  assert(pbns_recovery_request_decode(payload, (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                      &fake->requests[fake->sign_calls - 1U]) == PBNS_OK);
  if (fake->sign_status != PBNS_OK) {
    return fake->sign_status;
  }
  if (output.cap < payload.len) {
    return PBNS_ERR_LIMIT;
  }
  memcpy(output.ptr, payload.ptr, payload.len);
  *written = fake->short_sign ? output.cap + 1U
             : fake->zero_sign ? 0U
             : payload.len;
  return PBNS_OK;
}

static pbns_status fake_exchange(void *context, const pbns_request_id *request_id,
                                 pbns_view signed_request, pbns_buffer output,
                                 size_t *written) {
  fixture *fake = context;
  ++fake->exchange_calls;
  assert(signed_request.len > 0U);
  fake->exchange_id = *request_id;
  if (fake->exchange_status != PBNS_OK) {
    return fake->exchange_status;
  }
  assert(output.cap >= fake->manifest_size);
  memcpy(output.ptr, fake->manifest_encoded, fake->manifest_size);
  *written = fake->short_exchange ? output.cap + 1U
             : fake->zero_exchange ? 0U
             : fake->manifest_size;
  return PBNS_OK;
}

static pbns_status fake_verify(void *context, pbns_view signed_manifest,
                               pbns_view aad, pbns_view *payload) {
  fixture *fake = context;
  ++fake->verify_calls;
  memcpy(fake->manifest_aad, aad.ptr, aad.len);
  fake->manifest_aad_size = aad.len;
  if (fake->verify_status != PBNS_OK) {
    return fake->verify_status;
  }
  switch (fake->view_mode) {
    case FAKE_VIEW_VALID:
      *payload = signed_manifest;
      break;
    case FAKE_VIEW_EXTERNAL:
      *payload = (pbns_view){fake->external_payload, fake->manifest_size};
      break;
    case FAKE_VIEW_NULL_NONZERO:
      *payload = (pbns_view){NULL, 1U};
      break;
    case FAKE_VIEW_EMPTY:
      *payload = (pbns_view){signed_manifest.ptr, 0U};
      break;
    case FAKE_VIEW_END_CROSSING:
      *payload = (pbns_view){signed_manifest.ptr + signed_manifest.len - 1U,
                             2U};
      break;
    case FAKE_VIEW_OVERSIZED:
      *payload = (pbns_view){signed_manifest.ptr,
                             signed_manifest.len + 1U};
      break;
  }
  return PBNS_OK;
}

static pbns_status fake_begin(void *context, const pbns_request_id *request_id,
                              pbns_view signed_request, uint64_t exact_size) {
  fixture *fake = context;
  ++fake->begin_calls;
  fake->begin_id = *request_id;
  assert(signed_request.len > 0U);
  assert(exact_size == sizeof(fake->source));
  return fake->begin_status;
}

static pbns_status fake_receive(void *context, pbns_frame *frame,
                                pbns_view *payload) {
  fixture *fake = context;
  ++fake->receive_calls;
  if (fake->receive_status != PBNS_OK) {
    return fake->receive_status;
  }
  if (fake->stream_mode == FAKE_STREAM_EARLY_COMPLETE ||
      fake->record >= 9U) {
    *frame = (pbns_frame){PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_COMPLETE,
                          0U, fake->begin_id, (uint32_t)fake->record};
    *payload = (pbns_view){NULL, 0U};
    if (fake->stream_mode == FAKE_STREAM_NONEMPTY_COMPLETE) {
      *payload = (pbns_view){fake->source, 1U};
    }
  } else {
    const size_t offset = fake->record * PBNS_RECOVERY_MANIFEST_CHUNK_SIZE;
    const size_t remaining = sizeof(fake->source) - offset;
    const size_t size = remaining > PBNS_RECOVERY_MANIFEST_CHUNK_SIZE
                            ? PBNS_RECOVERY_MANIFEST_CHUNK_SIZE
                            : remaining;
    *frame = (pbns_frame){PBNS_SERVICE_RECOVERY_ARTIFACT, PBNS_MESSAGE_DATA,
                          0U, fake->begin_id, (uint32_t)fake->record};
    *payload = (pbns_view){fake->source + offset, size};
    if (!fake->have_first_data) {
      fake->first_data_sequence = frame->sequence;
      fake->have_first_data = true;
    }
    switch (fake->stream_mode) {
      case FAKE_STREAM_VALID:
      case FAKE_STREAM_EARLY_COMPLETE:
      case FAKE_STREAM_NONEMPTY_COMPLETE:
        break;
      case FAKE_STREAM_INVALID_PAYLOAD:
        *payload = (pbns_view){NULL, 1U};
        break;
      case FAKE_STREAM_SHORT_DATA:
        *payload = (pbns_view){fake->source + offset, size - 1U};
        break;
      case FAKE_STREAM_OVERSIZE_DATA:
        *payload = (pbns_view){fake->source + offset,
                               PBNS_RECOVERY_MANIFEST_CHUNK_SIZE + 1U};
        break;
      case FAKE_STREAM_WRONG_ID:
        frame->request_id.bytes[0] ^= 1U;
        break;
      case FAKE_STREAM_WRONG_SERVICE:
        frame->service = PBNS_SERVICE_TRUSTED_TIME;
        break;
      case FAKE_STREAM_WRONG_TYPE:
        frame->type = PBNS_MESSAGE_RESPONSE;
        break;
      case FAKE_STREAM_FLAGS:
        frame->flags = 1U;
        break;
      case FAKE_STREAM_SEQUENCE:
        frame->sequence = 1U;
        break;
    }
  }
  ++fake->record;
  return PBNS_OK;
}

static pbns_status fake_ack(void *context, uint32_t next_sequence,
                            uint32_t window) {
  fixture *fake = context;
  assert(fake->ack_calls < sizeof(fake->ack_sequence) / sizeof(fake->ack_sequence[0]));
  fake->ack_sequence[fake->ack_calls] = next_sequence;
  fake->ack_window[fake->ack_calls] = window;
  ++fake->ack_calls;
  return fake->ack_status;
}

static pbns_status fake_finish(void *context) {
  fixture *fake = context;
  ++fake->finish_calls;
  return fake->finish_status;
}

static pbns_status fake_cancel(void *context) {
  fixture *fake = context;
  ++fake->cancel_calls;
  return fake->cancel_status;
}

static pbns_recovery_live_client client_for(fixture *fake) {
  return (pbns_recovery_live_client){
      fake_random, fake_sign, fake_exchange, fake_verify, fake_begin,
      fake_receive, fake_ack, fake_finish, fake_cancel, &hash_ops, fake,
      &fake->hash, {fake->manifest_kid, sizeof(fake->manifest_kid)},
      {fake->policy_kid, sizeof(fake->policy_kid)}};
}

static void init_fixture(fixture *fake) {
  *fake = (fixture){0};
  fake->policy[0] = 0x91U;
  fake->policy[1] = 0x92U;
  fake->policy[2] = 0x93U;
  fake->manifest_kid[0] = 0x31U;
  fake->manifest_kid[1] = 0x32U;
  fake->manifest_kid[2] = 0x33U;
  fake->policy_kid[0] = 0x41U;
  fake->policy_kid[1] = 0x42U;
  fake->policy_kid[2] = 0x43U;
  for (size_t index = 0U; index < sizeof(fake->source); ++index) {
    fake->source[index] = (uint8_t)(index * 19U + 7U);
  }
  uint8_t digest[PBNS_RECOVERY_MANIFEST_DIGEST_SIZE] = {0};
  fake_digest(fake->source, sizeof(fake->source), digest);
  pbns_recovery_manifest *manifest = &fake->response_manifest;
  for (size_t index = 0U; index < PBNS_RECOVERY_MANIFEST_REQUEST_ID_SIZE; ++index) {
    manifest->request_id[index] = (uint8_t)(18U + index);
  }
  for (size_t index = 0U; index < PBNS_RECOVERY_MANIFEST_HOST_SIZE; ++index) {
    manifest->host_binding[index] = 0x5aU;
    manifest->nonce[index] = (uint8_t)(35U + index);
  }
  memcpy(manifest->artifact_digest, digest, sizeof(digest));
  manifest->artifact_version = 7U;
  manifest->image_size = sizeof(fake->source);
  manifest->chunk_size = PBNS_RECOVERY_MANIFEST_CHUNK_SIZE;
  manifest->minimum_version = 6U;
  manifest->not_before_ns = 100;
  manifest->not_after_ns = 200;
  manifest->policy_authorization = (pbns_view){fake->policy, sizeof(fake->policy)};
  manifest->policy_key_id = (pbns_view){fake->policy_kid, sizeof(fake->policy_kid)};
  assert(pbns_recovery_manifest_encode(manifest,
                                       (pbns_buffer){fake->manifest_encoded, 0U,
                                                     sizeof(fake->manifest_encoded)},
                                       &fake->manifest_size) == PBNS_OK);
  memcpy(fake->external_payload, fake->manifest_encoded, fake->manifest_size);
}

static void encode_response_manifest(fixture *fake) {
  assert(pbns_recovery_manifest_encode(
             &fake->response_manifest,
             (pbns_buffer){fake->manifest_encoded, 0U,
                           sizeof(fake->manifest_encoded)},
             &fake->manifest_size) == PBNS_OK);
  memcpy(fake->external_payload, fake->manifest_encoded, fake->manifest_size);
}

static void assert_zero(const uint8_t *bytes, size_t size) {
  for (size_t index = 0U; index < size; ++index) {
    assert(bytes[index] == 0U);
  }
}

static void assert_transient_clear(const pbns_recovery_live_workspace *workspace,
                                   const fake_hash *hash) {
  assert_zero(workspace->request_payload, sizeof(workspace->request_payload));
  assert_zero(workspace->signed_request, sizeof(workspace->signed_request));
  assert_zero(workspace->canonical_scratch, sizeof(workspace->canonical_scratch));
  assert_zero(workspace->aad_scratch, sizeof(workspace->aad_scratch));
  assert(workspace->frame.service == PBNS_SERVICE_INVALID);
  assert(workspace->frame.type == PBNS_MESSAGE_INVALID);
  assert(workspace->frame.flags == 0U);
  assert_zero(workspace->frame.request_id.bytes,
              sizeof(workspace->frame.request_id.bytes));
  assert(workspace->frame.sequence == 0U);
  assert(workspace->payload.ptr == NULL && workspace->payload.len == 0U);
  assert_zero(hash->state, sizeof(hash->state));
  assert(hash->offset == 0U);
}

static void test_manifest_and_artifact_happy_path(void) {
  fixture fake = {0};
  init_fixture(&fake);
  uint8_t host[32] = {0};
  memset(host, 0x5a, sizeof(host));
  pbns_recovery_live_workspace workspace = {0};
  pbns_recovery_manifest manifest = {0};
  const pbns_recovery_live_client client = client_for(&fake);
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &manifest) == PBNS_OK);
  assert(fake.sign_calls == 1U);
  assert(fake.requests[0].operation == PBNS_RECOVERY_OPERATION_MANIFEST);
  for (size_t index = 0U; index < sizeof(fake.requests[0].artifact_digest); ++index) {
    assert(fake.requests[0].artifact_digest[index] == 0U);
  }
  assert(memcmp(fake.exchange_id.bytes, fake.requests[0].request_id,
                sizeof(fake.exchange_id.bytes)) == 0);
  assert(fake.request_aad_size == sizeof(PBNS_RECOVERY_REQUEST_AAD) - 1U);
  pbns_recovery_manifest_expectation expectation = {0};
  memcpy(expectation.request_id, fake.requests[0].request_id,
         sizeof(expectation.request_id));
  memcpy(expectation.host_binding, host, sizeof(expectation.host_binding));
  memcpy(expectation.nonce, fake.requests[0].nonce, sizeof(expectation.nonce));
  expectation.recovery_signing_key_id = client.manifest_key_id;
  expectation.expected_policy_key_id = client.policy_key_id;
  expectation.current_version = 0U;
  expectation.trusted_time = (pbns_time_interval){100, 200};
  uint8_t expected_aad[PBNS_RECOVERY_MANIFEST_AAD_MAX_SIZE] = {0};
  size_t expected_aad_size = 0U;
  assert(pbns_recovery_manifest_aad(
             &expectation,
             (pbns_buffer){expected_aad, 0U, sizeof(expected_aad)},
             &expected_aad_size) == PBNS_OK);
  assert(fake.manifest_aad_size == expected_aad_size);
  assert(memcmp(fake.manifest_aad, expected_aad, expected_aad_size) == 0);
  assert_transient_clear(&workspace, &fake.hash);
  assert(workspace.signed_manifest_size == fake.manifest_size);
  assert(memcmp(manifest.policy_authorization.ptr, fake.policy,
                sizeof(fake.policy)) == 0);
  assert(memcmp(manifest.policy_key_id.ptr, fake.policy_kid,
                sizeof(fake.policy_kid)) == 0);
  uint8_t pages[sizeof(fake.source)] = {0};
  assert(pbns_recovery_live_artifact(&client, &manifest,
                                     (pbns_buffer){pages, 0U, sizeof(pages)},
                                     &workspace) == PBNS_OK);
  assert(fake.sign_calls == 2U);
  assert(fake.random_calls == 4U);
  assert(memcmp(fake.requests[0].request_id, fake.requests[1].request_id,
                sizeof(fake.requests[0].request_id)) != 0);
  assert(memcmp(fake.requests[0].nonce, fake.requests[1].nonce,
                sizeof(fake.requests[0].nonce)) != 0);
  assert(fake.requests[1].operation == PBNS_RECOVERY_OPERATION_ARTIFACT);
  assert(memcmp(fake.requests[1].artifact_digest, manifest.artifact_digest,
                sizeof(manifest.artifact_digest)) == 0);
  assert(memcmp(fake.begin_id.bytes, fake.requests[1].request_id,
                sizeof(fake.begin_id.bytes)) == 0);
  assert(fake.ack_calls == 1U && fake.ack_sequence[0] == 8U && fake.ack_window[0] == 8U);
  assert(fake.finish_calls == 1U && fake.cancel_calls == 0U);
  assert(memcmp(pages, fake.source, sizeof(pages)) == 0);
  assert(workspace.signed_manifest_size == fake.manifest_size);
  assert(memcmp(manifest.policy_authorization.ptr, fake.policy,
                sizeof(fake.policy)) == 0);
  assert_transient_clear(&workspace, &fake.hash);
}

static void test_artifact_failures_cancel_and_zero_pages(void) {
  uint8_t host[32] = {0};
  memset(host, 0x5a, sizeof(host));
  for (size_t mode = 0U; mode < 4U; ++mode) {
    fixture fake = {0};
    init_fixture(&fake);
    pbns_recovery_live_workspace workspace = {0};
    pbns_recovery_manifest manifest = {0};
    const pbns_recovery_live_client client = client_for(&fake);
    assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                       &workspace, &manifest) == PBNS_OK);
    if (mode == 0U) { fake.receive_status = PBNS_ERR_TRANSPORT; }
    if (mode == 1U) { fake.stream_mode = FAKE_STREAM_SEQUENCE; }
    if (mode == 2U) { fake.ack_status = PBNS_ERR_TRANSPORT; }
    if (mode == 3U) { manifest.artifact_digest[0] ^= 1U; }
    uint8_t pages[sizeof(fake.source)];
    memset(pages, 0xa5, sizeof(pages));
    assert(pbns_recovery_live_artifact(&client, &manifest,
                                       (pbns_buffer){pages, 0U, sizeof(pages)},
                                       &workspace) != PBNS_OK);
    assert(fake.begin_calls == 1U && fake.cancel_calls == 1U && fake.finish_calls == 0U);
    for (size_t index = 0U; index < sizeof(pages); ++index) { assert(pages[index] == 0U); }
  }
}

static void test_begin_failure_does_not_cancel(void) {
  fixture fake = {0};
  init_fixture(&fake);
  uint8_t host[32] = {0};
  memset(host, 0x5a, sizeof(host));
  pbns_recovery_live_workspace workspace = {0};
  pbns_recovery_manifest manifest = {0};
  const pbns_recovery_live_client client = client_for(&fake);
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &manifest) == PBNS_OK);
  fake.begin_status = PBNS_ERR_TRANSPORT;
  uint8_t pages[sizeof(fake.source)];
  memset(pages, 0xa5, sizeof(pages));
  assert(pbns_recovery_live_artifact(&client, &manifest,
                                     (pbns_buffer){pages, 0U, sizeof(pages)},
                                     &workspace) == PBNS_ERR_TRANSPORT);
  assert(fake.cancel_calls == 0U && fake.finish_calls == 0U);
  for (size_t index = 0U; index < sizeof(pages); ++index) { assert(pages[index] == 0U); }
}

static void test_manifest_rejects_callback_and_time_failures(void) {
  uint8_t host[32] = {0};
  memset(host, 0x5a, sizeof(host));
  for (size_t mode = 0U; mode < 5U; ++mode) {
    fixture fake = {0};
    init_fixture(&fake);
    pbns_recovery_live_workspace workspace = {0};
    pbns_recovery_manifest manifest = {0};
    const pbns_recovery_live_client client = client_for(&fake);
    pbns_time_interval interval = {100, 200};
    if (mode == 0U) { fake.random_status = PBNS_ERR_ENTROPY; }
    if (mode == 1U) { fake.sign_status = PBNS_ERR_CRYPTO; }
    if (mode == 2U) { fake.exchange_status = PBNS_ERR_TRANSPORT; }
    if (mode == 3U) { fake.verify_status = PBNS_ERR_AUTHENTICATION; }
    if (mode == 4U) { interval.earliest_ns = 99; }
    assert(pbns_recovery_live_manifest(&client, host, &interval, &workspace,
                                       &manifest) != PBNS_OK);
    assert(manifest.policy_authorization.ptr == NULL);
    assert(workspace.signed_manifest_size == 0U);
  }
}

static void test_artifact_rejects_unbound_manifest_without_callbacks(void) {
  fixture fake = {0};
  init_fixture(&fake);
  uint8_t host[PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE] = {0};
  memset(host, 0x5a, sizeof(host));
  pbns_recovery_live_workspace workspace = {0};
  pbns_recovery_manifest manifest = {0};
  const pbns_recovery_live_client client = client_for(&fake);
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &manifest) == PBNS_OK);
  memset(manifest.host_binding, 0, sizeof(manifest.host_binding));
  fake.random_calls = 0U;
  fake.sign_calls = 0U;
  uint8_t pages[sizeof(fake.source)] = {0};
  assert(pbns_recovery_live_artifact(&client, &manifest,
                                     (pbns_buffer){pages, 0U, sizeof(pages)},
                                     &workspace) == PBNS_ERR_ARGUMENT);
  assert(fake.random_calls == 0U && fake.sign_calls == 0U &&
         fake.begin_calls == 0U && fake.cancel_calls == 0U);
}

static void test_manifest_rejects_transient_verified_view(void) {
  fixture fake = {0};
  init_fixture(&fake);
  uint8_t host[32] = {0};
  memset(host, 0x5a, sizeof(host));
  pbns_recovery_live_workspace workspace = {0};
  pbns_recovery_manifest manifest = {0};
  const pbns_recovery_live_client client = client_for(&fake);
  fake.view_mode = FAKE_VIEW_EXTERNAL;
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &manifest) == PBNS_ERR_AUTHENTICATION);
}

static void test_manifest_request_failure_matrix(void) {
  uint8_t host[PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE] = {0};
  memset(host, 0x5a, sizeof(host));
  for (size_t mode = 0U; mode < 6U; ++mode) {
    fixture fake = {0};
    init_fixture(&fake);
    pbns_recovery_live_workspace workspace = {0};
    pbns_recovery_manifest manifest = {0};
    const pbns_recovery_live_client client = client_for(&fake);
    if (mode == 0U) { fake.random_zero_call = 1U; }
    if (mode == 1U) { fake.random_fail_call = 1U; }
    if (mode == 2U) { fake.random_fail_call = 2U; }
    if (mode == 3U) { fake.zero_sign = true; }
    if (mode == 4U) { fake.short_sign = true; }
    if (mode == 5U) { fake.zero_exchange = true; }
    assert(pbns_recovery_live_manifest(&client, host,
                                       &(pbns_time_interval){100, 200},
                                       &workspace, &manifest) != PBNS_OK);
    assert(workspace.signed_manifest_size == 0U);
    assert_zero(workspace.signed_manifest, sizeof(workspace.signed_manifest));
    assert_transient_clear(&workspace, &fake.hash);
  }
  fixture exchange = {0};
  init_fixture(&exchange);
  pbns_recovery_live_workspace workspace = {0};
  pbns_recovery_manifest manifest = {0};
  const pbns_recovery_live_client client = client_for(&exchange);
  exchange.short_exchange = true;
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &manifest) == PBNS_ERR_LIMIT);
  assert_zero(workspace.signed_manifest, sizeof(workspace.signed_manifest));
  assert_transient_clear(&workspace, &exchange.hash);
}

static void test_manifest_rejects_zero_nonce_without_side_effects(void) {
  fixture fake = {0};
  init_fixture(&fake);
  uint8_t host[PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE] = {0};
  memset(host, 0x5a, sizeof(host));
  pbns_recovery_live_workspace workspace = {0};
  pbns_recovery_manifest manifest = {0};
  const pbns_recovery_live_client client = client_for(&fake);
  fake.random_zero_call = 2U;
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &manifest) == PBNS_ERR_ENTROPY);
  assert(fake.random_calls == 2U && fake.sign_calls == 0U &&
         fake.exchange_calls == 0U && fake.verify_calls == 0U &&
         fake.begin_calls == 0U && fake.cancel_calls == 0U);
  assert(manifest.policy_authorization.ptr == NULL &&
         manifest.policy_key_id.ptr == NULL);
  assert(workspace.signed_manifest_size == 0U);
  assert_zero(workspace.signed_manifest, sizeof(workspace.signed_manifest));
  assert_transient_clear(&workspace, &fake.hash);
}

static void test_manifest_view_and_binding_matrix(void) {
  uint8_t host[PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE] = {0};
  memset(host, 0x5a, sizeof(host));
  static const fake_view_mode invalid_views[] = {
      FAKE_VIEW_EXTERNAL, FAKE_VIEW_NULL_NONZERO, FAKE_VIEW_EMPTY,
      FAKE_VIEW_END_CROSSING, FAKE_VIEW_OVERSIZED};
  for (size_t index = 0U; index < sizeof(invalid_views) / sizeof(invalid_views[0]); ++index) {
    fixture fake = {0};
    init_fixture(&fake);
    fake.view_mode = invalid_views[index];
    pbns_recovery_live_workspace workspace = {0};
    pbns_recovery_manifest manifest = {0};
    const pbns_recovery_live_client client = client_for(&fake);
    assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                       &workspace, &manifest) != PBNS_OK);
    assert_zero(workspace.signed_manifest, sizeof(workspace.signed_manifest));
    assert_transient_clear(&workspace, &fake.hash);
  }
  for (size_t mode = 0U; mode < 7U; ++mode) {
    fixture fake = {0};
    init_fixture(&fake);
    if (mode == 0U) { fake.response_manifest.request_id[0] ^= 1U; }
    if (mode == 1U) { fake.response_manifest.host_binding[0] ^= 1U; }
    if (mode == 2U) { fake.response_manifest.nonce[0] ^= 1U; }
    if (mode == 3U) { fake.response_manifest.policy_key_id = (pbns_view){fake.manifest_kid, sizeof(fake.manifest_kid)}; }
    if (mode == 4U) { fake.response_manifest.not_before_ns = 101; }
    if (mode == 5U) { fake.response_manifest.not_after_ns = 199; }
    if (mode == 6U) { fake.manifest_encoded[0] = 0xb8U; }
    if (mode != 6U) { encode_response_manifest(&fake); }
    pbns_recovery_live_workspace workspace = {0};
    pbns_recovery_manifest manifest = {0};
    const pbns_recovery_live_client client = client_for(&fake);
    assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                       &workspace, &manifest) != PBNS_OK);
    assert_zero(workspace.signed_manifest, sizeof(workspace.signed_manifest));
    assert_transient_clear(&workspace, &fake.hash);
  }
}

static void test_artifact_callback_failure_matrix(void) {
  uint8_t host[PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE] = {0};
  memset(host, 0x5a, sizeof(host));
  for (size_t mode = 0U; mode < 5U; ++mode) {
    fixture fake = {0};
    init_fixture(&fake);
    pbns_recovery_live_workspace workspace = {0};
    pbns_recovery_manifest manifest = {0};
    const pbns_recovery_live_client client = client_for(&fake);
    assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                       &workspace, &manifest) == PBNS_OK);
    if (mode == 0U) { fake.random_zero_call = fake.random_calls + 1U; }
    if (mode == 1U) { fake.random_fail_call = fake.random_calls + 1U; }
    if (mode == 2U) { fake.random_fail_call = fake.random_calls + 2U; }
    if (mode == 3U) { fake.sign_status = PBNS_ERR_CRYPTO; }
    if (mode == 4U) { fake.hash.fail_begin = true; }
    uint8_t pages[sizeof(fake.source)];
    memset(pages, 0xa5, sizeof(pages));
    assert(pbns_recovery_live_artifact(&client, &manifest,
                                       (pbns_buffer){pages, 0U, sizeof(pages)},
                                       &workspace) != PBNS_OK);
    assert(fake.begin_calls == 0U && fake.cancel_calls == 0U && fake.finish_calls == 0U);
    assert_zero(pages, sizeof(pages));
    assert_transient_clear(&workspace, &fake.hash);
  }
}

static void test_artifact_rejects_zero_nonce_and_retains_manifest(void) {
  fixture fake = {0};
  init_fixture(&fake);
  uint8_t host[PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE] = {0};
  memset(host, 0x5a, sizeof(host));
  pbns_recovery_live_workspace workspace = {0};
  pbns_recovery_manifest manifest = {0};
  const pbns_recovery_live_client client = client_for(&fake);
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &manifest) == PBNS_OK);
  const pbns_view policy = manifest.policy_authorization;
  const pbns_view policy_kid = manifest.policy_key_id;
  const size_t signed_manifest_size = workspace.signed_manifest_size;
  const size_t signs_before = fake.sign_calls;
  fake.random_zero_call = fake.random_calls + 2U;
  uint8_t pages[sizeof(fake.source)];
  memset(pages, 0xa5, sizeof(pages));
  assert(pbns_recovery_live_artifact(&client, &manifest,
                                     (pbns_buffer){pages, 0U, sizeof(pages)},
                                     &workspace) == PBNS_ERR_ENTROPY);
  assert(fake.random_calls == 4U && fake.sign_calls == signs_before &&
         fake.begin_calls == 0U && fake.cancel_calls == 0U &&
         fake.finish_calls == 0U);
  assert_zero(pages, sizeof(pages));
  assert_transient_clear(&workspace, &fake.hash);
  assert(workspace.signed_manifest_size == signed_manifest_size);
  assert(manifest.policy_authorization.ptr == policy.ptr &&
         manifest.policy_authorization.len == policy.len &&
         manifest.policy_key_id.ptr == policy_kid.ptr &&
         manifest.policy_key_id.len == policy_kid.len);
  assert(memcmp(policy.ptr, fake.policy, sizeof(fake.policy)) == 0);
  assert(memcmp(policy_kid.ptr, fake.policy_kid, sizeof(fake.policy_kid)) == 0);
}

static void test_artifact_stream_failure_matrix(void) {
  uint8_t host[PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE] = {0};
  memset(host, 0x5a, sizeof(host));
  static const fake_stream_mode modes[] = {
      FAKE_STREAM_INVALID_PAYLOAD, FAKE_STREAM_EARLY_COMPLETE,
      FAKE_STREAM_SHORT_DATA, FAKE_STREAM_OVERSIZE_DATA,
      FAKE_STREAM_WRONG_ID, FAKE_STREAM_WRONG_SERVICE,
      FAKE_STREAM_WRONG_TYPE, FAKE_STREAM_FLAGS, FAKE_STREAM_SEQUENCE,
      FAKE_STREAM_NONEMPTY_COMPLETE};
  for (size_t index = 0U; index < sizeof(modes) / sizeof(modes[0]); ++index) {
    fixture fake = {0};
    init_fixture(&fake);
    pbns_recovery_live_workspace workspace = {0};
    pbns_recovery_manifest manifest = {0};
    const pbns_recovery_live_client client = client_for(&fake);
    assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                       &workspace, &manifest) == PBNS_OK);
    fake.stream_mode = modes[index];
    uint8_t pages[sizeof(fake.source)];
    memset(pages, 0xa5, sizeof(pages));
    assert(pbns_recovery_live_artifact(&client, &manifest,
                                       (pbns_buffer){pages, 0U, sizeof(pages)},
                                       &workspace) != PBNS_OK);
    assert(fake.begin_calls == 1U && fake.cancel_calls == 1U && fake.finish_calls == 0U);
    assert_zero(pages, sizeof(pages));
    assert_transient_clear(&workspace, &fake.hash);
  }
}

static void test_artifact_terminal_failure_matrix(void) {
  uint8_t host[PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE] = {0};
  memset(host, 0x5a, sizeof(host));
  for (size_t mode = 0U; mode < 6U; ++mode) {
    fixture fake = {0};
    init_fixture(&fake);
    pbns_recovery_live_workspace workspace = {0};
    pbns_recovery_manifest manifest = {0};
    const pbns_recovery_live_client client = client_for(&fake);
    assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                       &workspace, &manifest) == PBNS_OK);
    if (mode == 0U) { fake.receive_status = PBNS_ERR_TRANSPORT; }
    if (mode == 1U) { fake.ack_status = PBNS_ERR_TRANSPORT; }
    if (mode == 2U) { fake.hash.fail_update = true; }
    if (mode == 3U) { fake.hash.fail_finish = true; }
    if (mode == 4U) { manifest.artifact_digest[0] ^= 1U; }
    if (mode == 5U) {
      fake.receive_status = PBNS_ERR_TRANSPORT;
      fake.cancel_status = PBNS_ERR_IO;
    }
    uint8_t pages[sizeof(fake.source)];
    memset(pages, 0xa5, sizeof(pages));
    const pbns_status status = pbns_recovery_live_artifact(
        &client, &manifest, (pbns_buffer){pages, 0U, sizeof(pages)}, &workspace);
    assert(status != PBNS_OK);
    if (mode == 5U) { assert(status == PBNS_ERR_TRANSPORT); }
    assert(fake.begin_calls == 1U && fake.cancel_calls == 1U && fake.finish_calls == 0U);
    assert_zero(pages, sizeof(pages));
    assert_transient_clear(&workspace, &fake.hash);
  }
  fixture finish = {0};
  init_fixture(&finish);
  pbns_recovery_live_workspace workspace = {0};
  pbns_recovery_manifest manifest = {0};
  const pbns_recovery_live_client client = client_for(&finish);
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &manifest) == PBNS_OK);
  finish.finish_status = PBNS_ERR_IO;
  uint8_t pages[sizeof(finish.source)];
  memset(pages, 0xa5, sizeof(pages));
  assert(pbns_recovery_live_artifact(&client, &manifest,
                                     (pbns_buffer){pages, 0U, sizeof(pages)},
                                     &workspace) == PBNS_ERR_IO);
  assert(finish.begin_calls == 1U && finish.finish_calls == 1U &&
         finish.cancel_calls == 0U);
  assert_zero(pages, sizeof(pages));
  assert_transient_clear(&workspace, &finish.hash);
}

static void test_artifact_retry_starts_from_zero(void) {
  fixture fake = {0};
  init_fixture(&fake);
  uint8_t host[PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE] = {0};
  memset(host, 0x5a, sizeof(host));
  pbns_recovery_live_workspace workspace = {0};
  pbns_recovery_manifest manifest = {0};
  const pbns_recovery_live_client client = client_for(&fake);
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &manifest) == PBNS_OK);
  fake.stream_mode = FAKE_STREAM_EARLY_COMPLETE;
  uint8_t failed_pages[sizeof(fake.source)];
  memset(failed_pages, 0xa5, sizeof(failed_pages));
  assert(pbns_recovery_live_artifact(&client, &manifest,
                                     (pbns_buffer){failed_pages, 0U,
                                                   sizeof(failed_pages)},
                                     &workspace) != PBNS_OK);
  const pbns_recovery_request interrupted = fake.requests[1];
  assert_zero(failed_pages, sizeof(failed_pages));
  fake.stream_mode = FAKE_STREAM_VALID;
  fake.record = 0U;
  fake.have_first_data = false;
  uint8_t pages[sizeof(fake.source)] = {0};
  assert(pbns_recovery_live_artifact(&client, &manifest,
                                     (pbns_buffer){pages, 0U, sizeof(pages)},
                                     &workspace) == PBNS_OK);
  assert(memcmp(interrupted.request_id, fake.requests[2].request_id,
                sizeof(interrupted.request_id)) != 0);
  assert(memcmp(interrupted.nonce, fake.requests[2].nonce,
                sizeof(interrupted.nonce)) != 0);
  assert(fake.have_first_data && fake.first_data_sequence == 0U);
  assert(fake.ack_calls == 1U && fake.ack_sequence[0] == 8U &&
         fake.ack_window[0] == 8U);
  assert(memcmp(pages, fake.source, sizeof(pages)) == 0);
  assert_transient_clear(&workspace, &fake.hash);
}

static void test_input_validation_matrix(void) {
  fixture fake = {0};
  init_fixture(&fake);
  uint8_t host[PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE] = {0};
  memset(host, 0x5a, sizeof(host));
  pbns_recovery_live_workspace workspace = {0};
  pbns_recovery_manifest output = {0};
  const pbns_recovery_live_client base = client_for(&fake);
  pbns_recovery_live_client client = base;
  client.random_fill = NULL;
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &output) == PBNS_ERR_ARGUMENT);
  client = base;
  client.sign_request = NULL;
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &output) == PBNS_ERR_ARGUMENT);
  client = base;
  client.manifest_exchange = NULL;
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &output) == PBNS_ERR_ARGUMENT);
  client = base;
  client.verify_manifest = NULL;
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &output) == PBNS_ERR_ARGUMENT);
  client = base;
  client.bulk_begin = NULL;
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &output) == PBNS_ERR_ARGUMENT);
  client = base;
  client.bulk_receive = NULL;
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &output) == PBNS_ERR_ARGUMENT);
  client = base;
  client.bulk_ack = NULL;
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &output) == PBNS_ERR_ARGUMENT);
  client = base;
  client.bulk_finish = NULL;
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &output) == PBNS_ERR_ARGUMENT);
  client = base;
  client.bulk_cancel = NULL;
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &output) == PBNS_ERR_ARGUMENT);
  client = base;
  client.manifest_key_id = (pbns_view){NULL, 1U};
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &output) == PBNS_ERR_ARGUMENT);
  client = base;
  client.manifest_key_id = (pbns_view){fake.manifest_kid,
                                       PBNS_RECOVERY_MANIFEST_KEY_ID_MAX_SIZE + 1U};
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &output) == PBNS_ERR_ARGUMENT);
  client = base;
  client.policy_key_id = (pbns_view){fake.policy,
                                     PBNS_RECOVERY_MANIFEST_KEY_ID_MAX_SIZE + 1U};
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &output) == PBNS_ERR_ARGUMENT);
  client = base;
  client.hash_ops = NULL;
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &output) == PBNS_ERR_ARGUMENT);
  pbns_recovery_hash_ops incomplete_hash = {0};
  client = base;
  client.hash_ops = &incomplete_hash;
  assert(pbns_recovery_live_manifest(&client, host, &(pbns_time_interval){100, 200},
                                     &workspace, &output) == PBNS_ERR_ARGUMENT);
  assert(pbns_recovery_live_manifest(&base, (uint8_t[32]){0},
                                     &(pbns_time_interval){100, 200},
                                     &workspace, &output) == PBNS_ERR_ARGUMENT);
  assert(pbns_recovery_live_manifest(&base, host, NULL, &workspace, &output) == PBNS_ERR_ARGUMENT);
  assert(pbns_recovery_live_manifest(&base, host, &(pbns_time_interval){200, 100},
                                     &workspace, &output) == PBNS_ERR_ARGUMENT);
  assert(pbns_recovery_live_manifest(&base, host, &(pbns_time_interval){100, 200},
                                     NULL, &output) == PBNS_ERR_ARGUMENT);
  assert(pbns_recovery_live_manifest(&base, host, &(pbns_time_interval){100, 200},
                                     &workspace, NULL) == PBNS_ERR_ARGUMENT);
  assert(fake.random_calls == 0U && fake.begin_calls == 0U);
}

static void test_artifact_input_validation_matrix(void) {
  fixture fake = {0};
  init_fixture(&fake);
  uint8_t host[PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE] = {0};
  memset(host, 0x5a, sizeof(host));
  pbns_recovery_live_workspace workspace = {0};
  pbns_recovery_manifest manifest = {0};
  const pbns_recovery_live_client base = client_for(&fake);
  assert(pbns_recovery_live_manifest(&base, host, &(pbns_time_interval){100, 200},
                                     &workspace, &manifest) == PBNS_OK);
  uint8_t pages[sizeof(fake.source) + 1U] = {0};
  for (size_t mode = 0U; mode < 10U; ++mode) {
    pbns_recovery_manifest invalid = manifest;
    pbns_recovery_live_client client = base;
    pbns_buffer page_buffer = {pages, 0U, sizeof(fake.source)};
    pbns_recovery_live_workspace *target_workspace = &workspace;
    if (mode == 0U) { memset(invalid.request_id, 0, sizeof(invalid.request_id)); }
    if (mode == 1U) { memset(invalid.nonce, 0, sizeof(invalid.nonce)); }
    if (mode == 2U) { invalid.chunk_size = 1U; }
    if (mode == 3U) { invalid.policy_authorization = (pbns_view){NULL, 1U}; }
    if (mode == 4U) { invalid.policy_key_id = (pbns_view){NULL, 1U}; }
    if (mode == 5U) { page_buffer.len = 1U; }
    if (mode == 6U) { page_buffer.cap = sizeof(fake.source) - 1U; }
    if (mode == 7U) { page_buffer.cap = sizeof(pages); }
    if (mode == 8U) { target_workspace = NULL; }
    if (mode == 9U) { page_buffer.ptr = NULL; }
    fake.random_calls = 0U;
    fake.sign_calls = 0U;
    fake.begin_calls = 0U;
    assert(pbns_recovery_live_artifact(&client, &invalid, page_buffer,
                                       target_workspace) == PBNS_ERR_ARGUMENT);
    assert(fake.random_calls == 0U && fake.sign_calls == 0U && fake.begin_calls == 0U);
  }
  pbns_recovery_live_client client = base;
  client.hash_ops = NULL;
  assert(pbns_recovery_live_artifact(&client, &manifest,
                                     (pbns_buffer){pages, 0U, sizeof(fake.source)},
                                     &workspace) == PBNS_ERR_ARGUMENT);
}

int main(void) {
  test_manifest_and_artifact_happy_path();
  test_artifact_failures_cancel_and_zero_pages();
  test_begin_failure_does_not_cancel();
  test_manifest_rejects_callback_and_time_failures();
  test_artifact_rejects_unbound_manifest_without_callbacks();
  test_manifest_rejects_transient_verified_view();
  test_manifest_request_failure_matrix();
  test_manifest_rejects_zero_nonce_without_side_effects();
  test_manifest_view_and_binding_matrix();
  test_artifact_callback_failure_matrix();
  test_artifact_rejects_zero_nonce_and_retains_manifest();
  test_artifact_stream_failure_matrix();
  test_artifact_terminal_failure_matrix();
  test_artifact_retry_starts_from_zero();
  test_input_validation_matrix();
  test_artifact_input_validation_matrix();
  return 0;
}
