#include "pbns/recovery_live.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static bool view_valid(pbns_view value) {
  return value.ptr != NULL || value.len == 0U;
}

static bool output_valid(pbns_buffer output) {
  return output.len == 0U && (output.ptr != NULL || output.cap == 0U);
}

static bool nonzero(const uint8_t *value, size_t length) {
  if (value == NULL) {
    return false;
  }
  uint8_t combined = 0U;
  for (size_t index = 0U; index < length; ++index) {
    combined |= value[index];
  }
  return combined != 0U;
}

static bool key_id_valid(pbns_view key_id) {
  return view_valid(key_id) && key_id.len > 0U &&
         key_id.len <= PBNS_RECOVERY_MANIFEST_KEY_ID_MAX_SIZE;
}

static bool hash_ops_valid(const pbns_recovery_hash_ops *hash_ops) {
  return hash_ops != NULL && hash_ops->begin != NULL &&
         hash_ops->update != NULL && hash_ops->finish != NULL &&
         hash_ops->clear != NULL;
}

static bool client_valid(const pbns_recovery_live_client *client) {
  return client != NULL && client->random_fill != NULL &&
         client->sign_request != NULL && client->manifest_exchange != NULL &&
         client->verify_manifest != NULL && client->bulk_begin != NULL &&
         client->bulk_receive != NULL && client->bulk_ack != NULL &&
         client->bulk_finish != NULL && client->bulk_cancel != NULL &&
         hash_ops_valid(client->hash_ops) && key_id_valid(client->manifest_key_id) &&
         key_id_valid(client->policy_key_id);
}

static bool trusted_time_valid(const pbns_time_interval *trusted_time) {
  return trusted_time != NULL && trusted_time->earliest_ns >= 0 &&
         trusted_time->earliest_ns <= trusted_time->latest_ns;
}

static bool pages_valid(pbns_buffer pages, uint64_t expected_size) {
  return output_valid(pages) && pages.ptr != NULL && expected_size > 0U &&
         expected_size <= PBNS_RECOVERY_MANIFEST_IMAGE_MAX &&
         expected_size <= SIZE_MAX && pages.cap == (size_t)expected_size;
}

static bool manifest_valid_for_artifact(const pbns_recovery_manifest *manifest) {
  return manifest != NULL &&
         nonzero(manifest->request_id, sizeof(manifest->request_id)) &&
         nonzero(manifest->host_binding, sizeof(manifest->host_binding)) &&
         nonzero(manifest->nonce, sizeof(manifest->nonce)) &&
         nonzero(manifest->artifact_digest, sizeof(manifest->artifact_digest)) &&
         manifest->artifact_version > 0U &&
         manifest->artifact_version >= manifest->minimum_version &&
         manifest->image_size > 0U &&
         manifest->image_size <= PBNS_RECOVERY_MANIFEST_IMAGE_MAX &&
         manifest->chunk_size == PBNS_RECOVERY_MANIFEST_CHUNK_SIZE &&
         manifest->not_before_ns >= 0 &&
         manifest->not_before_ns < manifest->not_after_ns &&
         view_valid(manifest->policy_authorization) &&
         manifest->policy_authorization.len > 0U &&
         manifest->policy_authorization.len <= PBNS_RECOVERY_MANIFEST_POLICY_MAX_SIZE &&
         key_id_valid(manifest->policy_key_id);
}

static void clear_transient(pbns_recovery_live_workspace *workspace) {
  memset(workspace->request_payload, 0, sizeof(workspace->request_payload));
  memset(workspace->signed_request, 0, sizeof(workspace->signed_request));
  memset(workspace->canonical_scratch, 0, sizeof(workspace->canonical_scratch));
  memset(workspace->aad_scratch, 0, sizeof(workspace->aad_scratch));
  workspace->frame = (pbns_frame){0};
  workspace->payload = (pbns_view){0};
}

static void clear_manifest(pbns_recovery_live_workspace *workspace) {
  memset(workspace->signed_manifest, 0, sizeof(workspace->signed_manifest));
  workspace->signed_manifest_size = 0U;
}

static bool view_in_manifest(const pbns_recovery_live_workspace *workspace,
                             pbns_view view) {
  if (!view_valid(view) || view.ptr == NULL || view.len == 0U ||
      workspace->signed_manifest_size == 0U) {
    return false;
  }
  const uintptr_t start = (uintptr_t)workspace->signed_manifest;
  const uintptr_t end = start + workspace->signed_manifest_size;
  const uintptr_t view_start = (uintptr_t)view.ptr;
  if (end < start || view_start < start || view_start > end) {
    return false;
  }
  return view.len <= (size_t)(end - view_start);
}

static pbns_status fill_nonzero(const pbns_recovery_live_client *client,
                                uint8_t *output, size_t size) {
  memset(output, 0, size);
  const pbns_status status =
      client->random_fill(client->context, (pbns_buffer){output, 0U, size});
  if (status != PBNS_OK) {
    return status;
  }
  return nonzero(output, size) ? PBNS_OK : PBNS_ERR_ENTROPY;
}

static pbns_status build_signed_request(
    const pbns_recovery_live_client *client,
    const uint8_t host_fingerprint[PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE],
    pbns_recovery_operation operation,
    const uint8_t artifact_digest[PBNS_RECOVERY_REQUEST_DIGEST_SIZE],
    pbns_recovery_live_workspace *workspace, pbns_request_id *request_id,
    uint8_t nonce[PBNS_RECOVERY_REQUEST_NONCE_SIZE], size_t *signed_size_out) {
  static const uint8_t request_aad[] = PBNS_RECOVERY_REQUEST_AAD;
  pbns_recovery_request request = {0};
  size_t request_size = 0U;
  size_t signed_size = 0U;
  if (signed_size_out != NULL) {
    *signed_size_out = 0U;
  }
  if (signed_size_out == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_status status = fill_nonzero(client, request.request_id,
                                    sizeof(request.request_id));
  if (status != PBNS_OK) {
    goto cleanup;
  }
  status = fill_nonzero(client, request.nonce, sizeof(request.nonce));
  if (status != PBNS_OK) {
    goto cleanup;
  }
  request.operation = operation;
  memcpy(request.host_fingerprint, host_fingerprint,
         sizeof(request.host_fingerprint));
  if (artifact_digest != NULL) {
    memcpy(request.artifact_digest, artifact_digest,
           sizeof(request.artifact_digest));
  }
  status = pbns_recovery_request_encode(
      &request,
      (pbns_buffer){workspace->request_payload, 0U,
                    sizeof(workspace->request_payload)},
      &request_size);
  if (status != PBNS_OK || request_size == 0U ||
      request_size > sizeof(workspace->request_payload)) {
    status = status == PBNS_OK ? PBNS_ERR_LIMIT : status;
    goto cleanup;
  }
  status = client->sign_request(
      client->context, (pbns_view){workspace->request_payload, request_size},
      (pbns_view){request_aad, sizeof(request_aad) - 1U},
      (pbns_buffer){workspace->signed_request, 0U,
                    sizeof(workspace->signed_request)},
      &signed_size);
  if (status != PBNS_OK) {
    goto cleanup;
  }
  if (signed_size == 0U || signed_size > sizeof(workspace->signed_request)) {
    status = PBNS_ERR_LIMIT;
    goto cleanup;
  }
  memcpy(request_id->bytes, request.request_id, sizeof(request_id->bytes));
  memcpy(nonce, request.nonce, PBNS_RECOVERY_REQUEST_NONCE_SIZE);
  *signed_size_out = signed_size;

cleanup:
  memset(&request, 0, sizeof(request));
  return status;
}

pbns_status pbns_recovery_live_manifest(
    const pbns_recovery_live_client *client,
    const uint8_t host_fingerprint[PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE],
    const pbns_time_interval *trusted_time, pbns_recovery_live_workspace *workspace,
    pbns_recovery_manifest *manifest) {
  if (manifest != NULL) {
    *manifest = (pbns_recovery_manifest){0};
  }
  if (!client_valid(client) || !nonzero(host_fingerprint,
                                        PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE) ||
      !trusted_time_valid(trusted_time) || workspace == NULL || manifest == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  clear_transient(workspace);
  clear_manifest(workspace);
  pbns_request_id request_id = {0};
  uint8_t nonce[PBNS_RECOVERY_REQUEST_NONCE_SIZE] = {0};
  size_t signed_request_size = 0U;
  size_t signed_manifest_size = 0U;
  size_t aad_size = 0U;
  pbns_recovery_manifest_expectation expectation = {0};
  pbns_view verified_payload = {0};
  pbns_status status = build_signed_request(
      client, host_fingerprint, PBNS_RECOVERY_OPERATION_MANIFEST, NULL,
      workspace, &request_id, nonce, &signed_request_size);
  if (status != PBNS_OK) {
    goto cleanup;
  }
  status = client->manifest_exchange(
      client->context, &request_id,
      (pbns_view){workspace->signed_request, signed_request_size},
      (pbns_buffer){workspace->signed_manifest, 0U,
                    sizeof(workspace->signed_manifest)},
      &signed_manifest_size);
  if (status != PBNS_OK) {
    goto cleanup;
  }
  if (signed_manifest_size == 0U ||
      signed_manifest_size > sizeof(workspace->signed_manifest)) {
    status = PBNS_ERR_LIMIT;
    goto cleanup;
  }
  workspace->signed_manifest_size = signed_manifest_size;
  memcpy(expectation.request_id, request_id.bytes, sizeof(expectation.request_id));
  memcpy(expectation.host_binding, host_fingerprint,
         sizeof(expectation.host_binding));
  memcpy(expectation.nonce, nonce, sizeof(expectation.nonce));
  expectation.recovery_signing_key_id = client->manifest_key_id;
  expectation.expected_policy_key_id = client->policy_key_id;
  expectation.current_version = 0U;
  expectation.trusted_time = *trusted_time;
  status = pbns_recovery_manifest_aad(
      &expectation,
      (pbns_buffer){workspace->aad_scratch, 0U, sizeof(workspace->aad_scratch)},
      &aad_size);
  if (status != PBNS_OK || aad_size == 0U ||
      aad_size > sizeof(workspace->aad_scratch)) {
    status = status == PBNS_OK ? PBNS_ERR_LIMIT : status;
    goto cleanup;
  }
  status = client->verify_manifest(
      client->context,
      (pbns_view){workspace->signed_manifest, workspace->signed_manifest_size},
      (pbns_view){workspace->aad_scratch, aad_size}, &verified_payload);
  if (status != PBNS_OK) {
    goto cleanup;
  }
  if (!view_in_manifest(workspace, verified_payload)) {
    status = PBNS_ERR_AUTHENTICATION;
    goto cleanup;
  }
  status = pbns_recovery_manifest_decode_verified(
      verified_payload, &expectation,
      (pbns_buffer){workspace->canonical_scratch, 0U,
                    sizeof(workspace->canonical_scratch)},
      manifest);

cleanup:
  memset(&request_id, 0, sizeof(request_id));
  memset(nonce, 0, sizeof(nonce));
  memset(&expectation, 0, sizeof(expectation));
  clear_transient(workspace);
  if (status != PBNS_OK) {
    clear_manifest(workspace);
    *manifest = (pbns_recovery_manifest){0};
  }
  return status;
}

pbns_status pbns_recovery_live_artifact(
    const pbns_recovery_live_client *client,
    const pbns_recovery_manifest *manifest, pbns_buffer exact_pages,
    pbns_recovery_live_workspace *workspace) {
  if (!client_valid(client) || !manifest_valid_for_artifact(manifest) ||
      !pages_valid(exact_pages, manifest == NULL ? 0U : manifest->image_size) ||
      workspace == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  clear_transient(workspace);
  pbns_request_id request_id = {0};
  uint8_t nonce[PBNS_RECOVERY_REQUEST_NONCE_SIZE] = {0};
  pbns_recovery_stream stream = {0};
  bool stream_ready = false;
  bool bulk_active = false;
  size_t signed_request_size = 0U;
  pbns_status status = build_signed_request(
      client, manifest->host_binding, PBNS_RECOVERY_OPERATION_ARTIFACT,
      manifest->artifact_digest, workspace, &request_id, nonce,
      &signed_request_size);
  if (status != PBNS_OK) {
    goto cleanup;
  }
  status = pbns_recovery_stream_init(&stream, request_id, exact_pages,
                                     manifest->artifact_digest, client->hash_ops,
                                     client->hash_context);
  if (status != PBNS_OK) {
    goto cleanup;
  }
  stream_ready = true;
  status = client->bulk_begin(
      client->context, &request_id,
      (pbns_view){workspace->signed_request, signed_request_size},
      manifest->image_size);
  if (status != PBNS_OK) {
    goto cleanup;
  }
  bulk_active = true;
  for (;;) {
    workspace->frame = (pbns_frame){0};
    workspace->payload = (pbns_view){0};
    status = client->bulk_receive(client->context, &workspace->frame,
                                  &workspace->payload);
    if (status != PBNS_OK || !view_valid(workspace->payload)) {
      status = status == PBNS_OK ? PBNS_ERR_FORMAT : status;
      goto cleanup;
    }
    if (workspace->frame.type == PBNS_MESSAGE_COMPLETE) {
      status = pbns_recovery_stream_complete(&stream, &workspace->frame,
                                             workspace->payload);
      if (status != PBNS_OK) {
        goto cleanup;
      }
      status = client->bulk_finish(client->context);
      bulk_active = false;
      if (status != PBNS_OK) {
        goto cleanup;
      }
      break;
    }
    pbns_recovery_ack ack = {0};
    status = pbns_recovery_stream_accept(&stream, &workspace->frame,
                                         workspace->payload, &ack);
    if (status != PBNS_OK) {
      goto cleanup;
    }
    if (ack.required) {
      status = client->bulk_ack(client->context, ack.next_sequence, ack.window);
      if (status != PBNS_OK) {
        goto cleanup;
      }
    }
  }

cleanup:
  memset(&request_id, 0, sizeof(request_id));
  memset(nonce, 0, sizeof(nonce));
  clear_transient(workspace);
  if (status != PBNS_OK) {
    if (stream_ready) {
      pbns_recovery_stream_reset(&stream);
    } else {
      memset(exact_pages.ptr, 0, exact_pages.cap);
    }
    if (bulk_active) {
      (void)client->bulk_cancel(client->context);
    }
  } else {
    memset(&stream, 0, sizeof(stream));
  }
  return status;
}
