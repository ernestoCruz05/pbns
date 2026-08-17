#ifndef PBNS_RECOVERY_LIVE_H
#define PBNS_RECOVERY_LIVE_H

#include <stddef.h>
#include <stdint.h>

#include "pbns/recovery_manifest.h"
#include "pbns/recovery_request.h"
#include "pbns/recovery_stream.h"

#define PBNS_RECOVERY_LIVE_SIGNED_REQUEST_MAX_SIZE 65536U

typedef pbns_status (*pbns_recovery_live_random_fn)(void *context,
                                                    pbns_buffer output);
typedef pbns_status (*pbns_recovery_live_sign_fn)(void *context,
                                                  pbns_view payload,
                                                  pbns_view aad,
                                                  pbns_buffer output,
                                                  size_t *written);
typedef pbns_status (*pbns_recovery_live_manifest_exchange_fn)(
    void *context, const pbns_request_id *request_id, pbns_view signed_request,
    pbns_buffer output, size_t *written);
/* O verificador confirma a assinatura Sign1, o perfil protegido e o KID de
 * manifesto fixado antes de devolver a carga autenticada. */
typedef pbns_status (*pbns_recovery_live_verify_fn)(void *context,
                                                    pbns_view signed_manifest,
                                                    pbns_view aad,
                                                    pbns_view *payload);
typedef pbns_status (*pbns_recovery_live_bulk_begin_fn)(
    void *context, const pbns_request_id *request_id, pbns_view signed_request,
    uint64_t exact_size);
typedef pbns_status (*pbns_recovery_live_bulk_receive_fn)(void *context,
                                                           pbns_frame *frame,
                                                           pbns_view *payload);
typedef pbns_status (*pbns_recovery_live_bulk_ack_fn)(void *context,
                                                       uint32_t next_sequence,
                                                       uint32_t window);
typedef pbns_status (*pbns_recovery_live_bulk_terminal_fn)(void *context);

typedef struct pbns_recovery_live_client {
  pbns_recovery_live_random_fn random_fill;
  pbns_recovery_live_sign_fn sign_request;
  pbns_recovery_live_manifest_exchange_fn manifest_exchange;
  pbns_recovery_live_verify_fn verify_manifest;
  pbns_recovery_live_bulk_begin_fn bulk_begin;
  pbns_recovery_live_bulk_receive_fn bulk_receive;
  pbns_recovery_live_bulk_ack_fn bulk_ack;
  pbns_recovery_live_bulk_terminal_fn bulk_finish;
  pbns_recovery_live_bulk_terminal_fn bulk_cancel;
  const pbns_recovery_hash_ops *hash_ops;
  void *context;
  void *hash_context;
  pbns_view manifest_key_id;
  pbns_view policy_key_id;
} pbns_recovery_live_client;

typedef struct pbns_recovery_live_workspace {
  uint8_t request_payload[PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE];
  uint8_t signed_request[PBNS_RECOVERY_LIVE_SIGNED_REQUEST_MAX_SIZE];
  uint8_t signed_manifest[PBNS_RECOVERY_MANIFEST_SIGNED_MAX_SIZE];
  size_t signed_manifest_size;
  uint8_t canonical_scratch[PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE];
  uint8_t aad_scratch[PBNS_RECOVERY_MANIFEST_AAD_MAX_SIZE];
  pbns_frame frame;
  pbns_view payload;
} pbns_recovery_live_workspace;

/* As vistas de política e KID mantêm-se válidas apenas enquanto o manifesto
 * assinado aceite no espaço de trabalho não for reutilizado ou limpo. */
pbns_status pbns_recovery_live_manifest(
    const pbns_recovery_live_client *client,
    const uint8_t host_fingerprint[PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE],
    const pbns_time_interval *trusted_time, pbns_recovery_live_workspace *workspace,
    pbns_recovery_manifest *manifest);

pbns_status pbns_recovery_live_artifact(
    const pbns_recovery_live_client *client,
    const pbns_recovery_manifest *manifest, pbns_buffer exact_pages,
    pbns_recovery_live_workspace *workspace);

#endif
