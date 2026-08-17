#include <Uefi.h>

#include <Library/BaseMemoryLib.h>
#include <Library/PbnsCoseCryptoLib.h>
#include <Library/PbnsIdentityLib.h>
#include <Library/PbnsTrustedTimeLib.h>
#include <Library/PbnsUefiPlatformLib.h>

#include <mbedtls/sha256.h>
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>

#include "PbnsRecoveryServiceLib.h"
#include "../../../src/core/recovery_service_adapter.h"
#include "pbns/broker.h"
#include "pbns/recovery_live.h"
#include "pbns/tls_policy.h"

#define PBNS_RECOVERY_MANIFEST_DEADLINE_MS UINT32_C(600000)
#define PBNS_RECOVERY_ARTIFACT_DEADLINE_MS UINT32_C(2700000)
#define PBNS_RECOVERY_TIME_MAX_RTT_MS UINT32_C(20000)

static const uint8_t RECOVERY_TLS_SPKI_SHA256[32] = {
    0xa0U, 0xd2U, 0x19U, 0x23U, 0xddU, 0xfcU, 0xcbU, 0xa1U, 0x2dU, 0x0aU,
    0x7bU, 0xbdU, 0x74U, 0x08U, 0x65U, 0x0cU, 0xb8U, 0xc5U, 0x4fU, 0x1bU,
    0xe5U, 0x37U, 0xfeU, 0x3aU, 0x7eU, 0x69U, 0xadU, 0xb1U, 0x37U, 0x6dU,
    0xa1U, 0x06U,
};
static const uint8_t RECOVERY_TLS_SERVER_NAME[] = "192.168.1.180";
/* The shared TLS policy fixes TLS 1.2, ECDHE-ECDSA-AES128-GCM-SHA256 and
 * PBNS_TLS_ALPN_PROTOCOL.  This narrow fixture route accepts only the pinned
 * leaf SPKI/SAN exception and never obtains trust material from the Pico or
 * RTC. */
static const pbns_tls_client_config RECOVERY_TLS_CONFIG = {
    .expected_server_name = {RECOVERY_TLS_SERVER_NAME,
                             sizeof(RECOVERY_TLS_SERVER_NAME) - 1U},
    .pinned_leaf_spki_sha256 = {RECOVERY_TLS_SPKI_SHA256,
                                sizeof(RECOVERY_TLS_SPKI_SHA256)},
    .handshake_timeout_ms = 15000U,
};

static const uint8_t TIME_KEY_X[32] = {
    0x18U, 0x4dU, 0x92U, 0x82U, 0xe7U, 0x2fU, 0x5bU, 0x3fU, 0x6eU, 0x0eU,
    0xa7U, 0x3bU, 0x42U, 0xacU, 0x55U, 0xd4U, 0x1fU, 0x18U, 0x58U, 0x8aU,
    0xcaU, 0x5cU, 0xc4U, 0x87U, 0x36U, 0x58U, 0x05U, 0xd5U, 0x78U, 0x2aU,
    0xb3U, 0xcaU,
};
static const uint8_t TIME_KEY_Y[32] = {
    0xeeU, 0x41U, 0x0fU, 0xd3U, 0xafU, 0xa3U, 0x58U, 0x94U, 0xf5U, 0x46U,
    0x0dU, 0x82U, 0x2dU, 0xaaU, 0x3aU, 0x3fU, 0x62U, 0xc6U, 0x1fU, 0x62U,
    0x0eU, 0xffU, 0x4fU, 0x65U, 0xabU, 0x7dU, 0x0eU, 0x31U, 0xb9U, 0x4cU,
    0x78U, 0x93U,
};
static const uint8_t MANIFEST_KEY_X[32] = {
    0x2eU, 0x5dU, 0x61U, 0xfeU, 0x51U, 0xb1U, 0xecU, 0x83U, 0x39U, 0x3eU,
    0x80U, 0x30U, 0x80U, 0x8bU, 0xfcU, 0x50U, 0x59U, 0x8bU, 0xdcU, 0xc8U,
    0xc8U, 0xa7U, 0xdbU, 0x9fU, 0x9fU, 0xb4U, 0x98U, 0xfaU, 0xfaU, 0x48U,
    0x31U, 0x3bU,
};
static const uint8_t MANIFEST_KEY_Y[32] = {
    0xcaU, 0xd9U, 0xefU, 0x86U, 0xbbU, 0x4eU, 0xc1U, 0x1fU, 0x17U, 0xc1U,
    0x2fU, 0xafU, 0x30U, 0xafU, 0x00U, 0xefU, 0xe4U, 0x77U, 0xafU, 0xc9U,
    0x16U, 0xefU, 0xf7U, 0x9bU, 0xb4U, 0x87U, 0x74U, 0x87U, 0x6eU, 0xcdU,
    0xa8U, 0xadU,
};
static const uint8_t POLICY_KEY_X[32] = {
    0x1eU, 0xb5U, 0xdcU, 0x01U, 0xeeU, 0xd6U, 0x85U, 0x63U, 0xe2U, 0x64U,
    0x3fU, 0x98U, 0xdaU, 0x59U, 0xb4U, 0xdbU, 0x72U, 0x0fU, 0x66U, 0x54U,
    0x7aU, 0xefU, 0xcbU, 0x3bU, 0xebU, 0x69U, 0x96U, 0x71U, 0x51U, 0x31U,
    0xcbU, 0x58U,
};
static const uint8_t POLICY_KEY_Y[32] = {
    0x97U, 0x9dU, 0x6bU, 0xdbU, 0x23U, 0xceU, 0xb0U, 0x65U, 0x9cU, 0xcfU,
    0xc8U, 0xf1U, 0xd5U, 0xf1U, 0x98U, 0x9bU, 0xc3U, 0x0cU, 0x1dU, 0xcfU,
    0x8fU, 0x13U, 0xe3U, 0xa5U, 0x56U, 0xc2U, 0x74U, 0x06U, 0xe2U, 0xa6U,
    0x73U, 0x35U,
};
static const uint8_t TIME_KEY_ID[] = "time-key-1";
static const uint8_t MANIFEST_KEY_ID[] = "recovery-manifest-key-1";
static const uint8_t POLICY_KEY_ID[] = "recovery-policy-key-1";

typedef struct recovery_live_context {
  pbns_broker *broker;
  const pbns_identity *identity;
  const pbns_cose_key *identity_key;
  const pbns_cose_key *manifest_key;
} recovery_live_context;

static bool bytes_equal(const uint8_t *left, const uint8_t *right,
                        size_t length) {
  uint8_t difference = 0U;
  for (size_t index = 0U; index < length; ++index) {
    difference |= (uint8_t)(left[index] ^ right[index]);
  }
  return difference == 0U;
}

static bool keys_pair_different(const uint8_t left_x[32],
                                const uint8_t left_y[32],
                                const uint8_t right_x[32],
                                const uint8_t right_y[32]) {
  return !bytes_equal(left_x, right_x, 32U) ||
         !bytes_equal(left_y, right_y, 32U);
}

static bool public_keys_distinct(void) {
  return keys_pair_different(TIME_KEY_X, TIME_KEY_Y, MANIFEST_KEY_X,
                             MANIFEST_KEY_Y) &&
         keys_pair_different(TIME_KEY_X, TIME_KEY_Y, POLICY_KEY_X,
                             POLICY_KEY_Y) &&
         keys_pair_different(MANIFEST_KEY_X, MANIFEST_KEY_Y, POLICY_KEY_X,
                             POLICY_KEY_Y);
}

static pbns_status manifest_random(void *context, pbns_buffer output) {
  const recovery_live_context *live = context;
  if (live == NULL || live->identity == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  return pbns_identity_random(live->identity, output);
}

static pbns_status manifest_sign(void *context, pbns_view payload, pbns_view aad,
                                 pbns_buffer output, size_t *written) {
  const recovery_live_context *live = context;
  if (live == NULL || live->identity_key == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  return pbns_cose_uefi_sign1_sign(live->identity_key, payload, aad, output,
                                   written);
}

static pbns_status manifest_exchange(void *context,
                                     const pbns_request_id *request_id,
                                     pbns_view signed_request,
                                     pbns_buffer output, size_t *written) {
  const recovery_live_context *live = context;
  pbns_broker_response response = {0};
  if (live == NULL || live->broker == NULL || request_id == NULL ||
      output.ptr == NULL || output.len != 0U || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  const pbns_status status = pbns_broker_request_with_id(
      live->broker, PBNS_SERVICE_RECOVERY_ARTIFACT, request_id, signed_request,
      PBNS_RECOVERY_MANIFEST_DEADLINE_MS, &response);
  if (status != PBNS_OK) {
    return status;
  }
  if (response.payload.len == 0U || response.payload.len > output.cap) {
    return PBNS_ERR_LIMIT;
  }
  CopyMem(output.ptr, response.payload.ptr, response.payload.len);
  *written = response.payload.len;
  return PBNS_OK;
}

static bool manifest_profile_valid(pbns_view signed_manifest) {
  QCBORDecodeContext outer = {0};
  QCBORItem item = {0};
  QCBORDecode_Init(&outer,
                   (UsefulBufC){signed_manifest.ptr, signed_manifest.len},
                   QCBOR_DECODE_MODE_NORMAL);
  if (QCBORDecode_GetNext(&outer, &item) != QCBOR_SUCCESS ||
      item.uDataType != QCBOR_TYPE_ARRAY || item.uLabelType != QCBOR_TYPE_NONE ||
      item.val.uCount != 4U || QCBORDecode_GetNthTag(&outer, &item, 0U) != 18U ||
      QCBORDecode_GetNthTag(&outer, &item, 1U) != CBOR_TAG_INVALID64 ||
      QCBORDecode_GetNext(&outer, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uLabelType != QCBOR_TYPE_NONE ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING) {
    return false;
  }
  const UsefulBufC protected_headers = item.val.string;
  if (QCBORDecode_GetNext(&outer, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uLabelType != QCBOR_TYPE_NONE ||
      item.uDataType != QCBOR_TYPE_MAP || item.val.uCount != 0U ||
      QCBORDecode_GetNext(&outer, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uLabelType != QCBOR_TYPE_NONE ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING || item.val.string.len == 0U ||
      QCBORDecode_GetNext(&outer, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uLabelType != QCBOR_TYPE_NONE ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING || item.val.string.len != 64U ||
      QCBORDecode_Finish(&outer) != QCBOR_SUCCESS) {
    return false;
  }
  QCBORDecodeContext headers = {0};
  QCBORDecode_Init(&headers, protected_headers, QCBOR_DECODE_MODE_NORMAL);
  if (QCBORDecode_GetNext(&headers, &item) != QCBOR_SUCCESS ||
      item.uDataType != QCBOR_TYPE_MAP || item.uLabelType != QCBOR_TYPE_NONE ||
      item.val.uCount != 2U ||
      QCBORDecode_GetNext(&headers, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uLabelType != QCBOR_TYPE_INT64 ||
      item.label.int64 != 1 || item.uDataType != QCBOR_TYPE_INT64 ||
      item.val.int64 != -7 || QCBORDecode_GetNext(&headers, &item) != QCBOR_SUCCESS ||
      item.uNestingLevel != 1U || item.uLabelType != QCBOR_TYPE_INT64 ||
      item.label.int64 != 4 || item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      item.val.string.len != sizeof(MANIFEST_KEY_ID) - 1U ||
      !bytes_equal(item.val.string.ptr, MANIFEST_KEY_ID,
                   sizeof(MANIFEST_KEY_ID) - 1U) ||
      QCBORDecode_Finish(&headers) != QCBOR_SUCCESS) {
    return false;
  }
  uint8_t canonical[96] = {0};
  QCBOREncodeContext encoder = {0};
  UsefulBufC encoded = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){canonical, sizeof(canonical)});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddInt64ToMapN(&encoder, 1, -7);
  QCBOREncode_AddBytesToMapN(
      &encoder, 4,
      (UsefulBufC){MANIFEST_KEY_ID, sizeof(MANIFEST_KEY_ID) - 1U});
  QCBOREncode_CloseMap(&encoder);
  return QCBOREncode_Finish(&encoder, &encoded) == QCBOR_SUCCESS &&
         encoded.len == protected_headers.len &&
         bytes_equal(encoded.ptr, protected_headers.ptr, encoded.len);
}

static pbns_status manifest_verify(void *context, pbns_view signed_manifest,
                                   pbns_view aad, pbns_view *payload) {
  const recovery_live_context *live = context;
  if (live == NULL || live->manifest_key == NULL || payload == NULL ||
      !manifest_profile_valid(signed_manifest)) {
    return PBNS_ERR_AUTHENTICATION;
  }
  return pbns_cose_uefi_sign1_verify(live->manifest_key, signed_manifest, aad,
                                     payload);
}

static pbns_status bulk_begin(void *context, const pbns_request_id *request_id,
                              pbns_view signed_request, uint64_t exact_size) {
  recovery_live_context *live = context;
  if (live == NULL || live->broker == NULL || request_id == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  return pbns_broker_bulk_begin(live->broker, PBNS_SERVICE_RECOVERY_ARTIFACT,
                                request_id, signed_request, exact_size,
                                PBNS_RECOVERY_ARTIFACT_DEADLINE_MS);
}

static pbns_status bulk_receive(void *context, pbns_frame *frame,
                                pbns_view *payload) {
  recovery_live_context *live = context;
  pbns_broker_response response = {0};
  if (live == NULL || live->broker == NULL || frame == NULL || payload == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status status = pbns_broker_bulk_receive(live->broker, &response);
  if (status == PBNS_OK) {
    *frame = response.frame;
    *payload = response.payload;
  }
  return status;
}

static pbns_status bulk_ack(void *context, uint32_t next_sequence,
                            uint32_t window) {
  recovery_live_context *live = context;
  return live == NULL || live->broker == NULL
             ? PBNS_ERR_ARGUMENT
             : pbns_broker_bulk_ack(live->broker, next_sequence, window);
}

static pbns_status bulk_finish(void *context) {
  recovery_live_context *live = context;
  return live == NULL || live->broker == NULL
             ? PBNS_ERR_ARGUMENT
             : pbns_broker_bulk_finish(live->broker);
}

static pbns_status bulk_cancel(void *context) {
  recovery_live_context *live = context;
  return live == NULL || live->broker == NULL
             ? PBNS_ERR_ARGUMENT
             : pbns_broker_cancel(live->broker);
}

static pbns_status hash_begin(void *context) {
  mbedtls_sha256_context *hash = context;
  if (hash == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  mbedtls_sha256_free(hash);
  mbedtls_sha256_init(hash);
  return mbedtls_sha256_starts(hash, 0) == 0 ? PBNS_OK : PBNS_ERR_CRYPTO;
}

static pbns_status hash_update(void *context, pbns_view data) {
  mbedtls_sha256_context *hash = context;
  return hash == NULL || (data.ptr == NULL && data.len != 0U)
             ? PBNS_ERR_ARGUMENT
             : (mbedtls_sha256_update(hash, data.ptr, data.len) == 0 ? PBNS_OK
                                                                      : PBNS_ERR_CRYPTO);
}

static pbns_status hash_finish(void *context, uint8_t digest[32]) {
  mbedtls_sha256_context *hash = context;
  if (hash == NULL || digest == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  return mbedtls_sha256_finish(hash, digest) == 0 ? PBNS_OK : PBNS_ERR_CRYPTO;
}

static void hash_clear(void *context) {
  mbedtls_sha256_context *hash = context;
  if (hash != NULL) {
    mbedtls_sha256_free(hash);
    SetMem(hash, sizeof(*hash), 0U);
  }
}

const pbns_tls_client_config *EFIAPI PbnsRecoveryServiceTrustConfig(void) {
  return &RECOVERY_TLS_CONFIG;
}

static const pbns_recovery_hash_ops RECOVERY_HASH_OPS = {
    .begin = hash_begin,
    .update = hash_update,
    .finish = hash_finish,
    .clear = hash_clear,
};

pbns_status PbnsRecoveryServiceTrustKeys(pbns_cose_key *time_key,
                                         pbns_cose_key *manifest_key,
                                         pbns_cose_key *policy_key) {
  if (time_key == NULL || manifest_key == NULL || policy_key == NULL ||
      !public_keys_distinct()) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_status status = pbns_cose_key_from_p256_public(
      time_key, (pbns_view){TIME_KEY_X, sizeof(TIME_KEY_X)},
      (pbns_view){TIME_KEY_Y, sizeof(TIME_KEY_Y)});
  if (status != PBNS_OK) {
    return status;
  }
  status = pbns_cose_key_from_p256_public(
      manifest_key, (pbns_view){MANIFEST_KEY_X, sizeof(MANIFEST_KEY_X)},
      (pbns_view){MANIFEST_KEY_Y, sizeof(MANIFEST_KEY_Y)});
  if (status != PBNS_OK) {
    pbns_cose_key_reset(time_key);
    return status;
  }
  status = pbns_cose_key_from_p256_public(
      policy_key, (pbns_view){POLICY_KEY_X, sizeof(POLICY_KEY_X)},
      (pbns_view){POLICY_KEY_Y, sizeof(POLICY_KEY_Y)});
  if (status != PBNS_OK) {
    pbns_cose_key_reset(manifest_key);
    pbns_cose_key_reset(time_key);
  }
  return status;
}

pbns_status PbnsRecoveryServiceTrustedTimeQuery(
    EFI_BOOT_SERVICES *boot_services, pbns_broker *broker,
    const pbns_identity *identity, const pbns_cose_key *identity_key,
    const pbns_cose_key *time_key, const uint8_t fingerprint[32],
    pbns_trusted_time_workspace *workspace, pbns_time_interval *interval) {
  pbns_uefi_trusted_time_environment environment = {
      .boot_services = boot_services,
      .broker = broker,
      .identity = identity,
      .identity_key = identity_key,
      .time_verification_key = time_key,
      .time_key_id = {TIME_KEY_ID, sizeof(TIME_KEY_ID) - 1U},
      .maximum_round_trip_ms = PBNS_RECOVERY_TIME_MAX_RTT_MS,
  };
  pbns_trusted_time_client client = {0};
  if (fingerprint == NULL || workspace == NULL || interval == NULL ||
      PbnsTrustedTimeClientInit(&environment, &client) != PBNS_OK) {
    return PBNS_ERR_ARGUMENT;
  }
  *interval = (pbns_time_interval){0};
  return pbns_trusted_time_query(&client, fingerprint, NULL, workspace,
                                 interval);
}

pbns_status PbnsRecoveryServiceLiveManifest(
    pbns_broker *broker, const pbns_identity *identity,
    const pbns_cose_key *identity_key, const pbns_cose_key *manifest_key,
    const uint8_t fingerprint[32], const pbns_time_interval *trusted_time,
    pbns_recovery_live_workspace *workspace, pbns_recovery_manifest *manifest) {
  recovery_live_context context = {
      .broker = broker,
      .identity = identity,
      .identity_key = identity_key,
      .manifest_key = manifest_key,
  };
  const pbns_recovery_live_client client = {
      .random_fill = manifest_random,
      .sign_request = manifest_sign,
      .manifest_exchange = manifest_exchange,
      .verify_manifest = manifest_verify,
      .bulk_begin = bulk_begin,
      .bulk_receive = bulk_receive,
      .bulk_ack = bulk_ack,
      .bulk_finish = bulk_finish,
      .bulk_cancel = bulk_cancel,
      .hash_ops = &RECOVERY_HASH_OPS,
      .context = &context,
      .hash_context = NULL,
      .manifest_key_id = {MANIFEST_KEY_ID, sizeof(MANIFEST_KEY_ID) - 1U},
      .policy_key_id = {POLICY_KEY_ID, sizeof(POLICY_KEY_ID) - 1U},
  };
  return pbns_recovery_live_manifest(&client, fingerprint, trusted_time,
                                     workspace, manifest);
}

pbns_status PbnsRecoveryServiceLiveArtifact(
    pbns_broker *broker, const pbns_identity *identity,
    const pbns_cose_key *identity_key, const pbns_cose_key *manifest_key,
    pbns_recovery_service_manifest_state *manifest_state, pbns_buffer pages,
    pbns_recovery_live_workspace *workspace, mbedtls_sha256_context *hash) {
  recovery_live_context context = {
      .broker = broker,
      .identity = identity,
      .identity_key = identity_key,
      .manifest_key = manifest_key,
  };
  const pbns_recovery_live_client client = {
      .random_fill = manifest_random,
      .sign_request = manifest_sign,
      .manifest_exchange = manifest_exchange,
      .verify_manifest = manifest_verify,
      .bulk_begin = bulk_begin,
      .bulk_receive = bulk_receive,
      .bulk_ack = bulk_ack,
      .bulk_finish = bulk_finish,
      .bulk_cancel = bulk_cancel,
      .hash_ops = &RECOVERY_HASH_OPS,
      .context = &context,
      .hash_context = hash,
      .manifest_key_id = {MANIFEST_KEY_ID, sizeof(MANIFEST_KEY_ID) - 1U},
      .policy_key_id = {POLICY_KEY_ID, sizeof(POLICY_KEY_ID) - 1U},
  };
  return pbns_recovery_service_stream(&client, manifest_state, pages,
                                      workspace);
}
