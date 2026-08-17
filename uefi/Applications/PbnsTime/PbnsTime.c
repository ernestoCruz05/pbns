#include <Uefi.h>

#include <Library/PbnsCoseCryptoLib.h>
#include <Library/PbnsTrustedTimeLib.h>
#include <Library/PbnsUefiPlatformLib.h>
#include <Library/UefiLib.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/identity.h"
#include "pbns/trusted_time.h"

static const uint8_t TIME_KEY_X[32] = {
    0x18U, 0x4dU, 0x92U, 0x82U, 0xe7U, 0x2fU, 0x5bU, 0x3fU, 0x6eU, 0x0eU, 0xa7U,
    0x3bU, 0x42U, 0xacU, 0x55U, 0xd4U, 0x1fU, 0x18U, 0x58U, 0x8aU, 0xcaU, 0x5cU,
    0xc4U, 0x87U, 0x36U, 0x58U, 0x05U, 0xd5U, 0x78U, 0x2aU, 0xb3U, 0xcaU,
};

static const uint8_t TIME_KEY_Y[32] = {
    0xeeU, 0x41U, 0x0fU, 0xd3U, 0xafU, 0xa3U, 0x58U, 0x94U, 0xf5U, 0x46U, 0x0dU,
    0x82U, 0x2dU, 0xaaU, 0x3aU, 0x3fU, 0x62U, 0xc6U, 0x1fU, 0x62U, 0x0eU, 0xffU,
    0x4fU, 0x65U, 0xabU, 0x7dU, 0x0eU, 0x31U, 0xb9U, 0x4cU, 0x78U, 0x93U,
};

static const uint8_t TIME_VECTOR_COSE[245] = {
    0xd2U, 0x84U, 0x4fU, 0xa2U, 0x01U, 0x26U, 0x04U, 0x4aU, 0x74U, 0x69U, 0x6dU,
    0x65U, 0x2dU, 0x6bU, 0x65U, 0x79U, 0x2dU, 0x31U, 0xa0U, 0x58U, 0x9eU, 0xacU,
    0x01U, 0x6cU, 0x50U, 0x42U, 0x4eU, 0x53U, 0x2dU, 0x54U, 0x49U, 0x4dU, 0x45U,
    0x2dU, 0x76U, 0x31U, 0x02U, 0x01U, 0x03U, 0x01U, 0x04U, 0x50U, 0x00U, 0x01U,
    0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU,
    0x0dU, 0x0eU, 0x0fU, 0x05U, 0x58U, 0x20U, 0x22U, 0x22U, 0x22U, 0x22U, 0x22U,
    0x22U, 0x22U, 0x22U, 0x22U, 0x22U, 0x22U, 0x22U, 0x22U, 0x22U, 0x22U, 0x22U,
    0x22U, 0x22U, 0x22U, 0x22U, 0x22U, 0x22U, 0x22U, 0x22U, 0x22U, 0x22U, 0x22U,
    0x22U, 0x22U, 0x22U, 0x22U, 0x22U, 0x06U, 0x58U, 0x20U, 0x33U, 0x33U, 0x33U,
    0x33U, 0x33U, 0x33U, 0x33U, 0x33U, 0x33U, 0x33U, 0x33U, 0x33U, 0x33U, 0x33U,
    0x33U, 0x33U, 0x33U, 0x33U, 0x33U, 0x33U, 0x33U, 0x33U, 0x33U, 0x33U, 0x33U,
    0x33U, 0x33U, 0x33U, 0x33U, 0x33U, 0x33U, 0x33U, 0x07U, 0x1aU, 0x6bU, 0x49U,
    0xd2U, 0x00U, 0x08U, 0x19U, 0x04U, 0xd2U, 0x09U, 0x1aU, 0x01U, 0x7dU, 0x78U,
    0x40U, 0x0aU, 0x71U, 0x74U, 0x65U, 0x73U, 0x74U, 0x2dU, 0x73U, 0x79U, 0x6eU,
    0x63U, 0x68U, 0x72U, 0x6fU, 0x6eU, 0x69U, 0x7aU, 0x65U, 0x64U, 0x0bU, 0x4aU,
    0x74U, 0x69U, 0x6dU, 0x65U, 0x2dU, 0x6bU, 0x65U, 0x79U, 0x2dU, 0x31U, 0x0cU,
    0x19U, 0x03U, 0xe8U, 0x58U, 0x40U, 0x2eU, 0xc6U, 0xe9U, 0xfcU, 0xc8U, 0x5dU,
    0xe9U, 0xf0U, 0xf0U, 0xaaU, 0x3eU, 0x9bU, 0x93U, 0xc7U, 0x6bU, 0x6fU, 0xa5U,
    0xadU, 0xd9U, 0xdbU, 0x14U, 0x35U, 0x24U, 0xdbU, 0xb1U, 0x57U, 0xe0U, 0x1aU,
    0x88U, 0x4bU, 0xdbU, 0xcbU, 0xd3U, 0xe3U, 0x56U, 0x21U, 0xdbU, 0xb1U, 0x33U,
    0xf1U, 0x47U, 0xa9U, 0x9bU, 0x3aU, 0xf3U, 0xc0U, 0x19U, 0xb2U, 0x1bU, 0xd5U,
    0x97U, 0x87U, 0x05U, 0x6dU, 0x2fU, 0x52U, 0xadU, 0xe0U, 0x69U, 0x1cU, 0x1cU,
    0x45U, 0x96U, 0x45U,
};

static const uint8_t TIME_KEY_ID[] = "time-key-1";

typedef struct time_probe_context {
  EFI_BOOT_SERVICES *boot_services;
  const pbns_cose_key *signing_key;
  const pbns_cose_key *verification_key;
} time_probe_context;

static pbns_status probe_public(void *context, pbns_buffer output,
                                size_t *written) {
  (void)context;
  (void)output;
  (void)written;
  return PBNS_ERR_UNSUPPORTED;
}

static pbns_status probe_fingerprint(void *context, pbns_buffer output) {
  (void)context;
  (void)output;
  return PBNS_ERR_UNSUPPORTED;
}

static pbns_status probe_identity_sign(void *context, pbns_view digest,
                                       pbns_buffer signature, size_t *written) {
  (void)context;
  if (digest.ptr == NULL || digest.len != 32U || signature.ptr == NULL ||
      signature.cap < 64U || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  memset(signature.ptr, 0x5a, 64U);
  *written = 64U;
  return PBNS_OK;
}

static pbns_status probe_identity_random(void *context, pbns_buffer output) {
  (void)context;
  (void)output;
  return PBNS_ERR_UNSUPPORTED;
}

static void probe_identity_close(void *context) { (void)context; }

static const pbns_identity_ops PROBE_IDENTITY_OPS = {
    .public_cose_key = probe_public,
    .fingerprint = probe_fingerprint,
    .sign_digest = probe_identity_sign,
    .random = probe_identity_random,
    .close = probe_identity_close,
};

static pbns_status time_random(void *context, pbns_buffer output) {
  (void)context;
  if (output.ptr == NULL || output.len != 0U || output.cap != 48U) {
    return PBNS_ERR_ARGUMENT;
  }
  for (size_t index = 0U; index < 16U; ++index) {
    output.ptr[index] = (uint8_t)index;
  }
  memset(output.ptr + 16U, 0x33, 32U);
  return PBNS_OK;
}

static pbns_status time_sign(void *context, pbns_view payload, pbns_view aad,
                             pbns_buffer output, size_t *written) {
  const time_probe_context *probe = context;
  return pbns_cose_uefi_sign1_sign(probe->signing_key, payload, aad, output,
                                   written);
}

static pbns_status time_exchange(void *context, pbns_view request,
                                 pbns_buffer response, size_t *written) {
  (void)context;
  if (request.ptr == NULL || request.len == 0U || response.ptr == NULL ||
      response.len != 0U || response.cap < sizeof(TIME_VECTOR_COSE) ||
      written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  memcpy(response.ptr, TIME_VECTOR_COSE, sizeof(TIME_VECTOR_COSE));
  *written = sizeof(TIME_VECTOR_COSE);
  return PBNS_OK;
}

static pbns_status time_verify(void *context, pbns_view message, pbns_view aad,
                               pbns_view *payload) {
  const time_probe_context *probe = context;
  return pbns_cose_uefi_sign1_verify(probe->verification_key, message, aad,
                                     payload);
}

static pbns_status time_monotonic(void *context, uint64_t *milliseconds) {
  const time_probe_context *probe = context;
  if (milliseconds == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  UINT64 current = 0U;
  const pbns_status status =
      PbnsUefiMonotonicMs(probe->boot_services, &current);
  if (status == PBNS_OK) {
    *milliseconds = (uint64_t)current;
  }
  return status;
}

EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE image_handle,
                           IN EFI_SYSTEM_TABLE *system_table) {
  (void)image_handle;
  pbns_cose_key verification_key = {0};
  pbns_cose_key signing_key = {0};
  pbns_identity identity = {0};
  uint8_t identity_context = 0U;
  if (system_table == NULL || system_table->BootServices == NULL ||
      pbns_cose_key_from_p256_public(
          &verification_key, (pbns_view){TIME_KEY_X, sizeof(TIME_KEY_X)},
          (pbns_view){TIME_KEY_Y, sizeof(TIME_KEY_Y)}) != PBNS_OK ||
      pbns_identity_open(&identity, &PROBE_IDENTITY_OPS, &identity_context,
                         PBNS_IDENTITY_SOFTWARE) != PBNS_OK ||
      pbns_cose_key_from_identity(&signing_key, &identity) != PBNS_OK) {
    pbns_identity_close(&identity);
    pbns_cose_key_reset(&signing_key);
    pbns_cose_key_reset(&verification_key);
    Print(L"PBNS TRUSTED TIME PROBE FAIL setup\r\n");
    return EFI_SECURITY_VIOLATION;
  }

  pbns_broker broker_contract = {0};
  pbns_uefi_trusted_time_environment production_environment = {
      .boot_services = system_table->BootServices,
      .broker = &broker_contract,
      .identity = &identity,
      .identity_key = &signing_key,
      .time_verification_key = &verification_key,
      .time_key_id = {TIME_KEY_ID, sizeof(TIME_KEY_ID) - 1U},
      .maximum_round_trip_ms = 1000U,
  };
  pbns_trusted_time_client production_client = {0};
  if (PbnsTrustedTimeClientInit(&production_environment, &production_client) !=
          PBNS_OK ||
      production_client.exchange == NULL ||
      production_client.monotonic_ms == NULL) {
    pbns_identity_close(&identity);
    pbns_cose_key_reset(&signing_key);
    pbns_cose_key_reset(&verification_key);
    Print(L"PBNS TRUSTED TIME PROBE FAIL adapter\r\n");
    return EFI_SECURITY_VIOLATION;
  }
  memset(&production_client, 0, sizeof(production_client));
  memset(&production_environment, 0, sizeof(production_environment));
  memset(&broker_contract, 0, sizeof(broker_contract));

  time_probe_context probe = {
      .boot_services = system_table->BootServices,
      .signing_key = &signing_key,
      .verification_key = &verification_key,
  };
  pbns_trusted_time_client client = {
      .random_fill = time_random,
      .sign_request = time_sign,
      .exchange = time_exchange,
      .verify_assertion = time_verify,
      .monotonic_ms = time_monotonic,
      .random_context = &probe,
      .sign_context = &probe,
      .exchange_context = &probe,
      .verify_context = &probe,
      .clock_context = &probe,
      .time_key_id = {TIME_KEY_ID, sizeof(TIME_KEY_ID) - 1U},
      .maximum_round_trip_ms = 1000U,
  };
  uint8_t request_payload[PBNS_TIME_ENCODED_MAX_SIZE] = {0};
  uint8_t signed_request[768] = {0};
  uint8_t signed_response[1024] = {0};
  uint8_t canonical_scratch[PBNS_TIME_ENCODED_MAX_SIZE] = {0};
  uint8_t aad[192] = {0};
  pbns_trusted_time_workspace workspace = {
      .request_payload = {request_payload, 0U, sizeof(request_payload)},
      .signed_request = {signed_request, 0U, sizeof(signed_request)},
      .signed_response = {signed_response, 0U, sizeof(signed_response)},
      .canonical_scratch = {canonical_scratch, 0U, sizeof(canonical_scratch)},
      .aad = {aad, 0U, sizeof(aad)},
  };
  uint8_t host_fingerprint[PBNS_TIME_FINGERPRINT_SIZE] = {0};
  memset(host_fingerprint, 0x22, sizeof(host_fingerprint));
  pbns_time_interval interval = {0};
  const pbns_status status = pbns_trusted_time_query(
      &client, host_fingerprint, NULL, &workspace, &interval);
  pbns_identity_close(&identity);
  pbns_cose_key_reset(&signing_key);
  pbns_cose_key_reset(&verification_key);
  memset(host_fingerprint, 0, sizeof(host_fingerprint));
  if (status != PBNS_OK || interval.earliest_ns <= 0 ||
      interval.latest_ns < interval.earliest_ns) {
    Print(L"PBNS TRUSTED TIME PROBE FAIL query\r\n");
    return EFI_SECURITY_VIOLATION;
  }
  Print(L"PBNS TRUSTED TIME INTERVAL PASS\r\n");
  return EFI_SUCCESS;
}
