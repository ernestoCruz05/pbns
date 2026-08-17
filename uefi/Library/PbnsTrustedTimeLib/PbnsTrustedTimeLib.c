#include <Library/PbnsTrustedTimeLib.h>
#include <Library/PbnsUefiPlatformLib.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static pbns_status time_random(void *context, pbns_buffer output) {
  const pbns_uefi_trusted_time_environment *environment = context;
  return pbns_identity_random(environment->identity, output);
}

static pbns_status time_sign(void *context, pbns_view payload, pbns_view aad,
                             pbns_buffer output, size_t *written) {
  const pbns_uefi_trusted_time_environment *environment = context;
  return pbns_cose_uefi_sign1_sign(environment->identity_key, payload, aad,
                                   output, written);
}

static pbns_status time_exchange(void *context, pbns_view request,
                                 pbns_buffer output, size_t *written) {
  const pbns_uefi_trusted_time_environment *environment = context;
  if (output.ptr == NULL || output.len != 0U || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  pbns_broker_response response = {0};
  const pbns_status status = pbns_broker_request(
      environment->broker, PBNS_SERVICE_TRUSTED_TIME, request,
      environment->maximum_round_trip_ms, &response);
  if (status != PBNS_OK) {
    return status;
  }
  if (response.payload.len == 0U || response.payload.len > output.cap) {
    return PBNS_ERR_LIMIT;
  }
  memcpy(output.ptr, response.payload.ptr, response.payload.len);
  *written = response.payload.len;
  return PBNS_OK;
}

static pbns_status time_verify(void *context, pbns_view message, pbns_view aad,
                               pbns_view *payload) {
  const pbns_uefi_trusted_time_environment *environment = context;
  return pbns_cose_uefi_sign1_verify(environment->time_verification_key,
                                     message, aad, payload);
}

static pbns_status time_monotonic(void *context, uint64_t *milliseconds) {
  const pbns_uefi_trusted_time_environment *environment = context;
  if (milliseconds == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  UINT64 current = 0U;
  const EFI_STATUS status =
      PbnsUefiMonotonicMs(environment->boot_services, &current);
  if (EFI_ERROR(status)) {
    return PBNS_ERR_STATE;
  }
  *milliseconds = (uint64_t)current;
  return PBNS_OK;
}

pbns_status EFIAPI
PbnsTrustedTimeClientInit(pbns_uefi_trusted_time_environment *environment,
                          pbns_trusted_time_client *client) {
  if (environment == NULL || client == NULL ||
      environment->boot_services == NULL || environment->broker == NULL ||
      environment->identity == NULL || environment->identity_key == NULL ||
      environment->identity_key->magic != PBNS_COSE_KEY_MAGIC ||
      environment->identity_key->kind != PBNS_COSE_KEY_IDENTITY ||
      environment->identity_key->identity != environment->identity ||
      environment->identity_key->native.key.ptr != environment->identity_key ||
      environment->time_verification_key == NULL ||
      environment->time_verification_key->magic != PBNS_COSE_KEY_MAGIC ||
      environment->time_verification_key->kind != PBNS_COSE_KEY_P256_PUBLIC ||
      environment->time_verification_key->native.key.ptr !=
          environment->time_verification_key ||
      environment->time_key_id.ptr == NULL ||
      environment->time_key_id.len == 0U ||
      environment->time_key_id.len > PBNS_TIME_KEY_ID_MAX_SIZE ||
      environment->maximum_round_trip_ms == 0U ||
      environment->maximum_round_trip_ms > PBNS_TIME_MAX_AGE_MS) {
    return PBNS_ERR_ARGUMENT;
  }
  *client = (pbns_trusted_time_client){
      .random_fill = time_random,
      .sign_request = time_sign,
      .exchange = time_exchange,
      .verify_assertion = time_verify,
      .monotonic_ms = time_monotonic,
      .random_context = environment,
      .sign_context = environment,
      .exchange_context = environment,
      .verify_context = environment,
      .clock_context = environment,
      .time_key_id = environment->time_key_id,
      .maximum_round_trip_ms = environment->maximum_round_trip_ms,
  };
  return PBNS_OK;
}
