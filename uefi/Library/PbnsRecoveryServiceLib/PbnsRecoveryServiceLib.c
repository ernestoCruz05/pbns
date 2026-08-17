#include <Uefi.h>

#include "PbnsTpmIdentityLib.h"
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PbnsCoseCryptoLib.h>
#include <Library/PbnsIdentityLib.h>
#include <Library/PbnsUefiPlatformLib.h>

#include <mbedtls/sha256.h>

#include <PbnsTlsTransportLib.h>
#include <PbnsUsbTransportLib.h>

#include "PbnsRecoveryRollbackUefi.h"
#include "PbnsRecoveryServiceLib.h"
#include "PbnsRecoveryStreamUefi.h"
#include "../../../src/core/recovery_service_adapter.h"
#include "pbns/broker.h"
#include "pbns/identity.h"
#include "pbns/recovery_live.h"
#include "pbns/trusted_time.h"

#define PBNS_RECOVERY_BROKER_BUFFER_SIZE PBNS_FRAME_V1_WIRE_MAX
#define PBNS_RECOVERY_BROKER_WORKSPACE_SIZE \
  ((size_t)PBNS_RECOVERY_BROKER_BUFFER_SIZE * 4U)

struct PBNS_RECOVERY_SERVICE {
  EFI_BOOT_SERVICES *boot_services;
  pbns_recovery_assurance_mode mode;
  pbns_identity identity;
  pbns_tpm_capability_result capabilities;
  pbns_cose_key identity_key;
  pbns_cose_key time_key;
  pbns_cose_key manifest_key;
  pbns_cose_key policy_key;
  PBNS_RECOVERY_ROLLBACK *rollback;
  pbns_usb_transport *usb_transport;
  PBNS_TLS_UEFI_TRANSPORT *tls_transport;
  PBNS_TPM_RANDOM_SOURCE tls_tpm_random;
  pbns_broker broker;
  uint8_t *broker_workspace;
  uint8_t fingerprint[PBNS_TIME_FINGERPRINT_SIZE];
  uint8_t time_request_payload[PBNS_TIME_ENCODED_MAX_SIZE];
  uint8_t time_signed_request[PBNS_TIME_SIGNED_MAX_SIZE];
  uint8_t time_signed_response[PBNS_TIME_SIGNED_MAX_SIZE];
  uint8_t time_canonical_scratch[PBNS_TIME_ENCODED_MAX_SIZE];
  uint8_t time_aad[PBNS_TIME_AAD_MAX_SIZE];
  pbns_recovery_live_workspace live_workspace;
  pbns_recovery_service_manifest_state manifest_state;
  mbedtls_sha256_context stream_hash;
  pbns_time_interval trusted_interval;
  bool identity_open;
  bool identity_key_ready;
  bool time_key_ready;
  bool manifest_key_ready;
  bool policy_key_ready;
  bool usb_ready;
  bool broker_ready;
  bool trusted_time_ready;
  bool ready;
};

pbns_status PbnsRecoveryServiceTrustKeys(pbns_cose_key *time_key,
                                         pbns_cose_key *manifest_key,
                                         pbns_cose_key *policy_key);
pbns_status PbnsRecoveryServiceTrustedTimeQuery(
    EFI_BOOT_SERVICES *boot_services, pbns_broker *broker,
    const pbns_identity *identity, const pbns_cose_key *identity_key,
    const pbns_cose_key *time_key, const uint8_t fingerprint[32],
    pbns_trusted_time_workspace *workspace, pbns_time_interval *interval);
pbns_status PbnsRecoveryServiceLiveManifest(
    pbns_broker *broker, const pbns_identity *identity,
    const pbns_cose_key *identity_key, const pbns_cose_key *manifest_key,
    const uint8_t fingerprint[32], const pbns_time_interval *trusted_time,
    pbns_recovery_live_workspace *workspace, pbns_recovery_manifest *manifest);

static void secure_zero(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  while (bytes != NULL && length > 0U) {
    *bytes = 0U;
    ++bytes;
    --length;
  }
}

static pbns_status broker_random(void *context, pbns_buffer output) {
  const PBNS_RECOVERY_SERVICE *service = context;
  if (service == NULL || !service->identity_open || output.ptr == NULL ||
      output.len != 0U ||
      (output.cap != PBNS_REQUEST_ID_SIZE &&
       output.cap != PBNS_RECOVERY_REQUEST_NONCE_SIZE)) {
    return PBNS_ERR_ARGUMENT;
  }
  return pbns_identity_random(&service->identity, output);
}

static EFI_STATUS EFIAPI tls_tpm_random_fill(void *context, UINTN size,
                                              UINT8 *output) {
  const PBNS_RECOVERY_SERVICE *service = context;
  if (service == NULL || !service->identity_open || output == NULL ||
      size == 0U) {
    return EFI_INVALID_PARAMETER;
  }
  return pbns_identity_random(&service->identity,
                              (pbns_buffer){output, 0U, (size_t)size}) == PBNS_OK
             ? EFI_SUCCESS
             : EFI_DEVICE_ERROR;
}

static pbns_status broker_monotonic(void *context, uint64_t *milliseconds) {
  const PBNS_RECOVERY_SERVICE *service = context;
  UINT64 now = 0U;
  if (service == NULL || service->boot_services == NULL || milliseconds == NULL ||
      EFI_ERROR(PbnsUefiMonotonicMs(service->boot_services, &now))) {
    return PBNS_ERR_STATE;
  }
  *milliseconds = (uint64_t)now;
  return PBNS_OK;
}

static const pbns_broker_platform_ops BROKER_PLATFORM_OPS = {
    .random = broker_random,
    .monotonic_ms = broker_monotonic,
};

static pbns_status open_tpm_pair(void *context) {
  PBNS_RECOVERY_SERVICE *service = context;
  if (service == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (EFI_ERROR(PbnsTpmIdentityOpen(&service->identity, &service->capabilities))) {
    return PBNS_ERR_CRYPTO;
  }
  service->identity_open = true;
  if (pbns_identity_assurance_level(&service->identity) !=
      PBNS_IDENTITY_TPM_UNVERIFIED_EK) {
    return PBNS_ERR_AUTHENTICATION;
  }
  return EFI_ERROR(PbnsRecoveryRollbackOpen(PBNS_RECOVERY_ASSURANCE_T,
                                            &service->rollback))
             ? PBNS_ERR_CRYPTO
             : PBNS_OK;
}

static pbns_status open_software_nvram_pair(void *context) {
  PBNS_RECOVERY_SERVICE *service = context;
  if (service == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (EFI_ERROR(PbnsSoftwareIdentityOpen(NULL, &service->identity))) {
    return PBNS_ERR_CRYPTO;
  }
  service->identity_open = true;
  if (pbns_identity_assurance_level(&service->identity) !=
      PBNS_IDENTITY_SOFTWARE) {
    return PBNS_ERR_AUTHENTICATION;
  }
  return EFI_ERROR(PbnsRecoveryRollbackOpen(PBNS_RECOVERY_ASSURANCE_S,
                                            &service->rollback))
             ? PBNS_ERR_IO
             : PBNS_OK;
}

static void clear_time_workspace(PBNS_RECOVERY_SERVICE *service) {
  secure_zero(service->time_request_payload,
              sizeof(service->time_request_payload));
  secure_zero(service->time_signed_request, sizeof(service->time_signed_request));
  secure_zero(service->time_signed_response,
              sizeof(service->time_signed_response));
  secure_zero(service->time_canonical_scratch,
              sizeof(service->time_canonical_scratch));
  secure_zero(service->time_aad, sizeof(service->time_aad));
}

void EFIAPI PbnsRecoveryServiceDestroy(PBNS_RECOVERY_SERVICE *service) {
  if (service == NULL) {
    return;
  }
  if (service->broker_ready) {
    pbns_broker_reset(&service->broker);
    service->broker_ready = false;
  }
  if (service->tls_transport != NULL) {
    /* The opaque TLS owner can retain a wipe/release retry after a failed
     * create or destroy.  Its lower USB transport stays alive until that
     * retry succeeds. */
    while (PbnsTlsTransportDestroy(service->tls_transport) != PBNS_OK) {
    }
    service->tls_transport = NULL;
  }
  if (service->broker_workspace != NULL) {
    secure_zero(service->broker_workspace, PBNS_RECOVERY_BROKER_WORKSPACE_SIZE);
    FreePool(service->broker_workspace);
    service->broker_workspace = NULL;
  }
  if (service->usb_ready) {
    pbns_usb_transport_destroy(service->usb_transport);
    service->usb_ready = false;
  }
  if (service->policy_key_ready) {
    pbns_cose_key_reset(&service->policy_key);
  }
  if (service->manifest_key_ready) {
    pbns_cose_key_reset(&service->manifest_key);
  }
  if (service->time_key_ready) {
    pbns_cose_key_reset(&service->time_key);
  }
  if (service->identity_key_ready) {
    pbns_cose_key_reset(&service->identity_key);
  }
  if (service->rollback != NULL) {
    PbnsRecoveryRollbackDestroy(service->rollback);
    service->rollback = NULL;
  }
  if (service->identity_open) {
    pbns_identity_close(&service->identity);
  }
  mbedtls_sha256_free(&service->stream_hash);
  pbns_recovery_service_manifest_invalidate(&service->manifest_state,
                                            &service->live_workspace);
  secure_zero(service->fingerprint, sizeof(service->fingerprint));
  secure_zero(&service->trusted_interval, sizeof(service->trusted_interval));
  clear_time_workspace(service);
  secure_zero(&service->capabilities, sizeof(service->capabilities));
  secure_zero(service, sizeof(*service));
  FreePool(service);
}

static EFI_STATUS fail_create(PBNS_RECOVERY_SERVICE *service,
                              EFI_STATUS status) {
  PbnsRecoveryServiceDestroy(service);
  return EFI_ERROR(status) ? status : EFI_SECURITY_VIOLATION;
}

EFI_STATUS EFIAPI PbnsRecoveryServiceCreate(
    EFI_SYSTEM_TABLE *system_table, pbns_recovery_assurance_mode mode,
    PBNS_RECOVERY_SERVICE **out_service) {
  if (out_service != NULL) {
    *out_service = NULL;
  }
  if (system_table == NULL || system_table->BootServices == NULL ||
      out_service == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if (mode != PBNS_RECOVERY_ASSURANCE_T && mode != PBNS_RECOVERY_ASSURANCE_S) {
    return EFI_INVALID_PARAMETER;
  }
  PBNS_RECOVERY_SERVICE *service = AllocateZeroPool(sizeof(*service));
  if (service == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  service->boot_services = system_table->BootServices;
  service->mode = mode;
  mbedtls_sha256_init(&service->stream_hash);
  EFI_STATUS status = EFI_SECURITY_VIOLATION;
  const pbns_recovery_assurance_ops assurance_ops = {
      .open_tpm_pair = open_tpm_pair,
      .open_software_nvram_pair = open_software_nvram_pair,
  };
  if (pbns_recovery_assurance_select(mode, &assurance_ops, service) != PBNS_OK ||
      service->rollback == NULL) {
    goto cleanup;
  }
  if (pbns_identity_fingerprint(
          &service->identity,
          (pbns_buffer){service->fingerprint, 0U, sizeof(service->fingerprint)}) !=
          PBNS_OK ||
      pbns_cose_key_from_identity(&service->identity_key, &service->identity) !=
          PBNS_OK) {
    goto cleanup;
  }
  service->identity_key_ready = true;
  if (PbnsRecoveryServiceTrustKeys(&service->time_key, &service->manifest_key,
                                   &service->policy_key) != PBNS_OK) {
    goto cleanup;
  }
  service->time_key_ready = true;
  service->manifest_key_ready = true;
  service->policy_key_ready = true;
  if (pbns_usb_transport_create(service->boot_services, &service->usb_transport) !=
      PBNS_OK) {
    status = EFI_NOT_FOUND;
    goto cleanup;
  }
  service->usb_ready = true;
  service->tls_tpm_random = (PBNS_TPM_RANDOM_SOURCE){
      .Fill = tls_tpm_random_fill,
      .Context = service,
  };
  if (PbnsTlsTransportCreate(
          service->boot_services,
          pbns_usb_transport_as_transport(service->usb_transport),
          PbnsRecoveryServiceTrustConfig(), &service->tls_tpm_random,
          &service->tls_transport) != PBNS_OK) {
    status = EFI_SECURITY_VIOLATION;
    goto cleanup;
  }
  service->broker_workspace =
      AllocatePool(PBNS_RECOVERY_BROKER_WORKSPACE_SIZE);
  if (service->broker_workspace == NULL) {
    status = EFI_OUT_OF_RESOURCES;
    goto cleanup;
  }
  if (pbns_broker_init(
          &service->broker,
          PbnsTlsTransportAsTransport(service->tls_transport),
          (pbns_broker_platform){.ops = &BROKER_PLATFORM_OPS,
                                 .context = service},
          (pbns_broker_storage){
              .encoded = {service->broker_workspace, 0U,
                          PBNS_RECOVERY_BROKER_BUFFER_SIZE},
              .raw_scratch = {service->broker_workspace +
                                  PBNS_RECOVERY_BROKER_BUFFER_SIZE,
                              0U, PBNS_RECOVERY_BROKER_BUFFER_SIZE},
              .receive = {service->broker_workspace +
                              (PBNS_RECOVERY_BROKER_BUFFER_SIZE * 2U),
                          0U, PBNS_RECOVERY_BROKER_BUFFER_SIZE},
              .decoded = {service->broker_workspace +
                              (PBNS_RECOVERY_BROKER_BUFFER_SIZE * 3U),
                          0U, PBNS_RECOVERY_BROKER_BUFFER_SIZE},
          }) != PBNS_OK) {
    goto cleanup;
  }
  service->broker_ready = true;
  service->ready = true;
  *out_service = service;
  return EFI_SUCCESS;

cleanup:
  return fail_create(service, status);
}

pbns_status PbnsRecoveryServiceTrustedTime(PBNS_RECOVERY_SERVICE *service) {
  if (service == NULL || !service->ready) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_recovery_service_manifest_invalidate(&service->manifest_state,
                                            &service->live_workspace);
  if (!service->broker_ready) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_trusted_time_workspace workspace = {
      .request_payload = {service->time_request_payload, 0U,
                          sizeof(service->time_request_payload)},
      .signed_request = {service->time_signed_request, 0U,
                         sizeof(service->time_signed_request)},
      .signed_response = {service->time_signed_response, 0U,
                          sizeof(service->time_signed_response)},
      .canonical_scratch = {service->time_canonical_scratch, 0U,
                            sizeof(service->time_canonical_scratch)},
      .aad = {service->time_aad, 0U, sizeof(service->time_aad)},
  };
  service->trusted_time_ready = false;
  service->trusted_interval = (pbns_time_interval){0};
  const pbns_status status = PbnsRecoveryServiceTrustedTimeQuery(
      service->boot_services, &service->broker, &service->identity,
      &service->identity_key, &service->time_key, service->fingerprint,
      &workspace, &service->trusted_interval);
  if (status != PBNS_OK || service->trusted_interval.earliest_ns < 0 ||
      service->trusted_interval.latest_ns < service->trusted_interval.earliest_ns) {
    service->trusted_interval = (pbns_time_interval){0};
    return status == PBNS_OK ? PBNS_ERR_FORMAT : status;
  }
  service->trusted_time_ready = true;
  return PBNS_OK;
}

pbns_status PbnsRecoveryServiceManifest(PBNS_RECOVERY_SERVICE *service,
                                        PBNS_RECOVERY_PLAN *plan) {
  if (plan != NULL) {
    *plan = (PBNS_RECOVERY_PLAN){0};
  }
  if (service == NULL || plan == NULL || !service->ready) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_recovery_service_manifest_invalidate(&service->manifest_state,
                                            &service->live_workspace);
  if (!service->trusted_time_ready) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_recovery_manifest manifest = {0};
  const pbns_status status = PbnsRecoveryServiceLiveManifest(
      &service->broker, &service->identity, &service->identity_key,
      &service->manifest_key, service->fingerprint, &service->trusted_interval,
      &service->live_workspace, &manifest);
  if (status != PBNS_OK) {
    return status;
  }
  if (pbns_recovery_service_manifest_set(&service->manifest_state,
                                         &manifest) != PBNS_OK) {
    return PBNS_ERR_STATE;
  }
  plan->artifact_size = service->manifest_state.manifest.image_size;
  plan->target_version = service->manifest_state.manifest.artifact_version;
  CopyMem(plan->artifact_digest, service->manifest_state.manifest.artifact_digest,
          sizeof(plan->artifact_digest));
  plan->version_authorization = service->manifest_state.manifest.policy_authorization;
  return PBNS_OK;
}

pbns_status PbnsRecoveryServiceStream(PBNS_RECOVERY_SERVICE *service,
                                      void *image, uint64_t size) {
  if (service == NULL || !service->ready) {
    return PBNS_ERR_ARGUMENT;
  }
  if (image == NULL || !service->manifest_state.ready ||
      size != service->manifest_state.manifest.image_size || size > SIZE_MAX) {
    pbns_recovery_service_manifest_invalidate(&service->manifest_state,
                                              &service->live_workspace);
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status status = PbnsRecoveryServiceStreamUefi(
      &service->broker, &service->identity, &service->identity_key,
      &service->manifest_key, &service->manifest_state,
      (pbns_buffer){image, 0U, (size_t)size}, &service->live_workspace,
      &service->stream_hash);
  if (status != PBNS_OK) {
    pbns_recovery_service_manifest_invalidate(&service->manifest_state,
                                              &service->live_workspace);
  }
  return status;
}

pbns_status PbnsRecoveryServiceReadVersion(PBNS_RECOVERY_SERVICE *service,
                                           uint64_t *version) {
  if (service == NULL || version == NULL || !service->ready ||
      service->rollback == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  return PbnsRecoveryRollbackRead(service->rollback, version);
}

pbns_status PbnsRecoveryServiceAdvanceVersion(PBNS_RECOVERY_SERVICE *service,
                                              uint64_t current, uint64_t target,
                                              pbns_view authorization) {
  if (service == NULL || !service->ready || !service->manifest_state.ready ||
      service->rollback == NULL ||
      !pbns_recovery_service_manifest_target_matches(&service->manifest_state,
                                                     target)) {
    return PBNS_ERR_ARGUMENT;
  }
  if (service->mode == PBNS_RECOVERY_ASSURANCE_T &&
      (authorization.ptr != service->manifest_state.manifest.policy_authorization.ptr ||
       authorization.len != service->manifest_state.manifest.policy_authorization.len)) {
    return PBNS_ERR_AUTHENTICATION;
  }
  return PbnsRecoveryRollbackAdvance(
      service->rollback, &service->manifest_state, current, target,
      service->manifest_state.manifest.policy_authorization);
}
