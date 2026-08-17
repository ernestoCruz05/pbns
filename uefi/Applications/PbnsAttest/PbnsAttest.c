#include <Uefi.h>

#include <Library/MemoryAllocationLib.h>
#include <Library/PbnsCoseCryptoLib.h>
#include <Library/PbnsIdentityLib.h>
#include <Library/PbnsMeasuredBootLib.h>
#include <Library/PbnsTrustedTimeLib.h>
#include <Library/PbnsUefiPlatformLib.h>
#include <Library/UefiLib.h>
#include <PbnsAttestationClientLib.h>
#include <PbnsInventoryLib.h>
#include <PbnsTlsTransportLib.h>
#include <PbnsTpmIdentityLib.h>
#include <PbnsUsbTransportLib.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "PbnsDeploymentTrust.h"
#include "pbns/attestation_run.h"
#include "pbns/broker.h"
#include "pbns/identity.h"
#include "pbns/trusted_time.h"

#define PBNS_ATTEST_BROKER_BUFFER_SIZE PBNS_FRAME_V1_WIRE_MAX
#define PBNS_ATTEST_TIMEOUT_MS UINT64_C(60000)
#define PBNS_ATTEST_TIME_MAX_RTT_MS UINT32_C(20000)

/* Cada ponteiro detém uma alocação com a capacidade exata. */
typedef struct pbns_attest_buffers {
  uint8_t *broker_encoded;
  uint8_t *broker_raw;
  uint8_t *broker_receive;
  uint8_t *broker_decoded;
  uint8_t *issue_wire;
  uint8_t *issue_canonical;
  uint8_t *submit_wire;
  uint8_t *submit_canonical;
  uint8_t *challenge_canonical;
  uint8_t *challenge_aad;
  uint8_t *inventory_variable_scratch;
  uint8_t *event_log_arena;
  uint8_t *inventory;
  uint8_t *selection;
  uint8_t *quote;
  uint8_t *quote_signature;
  uint8_t *evidence;
  uint8_t *signed_evidence;
  uint8_t *ciphertext;
  uint8_t *attestation_aad;
  uint8_t *receipt_payload;
  uint8_t *receipt_cose;
  uint8_t *receipt_aad;
  uint8_t *evidence_digest;
  uint8_t *time_request;
  uint8_t *time_signed_request;
  uint8_t *time_signed_response;
  uint8_t *time_canonical;
  uint8_t *time_aad;
} pbns_attest_buffers;

typedef struct pbns_attest_run_context {
  EFI_SYSTEM_TABLE *system_table;
  pbns_identity *identity;
  pbns_broker *broker;
  const pbns_cose_key *identity_key;
  const pbns_cose_key *time_key;
  const pbns_attest_buffers *buffers;
  const uint8_t *host_fingerprint;
} pbns_attest_run_context;

typedef struct pbns_attest_tls_random_context {
  pbns_identity *identity;
} pbns_attest_tls_random_context;

static void secure_zero(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  if (bytes == NULL) {
    return;
  }
  for (size_t index = 0U; index < length; ++index) {
    bytes[index] = 0U;
  }
}

static void free_buffer(uint8_t **buffer, size_t capacity) {
  if (buffer != NULL && *buffer != NULL) {
    secure_zero(*buffer, capacity);
    FreePool(*buffer);
    *buffer = NULL;
  }
}

static bool allocate_buffers(pbns_attest_buffers *buffers) {
  if (buffers == NULL) {
    return false;
  }
  *buffers = (pbns_attest_buffers){0};
#define ALLOCATE(Name, Capacity) buffers->Name = AllocatePool((Capacity))
  ALLOCATE(broker_encoded, PBNS_ATTEST_BROKER_BUFFER_SIZE);
  ALLOCATE(broker_raw, PBNS_ATTEST_BROKER_BUFFER_SIZE);
  ALLOCATE(broker_receive, PBNS_ATTEST_BROKER_BUFFER_SIZE);
  ALLOCATE(broker_decoded, PBNS_ATTEST_BROKER_BUFFER_SIZE);
  ALLOCATE(issue_wire, PBNS_ATTESTATION_WIRE_MAX_SIZE);
  ALLOCATE(issue_canonical, PBNS_ATTESTATION_WIRE_MAX_SIZE);
  ALLOCATE(submit_wire, PBNS_ATTESTATION_WIRE_MAX_SIZE);
  ALLOCATE(submit_canonical, PBNS_ATTESTATION_WIRE_MAX_SIZE);
  ALLOCATE(challenge_canonical, PBNS_ATTESTATION_CHALLENGE_MAX_SIZE);
  ALLOCATE(challenge_aad, PBNS_ATTESTATION_AAD_MAX_SIZE);
  ALLOCATE(inventory_variable_scratch, PBNS_INVENTORY_VARIABLE_MAX_SIZE);
  ALLOCATE(event_log_arena, PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE);
  ALLOCATE(inventory, PBNS_INVENTORY_ENCODED_MAX_SIZE);
  ALLOCATE(selection, PBNS_ATTESTATION_SELECTION_WORKSPACE_SIZE);
  ALLOCATE(quote, PBNS_ATTESTATION_QUOTE_MAX_SIZE);
  ALLOCATE(quote_signature, PBNS_ATTESTATION_QUOTE_SIGNATURE_MAX_SIZE);
  ALLOCATE(evidence, PBNS_ATTESTATION_EVIDENCE_MAX_SIZE);
  ALLOCATE(signed_evidence, PBNS_ATTESTATION_SIGNED_MAX_SIZE);
  ALLOCATE(ciphertext, PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE);
  ALLOCATE(attestation_aad, PBNS_ATTESTATION_AAD_MAX_SIZE);
  ALLOCATE(receipt_payload, PBNS_ATTESTATION_RECEIPT_MAX_PAYLOAD_SIZE);
  ALLOCATE(receipt_cose, PBNS_ATTESTATION_RECEIPT_MAX_SIGNED_SIZE);
  ALLOCATE(receipt_aad, PBNS_ATTESTATION_RECEIPT_MAX_AAD_SIZE);
  ALLOCATE(evidence_digest, PBNS_ATTESTATION_DIGEST_SIZE);
  ALLOCATE(time_request, PBNS_TIME_ENCODED_MAX_SIZE);
  ALLOCATE(time_signed_request, PBNS_TIME_SIGNED_MAX_SIZE);
  ALLOCATE(time_signed_response, PBNS_TIME_SIGNED_MAX_SIZE);
  ALLOCATE(time_canonical, PBNS_TIME_ENCODED_MAX_SIZE);
  ALLOCATE(time_aad, PBNS_TIME_AAD_MAX_SIZE);
#undef ALLOCATE
#define PRESENT(Name) (buffers->Name != NULL)
  return PRESENT(broker_encoded) && PRESENT(broker_raw) &&
         PRESENT(broker_receive) && PRESENT(broker_decoded) &&
         PRESENT(issue_wire) && PRESENT(issue_canonical) &&
         PRESENT(submit_wire) && PRESENT(submit_canonical) &&
         PRESENT(challenge_canonical) && PRESENT(challenge_aad) &&
         PRESENT(inventory_variable_scratch) && PRESENT(event_log_arena) &&
         PRESENT(inventory) && PRESENT(selection) && PRESENT(quote) &&
         PRESENT(quote_signature) && PRESENT(evidence) &&
         PRESENT(signed_evidence) && PRESENT(ciphertext) &&
         PRESENT(attestation_aad) && PRESENT(receipt_payload) &&
         PRESENT(receipt_cose) && PRESENT(receipt_aad) &&
         PRESENT(evidence_digest) && PRESENT(time_request) &&
         PRESENT(time_signed_request) && PRESENT(time_signed_response) &&
         PRESENT(time_canonical) && PRESENT(time_aad);
#undef PRESENT
}

static void free_buffers(pbns_attest_buffers *buffers) {
  if (buffers == NULL) {
    return;
  }
#define RELEASE(Name, Capacity) free_buffer(&buffers->Name, (Capacity))
  RELEASE(time_aad, PBNS_TIME_AAD_MAX_SIZE);
  RELEASE(time_canonical, PBNS_TIME_ENCODED_MAX_SIZE);
  RELEASE(time_signed_response, PBNS_TIME_SIGNED_MAX_SIZE);
  RELEASE(time_signed_request, PBNS_TIME_SIGNED_MAX_SIZE);
  RELEASE(time_request, PBNS_TIME_ENCODED_MAX_SIZE);
  RELEASE(evidence_digest, PBNS_ATTESTATION_DIGEST_SIZE);
  RELEASE(receipt_aad, PBNS_ATTESTATION_RECEIPT_MAX_AAD_SIZE);
  RELEASE(receipt_cose, PBNS_ATTESTATION_RECEIPT_MAX_SIGNED_SIZE);
  RELEASE(receipt_payload, PBNS_ATTESTATION_RECEIPT_MAX_PAYLOAD_SIZE);
  RELEASE(attestation_aad, PBNS_ATTESTATION_AAD_MAX_SIZE);
  RELEASE(ciphertext, PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE);
  RELEASE(signed_evidence, PBNS_ATTESTATION_SIGNED_MAX_SIZE);
  RELEASE(evidence, PBNS_ATTESTATION_EVIDENCE_MAX_SIZE);
  RELEASE(quote_signature, PBNS_ATTESTATION_QUOTE_SIGNATURE_MAX_SIZE);
  RELEASE(quote, PBNS_ATTESTATION_QUOTE_MAX_SIZE);
  RELEASE(selection, PBNS_ATTESTATION_SELECTION_WORKSPACE_SIZE);
  RELEASE(inventory, PBNS_INVENTORY_ENCODED_MAX_SIZE);
  RELEASE(event_log_arena, PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE);
  RELEASE(inventory_variable_scratch, PBNS_INVENTORY_VARIABLE_MAX_SIZE);
  RELEASE(challenge_aad, PBNS_ATTESTATION_AAD_MAX_SIZE);
  RELEASE(challenge_canonical, PBNS_ATTESTATION_CHALLENGE_MAX_SIZE);
  RELEASE(submit_canonical, PBNS_ATTESTATION_WIRE_MAX_SIZE);
  RELEASE(submit_wire, PBNS_ATTESTATION_WIRE_MAX_SIZE);
  RELEASE(issue_canonical, PBNS_ATTESTATION_WIRE_MAX_SIZE);
  RELEASE(issue_wire, PBNS_ATTESTATION_WIRE_MAX_SIZE);
  RELEASE(broker_decoded, PBNS_ATTEST_BROKER_BUFFER_SIZE);
  RELEASE(broker_receive, PBNS_ATTEST_BROKER_BUFFER_SIZE);
  RELEASE(broker_raw, PBNS_ATTEST_BROKER_BUFFER_SIZE);
  RELEASE(broker_encoded, PBNS_ATTEST_BROKER_BUFFER_SIZE);
#undef RELEASE
  secure_zero(buffers, sizeof(*buffers));
}

static pbns_status efi_to_pbns(EFI_STATUS status) {
  if (!EFI_ERROR(status)) {
    return PBNS_OK;
  }
  if (status == EFI_INVALID_PARAMETER) {
    return PBNS_ERR_ARGUMENT;
  }
  if (status == EFI_OUT_OF_RESOURCES) {
    return PBNS_ERR_RESOURCE;
  }
  if (status == EFI_TIMEOUT) {
    return PBNS_ERR_TIMEOUT;
  }
  if (status == EFI_UNSUPPORTED) {
    return PBNS_ERR_UNSUPPORTED;
  }
  if (status == EFI_NOT_READY) {
    return PBNS_ERR_BUSY;
  }
  if (status == EFI_BAD_BUFFER_SIZE || status == EFI_BUFFER_TOO_SMALL) {
    return PBNS_ERR_LIMIT;
  }
  if (status == EFI_DEVICE_ERROR) {
    return PBNS_ERR_IO;
  }
  if (status == EFI_SECURITY_VIOLATION || status == EFI_COMPROMISED_DATA) {
    return PBNS_ERR_AUTHENTICATION;
  }
  if (status == EFI_NO_RESPONSE) {
    return PBNS_ERR_TRANSPORT;
  }
  return PBNS_ERR_IO;
}

static EFI_STATUS pbns_to_efi(pbns_status status) {
  switch (status) {
  case PBNS_OK:
    return EFI_SUCCESS;
  case PBNS_ERR_ARGUMENT:
    return EFI_INVALID_PARAMETER;
  case PBNS_ERR_LIMIT:
    return EFI_BAD_BUFFER_SIZE;
  case PBNS_ERR_TIMEOUT:
    return EFI_TIMEOUT;
  case PBNS_ERR_AUTHENTICATION:
  case PBNS_ERR_REPLAY:
    return EFI_SECURITY_VIOLATION;
  case PBNS_ERR_RESOURCE:
    return EFI_OUT_OF_RESOURCES;
  case PBNS_ERR_TRANSPORT:
    return EFI_NO_RESPONSE;
  case PBNS_ERR_UNSUPPORTED:
    return EFI_UNSUPPORTED;
  default:
    return EFI_DEVICE_ERROR;
  }
}

static pbns_status broker_random(void *context, pbns_buffer output) {
  const pbns_attest_run_context *run = context;
  return run == NULL || run->identity == NULL
             ? PBNS_ERR_ARGUMENT
             : pbns_identity_random(run->identity, output);
}

static pbns_status run_monotonic(void *context, uint64_t *milliseconds) {
  const pbns_attest_run_context *run = context;
  UINT64 now = 0U;
  if (run == NULL || run->system_table == NULL ||
      run->system_table->BootServices == NULL || milliseconds == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  const EFI_STATUS status =
      PbnsUefiMonotonicMs(run->system_table->BootServices, &now);
  if (EFI_ERROR(status)) {
    return efi_to_pbns(status);
  }
  *milliseconds = (uint64_t)now;
  return PBNS_OK;
}

static const pbns_broker_platform_ops BROKER_PLATFORM_OPS = {
    .random = broker_random,
    .monotonic_ms = run_monotonic,
};

static EFI_STATUS EFIAPI tls_tpm_random_fill(void *context, UINTN size,
                                              UINT8 *output) {
  const pbns_attest_tls_random_context *random = context;
  if (random == NULL || random->identity == NULL || output == NULL ||
      size == 0U) {
    return EFI_INVALID_PARAMETER;
  }
  return pbns_identity_random(
             random->identity,
             (pbns_buffer){output, 0U, (size_t)size}) == PBNS_OK
             ? EFI_SUCCESS
             : EFI_DEVICE_ERROR;
}

static pbns_status run_trusted_time(void *context,
                                    pbns_time_interval *interval) {
  const pbns_attest_run_context *run = context;
  if (run == NULL || interval == NULL || run->buffers == NULL ||
      run->identity_key == NULL || run->time_key == NULL ||
      run->host_fingerprint == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  Print(L"PBNS ATTEST: Querying live trusted time from gateway...\r\n");
  pbns_uefi_trusted_time_environment environment = {
      .boot_services = run->system_table->BootServices,
      .broker = run->broker,
      .identity = run->identity,
      .identity_key = run->identity_key,
      .time_verification_key = run->time_key,
      .time_key_id = PBNS_DEPLOYMENT_TRUST.time.kid,
      .maximum_round_trip_ms = PBNS_ATTEST_TIME_MAX_RTT_MS,
  };
  pbns_trusted_time_client client = {0};
  pbns_trusted_time_workspace workspace = {
      .request_payload = {run->buffers->time_request, 0U,
                          PBNS_TIME_ENCODED_MAX_SIZE},
      .signed_request = {run->buffers->time_signed_request, 0U,
                         PBNS_TIME_SIGNED_MAX_SIZE},
      .signed_response = {run->buffers->time_signed_response, 0U,
                          PBNS_TIME_SIGNED_MAX_SIZE},
      .canonical_scratch = {run->buffers->time_canonical, 0U,
                            PBNS_TIME_ENCODED_MAX_SIZE},
      .aad = {run->buffers->time_aad, 0U, PBNS_TIME_AAD_MAX_SIZE},
  };
  if (PbnsTrustedTimeClientInit(&environment, &client) != PBNS_OK) {
    Print(L"PBNS ATTEST: PbnsTrustedTimeClientInit failed\r\n");
    secure_zero(&workspace, sizeof(workspace));
    secure_zero(&environment, sizeof(environment));
    return PBNS_ERR_ARGUMENT;
  }
  *interval = (pbns_time_interval){0};
  const pbns_status status = pbns_trusted_time_query(
      &client, run->host_fingerprint, NULL, &workspace, interval);
  Print(L"PBNS ATTEST: Trusted time query result status=%d\r\n", (INT32)status);
  secure_zero(&client, sizeof(client));
  secure_zero(&workspace, sizeof(workspace));
  secure_zero(&environment, sizeof(environment));
  return status;
}

static pbns_status run_cancel_requested(void *context, bool *requested) {
  if (context == NULL || requested == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *requested = false;
  return PBNS_OK;
}

static pbns_status run_capture_inventory(void *context,
                                         pbns_buffer variable_scratch,
                                         pbns_inventory_report *report) {
  const pbns_attest_run_context *run = context;
  if (run == NULL || run->system_table == NULL ||
      run->host_fingerprint == NULL || report == NULL ||
      variable_scratch.ptr == NULL || variable_scratch.len != 0U ||
      variable_scratch.cap != PBNS_INVENTORY_VARIABLE_MAX_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  const PBNS_INVENTORY_CONFIGURATION configuration = {
      .HostFingerprint = {run->host_fingerprint, PBNS_INVENTORY_DIGEST_SIZE},
      .VariableScratch = variable_scratch,
      .PbnsVersion = 1U,
      .PicoVersion = 1U,
      .GatewayVersion = 1U,
      .PriorLoaderEfiStatus = 0U,
  };
  return efi_to_pbns(
      PbnsInventoryCapture(run->system_table, &configuration, report));
}

static bool exact_selection(void *context,
                            pbns_measured_boot_selection selection) {
  const pbns_measured_boot_selection *expected = context;
  if (expected == NULL || selection.count != expected->count) {
    return false;
  }
  for (size_t index = 0U; index < selection.count; ++index) {
    if (selection.items[index].hash_algorithm !=
            expected->items[index].hash_algorithm ||
        selection.items[index].pcr_index != expected->items[index].pcr_index) {
      return false;
    }
  }
  return true;
}

static bool view_in_arena(pbns_view view, pbns_buffer arena) {
  if (view.ptr == NULL || view.len == 0U || arena.ptr == NULL ||
      arena.cap == 0U) {
    return false;
  }
  const uintptr_t start = (uintptr_t)view.ptr;
  const uintptr_t arena_start = (uintptr_t)arena.ptr;
  return start >= arena_start && view.len <= UINTPTR_MAX - start &&
         arena.cap <= UINTPTR_MAX - arena_start &&
         start + view.len <= arena_start + arena.cap;
}

static pbns_status run_capture_measured(
    void *context, pbns_measured_boot_selection selection,
    pbns_buffer event_log_arena, pbns_measured_boot_evidence *evidence) {
  const pbns_attest_run_context *run = context;
  if (run == NULL || run->system_table == NULL || evidence == NULL ||
      selection.items == NULL || selection.count == 0U ||
      event_log_arena.ptr == NULL || event_log_arena.len != 0U ||
      event_log_arena.cap != PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_measured_boot_selection expected = selection;
  const EFI_STATUS status = PbnsMeasuredBootCaptureSelection(
      run->system_table, selection, exact_selection, &expected,
      event_log_arena, evidence);
  if (EFI_ERROR(status)) {
    return efi_to_pbns(status);
  }
  return view_in_arena(evidence->event_log, event_log_arena)
             ? PBNS_OK
             : PBNS_ERR_ARGUMENT;
}

static pbns_status run_display_authenticated(
    void *context, const pbns_attestation_run_result *result) {
  if (context == NULL || result == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  switch (result->display_state) {
  case PBNS_ATTESTATION_DISPLAY_FULL:
    Print(L"PBNS ATTEST FULL VERIFIED\r\n");
    return PBNS_OK;
  case PBNS_ATTESTATION_DISPLAY_REDUCED:
    Print(L"PBNS ATTEST REDUCED VERIFIED\r\n");
    return PBNS_OK;
  case PBNS_ATTESTATION_DISPLAY_FAILURE:
    Print(L"PBNS ATTEST FAILURE VERIFIED\r\n");
    return PBNS_OK;
  default:
    return PBNS_ERR_ARGUMENT;
  }
}

static EFI_STATUS trust_keys(pbns_cose_key *time_key,
                             pbns_cose_key *challenge_key,
                             pbns_cose_key *recipient_key,
                             pbns_cose_key *receipt_key) {
  if (pbns_cose_key_from_p256_public(
          time_key, PBNS_DEPLOYMENT_TRUST.time.x,
          PBNS_DEPLOYMENT_TRUST.time.y) != PBNS_OK ||
      pbns_cose_key_from_p256_public(
          challenge_key, PBNS_DEPLOYMENT_TRUST.challenge.x,
          PBNS_DEPLOYMENT_TRUST.challenge.y) != PBNS_OK ||
      pbns_cose_key_from_p256_public(
          recipient_key, PBNS_DEPLOYMENT_TRUST.recipient.x,
          PBNS_DEPLOYMENT_TRUST.recipient.y) != PBNS_OK ||
      pbns_cose_key_from_p256_public(
          receipt_key, PBNS_DEPLOYMENT_TRUST.receipt.x,
          PBNS_DEPLOYMENT_TRUST.receipt.y) != PBNS_OK) {
    return EFI_SECURITY_VIOLATION;
  }
  return EFI_SUCCESS;
}

#define PBNS_ATTEST_BUILD_VERSION "v2.1.0-hardware-diag"

EFI_STATUS EFIAPI UefiMain(EFI_HANDLE image_handle,
                           EFI_SYSTEM_TABLE *system_table) {
  (void)image_handle;
  if (system_table == NULL || system_table->BootServices == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Print(L"\r\n=================================================\r\n");
  Print(L"PBNS ATTESTATION CLIENT (Build: %a)\r\n", PBNS_ATTEST_BUILD_VERSION);
  Print(L"=================================================\r\n");

  EFI_STATUS result = EFI_SECURITY_VIOLATION;
  bool operational_failure = true;
  pbns_attest_buffers buffers = {0};
  pbns_identity *identity = NULL;
  pbns_attest_tls_random_context *tls_random_context = NULL;
  pbns_tpm_capability_result capabilities = {0};
  pbns_cose_key time_key = {0};
  pbns_cose_key challenge_key = {0};
  pbns_cose_key recipient_key = {0};
  pbns_cose_key receipt_key = {0};
  PBNS_ATTESTATION_CLIENT_ADAPTER adapter = {0};
  pbns_usb_transport *usb = NULL;
  PBNS_TLS_UEFI_TRANSPORT *tls = NULL;
  pbns_broker broker = {0};
  bool broker_ready = false;
  uint8_t fingerprint[PBNS_INVENTORY_DIGEST_SIZE] = {0};
  uint8_t ek_public[PBNS_TPM_ENROLLMENT_PUBLIC_MAX_SIZE] = {0};
  uint8_t ak_public[PBNS_TPM_ENROLLMENT_PUBLIC_MAX_SIZE] = {0};
  uint8_t ak_name[PBNS_TPM_ENROLLMENT_NAME_MAX_SIZE] = {0};
  uint8_t identity_public[PBNS_TPM_ENROLLMENT_PUBLIC_MAX_SIZE] = {0};
  pbns_tpm_enrollment_public tpm_public = {0};
  pbns_view tls_region = {0};
  pbns_attestation_run_workspace workspace = {0};
  pbns_attestation_run_config config = {0};
  pbns_attestation_run_result run_result = {
      .verdict = PBNS_ATTESTATION_RECEIPT_FAILURE,
      .display_state = PBNS_ATTESTATION_DISPLAY_FAILURE,
  };
  pbns_attest_run_context run_context = {0};
  PBNS_TPM_RANDOM_SOURCE tls_random = {0};
  pbns_status run_status = PBNS_ERR_STATE;

  if (!allocate_buffers(&buffers)) {
    Print(L"PBNS ATTEST FAILURE allocation\r\n");
    result = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }
  identity = AllocateZeroPool(sizeof(*identity));
  tls_random_context = AllocateZeroPool(sizeof(*tls_random_context));
  if (identity == NULL || tls_random_context == NULL) {
    result = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }

  EFI_STATUS status = PbnsTpmIdentityOpen(identity, &capabilities);
  if (EFI_ERROR(status) ||
      pbns_identity_assurance_level(identity) !=
          PBNS_IDENTITY_TPM_UNVERIFIED_EK) {
    Print(L"PBNS ATTEST FAILURE enrolled TPM identity status=%r\r\n", status);
    result = EFI_ERROR(status) ? status : EFI_SECURITY_VIOLATION;
    goto Cleanup;
  }
  Print(L"PBNS ATTEST: [1/4] TPM Identity OK (Assurance: TPM-UNVERIFIED-EK)\r\n");
  if (pbns_identity_fingerprint(
          identity, (pbns_buffer){fingerprint, 0U, sizeof(fingerprint)}) !=
          PBNS_OK ||
      EFI_ERROR(trust_keys(&time_key, &challenge_key, &recipient_key,
                           &receipt_key)) ||
      EFI_ERROR(PbnsAttestationClientAdapterInit(
          &adapter, identity, &challenge_key, &recipient_key, &receipt_key))) {
    Print(L"PBNS ATTEST FAILURE trusted key setup\r\n");
    goto Cleanup;
  }
  Print(L"PBNS ATTEST: [2/4] Trusted keys initialized (Fingerprint: %02x%02x%02x%02x...)\r\n",
        fingerprint[0], fingerprint[1], fingerprint[2], fingerprint[3]);

  tpm_public = (pbns_tpm_enrollment_public){
      .EkPublic = {ek_public, 0U, sizeof(ek_public)},
      .AkPublic = {ak_public, 0U, sizeof(ak_public)},
      .AkName = {ak_name, 0U, sizeof(ak_name)},
      .IdentityPublic = {identity_public, 0U, sizeof(identity_public)},
  };
  status = PbnsTpmIdentityEnrollmentPublic(identity, &tpm_public);
  secure_zero(ek_public, sizeof(ek_public));
  secure_zero(identity_public, sizeof(identity_public));
  if (EFI_ERROR(status) || tpm_public.AkPublic.ptr != ak_public ||
      tpm_public.AkPublic.len == 0U ||
      tpm_public.AkPublic.len > sizeof(ak_public) ||
      tpm_public.AkName.ptr != ak_name || tpm_public.AkName.len == 0U ||
      tpm_public.AkName.len > sizeof(ak_name)) {
    Print(L"PBNS ATTEST FAILURE enrolled AK\r\n");
    result = EFI_ERROR(status) ? status : EFI_COMPROMISED_DATA;
    goto Cleanup;
  }

  if (pbns_usb_transport_create(system_table->BootServices, &usb) != PBNS_OK) {
    Print(L"PBNS ATTEST FAILURE USB proxy unavailable\r\n");
    result = EFI_NOT_FOUND;
    goto Cleanup;
  }
  tls_random_context->identity = identity;
  tls_random = (PBNS_TPM_RANDOM_SOURCE){
      .Fill = tls_tpm_random_fill,
      .Context = tls_random_context,
  };
  Print(L"PBNS ATTEST: [3/4] Establishing TLS 1.2 to Gateway SAN: %a...\r\n",
        PBNS_DEPLOYMENT_TRUST.tls.expected_server_name.ptr);
  if (PbnsTlsTransportCreate(system_table->BootServices,
                             pbns_usb_transport_as_transport(usb),
                             &PBNS_DEPLOYMENT_TRUST.tls, &tls_random,
                             &tls) != PBNS_OK ||
      tls == NULL) {
    Print(L"PBNS ATTEST FAILURE TLS 1.2\r\n");
    goto Cleanup;
  }
  if (EFI_ERROR(PbnsTlsTransportContextRegion(tls, &tls_region))) {
    Print(L"PBNS ATTEST FAILURE TLS context\r\n");
    goto Cleanup;
  }

  run_context = (pbns_attest_run_context){
      .system_table = system_table,
      .identity = identity,
      .broker = &broker,
      .identity_key = &adapter.IdentityKey,
      .time_key = &time_key,
      .buffers = &buffers,
      .host_fingerprint = fingerprint,
  };
  if (pbns_broker_init(
          &broker, PbnsTlsTransportAsTransport(tls),
          (pbns_broker_platform){.ops = &BROKER_PLATFORM_OPS,
                                 .context = &run_context},
          (pbns_broker_storage){
              .encoded = {buffers.broker_encoded, 0U,
                          PBNS_ATTEST_BROKER_BUFFER_SIZE},
              .raw_scratch = {buffers.broker_raw, 0U,
                              PBNS_ATTEST_BROKER_BUFFER_SIZE},
              .receive = {buffers.broker_receive, 0U,
                          PBNS_ATTEST_BROKER_BUFFER_SIZE},
              .decoded = {buffers.broker_decoded, 0U,
                          PBNS_ATTEST_BROKER_BUFFER_SIZE},
          }) != PBNS_OK) {
    Print(L"PBNS ATTEST FAILURE broker setup\r\n");
    goto Cleanup;
  }
  broker_ready = true;

  workspace = (pbns_attestation_run_workspace){
      .issue_wire = {buffers.issue_wire, 0U, PBNS_ATTESTATION_WIRE_MAX_SIZE},
      .issue_canonical = {buffers.issue_canonical, 0U,
                          PBNS_ATTESTATION_WIRE_MAX_SIZE},
      .submit_wire = {buffers.submit_wire, 0U, PBNS_ATTESTATION_WIRE_MAX_SIZE},
      .submit_canonical = {buffers.submit_canonical, 0U,
                           PBNS_ATTESTATION_WIRE_MAX_SIZE},
      .challenge = {
          .canonical = {buffers.challenge_canonical, 0U,
                        PBNS_ATTESTATION_CHALLENGE_MAX_SIZE},
          .aad = {buffers.challenge_aad, 0U, PBNS_ATTESTATION_AAD_MAX_SIZE},
      },
      .inventory_variable_scratch = {buffers.inventory_variable_scratch, 0U,
                                     PBNS_INVENTORY_VARIABLE_MAX_SIZE},
      .event_log_arena = {buffers.event_log_arena, 0U,
                          PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE},
      .attestation = {
          .inventory = {buffers.inventory, 0U, PBNS_INVENTORY_ENCODED_MAX_SIZE},
          .selection = {buffers.selection, 0U,
                        PBNS_ATTESTATION_SELECTION_WORKSPACE_SIZE},
          .quote = {buffers.quote, 0U, PBNS_ATTESTATION_QUOTE_MAX_SIZE},
          .quote_signature = {buffers.quote_signature, 0U,
                              PBNS_ATTESTATION_QUOTE_SIGNATURE_MAX_SIZE},
          .evidence = {buffers.evidence, 0U,
                       PBNS_ATTESTATION_EVIDENCE_MAX_SIZE},
          .signed_evidence = {buffers.signed_evidence, 0U,
                              PBNS_ATTESTATION_SIGNED_MAX_SIZE},
          .ciphertext = {buffers.ciphertext, 0U,
                         PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE},
          .aad = {buffers.attestation_aad, 0U,
                  PBNS_ATTESTATION_AAD_MAX_SIZE},
      },
      .receipt = {
          .canonical_payload = {buffers.receipt_payload, 0U,
                                PBNS_ATTESTATION_RECEIPT_MAX_PAYLOAD_SIZE},
          .canonical_cose = {buffers.receipt_cose, 0U,
                             PBNS_ATTESTATION_RECEIPT_MAX_SIGNED_SIZE},
          .aad = {buffers.receipt_aad, 0U,
                  PBNS_ATTESTATION_RECEIPT_MAX_AAD_SIZE},
      },
      .evidence_digest = {buffers.evidence_digest, 0U,
                          PBNS_ATTESTATION_DIGEST_SIZE},
  };
  config = (pbns_attestation_run_config){
      .broker = &broker,
      .broker_transport_context_region = tls_region,
      .broker_platform_context_region = {
          (const uint8_t *)&run_context, sizeof(run_context)},
      .identity_assurance = PBNS_IDENTITY_TPM_UNVERIFIED_EK,
      .recipient_kid = PBNS_DEPLOYMENT_TRUST.recipient.kid,
      .challenge_kid = PBNS_DEPLOYMENT_TRUST.challenge.kid,
      .receipt_kid = PBNS_DEPLOYMENT_TRUST.receipt.kid,
      .ak_name = {tpm_public.AkName.ptr, tpm_public.AkName.len},
      .ak_reference = {tpm_public.AkPublic.ptr, tpm_public.AkPublic.len},
      .challenge_verifier = &adapter.ChallengeVerifier,
      .receipt_verifier = &adapter.ReceiptVerifier,
      .challenge_verifier_context_region =
          adapter.ChallengeVerifierContextRegion,
      .receipt_verifier_context_region = adapter.ReceiptVerifierContextRegion,
      .submission_template = adapter.Submission,
      .ops = {
          .trusted_time = run_trusted_time,
          .monotonic_ms = run_monotonic,
          .cancel_requested = run_cancel_requested,
          .capture_inventory = run_capture_inventory,
          .capture_measured = run_capture_measured,
          .display_authenticated = run_display_authenticated,
      },
      .context = &run_context,
      .context_region = {(const uint8_t *)&run_context, sizeof(run_context)},
      .timeout_ms = PBNS_ATTEST_TIMEOUT_MS,
  };
  for (size_t index = 0U; index < sizeof(fingerprint); ++index) {
    config.host_fingerprint[index] = fingerprint[index];
  }

  Print(L"PBNS ATTEST: Starting attestation exchange (Fingerprint=%02x%02x%02x%02x...)\r\n",
        fingerprint[0], fingerprint[1], fingerprint[2], fingerprint[3]);
  run_status = pbns_attestation_run(&config, &workspace, &run_result);
  result = pbns_to_efi(run_status);
  operational_failure = run_status != PBNS_OK;
  if (run_status != PBNS_OK) {
    Print(L"PBNS ATTEST FAILURE run status=%d command=0x%08x\r\n",
          (INT32)run_status, adapter.TpmCommandResult);
  } else {
    Print(L"PBNS ATTEST SUCCESS appraisal receipt verified!\r\n");
  }

Cleanup:
  secure_zero(&run_result, sizeof(run_result));
  secure_zero(&config, sizeof(config));
  secure_zero(&workspace, sizeof(workspace));
  if (broker_ready) {
    pbns_broker_reset(&broker);
  }
  secure_zero(&broker, sizeof(broker));
  secure_zero(&run_context, sizeof(run_context));
  secure_zero(&tls_region, sizeof(tls_region));

  pbns_status tls_cleanup_status = PBNS_OK;
  if (tls != NULL) {
    for (size_t attempt = 0U; attempt < 3U; ++attempt) {
      tls_cleanup_status = PbnsTlsTransportDestroy(tls);
      if (tls_cleanup_status == PBNS_OK) {
        tls = NULL;
        break;
      }
    }
    if (tls != NULL && !operational_failure) {
      result = pbns_to_efi(tls_cleanup_status);
    }
  }
  if (tls == NULL) {
    pbns_usb_transport_destroy(usb);
    usb = NULL;
  }

  PbnsAttestationClientAdapterReset(&adapter);
  pbns_cose_key_reset(&receipt_key);
  pbns_cose_key_reset(&recipient_key);
  pbns_cose_key_reset(&challenge_key);
  pbns_cose_key_reset(&time_key);
  secure_zero(&tls_random, sizeof(tls_random));
  secure_zero(&tpm_public, sizeof(tpm_public));
  secure_zero(ek_public, sizeof(ek_public));
  secure_zero(ak_public, sizeof(ak_public));
  secure_zero(ak_name, sizeof(ak_name));
  secure_zero(identity_public, sizeof(identity_public));
  secure_zero(fingerprint, sizeof(fingerprint));
  secure_zero(&capabilities, sizeof(capabilities));
  free_buffers(&buffers);

  if (tls == NULL) {
    if (identity != NULL) {
      pbns_identity_close(identity);
      secure_zero(identity, sizeof(*identity));
      FreePool(identity);
      identity = NULL;
    }
    if (tls_random_context != NULL) {
      secure_zero(tls_random_context, sizeof(*tls_random_context));
      FreePool(tls_random_context);
      tls_random_context = NULL;
    }
  }
  return result;
}
