#include <Uefi.h>

#include "PbnsTpmIdentityLib.h"
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PbnsCoseCryptoLib.h>
#include <Library/PbnsIdentityLib.h>
#include <Library/PbnsTrustedTimeLib.h>
#include <Library/PbnsUefiPlatformLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#include <PbnsUsbTransportLib.h>

#include <stddef.h>
#include <stdint.h>

#include "pbns/broker.h"
#include "pbns/identity.h"
#include "pbns/trusted_time.h"

#define PBNS_TIME_LIVE_BROKER_BUFFER_SIZE PBNS_FRAME_V1_WIRE_MAX
#define PBNS_TIME_LIVE_REPLAY_BUFFER_SIZE PBNS_FRAME_V1_WIRE_MAX
#define PBNS_TIME_LIVE_BROKER_WORKSPACE_SIZE                                   \
  ((PBNS_TIME_LIVE_BROKER_BUFFER_SIZE * 4U) + PBNS_TIME_LIVE_REPLAY_BUFFER_SIZE)
#define PBNS_TIME_LIVE_SIGNED_BUFFER_SIZE 1024U
#define PBNS_TIME_LIVE_AAD_BUFFER_SIZE 192U
#define PBNS_TIME_LIVE_MAX_RTT_MS 20000U

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

static const uint8_t TIME_KEY_ID[] = "time-key-1";

typedef enum time_identity_mode {
  TIME_IDENTITY_SOFTWARE = 1,
  TIME_IDENTITY_TPM = 2,
} time_identity_mode;

typedef struct time_platform_context {
  EFI_SYSTEM_TABLE *system_table;
  const pbns_identity *identity;
} time_platform_context;

typedef struct time_replay_transport {
  pbns_transport inner;
  uint8_t *record;
  size_t record_capacity;
  size_t record_length;
  size_t replay_offset;
  bool replay;
} time_replay_transport;

static pbns_status replay_open(void *context) {
  time_replay_transport *transport = context;
  if (transport == NULL || transport->inner.ops == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  transport->replay_offset = 0U;
  if (transport->replay) {
    return transport->record_length > 0U ? PBNS_OK : PBNS_ERR_STATE;
  }
  transport->record_length = 0U;
  return transport->inner.ops->open(transport->inner.context);
}

static pbns_status replay_close(void *context) {
  time_replay_transport *transport = context;
  if (transport == NULL || transport->inner.ops == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (transport->replay) {
    return PBNS_OK;
  }
  return transport->inner.ops->close(transport->inner.context);
}

static pbns_status replay_send(void *context, pbns_view bytes,
                               uint32_t timeout_ms) {
  time_replay_transport *transport = context;
  if (transport == NULL || transport->inner.ops == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (transport->replay) {
    return PBNS_OK;
  }
  return transport->inner.ops->send(transport->inner.context, bytes,
                                    timeout_ms);
}

static pbns_status replay_receive(void *context, pbns_buffer output,
                                  uint32_t timeout_ms, size_t *received) {
  time_replay_transport *transport = context;
  if (transport == NULL || transport->inner.ops == NULL || output.ptr == NULL ||
      output.len != 0U || output.cap == 0U || received == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *received = 0U;
  if (transport->replay) {
    if (transport->replay_offset >= transport->record_length) {
      return PBNS_ERR_TIMEOUT;
    }
    const size_t remaining =
        transport->record_length - transport->replay_offset;
    const size_t amount = remaining < output.cap ? remaining : output.cap;
    CopyMem(output.ptr, transport->record + transport->replay_offset, amount);
    transport->replay_offset += amount;
    *received = amount;
    return PBNS_OK;
  }
  const pbns_status status = transport->inner.ops->receive(
      transport->inner.context, output, timeout_ms, received);
  if (status != PBNS_OK) {
    return status;
  }
  if (*received > output.cap ||
      *received > transport->record_capacity - transport->record_length) {
    return PBNS_ERR_LIMIT;
  }
  CopyMem(transport->record + transport->record_length, output.ptr, *received);
  transport->record_length += *received;
  return PBNS_OK;
}

static pbns_status replay_cancel(void *context,
                                 const pbns_request_id *request_id) {
  time_replay_transport *transport = context;
  if (transport == NULL || transport->inner.ops == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (transport->replay) {
    return PBNS_OK;
  }
  return transport->inner.ops->cancel(transport->inner.context, request_id);
}

static pbns_status replay_limits(void *context, pbns_frame_limits *limits) {
  time_replay_transport *transport = context;
  if (transport == NULL || transport->inner.ops == NULL || limits == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  return transport->inner.ops->limits(transport->inner.context, limits);
}

static const pbns_transport_ops REPLAY_TRANSPORT_OPS = {
    .open = replay_open,
    .close = replay_close,
    .send = replay_send,
    .receive = replay_receive,
    .cancel = replay_cancel,
    .limits = replay_limits,
};

static void secure_zero(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  if (bytes == NULL) {
    return;
  }
  while (length > 0U) {
    *bytes = 0U;
    ++bytes;
    --length;
  }
}

static EFI_STATUS choose_identity(EFI_SYSTEM_TABLE *system_table,
                                  time_identity_mode *mode) {
  if (system_table == NULL || system_table->ConIn == NULL || mode == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *mode = 0;
  Print(L"PBNS TIME MODE: S=enrolled reduced software, T=enrolled TPM\r\n");
  while (TRUE) {
    UINTN index = 0U;
    if (EFI_ERROR(
            gBS->WaitForEvent(1U, &system_table->ConIn->WaitForKey, &index))) {
      return EFI_DEVICE_ERROR;
    }
    EFI_INPUT_KEY key = {0};
    if (EFI_ERROR(
            system_table->ConIn->ReadKeyStroke(system_table->ConIn, &key))) {
      continue;
    }
    if (key.UnicodeChar == 's' || key.UnicodeChar == 'S') {
      *mode = TIME_IDENTITY_SOFTWARE;
      Print(L"PBNS TIME SOFTWARE MODE EXPLICIT\r\n");
      return EFI_SUCCESS;
    }
    if (key.UnicodeChar == 't' || key.UnicodeChar == 'T') {
      *mode = TIME_IDENTITY_TPM;
      Print(L"PBNS TIME TPM MODE EXPLICIT\r\n");
      return EFI_SUCCESS;
    }
    return EFI_ABORTED;
  }
}

static pbns_status platform_random(void *context, pbns_buffer output) {
  const time_platform_context *platform = context;
  if (platform == NULL || platform->identity == NULL || output.ptr == NULL ||
      output.len != 0U || output.cap != PBNS_REQUEST_ID_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  return pbns_identity_random(platform->identity, output);
}

static pbns_status platform_monotonic(void *context, uint64_t *milliseconds) {
  const time_platform_context *platform = context;
  if (platform == NULL || platform->system_table == NULL ||
      platform->system_table->BootServices == NULL || milliseconds == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  UINT64 current = 0U;
  const EFI_STATUS status =
      PbnsUefiMonotonicMs(platform->system_table->BootServices, &current);
  if (EFI_ERROR(status)) {
    return PBNS_ERR_STATE;
  }
  *milliseconds = current;
  return PBNS_OK;
}

static const pbns_broker_platform_ops PLATFORM_OPS = {
    .random = platform_random,
    .monotonic_ms = platform_monotonic,
};

EFI_STATUS EFIAPI UefiMain(EFI_HANDLE image_handle,
                           EFI_SYSTEM_TABLE *system_table) {
  (void)image_handle;
  EFI_STATUS result = EFI_SECURITY_VIOLATION;
  pbns_identity identity = {0};
  pbns_tpm_capability_result capabilities = {0};
  pbns_cose_key identity_key = {0};
  pbns_cose_key time_key = {0};
  pbns_usb_transport *usb_transport = NULL;
  pbns_broker broker = {0};
  BOOLEAN broker_ready = FALSE;
  uint8_t *broker_workspace = NULL;
  uint8_t request_payload[PBNS_TIME_ENCODED_MAX_SIZE] = {0};
  uint8_t signed_request[PBNS_TIME_LIVE_SIGNED_BUFFER_SIZE] = {0};
  uint8_t signed_response[PBNS_TIME_LIVE_SIGNED_BUFFER_SIZE] = {0};
  uint8_t canonical_scratch[PBNS_TIME_ENCODED_MAX_SIZE] = {0};
  uint8_t aad[PBNS_TIME_LIVE_AAD_BUFFER_SIZE] = {0};
  uint8_t fingerprint[PBNS_TIME_FINGERPRINT_SIZE] = {0};
  time_identity_mode mode = 0;

  if (system_table == NULL || system_table->BootServices == NULL ||
      EFI_ERROR(choose_identity(system_table, &mode))) {
    Print(L"PBNS TIME LIVE FAIL explicit identity mode\r\n");
    return EFI_INVALID_PARAMETER;
  }
  EFI_STATUS status = mode == TIME_IDENTITY_TPM
                          ? PbnsTpmIdentityOpen(&identity, &capabilities)
                          : PbnsSoftwareIdentityOpen(NULL, &identity);
  if (EFI_ERROR(status)) {
    Print(L"PBNS TIME LIVE FAIL identity open status=%r\r\n", status);
    result = status;
    goto Cleanup;
  }
  const pbns_identity_assurance expected = mode == TIME_IDENTITY_TPM
                                               ? PBNS_IDENTITY_TPM_UNVERIFIED_EK
                                               : PBNS_IDENTITY_SOFTWARE;
  if (pbns_identity_assurance_level(&identity) != expected ||
      pbns_identity_fingerprint(
          &identity, (pbns_buffer){fingerprint, 0U, sizeof(fingerprint)}) !=
          PBNS_OK ||
      pbns_cose_key_from_identity(&identity_key, &identity) != PBNS_OK ||
      pbns_cose_key_from_p256_public(
          &time_key, (pbns_view){TIME_KEY_X, sizeof(TIME_KEY_X)},
          (pbns_view){TIME_KEY_Y, sizeof(TIME_KEY_Y)}) != PBNS_OK) {
    Print(L"PBNS TIME LIVE FAIL key setup\r\n");
    goto Cleanup;
  }
  if (pbns_usb_transport_create(system_table->BootServices, &usb_transport) !=
      PBNS_OK) {
    Print(L"PBNS TIME LIVE FAIL CDC0 unavailable\r\n");
    result = EFI_NOT_FOUND;
    goto Cleanup;
  }
  broker_workspace = AllocatePool(PBNS_TIME_LIVE_BROKER_WORKSPACE_SIZE);
  if (broker_workspace == NULL) {
    result = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }
  time_platform_context platform = {
      .system_table = system_table,
      .identity = &identity,
  };
  time_replay_transport replay_transport = {
      .inner = pbns_usb_transport_as_transport(usb_transport),
      .record = broker_workspace + (PBNS_TIME_LIVE_BROKER_BUFFER_SIZE * 4U),
      .record_capacity = PBNS_TIME_LIVE_REPLAY_BUFFER_SIZE,
  };
  if (pbns_broker_init(
          &broker, (pbns_transport){&REPLAY_TRANSPORT_OPS, &replay_transport},
          (pbns_broker_platform){&PLATFORM_OPS, &platform},
          (pbns_broker_storage){
              .encoded = {broker_workspace, 0U,
                          PBNS_TIME_LIVE_BROKER_BUFFER_SIZE},
              .raw_scratch = {broker_workspace +
                                  PBNS_TIME_LIVE_BROKER_BUFFER_SIZE,
                              0U, PBNS_TIME_LIVE_BROKER_BUFFER_SIZE},
              .receive = {broker_workspace +
                              (PBNS_TIME_LIVE_BROKER_BUFFER_SIZE * 2U),
                          0U, PBNS_TIME_LIVE_BROKER_BUFFER_SIZE},
              .decoded = {broker_workspace +
                              (PBNS_TIME_LIVE_BROKER_BUFFER_SIZE * 3U),
                          0U, PBNS_TIME_LIVE_BROKER_BUFFER_SIZE},
          }) != PBNS_OK) {
    Print(L"PBNS TIME LIVE FAIL broker setup\r\n");
    goto Cleanup;
  }
  broker_ready = TRUE;

  pbns_uefi_trusted_time_environment environment = {
      .boot_services = system_table->BootServices,
      .broker = &broker,
      .identity = &identity,
      .identity_key = &identity_key,
      .time_verification_key = &time_key,
      .time_key_id = {TIME_KEY_ID, sizeof(TIME_KEY_ID) - 1U},
      .maximum_round_trip_ms = PBNS_TIME_LIVE_MAX_RTT_MS,
  };
  pbns_trusted_time_client client = {0};
  pbns_trusted_time_workspace workspace = {
      .request_payload = {request_payload, 0U, sizeof(request_payload)},
      .signed_request = {signed_request, 0U, sizeof(signed_request)},
      .signed_response = {signed_response, 0U, sizeof(signed_response)},
      .canonical_scratch = {canonical_scratch, 0U, sizeof(canonical_scratch)},
      .aad = {aad, 0U, sizeof(aad)},
  };
  pbns_time_interval interval = {0};
  UINT64 started = 0U;
  UINT64 finished = 0U;
  if (PbnsTrustedTimeClientInit(&environment, &client) != PBNS_OK ||
      EFI_ERROR(PbnsUefiMonotonicMs(system_table->BootServices, &started))) {
    Print(L"PBNS TIME LIVE FAIL client setup\r\n");
    goto Cleanup;
  }
  const pbns_status query_status = pbns_trusted_time_query(
      &client, fingerprint, NULL, &workspace, &interval);
  if (EFI_ERROR(PbnsUefiMonotonicMs(system_table->BootServices, &finished)) ||
      query_status != PBNS_OK || finished < started ||
      interval.earliest_ns <= 0 || interval.latest_ns < interval.earliest_ns) {
    Print(L"PBNS TIME LIVE FAIL query status=%d\r\n", query_status);
    goto Cleanup;
  }
  Print(L"PBNS TIME LIVE TOTAL MS %Lu\r\n", finished - started);
  Print(L"PBNS TIME LIVE INTERVAL WIDTH NS %Ld\r\n",
        interval.latest_ns - interval.earliest_ns);
  Print(L"PBNS TIME LIVE INTERVAL PASS earliest=%Ld latest=%Ld\r\n",
        interval.earliest_ns, interval.latest_ns);
  if (replay_transport.record_length == 0U) {
    Print(L"PBNS TIME LIVE FAIL replay capture\r\n");
    goto Cleanup;
  }
  replay_transport.replay = true;
  pbns_time_interval replay_interval = {0};
  const pbns_status replay_status = pbns_trusted_time_query(
      &client, fingerprint, &interval, &workspace, &replay_interval);
  replay_transport.replay = false;
  if (replay_status == PBNS_OK) {
    Print(L"PBNS TIME LIVE FAIL replay accepted\r\n");
    goto Cleanup;
  }
  Print(L"PBNS TIME LIVE REPLAY REJECT PASS status=%d\r\n", replay_status);
  result = EFI_SUCCESS;

Cleanup:
  secure_zero(fingerprint, sizeof(fingerprint));
  secure_zero(request_payload, sizeof(request_payload));
  secure_zero(signed_request, sizeof(signed_request));
  secure_zero(signed_response, sizeof(signed_response));
  secure_zero(canonical_scratch, sizeof(canonical_scratch));
  secure_zero(aad, sizeof(aad));
  secure_zero(&capabilities, sizeof(capabilities));
  if (broker_ready) {
    pbns_broker_reset(&broker);
  }
  if (broker_workspace != NULL) {
    secure_zero(broker_workspace, PBNS_TIME_LIVE_BROKER_WORKSPACE_SIZE);
    FreePool(broker_workspace);
  }
  pbns_usb_transport_destroy(usb_transport);
  pbns_cose_key_reset(&time_key);
  pbns_cose_key_reset(&identity_key);
  pbns_identity_close(&identity);
  return result;
}
