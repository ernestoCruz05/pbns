#include <Uefi.h>

#include <Library/BaseMemoryLib.h>
#include <Library/PbnsUefiPlatformLib.h>
#include <Library/UefiLib.h>

#include <PbnsUsbTransportLib.h>

#include <pbns/broker.h>
#include <pbns/frame.h>

#define PBNS_PROBE_ENCODED_CAP 1024U
#define PBNS_PROBE_RAW_CAP 1024U
#define PBNS_PROBE_RECEIVE_CAP 256U
#define PBNS_PROBE_DECODED_CAP 1024U
#define PBNS_PROBE_WORKSPACE_SIZE \
  (PBNS_PROBE_ENCODED_CAP + PBNS_PROBE_RAW_CAP + PBNS_PROBE_RECEIVE_CAP + \
   PBNS_PROBE_DECODED_CAP)
#define PBNS_PROBE_TIMEOUT_MS 15000U

static pbns_status
ProbeRandom (
  void         *Context,
  pbns_buffer  Output
  )
{
  pbns_request_id RequestId = { 0 };
  EFI_STATUS      Status;

  (void)Context;
  if (Output.ptr == NULL || Output.len != 0U ||
      Output.cap != sizeof (RequestId.bytes)) {
    return PBNS_ERR_ARGUMENT;
  }
  Status = PbnsUefiRandomRequestId (&RequestId);
  if (EFI_ERROR (Status)) {
    return PBNS_ERR_ENTROPY;
  }
  CopyMem (Output.ptr, RequestId.bytes, sizeof (RequestId.bytes));
  ZeroMem (&RequestId, sizeof (RequestId));
  return PBNS_OK;
}

static pbns_status
ProbeMonotonicMs (
  void      *Context,
  uint64_t  *NowMs
  )
{
  EFI_SYSTEM_TABLE  *SystemTable = Context;
  UINT64            Current = 0U;
  EFI_STATUS        Status;

  if (NowMs == NULL || SystemTable == NULL || SystemTable->BootServices == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *NowMs = 0U;
  Status = PbnsUefiMonotonicMs (SystemTable->BootServices, &Current);
  if (EFI_ERROR (Status)) {
    return PBNS_ERR_TRANSPORT;
  }
  *NowMs = (uint64_t)Current;
  return PBNS_OK;
}

static const pbns_broker_platform_ops mProbePlatformOps = {
  .random       = ProbeRandom,
  .monotonic_ms = ProbeMonotonicMs,
};

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  pbns_usb_transport  *UsbTransport = NULL;
  UINT8               *Workspace    = NULL;
  pbns_broker          Broker       = { 0 };
  BOOLEAN              BrokerReady  = FALSE;
  pbns_broker_response Response     = { 0 };
  pbns_status          Status;
  EFI_STATUS           Result = EFI_DEVICE_ERROR;

  (void)ImageHandle;
  Print (
    L"PBNS probe protocol=%u build=edk2-b03a21a-x64\n",
    (UINT32)PBNS_FRAME_V1_PROTOCOL_VERSION
    );
  if (SystemTable == NULL || SystemTable->BootServices == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = pbns_usb_transport_create (SystemTable->BootServices, &UsbTransport);
  if (Status != PBNS_OK) {
    Print (L"PBNS probe: CDC0 adapter unavailable (%d)\n", (INT32)Status);
    return EFI_NOT_FOUND;
  }
  Print (L"PBNS probe: CDC0 adapter discovered\n");

  Workspace = PbnsUefiAllocatePool (PBNS_PROBE_WORKSPACE_SIZE);
  if (Workspace == NULL) {
    Result = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }
  Status = pbns_broker_init (
             &Broker,
             pbns_usb_transport_as_transport (UsbTransport),
             (pbns_broker_platform){ &mProbePlatformOps, SystemTable },
             (pbns_broker_storage){
               .encoded = { Workspace, 0U, PBNS_PROBE_ENCODED_CAP },
               .raw_scratch = {
                 Workspace + PBNS_PROBE_ENCODED_CAP,
                 0U,
                 PBNS_PROBE_RAW_CAP
               },
               .receive = {
                 Workspace + PBNS_PROBE_ENCODED_CAP + PBNS_PROBE_RAW_CAP,
                 0U,
                 PBNS_PROBE_RECEIVE_CAP
               },
               .decoded = {
                 Workspace + PBNS_PROBE_ENCODED_CAP + PBNS_PROBE_RAW_CAP +
                   PBNS_PROBE_RECEIVE_CAP,
                 0U,
                 PBNS_PROBE_DECODED_CAP
               },
             }
             );
  if (Status != PBNS_OK) {
    Print (L"PBNS probe: broker initialization failed (%d)\n", (INT32)Status);
    Result = EFI_COMPROMISED_DATA;
    goto Cleanup;
  }
  BrokerReady = TRUE;

  Status = pbns_broker_request (
             &Broker,
             PBNS_SERVICE_TRUSTED_TIME,
             (pbns_view){ NULL, 0U },
             PBNS_PROBE_TIMEOUT_MS,
             &Response
             );
  if (Status != PBNS_ERR_UNIMPLEMENTED) {
    Print (L"PBNS probe: unexpected broker result (%d)\n", (INT32)Status);
    Result = EFI_PROTOCOL_ERROR;
    goto Cleanup;
  }
  Print (L"PBNS probe: correlated unimplemented response\n");
  Result = EFI_SUCCESS;

Cleanup:
  if (BrokerReady) {
    pbns_broker_reset (&Broker);
  }
  if (Workspace != NULL) {
    PbnsUefiFreePool (Workspace);
  }
  pbns_usb_transport_destroy (UsbTransport);
  return Result;
}
