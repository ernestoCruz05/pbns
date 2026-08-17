#include <Uefi.h>

#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PbnsUefiPlatformLib.h>
#include <Library/RngLib.h>
#include <Protocol/Cpu.h>

#include <stddef.h>
#include <string.h>

#include "PbnsUefiClockMath.h"

typedef struct {
  EFI_BOOT_SERVICES      *BootServices;
  EFI_CPU_ARCH_PROTOCOL  *Protocol;
  UINT64                 OriginTicks;
  UINT64                 PeriodFemtoseconds;
  BOOLEAN                Initialized;
} PBNS_UEFI_CLOCK_STATE;

STATIC PBNS_UEFI_CLOCK_STATE  mClockState = { 0 };

size_t
strlen (
  const char  *String
  )
{
  size_t Length = 0U;
  while (String[Length] != '\0') {
    ++Length;
  }
  return Length;
}

VOID *
EFIAPI
PbnsUefiAllocatePool (
  IN UINTN  Size
  )
{
  if (Size == 0U) {
    return NULL;
  }
  return AllocatePool (Size);
}

VOID
EFIAPI
PbnsUefiFreePool (
  IN VOID  *Allocation
  )
{
  if (Allocation != NULL) {
    FreePool (Allocation);
  }
}

EFI_STATUS
EFIAPI
PbnsUefiRandomRequestId (
  OUT pbns_request_id  *RequestId
  )
{
  UINT64 Random[2] = { 0U, 0U };
  if (RequestId == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  ZeroMem (RequestId, sizeof (*RequestId));
  if (!GetRandomNumber128 (Random)) {
    ZeroMem (Random, sizeof (Random));
    return EFI_NOT_READY;
  }
  CopyMem (RequestId->bytes, Random, sizeof (RequestId->bytes));
  ZeroMem (Random, sizeof (Random));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
PbnsUefiMonotonicMs (
  IN EFI_BOOT_SERVICES  *BootServices,
  OUT UINT64            *Milliseconds
  )
{
  EFI_CPU_ARCH_PROTOCOL  *Protocol = NULL;
  UINT64                 CurrentTicks = 0U;
  UINT64                 PeriodFemtoseconds = 0U;
  uint64_t               ElapsedMilliseconds = UINT64_C (0);
  EFI_STATUS             Status;

  if (BootServices == NULL || Milliseconds == NULL ||
      BootServices->LocateProtocol == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *Milliseconds = 0U;
  if (!mClockState.Initialized) {
    Status = BootServices->LocateProtocol (
                             &gEfiCpuArchProtocolGuid,
                             NULL,
                             (VOID **)&Protocol
                             );
    if (EFI_ERROR (Status)) {
      return Status;
    }
    if (Protocol == NULL || Protocol->GetTimerValue == NULL) {
      return EFI_UNSUPPORTED;
    }
    Status = Protocol->GetTimerValue (
                         Protocol,
                         0U,
                         &CurrentTicks,
                         &PeriodFemtoseconds
                         );
    if (EFI_ERROR (Status)) {
      return Status;
    }
    if (PeriodFemtoseconds == 0U) {
      return EFI_UNSUPPORTED;
    }
    mClockState = (PBNS_UEFI_CLOCK_STATE) {
      .BootServices = BootServices,
      .Protocol = Protocol,
      .OriginTicks = CurrentTicks,
      .PeriodFemtoseconds = PeriodFemtoseconds,
      .Initialized = TRUE,
    };
    return EFI_SUCCESS;
  }
  if (mClockState.BootServices != BootServices) {
    return EFI_DEVICE_ERROR;
  }
  Status = mClockState.Protocol->GetTimerValue (
                                  mClockState.Protocol,
                                  0U,
                                  &CurrentTicks,
                                  &PeriodFemtoseconds
                                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }
  if (PeriodFemtoseconds == 0U) {
    return EFI_UNSUPPORTED;
  }
  if (PeriodFemtoseconds != mClockState.PeriodFemtoseconds ||
      !pbns_uefi_clock_elapsed_ms (
         (uint64_t)CurrentTicks,
         (uint64_t)mClockState.OriginTicks,
         (uint64_t)PeriodFemtoseconds,
         &ElapsedMilliseconds
         )) {
    return EFI_DEVICE_ERROR;
  }
  *Milliseconds = (UINT64)ElapsedMilliseconds;
  return EFI_SUCCESS;
}
