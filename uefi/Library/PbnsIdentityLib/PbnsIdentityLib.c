#include <Uefi.h>

#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PbnsIdentityLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include "PbnsIdentityRecord.h"
#include "PbnsSoftwareIdentity.h"

#define PBNS_SOFTWARE_IDENTITY_VARIABLE_ATTRIBUTES                             \
  (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS)

static CHAR16 software_identity_name[] = L"PbnsSoftwareIdentity";

static void secure_zero(void *Value, size_t Size) {
  volatile uint8_t *Bytes = Value;
  while (Size > 0U) {
    *Bytes = 0U;
    ++Bytes;
    --Size;
  }
}

typedef struct uefi_random_state {
  BOOLEAN has_tpm_source;
  PBNS_TPM_RANDOM_SOURCE tpm_source;
} uefi_random_state;

_Static_assert(sizeof(uefi_random_state) <= PBNS_SOFTWARE_RANDOM_STATE_SIZE,
               "UEFI random state exceeds the portable bound");
_Static_assert(PBNS_IDENTITY_VARIABLE_ATTRIBUTES ==
                   PBNS_SOFTWARE_IDENTITY_VARIABLE_ATTRIBUTES,
               "portable and UEFI variable attributes differ");

static pbns_status variable_read(void *Context, pbns_buffer Output,
                                 size_t *Written, uint32_t *Attributes) {
  (void)Context;
  UINTN Size = Output.cap;
  UINT32 UefiAttributes = 0U;
  const EFI_STATUS Status = gRT->GetVariable(
      software_identity_name, &gPbnsSoftwareIdentityVariableGuid,
      &UefiAttributes, &Size, Output.ptr);
  *Written = 0U;
  *Attributes = 0U;
  if (Status == EFI_NOT_FOUND) {
    return PBNS_ERR_STATE;
  }
  if (Status == EFI_BUFFER_TOO_SMALL || Size > Output.cap) {
    return PBNS_ERR_LIMIT;
  }
  if (EFI_ERROR(Status)) {
    return PBNS_ERR_IO;
  }
  *Written = Size;
  *Attributes = UefiAttributes;
  return PBNS_OK;
}

static pbns_status variable_write(void *Context, pbns_view Value,
                                  uint32_t Attributes) {
  (void)Context;
  if (Attributes != PBNS_SOFTWARE_IDENTITY_VARIABLE_ATTRIBUTES) {
    return PBNS_ERR_ARGUMENT;
  }
  if (Value.ptr == NULL || Value.len == 0U ||
      Value.len > PBNS_IDENTITY_RECORD_MAX_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  UINT8 Record[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
  CopyMem(Record, Value.ptr, Value.len);
  const EFI_STATUS Status = gRT->SetVariable(
      software_identity_name, &gPbnsSoftwareIdentityVariableGuid,
      PBNS_SOFTWARE_IDENTITY_VARIABLE_ATTRIBUTES, Value.len, Record);
  secure_zero(Record, sizeof(Record));
  return EFI_ERROR(Status) ? PBNS_ERR_IO : PBNS_OK;
}

static pbns_status variable_remove(void *Context) {
  (void)Context;
  const EFI_STATUS Status = gRT->SetVariable(
      software_identity_name, &gPbnsSoftwareIdentityVariableGuid, 0U, 0U, NULL);
  return Status == EFI_NOT_FOUND || !EFI_ERROR(Status) ? PBNS_OK : PBNS_ERR_IO;
}

static void *identity_allocate(void *Context, size_t Size) {
  (void)Context;
  return AllocateZeroPool(Size);
}

static void identity_release(void *Context, void *Value, size_t Size) {
  (void)Context;
  if (Value != NULL) {
    secure_zero(Value, Size);
    FreePool(Value);
  }
}

static pbns_status identity_random(void *State, pbns_buffer Output) {
  uefi_random_state Random = {0};
  CopyMem(&Random, State, sizeof(Random));
  const pbns_status Status = PbnsIdentityRandomFill(
      Random.has_tpm_source ? &Random.tpm_source : NULL, Output);
  secure_zero(&Random, sizeof(Random));
  return Status;
}

static pbns_software_identity_environment
make_environment(const PBNS_TPM_RANDOM_SOURCE *TpmSource) {
  pbns_software_identity_environment Environment = {
      .store =
          {
              .read = variable_read,
              .write = variable_write,
              .remove = variable_remove,
              .context = gRT,
          },
      .memory =
          {
              .allocate = identity_allocate,
              .release = identity_release,
              .context = gBS,
          },
      .random_fill = identity_random,
  };
  uefi_random_state Random = {0};
  if (TpmSource != NULL && TpmSource->Fill != NULL) {
    Random.has_tpm_source = TRUE;
    Random.tpm_source = *TpmSource;
  }
  CopyMem(Environment.random_state.bytes, &Random, sizeof(Random));
  secure_zero(&Random, sizeof(Random));
  return Environment;
}

static EFI_STATUS map_status(pbns_status Status) {
  switch (Status) {
  case PBNS_OK:
    return EFI_SUCCESS;
  case PBNS_ERR_ARGUMENT:
    return EFI_INVALID_PARAMETER;
  case PBNS_ERR_LIMIT:
    return EFI_BAD_BUFFER_SIZE;
  case PBNS_ERR_STATE:
    return EFI_NOT_FOUND;
  case PBNS_ERR_ENTROPY:
  case PBNS_ERR_AUTHENTICATION:
  case PBNS_ERR_CRC:
    return EFI_SECURITY_VIOLATION;
  case PBNS_ERR_RESOURCE:
    return EFI_OUT_OF_RESOURCES;
  case PBNS_ERR_UNSUPPORTED:
    return EFI_UNSUPPORTED;
  default:
    return EFI_DEVICE_ERROR;
  }
}

EFI_STATUS EFIAPI PbnsSoftwareIdentityCreate(
    const PBNS_TPM_RANDOM_SOURCE *TpmSource, pbns_identity *Identity) {
  pbns_software_identity_environment Environment = make_environment(TpmSource);
  const pbns_status Status =
      pbns_software_identity_create(&Environment, Identity);
  secure_zero(&Environment, sizeof(Environment));
  return Status == PBNS_ERR_STATE ? EFI_ALREADY_STARTED : map_status(Status);
}

EFI_STATUS EFIAPI PbnsSoftwareIdentityOpen(
    const PBNS_TPM_RANDOM_SOURCE *TpmSource, pbns_identity *Identity) {
  pbns_software_identity_environment Environment = make_environment(TpmSource);
  const pbns_status Status =
      pbns_software_identity_open(&Environment, Identity);
  secure_zero(&Environment, sizeof(Environment));
  return map_status(Status);
}

EFI_STATUS EFIAPI PbnsSoftwareIdentityReset(void) {
  pbns_software_identity_environment Environment = make_environment(NULL);
  const pbns_status Status = pbns_software_identity_reset(&Environment);
  secure_zero(&Environment, sizeof(Environment));
  return map_status(Status);
}
