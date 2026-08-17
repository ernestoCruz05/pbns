#include <Uefi.h>

#include <Library/PbnsIdentityLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Rng.h>

#include "PbnsRandomPolicy.h"

static pbns_status efi_rng_fill(void *Context, pbns_buffer Output) {
  (void)Context;
  EFI_RNG_PROTOCOL *Rng = NULL;
  EFI_STATUS Status =
      gBS->LocateProtocol(&gEfiRngProtocolGuid, NULL, (void **)&Rng);
  if (Status == EFI_NOT_FOUND || Status == EFI_UNSUPPORTED) {
    return PBNS_ERR_UNSUPPORTED;
  }
  if (EFI_ERROR(Status) || Rng == NULL) {
    return PBNS_ERR_ENTROPY;
  }
  Status = Rng->GetRNG(Rng, NULL, Output.cap, Output.ptr);
  return EFI_ERROR(Status) ? PBNS_ERR_ENTROPY : PBNS_OK;
}

static pbns_status tpm_source_fill(void *Context, pbns_buffer Output) {
  const PBNS_TPM_RANDOM_SOURCE *Source = Context;
  if (Source == NULL || Source->Fill == NULL) {
    return PBNS_ERR_UNSUPPORTED;
  }
  const EFI_STATUS Status =
      Source->Fill(Source->Context, Output.cap, Output.ptr);
  return EFI_ERROR(Status) ? PBNS_ERR_ENTROPY : PBNS_OK;
}

pbns_status EFIAPI PbnsIdentityRandomFill(
    const PBNS_TPM_RANDOM_SOURCE *TpmSource, pbns_buffer Output) {
  const pbns_random_source EfiSource = {.fill = efi_rng_fill, .context = gBS};
  PBNS_TPM_RANDOM_SOURCE TpmCopy = {0};
  pbns_random_source TpmAdapter = {0};
  const pbns_random_source *Fallback = NULL;
  if (TpmSource != NULL && TpmSource->Fill != NULL) {
    TpmCopy = *TpmSource;
    TpmAdapter =
        (pbns_random_source){.fill = tpm_source_fill, .context = &TpmCopy};
    Fallback = &TpmAdapter;
  }
  return pbns_random_priority_fill(&EfiSource, Fallback, Output);
}
