#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/LoadedImage.h>

#include "PbnsTpmIdentityLib.h"

static BOOLEAN option_is(EFI_HANDLE ImageHandle, const CHAR16 *Expected) {
  EFI_LOADED_IMAGE_PROTOCOL *loaded = NULL;
  if (EFI_ERROR(gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid,
                                    (VOID **)&loaded)) ||
      loaded == NULL || loaded->LoadOptions == NULL ||
      loaded->LoadOptionsSize < sizeof(CHAR16)) {
    return FALSE;
  }
  return StrStr((CHAR16 *)loaded->LoadOptions, Expected) != NULL;
}

EFI_STATUS EFIAPI UefiMain(EFI_HANDLE ImageHandle,
                           EFI_SYSTEM_TABLE *SystemTable) {
  (void)SystemTable;
  if (option_is(ImageHandle, L"reset")) {
    const EFI_STATUS reset_status = PbnsTpmIdentityReset();
    Print(L"PBNS_TPM_IDENTITY_RESET status=%r\r\n", reset_status);
    return reset_status;
  }

  pbns_tpm_capability_result capabilities = {0};
  EFI_STATUS status = PbnsTpmIdentityCapabilities(&capabilities);
  if (EFI_ERROR(status)) {
    Print(L"PBNS_TPM_CAPABILITIES_FAIL status=%r\r\n", status);
    return status;
  }
  Print(L"PBNS_TPM_CAPABILITIES_PASS manufacturer=%08x firmware=%08x:%08x "
        L"sha256_pcr=%d\r\n",
        capabilities.required.manufacturer, capabilities.required.firmware1,
        capabilities.required.firmware2,
        capabilities.required.sha256_pcr_bank ? 1 : 0);

  pbns_identity identity = {0};
  const BOOLEAN force_create = option_is(ImageHandle, L"create");
  status = force_create ? PbnsTpmIdentityCreate(&identity, &capabilities)
                        : PbnsTpmIdentityOpen(&identity, &capabilities);
  const CHAR16 *operation = force_create ? L"CREATE" : L"OPEN";
  if (EFI_ERROR(status)) {
    Print(L"PBNS_TPM_IDENTITY_%s_FAIL status=%r\r\n", operation, status);
    return status;
  }

  uint8_t fingerprint[32] = {0};
  uint8_t digest[32] = {0};
  uint8_t signature[64] = {0};
  size_t signature_size = 0U;
  SetMem(digest, sizeof(digest), 0x5aU);
  const pbns_status fingerprint_status = pbns_identity_fingerprint(
      &identity, (pbns_buffer){fingerprint, 0U, sizeof(fingerprint)});
  const pbns_status sign_status = pbns_identity_sign(
      &identity, (pbns_view){digest, sizeof(digest)},
      (pbns_buffer){signature, 0U, sizeof(signature)}, &signature_size);
  const pbns_identity_assurance assurance =
      pbns_identity_assurance_level(&identity);
  ZeroMem(digest, sizeof(digest));
  ZeroMem(signature, sizeof(signature));
  pbns_identity_close(&identity);
  if (fingerprint_status != PBNS_OK || sign_status != PBNS_OK ||
      signature_size != sizeof(signature)) {
    ZeroMem(fingerprint, sizeof(fingerprint));
    Print(L"PBNS_TPM_IDENTITY_%s_OPERATION_FAIL\r\n", operation);
    return EFI_SECURITY_VIOLATION;
  }
  Print(L"PBNS_TPM_IDENTITY_%s_PASS assurance=%d "
        L"fingerprint_prefix=%02x%02x%02x%02x\r\n",
        operation, assurance, fingerprint[0], fingerprint[1], fingerprint[2],
        fingerprint[3]);
  ZeroMem(fingerprint, sizeof(fingerprint));
  return EFI_SUCCESS;
}
