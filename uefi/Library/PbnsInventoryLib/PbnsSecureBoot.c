#include <Uefi.h>

#include <Guid/GlobalVariable.h>
#include <Guid/ImageAuthentication.h>
#include <Library/BaseMemoryLib.h>

#include "PbnsInventoryAdapterCore.h"
#include "PbnsInventoryLib.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mbedtls/sha256.h"

static CHAR16 mSecureBootName[] = L"SecureBoot";
static CHAR16 mSetupModeName[] = L"SetupMode";
static CHAR16 mDbName[] = EFI_IMAGE_SECURITY_DATABASE;
static CHAR16 mDbxName[] = EFI_IMAGE_SECURITY_DATABASE1;

typedef struct variable_context {
  EFI_RUNTIME_SERVICES *runtime;
} variable_context;

static pbns_inventory_platform_result platform_result(EFI_STATUS Status) {
  return (pbns_inventory_platform_result)
      PbnsInventoryCapabilityFromEfiStatus(Status);
}

static pbns_inventory_adapter_result get_variable(
    void *Context, pbns_inventory_adapter_variable Variable, uint8_t *Data,
    size_t *Size, uint32_t *Attributes) {
  variable_context *context = Context;
  CHAR16 *name = NULL;
  EFI_GUID *guid = NULL;
  switch (Variable) {
    case PBNS_ADAPTER_SECURE_BOOT:
      name = mSecureBootName;
      guid = &gEfiGlobalVariableGuid;
      break;
    case PBNS_ADAPTER_SETUP_MODE:
      name = mSetupModeName;
      guid = &gEfiGlobalVariableGuid;
      break;
    case PBNS_ADAPTER_DB:
      name = mDbName;
      guid = &gEfiImageSecurityDatabaseGuid;
      break;
    case PBNS_ADAPTER_DBX:
      name = mDbxName;
      guid = &gEfiImageSecurityDatabaseGuid;
      break;
    default:
      return (pbns_inventory_adapter_result){PBNS_PLATFORM_ERROR,
                                             EFI_INVALID_PARAMETER};
  }
  UINTN size = *Size;
  UINT32 attributes = 0U;
  const EFI_STATUS status =
      context->runtime->GetVariable(name, guid, &attributes, &size, Data);
  *Size = size;
  *Attributes = attributes;
  return (pbns_inventory_adapter_result){platform_result(status), status};
}

static pbns_status hash_parts(void *Context, const pbns_view *Parts,
                              size_t PartCount, uint8_t Digest[32]) {
  (void)Context;
  mbedtls_sha256_context hash;
  mbedtls_sha256_init(&hash);
  bool success = mbedtls_sha256_starts(&hash, 0) == 0;
  for (size_t index = 0U; success && index < PartCount; ++index) {
    success = (Parts[index].ptr != NULL || Parts[index].len == 0U) &&
              mbedtls_sha256_update(&hash, Parts[index].ptr,
                                    Parts[index].len) == 0;
  }
  success = success && mbedtls_sha256_finish(&hash, Digest) == 0;
  mbedtls_sha256_free(&hash);
  return success ? PBNS_OK : PBNS_ERR_CRYPTO;
}

EFI_STATUS EFIAPI PbnsInventorySecureBoot(EFI_RUNTIME_SERVICES *RuntimeServices,
                                          pbns_buffer Scratch,
                                          pbns_inventory_inputs *Inputs) {
  if (RuntimeServices == NULL || Scratch.ptr == NULL || Scratch.len != 0U ||
      Scratch.cap == 0U || Scratch.cap > PBNS_INVENTORY_VARIABLE_MAX_SIZE ||
      Inputs == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  variable_context context = {.runtime = RuntimeServices};
  const pbns_inventory_adapter_result status =
      pbns_inventory_adapter_secure_boot(get_variable, &context, Scratch,
                                         hash_parts, NULL,
                                         &Inputs->secure_boot);
  return PbnsInventoryEfiStatusFromAdapterResult(status);
}
