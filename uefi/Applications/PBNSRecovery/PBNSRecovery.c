#include <Uefi.h>

#include <Guid/GlobalVariable.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/PbnsUefiPlatformLib.h>

#include <mbedtls/sha256.h>

#include <pbns/boot_config.h>

#include "PbnsBootConfigLib.h"
#include "PbnsRecoveryClientLib.h"
#include "PbnsRecoveryServiceLib.h"

typedef struct PBNS_RECOVERY_UEFI_CONTEXT {
  EFI_HANDLE ImageHandle;
  EFI_SYSTEM_TABLE *SystemTable;
  PBNS_RECOVERY_SERVICE *Service;
  pbns_recovery_assurance_mode Mode;
  UINT64 TargetVersion;
} PBNS_RECOVERY_UEFI_CONTEXT;

static pbns_status StatusToPbns(EFI_STATUS Status) {
  if (Status == EFI_SUCCESS) {
    return PBNS_OK;
  }
  if (Status == EFI_OUT_OF_RESOURCES) {
    return PBNS_ERR_RESOURCE;
  }
  if (Status == EFI_SECURITY_VIOLATION || Status == EFI_ACCESS_DENIED) {
    return PBNS_ERR_AUTHENTICATION;
  }
  if (Status == EFI_UNSUPPORTED) {
    return PBNS_ERR_UNSUPPORTED;
  }
  if (Status == EFI_INVALID_PARAMETER) {
    return PBNS_ERR_ARGUMENT;
  }
  return PBNS_ERR_IO;
}

static void DisplayLauncherFailure(void) {
  UINT8 encoded[PBNS_BOOT_FAILURE_ENCODED_SIZE] = {0};
  UINTN size = sizeof(encoded);
  UINT32 attributes = 0U;
  EFI_STATUS status =
      gRT->GetVariable(PBNS_BOOT_FAILURE_VARIABLE_NAME, &gPbnsBootConfigGuid,
                       &attributes, &size, encoded);
  if (!EFI_ERROR(status) && attributes == EFI_VARIABLE_BOOTSERVICE_ACCESS &&
      size == sizeof(encoded)) {
    pbns_boot_failure failure = {0};
    if (pbns_boot_failure_decode((pbns_view){encoded, sizeof(encoded)},
                                 &failure) == PBNS_OK) {
      Print(L"PBNS RECOVERY FALLBACK stage=%u loader_status=0x%lx\r\n",
            failure.stage, failure.platform_status);
    }
    (void)gRT->SetVariable(PBNS_BOOT_FAILURE_VARIABLE_NAME,
                           &gPbnsBootConfigGuid, 0U, 0U, NULL);
  } else {
    Print(L"PBNS RECOVERY MANUAL ENTRY\r\n");
  }
  ZeroMem(encoded, sizeof(encoded));
}

static pbns_status Confirm(void *Context, bool *Accepted) {
  PBNS_RECOVERY_UEFI_CONTEXT *uefi = Context;
  static const CHAR16 expected[] = L"RECOVER";
  CHAR16 entered[sizeof(expected) / sizeof(expected[0])] = {0};
  UINTN length = 0U;
  bool overflowed = false;
  if (uefi == NULL || Accepted == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *Accepted = false;
  Print(L"Type RECOVER to download a RAM-only recovery image: ");
  for (;;) {
    EFI_INPUT_KEY key = {0};
    EFI_STATUS status = gST->ConIn->ReadKeyStroke(gST->ConIn, &key);
    if (status == EFI_NOT_READY) {
      UINTN index = 0U;
      status = gBS->WaitForEvent(1U, &gST->ConIn->WaitForKey, &index);
      if (EFI_ERROR(status)) {
        return StatusToPbns(status);
      }
      continue;
    }
    if (EFI_ERROR(status)) {
      return StatusToPbns(status);
    }
    if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
      break;
    }
    if (key.UnicodeChar == CHAR_BACKSPACE) {
      if (length > 0U) {
        --length;
        entered[length] = L'\0';
        Print(L"\b \b");
      }
      continue;
    }
    if (key.UnicodeChar >= L' ') {
      if (length + 1U < ARRAY_SIZE(entered)) {
        entered[length++] = key.UnicodeChar;
        Print(L"%c", key.UnicodeChar);
      } else {
        overflowed = true;
      }
    }
  }
  Print(L"\r\n");
  if (overflowed || StrCmp(entered, expected) != 0) {
    ZeroMem(entered, sizeof(entered));
    return PBNS_OK;
  }
  ZeroMem(entered, sizeof(entered));
  Print(L"Select recovery assurance: T/t or S/s: ");
  for (;;) {
    EFI_INPUT_KEY key = {0};
    EFI_STATUS status = gST->ConIn->ReadKeyStroke(gST->ConIn, &key);
    if (status == EFI_NOT_READY) {
      UINTN index = 0U;
      status = gBS->WaitForEvent(1U, &gST->ConIn->WaitForKey, &index);
      if (EFI_ERROR(status)) {
        return StatusToPbns(status);
      }
      continue;
    }
    if (EFI_ERROR(status)) {
      return StatusToPbns(status);
    }
    if (key.UnicodeChar == L'T' || key.UnicodeChar == L't') {
      uefi->Mode = PBNS_RECOVERY_ASSURANCE_T;
    } else if (key.UnicodeChar == L'S' || key.UnicodeChar == L's') {
      uefi->Mode = PBNS_RECOVERY_ASSURANCE_S;
    } else {
      return PBNS_OK;
    }
    Print(L"\r\n");
    *Accepted = true;
    return PBNS_OK;
  }
}

static pbns_status PlatformReady(void *Context) {
  (void)Context;
  UINT8 secure_boot = 0U;
  UINT8 setup_mode = 1U;
  UINTN size = sizeof(secure_boot);
  EFI_STATUS status = gRT->GetVariable(L"SecureBoot", &gEfiGlobalVariableGuid,
                                       NULL, &size, &secure_boot);
  if (EFI_ERROR(status) || size != sizeof(secure_boot)) {
    return PBNS_ERR_UNSUPPORTED;
  }
  size = sizeof(setup_mode);
  status = gRT->GetVariable(L"SetupMode", &gEfiGlobalVariableGuid, NULL, &size,
                            &setup_mode);
  return !EFI_ERROR(status) && size == sizeof(setup_mode) &&
                 secure_boot == 1U && setup_mode == 0U
             ? PBNS_OK
             : PBNS_ERR_UNSUPPORTED;
}

static pbns_status TrustedTime(void *Context) {
  PBNS_RECOVERY_UEFI_CONTEXT *uefi = Context;
  if (uefi == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (uefi->Service == NULL) {
    const EFI_STATUS status = PbnsRecoveryServiceCreate(
        uefi->SystemTable, uefi->Mode, &uefi->Service);
    if (EFI_ERROR(status)) {
      return StatusToPbns(status);
    }
    if (uefi->Service == NULL) {
      return PBNS_ERR_STATE;
    }
  }
  return PbnsRecoveryServiceTrustedTime(uefi->Service);
}

static pbns_status VerifiedManifest(void *Context, PBNS_RECOVERY_PLAN *Plan) {
  PBNS_RECOVERY_UEFI_CONTEXT *uefi = Context;
  if (Plan == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *Plan = (PBNS_RECOVERY_PLAN){0};
  if (uefi == NULL || uefi->Service == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status status = PbnsRecoveryServiceManifest(uefi->Service, Plan);
  uefi->TargetVersion = 0U;
  if (status == PBNS_OK) {
    uefi->TargetVersion = Plan->target_version;
  }
  return status;
}

static pbns_status AllocatePages(void *Context, uint64_t Size, void **Image) {
  (void)Context;
  if (Image == NULL || Size == 0U || Size > (uint64_t)MAX_UINTN) {
    return PBNS_ERR_ARGUMENT;
  }
  *Image = NULL;
  const UINTN pages = EFI_SIZE_TO_PAGES((UINTN)Size);
  EFI_PHYSICAL_ADDRESS address = 0U;
  const EFI_STATUS status =
      gBS->AllocatePages(AllocateAnyPages, EfiLoaderData, pages, &address);
  if (EFI_ERROR(status)) {
    return StatusToPbns(status);
  }
  *Image = (void *)(UINTN)address;
  return PBNS_OK;
}

static pbns_status StreamImage(void *Context, void *Image, uint64_t Size) {
  PBNS_RECOVERY_UEFI_CONTEXT *uefi = Context;
  UINT64 started_ms = 0U;
  UINT64 finished_ms = 0U;
  if (uefi == NULL || uefi->Service == NULL || Image == NULL || Size == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  if (EFI_ERROR(PbnsUefiMonotonicMs(uefi->SystemTable->BootServices,
                                    &started_ms))) {
    return PBNS_ERR_IO;
  }
  const pbns_status stream_status =
      PbnsRecoveryServiceStream(uefi->Service, Image, Size);
  const EFI_STATUS clock_status =
      PbnsUefiMonotonicMs(uefi->SystemTable->BootServices, &finished_ms);
  if (stream_status != PBNS_OK) {
    return stream_status;
  }
  if (EFI_ERROR(clock_status) || finished_ms < started_ms) {
    return PBNS_ERR_IO;
  }
  Print(L"PBNS RECOVERY STREAM DURATION MS=%Lu\r\n", finished_ms - started_ms);
  return PBNS_OK;
}

static pbns_status VerifyDigest(void *Context, pbns_view Image,
                                const uint8_t ExpectedDigest[32]) {
  (void)Context;
  UINT8 digest[32] = {0};
  if (Image.ptr == NULL || Image.len == 0U || ExpectedDigest == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  const bool valid = mbedtls_sha256(Image.ptr, Image.len, digest, 0) == 0;
  const bool equal =
      valid && CompareMem(digest, ExpectedDigest, sizeof(digest)) == 0;
  ZeroMem(digest, sizeof(digest));
  return equal ? PBNS_OK : PBNS_ERR_AUTHENTICATION;
}

static pbns_status ReadVersion(void *Context, uint64_t *Version) {
  PBNS_RECOVERY_UEFI_CONTEXT *uefi = Context;
  if (Version == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *Version = 0U;
  if (uefi == NULL || uefi->Service == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  return PbnsRecoveryServiceReadVersion(uefi->Service, Version);
}

static pbns_status LoadImage(void *Context, pbns_buffer Image,
                             void **ImageHandle) {
  PBNS_RECOVERY_UEFI_CONTEXT *uefi = Context;
  if (uefi == NULL || Image.ptr == NULL || Image.len == 0U ||
      ImageHandle == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *ImageHandle = NULL;
  EFI_HANDLE handle = NULL;
  Print(L"PBNS RECOVERY MEMORY LOAD BEGIN size=%Lu version=%Lu\r\n",
        (UINT64)Image.len, uefi->TargetVersion);
  const EFI_STATUS status = gBS->LoadImage(FALSE, uefi->ImageHandle, NULL,
                                           Image.ptr, Image.len, &handle);
  if (!EFI_ERROR(status) && handle != NULL) {
    Print(L"PBNS RECOVERY MEMORY LOAD PASS\r\n");
  } else {
    Print(L"PBNS RECOVERY MEMORY LOAD REJECT status=0x%lx\r\n", status);
  }
  *ImageHandle = handle;
  return StatusToPbns(status);
}

static pbns_status AdvanceVersion(void *Context, uint64_t CurrentVersion,
                                  uint64_t TargetVersion,
                                  pbns_view Authorization) {
  PBNS_RECOVERY_UEFI_CONTEXT *uefi = Context;
  if (uefi == NULL || uefi->Service == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  Print(L"PBNS RECOVERY ROLLBACK ADVANCE BEGIN current=%Lu target=%Lu\r\n",
        CurrentVersion, TargetVersion);
  const pbns_status status = PbnsRecoveryServiceAdvanceVersion(
      uefi->Service, CurrentVersion, TargetVersion, Authorization);
  if (status == PBNS_OK) {
    Print(L"PBNS RECOVERY ROLLBACK ADVANCE PASS\r\n");
  }
  return status;
}

static pbns_status StartImage(void *Context, void *ImageHandle) {
  (void)Context;
  if (ImageHandle == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  Print(L"PBNS RECOVERY STARTIMAGE BEGIN\r\n");
  return StatusToPbns(gBS->StartImage((EFI_HANDLE)ImageHandle, NULL, NULL));
}

static pbns_status UnloadImage(void *Context, void *ImageHandle) {
  (void)Context;
  if (ImageHandle == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  Print(L"PBNS RECOVERY UNLOAD BEGIN\r\n");
  const EFI_STATUS status = gBS->UnloadImage((EFI_HANDLE)ImageHandle);
  if (!EFI_ERROR(status)) {
    Print(L"PBNS RECOVERY UNLOAD PASS\r\n");
  }
  return StatusToPbns(status);
}

static pbns_status FreePages(void *Context, void *Image, uint64_t Size) {
  (void)Context;
  if (Image == NULL || Size == 0U || Size > (uint64_t)MAX_UINTN) {
    return PBNS_ERR_ARGUMENT;
  }
  Print(L"PBNS RECOVERY FREE BEGIN size=%Lu\r\n", Size);
  const EFI_STATUS status = gBS->FreePages((EFI_PHYSICAL_ADDRESS)(UINTN)Image,
                                           EFI_SIZE_TO_PAGES((UINTN)Size));
  if (!EFI_ERROR(status)) {
    Print(L"PBNS RECOVERY FREE PASS\r\n");
  }
  return StatusToPbns(status);
}

static void StateChanged(void *Context, PBNS_RECOVERY_CLIENT_STATE State) {
  (void)Context;
  Print(L"PBNS RECOVERY STATE %u\r\n", (UINT32)State);
}

static void Failed(void *Context, PBNS_RECOVERY_CLIENT_STATE Stage,
                   pbns_status Status) {
  (void)Context;
  Print(L"PBNS RECOVERY FAILED stage=%u status=%d\r\n", (UINT32)Stage,
        (INT32)Status);
}

EFI_STATUS EFIAPI UefiMain(EFI_HANDLE ImageHandle,
                           EFI_SYSTEM_TABLE *SystemTable) {
  DisplayLauncherFailure();
  PBNS_RECOVERY_UEFI_CONTEXT context = {
      .ImageHandle = ImageHandle,
      .SystemTable = SystemTable,
  };
  const PBNS_RECOVERY_CLIENT_OPS ops = {
      .confirm = Confirm,
      .platform_ready = PlatformReady,
      .trusted_time = TrustedTime,
      .verified_manifest = VerifiedManifest,
      .allocate_pages = AllocatePages,
      .stream_image = StreamImage,
      .verify_digest = VerifyDigest,
      .read_version = ReadVersion,
      .load_image = LoadImage,
      .advance_version = AdvanceVersion,
      .start_image = StartImage,
      .unload_image = UnloadImage,
      .free_pages = FreePages,
      .state_changed = StateChanged,
      .failed = Failed,
  };
  PBNS_RECOVERY_CLIENT_RESULT result = {0};
  const pbns_status status = PbnsRecoveryClientRun(&ops, &context, &result);
  PbnsRecoveryServiceDestroy(context.Service);
  context = (PBNS_RECOVERY_UEFI_CONTEXT){0};
  result = (PBNS_RECOVERY_CLIENT_RESULT){0};
  (void)status;
  return EFI_ABORTED;
}
