#include "PbnsAntiRollbackLib.h"

#include <Library/BaseMemoryLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#define PBNS_ANTI_ROLLBACK_VARIABLE_ATTRIBUTES                                 \
  (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS)

static CHAR16 mVariableName0[] = L"PbnsRecoveryVersion0";
static CHAR16 mVariableName1[] = L"PbnsRecoveryVersion1";
static CHAR16 *mVariableNames[PBNS_ANTI_ROLLBACK_SLOT_COUNT] = {
    mVariableName0,
    mVariableName1,
};

static pbns_status read_slot(void *Context, size_t Slot,
                             uint8_t Record[PBNS_ANTI_ROLLBACK_RECORD_SIZE],
                             bool *Present) {
  (void)Context;
  if (Slot >= PBNS_ANTI_ROLLBACK_SLOT_COUNT || Record == NULL ||
      Present == NULL || gRT == NULL || gRT->GetVariable == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *Present = false;
  SetMem(Record, PBNS_ANTI_ROLLBACK_RECORD_SIZE, 0U);
  UINT32 Attributes = 0U;
  UINTN Size = PBNS_ANTI_ROLLBACK_RECORD_SIZE;
  const EFI_STATUS Status =
      gRT->GetVariable(mVariableNames[Slot], &gPbnsAntiRollbackVariableGuid,
                       &Attributes, &Size, Record);
  if (Status == EFI_NOT_FOUND) {
    return PBNS_OK;
  }
  if (EFI_ERROR(Status)) {
    SetMem(Record, PBNS_ANTI_ROLLBACK_RECORD_SIZE, 0U);
    return PBNS_ERR_IO;
  }
  if (Attributes != PBNS_ANTI_ROLLBACK_VARIABLE_ATTRIBUTES ||
      Size != PBNS_ANTI_ROLLBACK_RECORD_SIZE) {
    SetMem(Record, PBNS_ANTI_ROLLBACK_RECORD_SIZE, 0U);
    return PBNS_ERR_FORMAT;
  }
  *Present = true;
  return PBNS_OK;
}

static pbns_status write_slot(void *Context, size_t Slot, pbns_view Record) {
  (void)Context;
  if (Slot >= PBNS_ANTI_ROLLBACK_SLOT_COUNT || Record.ptr == NULL ||
      Record.len != PBNS_ANTI_ROLLBACK_RECORD_SIZE || gRT == NULL ||
      gRT->SetVariable == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  uint8_t Data[PBNS_ANTI_ROLLBACK_RECORD_SIZE] = {0};
  CopyMem(Data, Record.ptr, Record.len);
  const EFI_STATUS Status = gRT->SetVariable(
      mVariableNames[Slot], &gPbnsAntiRollbackVariableGuid,
      PBNS_ANTI_ROLLBACK_VARIABLE_ATTRIBUTES, sizeof(Data), Data);
  ZeroMem(Data, sizeof(Data));
  return EFI_ERROR(Status) ? PBNS_ERR_IO : PBNS_OK;
}

EFI_STATUS EFIAPI
PbnsAntiRollbackNvramController(pbns_anti_rollback *Controller) {
  if (Controller == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  return pbns_anti_rollback_init_nvram(Controller, read_slot, write_slot,
                                       NULL) == PBNS_OK
             ? EFI_SUCCESS
             : EFI_DEVICE_ERROR;
}
