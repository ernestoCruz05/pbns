#include <Uefi.h>
#include <Guid/SmBios.h>
#include <Library/BaseMemoryLib.h>
#include "PbnsInventoryLib.h"
#include <Protocol/BlockIo.h>
#include <Protocol/PciIo.h>
#include <Protocol/Tcg2Protocol.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <openssl/evp.h>

#define ARRAY_COUNT(values) (sizeof(values) / sizeof((values)[0]))
#define SCRATCH_SIZE 128U

typedef struct variable_fixture {
  EFI_STATUS setup_status;
  EFI_STATUS db_query_status;
  EFI_STATUS db_read_status;
  EFI_STATUS dbx_query_status;
  EFI_STATUS dbx_read_status;
  UINT8 secure_boot;
  UINT8 setup_mode;
  UINTN secure_boot_size;
  UINTN setup_mode_size;
  const UINT8 *db;
  UINTN db_size;
  const UINT8 *dbx;
  UINTN dbx_size;
  UINTN calls[8];
  size_t call_count;
} variable_fixture;

static variable_fixture *mVariables;
static EFI_PCI_IO_PROTOCOL *mPciProtocols[4];
static size_t mPciCount;
static EFI_BLOCK_IO_PROTOCOL *mBlockProtocols[4];
static size_t mBlockCount;
static EFI_TCG2_PROTOCOL *mTcg;
static EFI_STATUS mTcgLocateStatus;

static bool name_equal(const CHAR16 *name, const CHAR16 *expected) {
  size_t index = 0U;
  while (name[index] == expected[index] && name[index] != 0U) {
    ++index;
  }
  return name[index] == expected[index];
}

static EFI_STATUS EFIAPI fake_get_variable(CHAR16 *Name, EFI_GUID *Guid,
                                            UINT32 *Attributes, UINTN *Size,
                                            VOID *Data) {
  (void)Guid;
  assert(mVariables != NULL && Size != NULL && Attributes != NULL);
  UINTN code = 0U;
  EFI_STATUS status = EFI_SUCCESS;
  const UINT8 *source = NULL;
  UINTN source_size = 0U;
  if (name_equal(Name, L"SecureBoot")) {
    code = 1U;
    source = &mVariables->secure_boot;
    source_size = mVariables->secure_boot_size;
  } else if (name_equal(Name, L"SetupMode")) {
    code = 2U;
    status = mVariables->setup_status;
    source = &mVariables->setup_mode;
    source_size = mVariables->setup_mode_size;
  } else if (name_equal(Name, L"db")) {
    code = Data == NULL ? 3U : 4U;
    status = Data == NULL ? mVariables->db_query_status
                          : mVariables->db_read_status;
    source = mVariables->db;
    source_size = mVariables->db_size;
  } else if (name_equal(Name, L"dbx")) {
    code = Data == NULL ? 5U : 6U;
    status = Data == NULL ? mVariables->dbx_query_status
                          : mVariables->dbx_read_status;
    source = mVariables->dbx;
    source_size = mVariables->dbx_size;
  } else {
    return EFI_NOT_FOUND;
  }
  assert(mVariables->call_count < ARRAY_COUNT(mVariables->calls));
  mVariables->calls[mVariables->call_count++] = code;
  *Attributes = UINT32_C(0x27);
  *Size = source_size;
  if (EFI_ERROR(status)) {
    return status;
  }
  if (Data != NULL && source_size != 0U) {
    memcpy(Data, source, source_size);
  }
  return EFI_SUCCESS;
}

static variable_fixture valid_variables(void) {
  static const UINT8 db[] = "database";
  static const UINT8 dbx[] = "revocations";
  return (variable_fixture){
      .setup_status = EFI_SUCCESS,
      .db_query_status = EFI_BUFFER_TOO_SMALL,
      .db_read_status = EFI_SUCCESS,
      .dbx_query_status = EFI_BUFFER_TOO_SMALL,
      .dbx_read_status = EFI_SUCCESS,
      .secure_boot = 1U,
      .setup_mode = 0U,
      .secure_boot_size = 1U,
      .setup_mode_size = 1U,
      .db = db,
      .db_size = sizeof(db) - 1U,
      .dbx = dbx,
      .dbx_size = sizeof(dbx) - 1U,
  };
}

static pbns_status openssl_hash_parts(void *context, const pbns_view *parts,
                                      size_t part_count, uint8_t digest[32]) {
  (void)context;
  EVP_MD_CTX *hash = EVP_MD_CTX_new();
  if (hash == NULL || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) {
    EVP_MD_CTX_free(hash);
    return PBNS_ERR_CRYPTO;
  }
  for (size_t index = 0U; index < part_count; ++index) {
    if (EVP_DigestUpdate(hash, parts[index].ptr, parts[index].len) != 1) {
      EVP_MD_CTX_free(hash);
      return PBNS_ERR_CRYPTO;
    }
  }
  unsigned int length = 0U;
  const int status = EVP_DigestFinal_ex(hash, digest, &length);
  EVP_MD_CTX_free(hash);
  return status == 1 && length == 32U ? PBNS_OK : PBNS_ERR_CRYPTO;
}

static void assert_zero(const UINT8 *bytes, size_t size) {
  for (size_t index = 0U; index < size; ++index) {
    assert(bytes[index] == 0U);
  }
}

static void test_actual_secure_boot_wrapper(void) {
  EFI_RUNTIME_SERVICES runtime = {.GetVariable = fake_get_variable};
  UINT8 scratch[SCRATCH_SIZE] = {0};
  pbns_inventory_inputs inputs = {0};
  variable_fixture fixture = valid_variables();
  mVariables = &fixture;
  assert(PbnsInventorySecureBoot(
             &runtime, (pbns_buffer){scratch, 0U, sizeof(scratch)}, &inputs) ==
         EFI_SUCCESS);
  static const UINTN expected_calls[] = {1U, 2U, 3U, 4U, 5U, 6U};
  assert(fixture.call_count == ARRAY_COUNT(expected_calls));
  assert(memcmp(fixture.calls, expected_calls, sizeof(expected_calls)) == 0);
  assert(inputs.secure_boot.status == PBNS_INVENTORY_OK);
  assert(inputs.secure_boot.secure_boot && !inputs.secure_boot.setup_mode);
  assert_zero(scratch, sizeof(scratch));
  UINT8 expected_db[32] = {0};
  UINT8 expected_dbx[32] = {0};
  assert(pbns_inventory_hash_variable(
             openssl_hash_parts, NULL, true, UINT32_C(0x27),
             (pbns_view){fixture.db, fixture.db_size}, expected_db) == PBNS_OK);
  assert(pbns_inventory_hash_variable(
             openssl_hash_parts, NULL, true, UINT32_C(0x27),
             (pbns_view){fixture.dbx, fixture.dbx_size}, expected_dbx) ==
         PBNS_OK);
  assert(memcmp(inputs.secure_boot.db_digest, expected_db, 32U) == 0);
  assert(memcmp(inputs.secure_boot.dbx_digest, expected_dbx, 32U) == 0);

  fixture = valid_variables();
  fixture.db_query_status = EFI_NOT_FOUND;
  fixture.dbx_query_status = EFI_NOT_FOUND;
  mVariables = &fixture;
  inputs = (pbns_inventory_inputs){0};
  assert(PbnsInventorySecureBoot(
             &runtime, (pbns_buffer){scratch, 0U, sizeof(scratch)}, &inputs) ==
         EFI_SUCCESS);
  static const UINTN absent_calls[] = {1U, 2U, 3U, 5U};
  assert(fixture.call_count == ARRAY_COUNT(absent_calls));
  assert(memcmp(fixture.calls, absent_calls, sizeof(absent_calls)) == 0);
  assert(inputs.secure_boot.status == PBNS_INVENTORY_OK);
  UINT8 expected_absent[32] = {0};
  assert(pbns_inventory_hash_variable(
             openssl_hash_parts, NULL, false, 0U, (pbns_view){NULL, 0U},
             expected_absent) == PBNS_OK);
  assert(memcmp(inputs.secure_boot.db_digest, expected_absent, 32U) == 0);
  assert(memcmp(inputs.secure_boot.dbx_digest, expected_absent, 32U) == 0);

  static const struct {
    EFI_STATUS status;
    pbns_inventory_capability capability;
  } setup_cases[] = {
      {EFI_NOT_FOUND, PBNS_INVENTORY_ABSENT},
      {EFI_UNSUPPORTED, PBNS_INVENTORY_UNSUPPORTED},
      {EFI_DEVICE_ERROR, PBNS_INVENTORY_ERROR},
  };
  for (size_t index = 0U; index < ARRAY_COUNT(setup_cases); ++index) {
    fixture = valid_variables();
    fixture.setup_status = setup_cases[index].status;
    mVariables = &fixture;
    inputs = (pbns_inventory_inputs){0};
    assert(PbnsInventorySecureBoot(
               &runtime, (pbns_buffer){scratch, 0U, sizeof(scratch)},
               &inputs) == setup_cases[index].status);
    assert(fixture.call_count == 2U && fixture.calls[0] == 1U &&
           fixture.calls[1] == 2U);
    assert(inputs.secure_boot.status == setup_cases[index].capability);
  }

  fixture = valid_variables();
  fixture.secure_boot = 2U;
  mVariables = &fixture;
  inputs = (pbns_inventory_inputs){0};
  assert(PbnsInventorySecureBoot(
             &runtime, (pbns_buffer){scratch, 0U, sizeof(scratch)}, &inputs) ==
         EFI_COMPROMISED_DATA);
  assert(inputs.secure_boot.status == PBNS_INVENTORY_MALFORMED);

  fixture = valid_variables();
  fixture.dbx_read_status = EFI_DEVICE_ERROR;
  mVariables = &fixture;
  memset(scratch, 0xa5, sizeof(scratch));
  memset(&inputs, 0xa5, sizeof(inputs));
  assert(PbnsInventorySecureBoot(
             &runtime, (pbns_buffer){scratch, 0U, sizeof(scratch)}, &inputs) ==
         EFI_DEVICE_ERROR);
  assert(fixture.call_count == 6U);
  assert(inputs.secure_boot.status == PBNS_INVENTORY_ERROR);
  assert_zero(scratch, sizeof(scratch));
  assert_zero(inputs.secure_boot.db_digest, 32U);
  assert_zero(inputs.secure_boot.dbx_digest, 32U);

  fixture = valid_variables();
  fixture.db_size = PBNS_INVENTORY_VARIABLE_MAX_SIZE + 1U;
  mVariables = &fixture;
  inputs = (pbns_inventory_inputs){0};
  assert(PbnsInventorySecureBoot(
             &runtime, (pbns_buffer){scratch, 0U, sizeof(scratch)}, &inputs) ==
         EFI_BAD_BUFFER_SIZE);
  assert(inputs.secure_boot.status == PBNS_INVENTORY_LIMIT);
  assert(fixture.call_count == 3U);
}

static void checksum(UINT8 *bytes, size_t start, size_t length,
                     size_t checksum_offset) {
  bytes[checksum_offset] = 0U;
  UINT8 sum = 0U;
  for (size_t index = start; index < start + length; ++index) {
    sum = (UINT8)(sum + bytes[index]);
  }
  bytes[checksum_offset] = (UINT8)(0U - sum);
}

static void store_u16(UINT8 *output, UINT16 value) {
  output[0] = (UINT8)value;
  output[1] = (UINT8)(value >> 8U);
}

static void store_u32(UINT8 *output, UINT32 value) {
  for (size_t index = 0U; index < 4U; ++index) {
    output[index] = (UINT8)(value >> (index * 8U));
  }
}

static void store_u64(UINT8 *output, UINT64 value) {
  for (size_t index = 0U; index < 8U; ++index) {
    output[index] = (UINT8)(value >> (index * 8U));
  }
}

static void make_smbios2(UINT8 *entry, UINT8 length, UINT32 address,
                         UINT16 table_length, UINT16 record_count) {
  memset(entry, 0, length);
  const UINT8 anchor[] = {'_', 'S', 'M', '_'};
  const UINT8 intermediate[] = {'_', 'D', 'M', 'I', '_'};
  memcpy(entry, anchor, sizeof(anchor));
  entry[5U] = length;
  entry[6U] = 2U;
  entry[7U] = 8U;
  memcpy(entry + 16U, intermediate, sizeof(intermediate));
  store_u16(entry + 22U, table_length);
  store_u32(entry + 24U, address);
  store_u16(entry + 28U, record_count);
  checksum(entry, 16U, (size_t)length - 16U, 21U);
  checksum(entry, 0U, length, 4U);
}

static void make_smbios3(UINT8 entry[24], uintptr_t address, UINT32 length) {
  const UINT8 anchor[] = {'_', 'S', 'M', '3', '_'};
  memset(entry, 0, 24U);
  memcpy(entry, anchor, sizeof(anchor));
  entry[6U] = 24U;
  entry[7U] = 3U;
  store_u32(entry + 12U, length);
  store_u64(entry + 16U, address);
  checksum(entry, 0U, 24U, 5U);
}

static void test_actual_smbios_wrapper(void) {
  UINT8 *table = mmap(NULL, 4096U, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
  assert(table != MAP_FAILED && (uintptr_t)table <= UINT32_MAX);
  const UINT8 terminal[] = {127U, 4U, 0U, 0U, 0U, 0U};
  memcpy(table, terminal, sizeof(terminal));

  struct legacy_entry {
    UINT8 declared[30];
    UINT8 canary;
  } legacy = {{0}, 0x5aU};
  make_smbios2(legacy.declared, 0x1eU, (UINT32)(uintptr_t)table,
               sizeof(terminal), 1U);
  EFI_CONFIGURATION_TABLE configuration = {
      .VendorGuid = gEfiSmbiosTableGuid,
      .VendorTable = legacy.declared,
  };
  EFI_SYSTEM_TABLE system = {
      .NumberOfTableEntries = 1U,
      .ConfigurationTable = &configuration,
  };
  pbns_inventory_inputs inputs = {0};
  assert(PbnsInventorySmbios(&system, &inputs) == EFI_SUCCESS);
  assert(inputs.smbios_status == PBNS_INVENTORY_OK && legacy.canary == 0x5aU);

  UINT8 entry2[31] = {0};
  make_smbios2(entry2, 0x1fU, (UINT32)(uintptr_t)table, sizeof(terminal), 1U);
  configuration.VendorTable = entry2;
  inputs = (pbns_inventory_inputs){0};
  assert(PbnsInventorySmbios(&system, &inputs) == EFI_SUCCESS);

  UINT8 entry3[24] = {0};
  make_smbios3(entry3, (uintptr_t)table, sizeof(terminal));
  configuration.VendorGuid = gEfiSmbios3TableGuid;
  configuration.VendorTable = entry3;
  inputs = (pbns_inventory_inputs){0};
  assert(PbnsInventorySmbios(&system, &inputs) == EFI_SUCCESS);

  entry3[7U] = 2U;
  checksum(entry3, 0U, sizeof(entry3), 5U);
  inputs = (pbns_inventory_inputs){0};
  assert(PbnsInventorySmbios(&system, &inputs) == EFI_COMPROMISED_DATA);
  make_smbios3(entry3, (uintptr_t)table, sizeof(terminal));
  entry3[0U] ^= 1U;
  inputs = (pbns_inventory_inputs){0};
  assert(PbnsInventorySmbios(&system, &inputs) == EFI_COMPROMISED_DATA);
  make_smbios3(entry3, UINT64_MAX - 2U, sizeof(terminal));
  inputs = (pbns_inventory_inputs){0};
  assert(PbnsInventorySmbios(&system, &inputs) == EFI_COMPROMISED_DATA);
  make_smbios3(entry3, (uintptr_t)table,
               (UINT32)(PBNS_INVENTORY_SMBIOS_TABLE_MAX_SIZE + 1U));
  inputs = (pbns_inventory_inputs){0};
  assert(PbnsInventorySmbios(&system, &inputs) == EFI_BAD_BUFFER_SIZE);
  make_smbios3(entry3, (uintptr_t)table, sizeof(terminal) - 1U);
  inputs = (pbns_inventory_inputs){0};
  assert(PbnsInventorySmbios(&system, &inputs) == EFI_COMPROMISED_DATA);

  configuration.VendorGuid = gEfiSmbiosTableGuid;
  make_smbios2(entry2, 0x1fU, (UINT32)(uintptr_t)table, sizeof(terminal), 2U);
  configuration.VendorTable = entry2;
  inputs = (pbns_inventory_inputs){0};
  assert(PbnsInventorySmbios(&system, &inputs) == EFI_COMPROMISED_DATA);
  assert(munmap(table, 4096U) == 0);
}

typedef struct fake_pci {
  EFI_PCI_IO_PROTOCOL protocol;
  UINT8 configuration[64];
  UINTN segment;
  UINTN bus;
  UINTN device;
  UINTN function;
} fake_pci;

typedef struct fake_block {
  EFI_BLOCK_IO_PROTOCOL protocol;
  EFI_BLOCK_IO_MEDIA media;
  UINT8 prohibited[64];
} fake_block;

static EFI_STATUS EFIAPI pci_location(EFI_PCI_IO_PROTOCOL *This,
                                      UINTN *Segment, UINTN *Bus,
                                      UINTN *Device, UINTN *Function) {
  fake_pci *pci = (fake_pci *)This;
  *Segment = pci->segment;
  *Bus = pci->bus;
  *Device = pci->device;
  *Function = pci->function;
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI pci_read(EFI_PCI_IO_PROTOCOL *This,
                                  EFI_PCI_IO_PROTOCOL_WIDTH Width,
                                  UINT32 Offset, UINTN Count, VOID *Buffer) {
  fake_pci *pci = (fake_pci *)This;
  assert(Width == EfiPciIoWidthUint8 && Offset + Count <= sizeof(pci->configuration));
  memcpy(Buffer, pci->configuration + Offset, Count);
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI locate_handles(EFI_LOCATE_SEARCH_TYPE SearchType,
                                        EFI_GUID *Protocol, VOID *SearchKey,
                                        UINTN *Count, EFI_HANDLE **Handles) {
  (void)SearchType;
  (void)SearchKey;
  size_t count = 0U;
  VOID **items = NULL;
  if (CompareGuid(Protocol, &gEfiPciIoProtocolGuid)) {
    count = mPciCount;
    items = (VOID **)mPciProtocols;
  } else if (CompareGuid(Protocol, &gEfiBlockIoProtocolGuid)) {
    count = mBlockCount;
    items = (VOID **)mBlockProtocols;
  } else {
    return EFI_NOT_FOUND;
  }
  EFI_HANDLE *result = (EFI_HANDLE *)calloc(count, sizeof(*result));
  assert(result != NULL);
  for (size_t index = 0U; index < count; ++index) {
    result[index] = items[index];
  }
  *Count = count;
  *Handles = result;
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI handle_protocol(EFI_HANDLE Handle, EFI_GUID *Protocol,
                                         VOID **Interface) {
  (void)Protocol;
  *Interface = Handle;
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI free_pool(VOID *Buffer) {
  free(Buffer);
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI locate_protocol(EFI_GUID *Protocol,
                                         VOID *Registration,
                                         VOID **Interface) {
  (void)Registration;
  if (!CompareGuid(Protocol, &gEfiTcg2ProtocolGuid)) {
    return EFI_NOT_FOUND;
  }
  if (EFI_ERROR(mTcgLocateStatus)) {
    return mTcgLocateStatus;
  }
  *Interface = mTcg;
  return EFI_SUCCESS;
}

static EFI_TCG2_BOOT_SERVICE_CAPABILITY mCapability;
static EFI_STATUS mCapabilityStatus;

static EFI_STATUS EFIAPI tcg_capability(
    EFI_TCG2_PROTOCOL *This, EFI_TCG2_BOOT_SERVICE_CAPABILITY *Capability) {
  (void)This;
  if (EFI_ERROR(mCapabilityStatus)) {
    return mCapabilityStatus;
  }
  *Capability = mCapability;
  return EFI_SUCCESS;
}

static void test_actual_pci_storage_tpm_wrappers(void) {
  EFI_BOOT_SERVICES boot = {
      .LocateProtocol = locate_protocol,
      .LocateHandleBuffer = locate_handles,
      .HandleProtocol = handle_protocol,
      .FreePool = free_pool,
  };
  fake_pci pci = {0};
  pci.protocol.Pci.Read = pci_read;
  pci.protocol.GetLocation = pci_location;
  pci.bus = 1U;
  pci.device = 2U;
  pci.configuration[0U] = 0x34U;
  pci.configuration[1U] = 0x12U;
  pci.configuration[2U] = 0x78U;
  pci.configuration[3U] = 0x56U;
  pci.configuration[9U] = 1U;
  pci.configuration[10U] = 2U;
  pci.configuration[11U] = 3U;
  static const UINT8 mac[] = "MAC-SENTINEL";
  memcpy(pci.configuration + 24U, mac, sizeof(mac) - 1U);
  mPciProtocols[0U] = &pci.protocol;
  mPciCount = 1U;
  pbns_inventory_inputs inputs = {0};
  assert(PbnsInventoryPci(&boot, &inputs) == EFI_SUCCESS);
  assert(inputs.pci_status == PBNS_INVENTORY_OK);
  for (size_t offset = 0U; offset + sizeof(mac) - 1U <= sizeof(inputs.pci_digest);
       ++offset) {
    assert(memcmp(inputs.pci_digest + offset, mac, sizeof(mac) - 1U) != 0);
  }

  fake_block removable = {0};
  fake_block accepted = {0};
  removable.protocol.Media = &removable.media;
  removable.media.RemovableMedia = TRUE;
  removable.media.BlockSize = 512U;
  removable.media.LastBlock = 100U;
  accepted.protocol.Media = &accepted.media;
  accepted.media.BlockSize = 512U;
  accepted.media.LastBlock = 2047U;
  static const UINT8 prohibited[] = "PARTITION-SENTINEL PATH-SENTINEL";
  memcpy(removable.prohibited, prohibited, sizeof(prohibited));
  memcpy(accepted.prohibited, prohibited, sizeof(prohibited));
  mBlockProtocols[0U] = &removable.protocol;
  mBlockProtocols[1U] = &accepted.protocol;
  mBlockCount = 2U;
  inputs = (pbns_inventory_inputs){0};
  assert(PbnsInventoryStorage(&boot, &inputs) == EFI_SUCCESS);
  assert(inputs.storage_status == PBNS_INVENTORY_OK);
  assert(inputs.block_device_count == 1U &&
         inputs.storage_capacity_gib == 0U);

  EFI_TCG2_PROTOCOL tcg = {.GetCapability = tcg_capability};
  mTcg = &tcg;
  mTcgLocateStatus = EFI_SUCCESS;
  mCapabilityStatus = EFI_SUCCESS;
  mCapability = (EFI_TCG2_BOOT_SERVICE_CAPABILITY){
      .Size = sizeof(mCapability),
      .TPMPresentFlag = TRUE,
      .ManufacturerID = UINT32_C(0x49465800),
      .NumberOfPCRBanks = 2U,
      .ActivePcrBanks = 0x02U,
  };
  UINT32 banks[5] = {0};
  inputs = (pbns_inventory_inputs){0};
  PbnsInventoryCollectTpm(&boot, &inputs, banks);
  assert(inputs.tpm.status == PBNS_INVENTORY_OK &&
         inputs.tpm.manufacturer == UINT32_C(0x49465800) &&
         inputs.tpm.active_bank_count == 1U && banks[0U] == 0x000bU);
  mTcgLocateStatus = EFI_NOT_FOUND;
  inputs = (pbns_inventory_inputs){0};
  PbnsInventoryCollectTpm(&boot, &inputs, banks);
  assert(inputs.tpm.status == PBNS_INVENTORY_ABSENT);
  mTcgLocateStatus = EFI_UNSUPPORTED;
  inputs = (pbns_inventory_inputs){0};
  PbnsInventoryCollectTpm(&boot, &inputs, banks);
  assert(inputs.tpm.status == PBNS_INVENTORY_UNSUPPORTED);
  mTcgLocateStatus = EFI_SUCCESS;
  mCapabilityStatus = EFI_DEVICE_ERROR;
  inputs = (pbns_inventory_inputs){0};
  PbnsInventoryCollectTpm(&boot, &inputs, banks);
  assert(inputs.tpm.status == PBNS_INVENTORY_ERROR);

  assert(PbnsInventoryCapabilityFromEfiStatus(EFI_NOT_FOUND) ==
         PBNS_INVENTORY_ABSENT);
  assert(PbnsInventoryCapabilityFromEfiStatus(EFI_UNSUPPORTED) ==
         PBNS_INVENTORY_UNSUPPORTED);
  assert(PbnsInventoryCapabilityFromEfiStatus(EFI_DEVICE_ERROR) ==
         PBNS_INVENTORY_ERROR);
}

int main(void) {
  test_actual_secure_boot_wrapper();
  test_actual_smbios_wrapper();
  test_actual_pci_storage_tpm_wrappers();
  return EXIT_SUCCESS;
}
