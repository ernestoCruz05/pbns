#include "PbnsTpmEkCertificateInternal.h"

#include <Library/Tpm2CommandLib.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define TEST_CERTIFICATE_SIZE 2500U
#define TEST_NV_PUBLIC_WIRE_SIZE 14U

typedef enum fake_mode {
  FAKE_VALID = 0,
  FAKE_MISSING,
  FAKE_WRONG_ATTRIBUTES,
  FAKE_OVERSIZE,
  FAKE_SHORT_CHUNK,
  FAKE_ZERO_CHUNK,
  FAKE_CHANGED_PUBLIC,
} fake_mode;

typedef struct fake_tpm {
  fake_mode mode;
  size_t public_calls;
  size_t read_calls;
  size_t next_offset;
  uint8_t certificate[TEST_CERTIFICATE_SIZE];
} fake_tpm;

static TPMA_NV expected_attributes(void) {
  return (TPMA_NV){
      .TPMA_NV_PPWRITE = 1U,
      .TPMA_NV_WRITEDEFINE = 1U,
      .TPMA_NV_PPREAD = 1U,
      .TPMA_NV_OWNERREAD = 1U,
      .TPMA_NV_AUTHREAD = 1U,
      .TPMA_NV_NO_DA = 1U,
      .TPMA_NV_WRITTEN = 1U,
      .TPMA_NV_PLATFORMCREATE = 1U,
  };
}

static void fill_public(TPM2B_NV_PUBLIC *value, UINT16 data_size) {
  memset(value, 0, sizeof(*value));
  value->size = TEST_NV_PUBLIC_WIRE_SIZE;
  value->nvPublic.nvIndex = PBNS_TPM_EK_CERTIFICATE_NV_INDEX;
  value->nvPublic.nameAlg = TPM_ALG_SHA256;
  value->nvPublic.attributes = expected_attributes();
  value->nvPublic.authPolicy.size = 0U;
  value->nvPublic.dataSize = data_size;
}

static EFI_STATUS fake_read_public(void *context, TPMI_RH_NV_INDEX index,
                                   TPM2B_NV_PUBLIC *public_value,
                                   TPM2B_NAME *name) {
  fake_tpm *fake = context;
  assert(fake != NULL && index == PBNS_TPM_EK_CERTIFICATE_NV_INDEX);
  assert(public_value != NULL && name != NULL);
  ++fake->public_calls;
  if (fake->mode == FAKE_MISSING) {
    return EFI_NOT_FOUND;
  }
  UINT16 data_size = TEST_CERTIFICATE_SIZE;
  if (fake->mode == FAKE_OVERSIZE) {
    data_size = (UINT16)(PBNS_TPM_EK_CERTIFICATE_MAX_SIZE + 1U);
  }
  if (fake->mode == FAKE_CHANGED_PUBLIC && fake->public_calls == 2U) {
    --data_size;
  }
  fill_public(public_value, data_size);
  if (fake->mode == FAKE_WRONG_ATTRIBUTES) {
    public_value->nvPublic.attributes.TPMA_NV_OWNERWRITE = 1U;
  }
  memset(name, 0, sizeof(*name));
  name->size = 34U;
  return EFI_SUCCESS;
}

static EFI_STATUS fake_read(void *context, TPMI_RH_NV_AUTH auth_handle,
                            TPMI_RH_NV_INDEX index,
                            TPMS_AUTH_COMMAND *auth_session, UINT16 size,
                            UINT16 offset, TPM2B_MAX_BUFFER *output) {
  fake_tpm *fake = context;
  assert(fake != NULL && auth_handle == TPM_RH_OWNER);
  assert(index == PBNS_TPM_EK_CERTIFICATE_NV_INDEX);
  assert(auth_session != NULL && auth_session->sessionHandle == TPM_RS_PW);
  assert(size > 0U && size <= MAX_DIGEST_BUFFER);
  assert((size_t)offset == fake->next_offset && output != NULL);
  ++fake->read_calls;
  output->size = size;
  if (fake->mode == FAKE_SHORT_CHUNK) {
    --output->size;
  } else if (fake->mode == FAKE_ZERO_CHUNK) {
    output->size = 0U;
  }
  memcpy(output->buffer, fake->certificate + offset, output->size);
  fake->next_offset += output->size;
  return EFI_SUCCESS;
}

EFI_STATUS Tpm2NvReadPublic(TPMI_RH_NV_INDEX index,
                            TPM2B_NV_PUBLIC *public_value, TPM2B_NAME *name) {
  (void)index;
  (void)public_value;
  (void)name;
  return EFI_DEVICE_ERROR;
}

EFI_STATUS Tpm2NvRead(TPMI_RH_NV_AUTH auth_handle, TPMI_RH_NV_INDEX index,
                      TPMS_AUTH_COMMAND *auth_session, UINT16 size,
                      UINT16 offset, TPM2B_MAX_BUFFER *output) {
  (void)auth_handle;
  (void)index;
  (void)auth_session;
  (void)size;
  (void)offset;
  (void)output;
  return EFI_DEVICE_ERROR;
}

static PBNS_TPM_EK_CERTIFICATE_COMMANDS commands(fake_tpm *fake) {
  return (PBNS_TPM_EK_CERTIFICATE_COMMANDS){
      .Context = fake,
      .NvReadPublic = fake_read_public,
      .NvRead = fake_read,
  };
}

static bool all_zero(const uint8_t *value, size_t length) {
  for (size_t index = 0U; index < length; ++index) {
    if (value[index] != 0U) {
      return false;
    }
  }
  return true;
}

static fake_tpm make_fake(fake_mode mode) {
  fake_tpm fake = {.mode = mode};
  for (size_t index = 0U; index < sizeof(fake.certificate); ++index) {
    fake.certificate[index] = (uint8_t)(index % 251U);
  }
  return fake;
}

static void test_missing_index_is_bounded_unverified_evidence(void) {
  fake_tpm fake = make_fake(FAKE_MISSING);
  PBNS_TPM_EK_CERTIFICATE_COMMANDS ops = commands(&fake);
  uint8_t output[PBNS_TPM_EK_CERTIFICATE_MAX_SIZE];
  memset(output, 0xa5, sizeof(output));
  size_t written = SIZE_MAX;
  assert(PbnsTpmEkCertificateReadWithCommands(
             &ops, (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
         PBNS_OK);
  assert(written == 0U && fake.public_calls == 1U && fake.read_calls == 0U);
  assert(all_zero(output, sizeof(output)));
}

static void test_valid_certificate_is_read_in_exact_chunks(void) {
  fake_tpm fake = make_fake(FAKE_VALID);
  PBNS_TPM_EK_CERTIFICATE_COMMANDS ops = commands(&fake);
  uint8_t output[PBNS_TPM_EK_CERTIFICATE_MAX_SIZE] = {0};
  size_t written = 0U;
  assert(PbnsTpmEkCertificateReadWithCommands(
             &ops, (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
         PBNS_OK);
  assert(written == TEST_CERTIFICATE_SIZE && fake.public_calls == 2U);
  assert(fake.read_calls == 3U && fake.next_offset == TEST_CERTIFICATE_SIZE);
  assert(memcmp(output, fake.certificate, written) == 0);
  assert(all_zero(output + written, sizeof(output) - written));
}

static void test_profile_and_complete_read_fail_closed(void) {
  for (fake_mode mode = FAKE_WRONG_ATTRIBUTES; mode <= FAKE_CHANGED_PUBLIC;
       mode = (fake_mode)(mode + 1)) {
    fake_tpm fake = make_fake(mode);
    PBNS_TPM_EK_CERTIFICATE_COMMANDS ops = commands(&fake);
    uint8_t output[PBNS_TPM_EK_CERTIFICATE_MAX_SIZE];
    memset(output, 0xa5, sizeof(output));
    size_t written = SIZE_MAX;
    const pbns_status status = PbnsTpmEkCertificateReadWithCommands(
        &ops, (pbns_buffer){output, 0U, sizeof(output)}, &written);
    const pbns_status expected =
        mode == FAKE_SHORT_CHUNK || mode == FAKE_ZERO_CHUNK
            ? PBNS_ERR_IO
            : PBNS_ERR_AUTHENTICATION;
    assert(status == expected);
    assert(written == 0U && all_zero(output, sizeof(output)));
  }
}

static void test_invalid_commands_clear_valid_outputs(void) {
  fake_tpm fake = make_fake(FAKE_VALID);
  PBNS_TPM_EK_CERTIFICATE_COMMANDS ops = commands(&fake);
  ops.NvRead = NULL;
  uint8_t output[64];
  memset(output, 0xa5, sizeof(output));
  size_t written = SIZE_MAX;
  assert(PbnsTpmEkCertificateReadWithCommands(
             &ops, (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
         PBNS_ERR_ARGUMENT);
  assert(written == 0U && all_zero(output, sizeof(output)));
}

static void test_small_arena_fails_before_nv_data_read(void) {
  fake_tpm fake = make_fake(FAKE_VALID);
  PBNS_TPM_EK_CERTIFICATE_COMMANDS ops = commands(&fake);
  uint8_t output[TEST_CERTIFICATE_SIZE - 1U];
  memset(output, 0xa5, sizeof(output));
  size_t written = SIZE_MAX;
  assert(PbnsTpmEkCertificateReadWithCommands(
             &ops, (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
         PBNS_ERR_LIMIT);
  assert(fake.public_calls == 1U && fake.read_calls == 0U);
  assert(written == 0U && all_zero(output, sizeof(output)));
}

int main(void) {
  test_missing_index_is_bounded_unverified_evidence();
  test_valid_certificate_is_read_in_exact_chunks();
  test_profile_and_complete_read_fail_closed();
  test_invalid_commands_clear_valid_outputs();
  test_small_arena_fails_before_nv_data_read();
  return 0;
}
