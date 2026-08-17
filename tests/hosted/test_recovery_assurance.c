#include <assert.h>
#include <stddef.h>

#include "pbns/recovery_assurance.h"

typedef struct calls {
  int tpm;
  int software;
  pbns_status tpm_result;
  pbns_status software_result;
} calls;

static pbns_status open_tpm(void *context) {
  calls *value = context;
  ++value->tpm;
  return value->tpm_result;
}

static pbns_status open_software(void *context) {
  calls *value = context;
  ++value->software;
  return value->software_result;
}

static void test_tpm_only(void) {
  calls value = {.tpm_result = PBNS_OK, .software_result = PBNS_ERR_IO};
  const pbns_recovery_assurance_ops ops = {
      .open_tpm_pair = open_tpm,
      .open_software_nvram_pair = open_software,
  };
  assert(pbns_recovery_assurance_select(PBNS_RECOVERY_ASSURANCE_T, &ops,
                                        &value) == PBNS_OK);
  assert(value.tpm == 1 && value.software == 0);
  value.tpm = 0;
  value.software = 0;
  value.tpm_result = PBNS_ERR_CRYPTO;
  assert(pbns_recovery_assurance_select(PBNS_RECOVERY_ASSURANCE_T, &ops,
                                        &value) == PBNS_ERR_CRYPTO);
  assert(value.tpm == 1 && value.software == 0);
}

static void test_software_only(void) {
  calls value = {.tpm_result = PBNS_ERR_IO, .software_result = PBNS_OK};
  const pbns_recovery_assurance_ops ops = {
      .open_tpm_pair = open_tpm,
      .open_software_nvram_pair = open_software,
  };
  assert(pbns_recovery_assurance_select(PBNS_RECOVERY_ASSURANCE_S, &ops,
                                        &value) == PBNS_OK);
  assert(value.tpm == 0 && value.software == 1);
  value.tpm = 0;
  value.software = 0;
  value.software_result = PBNS_ERR_IO;
  assert(pbns_recovery_assurance_select(PBNS_RECOVERY_ASSURANCE_S, &ops,
                                        &value) == PBNS_ERR_IO);
  assert(value.tpm == 0 && value.software == 1);
}

static void test_invalid_never_calls(void) {
  calls value = {.tpm_result = PBNS_OK, .software_result = PBNS_OK};
  const pbns_recovery_assurance_ops complete = {
      .open_tpm_pair = open_tpm,
      .open_software_nvram_pair = open_software,
  };
  const pbns_recovery_assurance_ops missing_tpm = {
      .open_tpm_pair = NULL,
      .open_software_nvram_pair = open_software,
  };
  const pbns_recovery_assurance_ops missing_software = {
      .open_tpm_pair = open_tpm,
      .open_software_nvram_pair = NULL,
  };
  assert(pbns_recovery_assurance_select((pbns_recovery_assurance_mode)0,
                                        &complete, &value) == PBNS_ERR_ARGUMENT);
  assert(pbns_recovery_assurance_select(PBNS_RECOVERY_ASSURANCE_T, NULL,
                                        &value) == PBNS_ERR_ARGUMENT);
  assert(pbns_recovery_assurance_select(PBNS_RECOVERY_ASSURANCE_T,
                                        &missing_tpm, &value) == PBNS_ERR_ARGUMENT);
  assert(pbns_recovery_assurance_select(PBNS_RECOVERY_ASSURANCE_S,
                                        &missing_software, &value) == PBNS_ERR_ARGUMENT);
  assert(value.tpm == 0 && value.software == 0);
}

int main(void) {
  test_tpm_only();
  test_software_only();
  test_invalid_never_calls();
  return 0;
}
