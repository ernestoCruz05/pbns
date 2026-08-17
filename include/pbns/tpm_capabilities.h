#ifndef PBNS_TPM_CAPABILITIES_H
#define PBNS_TPM_CAPABILITIES_H

#include <stdbool.h>
#include <stdint.h>

typedef struct pbns_tpm_capabilities {
  uint32_t manufacturer;
  uint32_t firmware1;
  uint32_t firmware2;
  bool tpm2;
  bool ecc_p256;
  bool sha256;
  bool sha256_pcr_bank;
  bool sign;
  bool certify;
  bool activate_credential;
  bool get_random;
} pbns_tpm_capabilities;

#endif
