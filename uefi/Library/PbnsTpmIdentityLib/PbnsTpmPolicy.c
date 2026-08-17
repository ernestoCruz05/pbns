#include "PbnsTpmPolicy.h"

#include "pbns/tpm_profile.h"

pbns_status PbnsTpmEndorsementTemplate(TPM2B_PUBLIC *Output) {
  return pbns_tpm_ek_template(Output);
}

pbns_status PbnsTpmStorageTemplate(TPM2B_PUBLIC *Output) {
  return pbns_tpm_srk_template(Output);
}
