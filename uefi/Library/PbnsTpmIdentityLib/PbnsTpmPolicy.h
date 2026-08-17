#ifndef PBNS_TPM_POLICY_H
#define PBNS_TPM_POLICY_H

#include <tss2/tss2_tpm2_types.h>

#include "pbns/status.h"

pbns_status PbnsTpmEndorsementTemplate(TPM2B_PUBLIC *Output);
pbns_status PbnsTpmStorageTemplate(TPM2B_PUBLIC *Output);

#endif
