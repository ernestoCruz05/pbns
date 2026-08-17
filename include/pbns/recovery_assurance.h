#ifndef PBNS_RECOVERY_ASSURANCE_H
#define PBNS_RECOVERY_ASSURANCE_H

#include "pbns/status.h"

typedef enum pbns_recovery_assurance_mode {
  PBNS_RECOVERY_ASSURANCE_T = 1,
  PBNS_RECOVERY_ASSURANCE_S = 2
} pbns_recovery_assurance_mode;

typedef pbns_status (*pbns_recovery_assurance_open_fn)(void *context);

typedef struct pbns_recovery_assurance_ops {
  pbns_recovery_assurance_open_fn open_tpm_pair;
  pbns_recovery_assurance_open_fn open_software_nvram_pair;
} pbns_recovery_assurance_ops;

pbns_status pbns_recovery_assurance_select(
    pbns_recovery_assurance_mode mode, const pbns_recovery_assurance_ops *ops,
    void *context);

#endif
