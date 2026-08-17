#include <stddef.h>

#include "pbns/recovery_assurance.h"

pbns_status pbns_recovery_assurance_select(
    pbns_recovery_assurance_mode mode, const pbns_recovery_assurance_ops *ops,
    void *context) {
  if (ops == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (mode == PBNS_RECOVERY_ASSURANCE_T) {
    return ops->open_tpm_pair == NULL ? PBNS_ERR_ARGUMENT
                                      : ops->open_tpm_pair(context);
  }
  if (mode == PBNS_RECOVERY_ASSURANCE_S) {
    return ops->open_software_nvram_pair == NULL ? PBNS_ERR_ARGUMENT
                                                   : ops->open_software_nvram_pair(context);
  }
  return PBNS_ERR_ARGUMENT;
}
