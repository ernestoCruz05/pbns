#ifndef PBNS_TSS2_TCTI_H
#define PBNS_TSS2_TCTI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tss2/tss2_tcti.h>

#include "PbnsTpmSubmit.h"

#define PBNS_TSS2_COMMAND_MAX 4096U
#define PBNS_TSS2_RESPONSE_MAX 4096U
#define PBNS_TSS2_TCTI_MAGIC UINT64_C(0x50424e5354435432)

typedef struct pbns_tss2_tcti {
  TSS2_TCTI_CONTEXT_COMMON_V2 common;
  pbns_tpm_submit submit;
  void *submit_context;
  uint8_t response[PBNS_TSS2_RESPONSE_MAX];
  size_t response_length;
  bool response_ready;
} pbns_tss2_tcti;

pbns_status pbns_tss2_tcti_initialize(pbns_tss2_tcti *context,
                                      pbns_tpm_submit submit,
                                      void *submit_context);

#endif
