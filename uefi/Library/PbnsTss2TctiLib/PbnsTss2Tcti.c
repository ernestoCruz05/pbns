#include "PbnsTss2Tcti.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void secure_zero(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  while (length > 0U) {
    *bytes = 0U;
    ++bytes;
    --length;
  }
}

static pbns_tss2_tcti *checked_context(TSS2_TCTI_CONTEXT *base) {
  if (base == NULL || TSS2_TCTI_MAGIC(base) != PBNS_TSS2_TCTI_MAGIC ||
      TSS2_TCTI_VERSION(base) != 2U) {
    return NULL;
  }
  return (pbns_tss2_tcti *)base;
}

static TSS2_RC tcti_transmit(TSS2_TCTI_CONTEXT *base, size_t size,
                             const uint8_t *command) {
  pbns_tss2_tcti *context = checked_context(base);
  if (context == NULL) {
    return TSS2_TCTI_RC_BAD_CONTEXT;
  }
  if (command == NULL) {
    return TSS2_TCTI_RC_BAD_REFERENCE;
  }
  if (size == 0U || size > PBNS_TSS2_COMMAND_MAX) {
    return TSS2_TCTI_RC_BAD_VALUE;
  }
  if (context->response_ready) {
    return TSS2_TCTI_RC_BAD_SEQUENCE;
  }

  secure_zero(context->response, sizeof(context->response));
  context->response_length = 0U;
  const pbns_status status = context->submit(
      context->submit_context, (pbns_view){command, size},
      (pbns_buffer){context->response, 0U, sizeof(context->response)},
      &context->response_length);
  if (status != PBNS_OK) {
    secure_zero(context->response, sizeof(context->response));
    context->response_length = 0U;
    return status == PBNS_ERR_LIMIT ? TSS2_TCTI_RC_INSUFFICIENT_BUFFER
                                    : TSS2_TCTI_RC_IO_ERROR;
  }
  if (context->response_length == 0U ||
      context->response_length > sizeof(context->response)) {
    secure_zero(context->response, sizeof(context->response));
    context->response_length = 0U;
    return TSS2_TCTI_RC_IO_ERROR;
  }
  context->response_ready = true;
  return TSS2_RC_SUCCESS;
}

static TSS2_RC tcti_receive(TSS2_TCTI_CONTEXT *base, size_t *size,
                            uint8_t *response, int32_t timeout) {
  (void)timeout;
  pbns_tss2_tcti *context = checked_context(base);
  if (context == NULL) {
    return TSS2_TCTI_RC_BAD_CONTEXT;
  }
  if (size == NULL) {
    return TSS2_TCTI_RC_BAD_REFERENCE;
  }
  if (!context->response_ready) {
    return TSS2_TCTI_RC_BAD_SEQUENCE;
  }
  if (response == NULL) {
    *size = context->response_length;
    return TSS2_RC_SUCCESS;
  }
  if (*size < context->response_length) {
    *size = context->response_length;
    return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
  }
  memcpy(response, context->response, context->response_length);
  *size = context->response_length;
  secure_zero(context->response, sizeof(context->response));
  context->response_length = 0U;
  context->response_ready = false;
  return TSS2_RC_SUCCESS;
}

static void tcti_finalize(TSS2_TCTI_CONTEXT *base) {
  pbns_tss2_tcti *context = checked_context(base);
  if (context != NULL) {
    secure_zero(context, sizeof(*context));
  }
}

static TSS2_RC tcti_cancel(TSS2_TCTI_CONTEXT *base) {
  pbns_tss2_tcti *context = checked_context(base);
  if (context == NULL) {
    return TSS2_TCTI_RC_BAD_CONTEXT;
  }
  if (!context->response_ready) {
    return TSS2_TCTI_RC_BAD_SEQUENCE;
  }
  secure_zero(context->response, sizeof(context->response));
  context->response_length = 0U;
  context->response_ready = false;
  return TSS2_RC_SUCCESS;
}

static TSS2_RC tcti_get_poll_handles(TSS2_TCTI_CONTEXT *base,
                                     TSS2_TCTI_POLL_HANDLE *handles,
                                     size_t *count) {
  (void)handles;
  (void)count;
  return checked_context(base) == NULL ? TSS2_TCTI_RC_BAD_CONTEXT
                                       : TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

static TSS2_RC tcti_set_locality(TSS2_TCTI_CONTEXT *base, uint8_t locality) {
  if (checked_context(base) == NULL) {
    return TSS2_TCTI_RC_BAD_CONTEXT;
  }
  return locality == 0U ? TSS2_RC_SUCCESS : TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

static TSS2_RC tcti_make_sticky(TSS2_TCTI_CONTEXT *base, TPM2_HANDLE *handle,
                                uint8_t sticky) {
  (void)handle;
  (void)sticky;
  return checked_context(base) == NULL ? TSS2_TCTI_RC_BAD_CONTEXT
                                       : TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

pbns_status pbns_tss2_tcti_initialize(pbns_tss2_tcti *context,
                                      pbns_tpm_submit submit,
                                      void *submit_context) {
  if (context == NULL || submit == NULL || submit_context == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *context = (pbns_tss2_tcti){0};
  context->common.v1.magic = PBNS_TSS2_TCTI_MAGIC;
  context->common.v1.version = 2U;
  context->common.v1.transmit = tcti_transmit;
  context->common.v1.receive = tcti_receive;
  context->common.v1.finalize = tcti_finalize;
  context->common.v1.cancel = tcti_cancel;
  context->common.v1.getPollHandles = tcti_get_poll_handles;
  context->common.v1.setLocality = tcti_set_locality;
  context->common.makeSticky = tcti_make_sticky;
  context->submit = submit;
  context->submit_context = submit_context;
  return PBNS_OK;
}
