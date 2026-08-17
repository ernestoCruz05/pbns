#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "PbnsTss2Tcti.h"

typedef struct submit_fixture {
  pbns_view expected_command;
  pbns_view response;
  pbns_status status;
  size_t calls;
} submit_fixture;

static pbns_status fake_submit(void *context, pbns_view command,
                               pbns_buffer response, size_t *response_length) {
  submit_fixture *fixture = context;
  fixture->calls++;
  assert(command.len == fixture->expected_command.len);
  assert(memcmp(command.ptr, fixture->expected_command.ptr, command.len) == 0);
  if (fixture->status != PBNS_OK) {
    return fixture->status;
  }
  if (response.cap < fixture->response.len) {
    return PBNS_ERR_LIMIT;
  }
  memcpy(response.ptr, fixture->response.ptr, fixture->response.len);
  *response_length = fixture->response.len;
  return PBNS_OK;
}

static bool all_zero(const uint8_t *bytes, size_t length) {
  for (size_t index = 0U; index < length; ++index) {
    if (bytes[index] != 0U) {
      return false;
    }
  }
  return true;
}

static void test_round_trip_and_sequence(void) {
  static const uint8_t command[] = {0x80, 0x01, 0x00, 0x00, 0x00, 0x0a};
  static const uint8_t response[] = {0x80, 0x01, 0x00, 0x00, 0x00,
                                     0x0a, 0x00, 0x00, 0x00, 0x00};
  submit_fixture fixture = {
      .expected_command = {command, sizeof(command)},
      .response = {response, sizeof(response)},
  };
  pbns_tss2_tcti context = {0};
  assert(pbns_tss2_tcti_initialize(&context, fake_submit, &fixture) == PBNS_OK);
  TSS2_TCTI_CONTEXT *base = (TSS2_TCTI_CONTEXT *)&context;
  assert(TSS2_TCTI_MAGIC(base) == PBNS_TSS2_TCTI_MAGIC);
  assert(TSS2_TCTI_VERSION(base) == 2U);

  size_t length = 0U;
  assert(Tss2_Tcti_Receive(base, &length, NULL, TSS2_TCTI_TIMEOUT_BLOCK) ==
         TSS2_TCTI_RC_BAD_SEQUENCE);
  assert(Tss2_Tcti_Transmit(base, sizeof(command), command) == TSS2_RC_SUCCESS);
  assert(fixture.calls == 1U);
  assert(Tss2_Tcti_Transmit(base, sizeof(command), command) ==
         TSS2_TCTI_RC_BAD_SEQUENCE);
  assert(fixture.calls == 1U);

  assert(Tss2_Tcti_Receive(base, &length, NULL, TSS2_TCTI_TIMEOUT_BLOCK) ==
         TSS2_RC_SUCCESS);
  assert(length == sizeof(response));
  uint8_t output[sizeof(response)] = {0};
  size_t short_length = sizeof(output) - 1U;
  assert(
      Tss2_Tcti_Receive(base, &short_length, output, TSS2_TCTI_TIMEOUT_BLOCK) ==
      TSS2_TCTI_RC_INSUFFICIENT_BUFFER);
  assert(short_length == sizeof(response));
  assert(all_zero(output, sizeof(output)));
  length = sizeof(output);
  assert(Tss2_Tcti_Receive(base, &length, output, TSS2_TCTI_TIMEOUT_BLOCK) ==
         TSS2_RC_SUCCESS);
  assert(length == sizeof(response));
  assert(memcmp(output, response, sizeof(output)) == 0);
  assert(Tss2_Tcti_Receive(base, &length, output, TSS2_TCTI_TIMEOUT_BLOCK) ==
         TSS2_TCTI_RC_BAD_SEQUENCE);
}

static void test_bounds_and_submit_failure(void) {
  uint8_t command[PBNS_TSS2_COMMAND_MAX] = {0};
  uint8_t response[PBNS_TSS2_RESPONSE_MAX] = {0};
  command[0] = 1U;
  response[0] = 2U;
  submit_fixture fixture = {
      .expected_command = {command, sizeof(command)},
      .response = {response, sizeof(response)},
  };
  pbns_tss2_tcti context = {0};
  assert(pbns_tss2_tcti_initialize(&context, fake_submit, &fixture) == PBNS_OK);
  TSS2_TCTI_CONTEXT *base = (TSS2_TCTI_CONTEXT *)&context;
  assert(Tss2_Tcti_Transmit(base, sizeof(command), command) == TSS2_RC_SUCCESS);
  size_t length = sizeof(response);
  uint8_t output[PBNS_TSS2_RESPONSE_MAX] = {0};
  assert(Tss2_Tcti_Receive(base, &length, output, TSS2_TCTI_TIMEOUT_NONE) ==
         TSS2_RC_SUCCESS);
  assert(memcmp(output, response, sizeof(output)) == 0);

  assert(Tss2_Tcti_Transmit(base, 0U, command) == TSS2_TCTI_RC_BAD_VALUE);
  assert(Tss2_Tcti_Transmit(base, sizeof(command) + 1U, command) ==
         TSS2_TCTI_RC_BAD_VALUE);
  fixture.expected_command = (pbns_view){command, 1U};
  fixture.status = PBNS_ERR_TRANSPORT;
  assert(Tss2_Tcti_Transmit(base, 1U, command) == TSS2_TCTI_RC_IO_ERROR);
  assert(fixture.calls == 2U);
}

static void test_response_size_header(void) {
  uint8_t response[PBNS_TPM_SUBMIT_RESPONSE_MAX] = {0};
  size_t length = 0U;
  response[2] = 0U;
  response[3] = 0U;
  response[4] = 0U;
  response[5] = 10U;
  assert(pbns_tpm_response_size(response, sizeof(response), &length) == PBNS_OK);
  assert(length == 10U);
  assert(pbns_tpm_response_size(response, 9U, &length) == PBNS_ERR_FORMAT);
  response[5] = 9U;
  assert(pbns_tpm_response_size(response, sizeof(response), &length) == PBNS_ERR_FORMAT);
  response[2] = 0U;
  response[3] = 0U;
  response[4] = 0x10U;
  response[5] = 1U;
  assert(pbns_tpm_response_size(response, sizeof(response), &length) == PBNS_ERR_FORMAT);
  assert(pbns_tpm_response_size(NULL, sizeof(response), &length) == PBNS_ERR_ARGUMENT);
  assert(pbns_tpm_response_size(response, sizeof(response), NULL) == PBNS_ERR_ARGUMENT);
}

static void test_cancel_locality_finalize_and_arguments(void) {
  static const uint8_t command[] = {1U};
  static const uint8_t response[] = {2U};
  submit_fixture fixture = {
      .expected_command = {command, sizeof(command)},
      .response = {response, sizeof(response)},
  };
  pbns_tss2_tcti context = {0};
  assert(pbns_tss2_tcti_initialize(NULL, fake_submit, &fixture) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_tss2_tcti_initialize(&context, NULL, &fixture) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_tss2_tcti_initialize(&context, fake_submit, NULL) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_tss2_tcti_initialize(&context, fake_submit, &fixture) == PBNS_OK);
  TSS2_TCTI_CONTEXT *base = (TSS2_TCTI_CONTEXT *)&context;
  assert(Tss2_Tcti_SetLocality(base, 0U) == TSS2_RC_SUCCESS);
  assert(Tss2_Tcti_SetLocality(base, 1U) == TSS2_TCTI_RC_NOT_IMPLEMENTED);
  size_t handles = 0U;
  assert(Tss2_Tcti_GetPollHandles(base, NULL, &handles) ==
         TSS2_TCTI_RC_NOT_IMPLEMENTED);
  TPM2_HANDLE handle = 0U;
  assert(Tss2_Tcti_MakeSticky(base, &handle, 1U) ==
         TSS2_TCTI_RC_NOT_IMPLEMENTED);
  assert(Tss2_Tcti_Cancel(base) == TSS2_TCTI_RC_BAD_SEQUENCE);
  assert(Tss2_Tcti_Transmit(base, sizeof(command), command) == TSS2_RC_SUCCESS);
  assert(Tss2_Tcti_Cancel(base) == TSS2_RC_SUCCESS);
  assert(!context.response_ready);
  assert(context.response_length == 0U);
  assert(all_zero(context.response, sizeof(context.response)));
  Tss2_Tcti_Finalize(base);
  assert(all_zero((const uint8_t *)&context, sizeof(context)));
}

int main(void) {
  test_round_trip_and_sequence();
  test_bounds_and_submit_failure();
  test_response_size_header();
  test_cancel_locality_finalize_and_arguments();
  return 0;
}
