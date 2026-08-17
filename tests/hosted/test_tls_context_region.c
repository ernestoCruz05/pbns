#include "PbnsTlsTransportContextRegionCore.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct test_owner {
  uint8_t concrete_object[64];
  bool usable;
} test_owner;

static size_t helper_calls;

static pbns_status owner_context_region(const test_owner *owner,
                                        size_t concrete_size,
                                        pbns_view *region) {
  ++helper_calls;
  return pbns_tls_transport_context_region_core(
      owner, concrete_size, owner != NULL && owner->usable, region);
}

static pbns_status owner_destroy(test_owner **owner) {
  if (owner == NULL || *owner == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  **owner = (test_owner){0};
  free(*owner);
  *owner = NULL;
  return PBNS_OK;
}

static void test_rejected_arguments_zero_output(void) {
  uint8_t object = 0U;
  uint8_t sentinel = 0U;
  pbns_view region = {&sentinel, 1U};
  assert(pbns_tls_transport_context_region_core(NULL, sizeof(object), true,
                                                &region) == PBNS_ERR_ARGUMENT);
  assert(region.ptr == NULL && region.len == 0U);

  region = (pbns_view){&sentinel, 1U};
  assert(pbns_tls_transport_context_region_core(&object, 0U, true, &region) ==
         PBNS_ERR_ARGUMENT);
  assert(region.ptr == NULL && region.len == 0U);
  assert(pbns_tls_transport_context_region_core(&object, sizeof(object), true,
                                                NULL) == PBNS_ERR_ARGUMENT);
}

static void test_state_and_exact_complete_region(void) {
  test_owner owner = {0};
  uint8_t sentinel = 0U;
  pbns_view region = {&sentinel, 1U};
  assert(owner_context_region(&owner, sizeof(owner), &region) ==
         PBNS_ERR_STATE);
  assert(region.ptr == NULL && region.len == 0U);

  owner.usable = true;
  assert(owner_context_region(&owner, sizeof(owner), &region) == PBNS_OK);
  assert(region.ptr == (const uint8_t *)&owner && region.len == sizeof(owner));

  const size_t smaller_size = sizeof(owner) - 7U;
  assert(owner_context_region(&owner, smaller_size, &region) == PBNS_OK);
  assert(region.ptr == (const uint8_t *)&owner && region.len == smaller_size);
}

static void test_no_helper_call_after_successful_destroy(void) {
  test_owner *owner = malloc(sizeof(*owner));
  assert(owner != NULL);
  *owner = (test_owner){.usable = true};
  pbns_view region = {0};
  assert(owner_context_region(owner, sizeof(*owner), &region) == PBNS_OK);
  const size_t calls_before_destroy = helper_calls;
  assert(owner_destroy(&owner) == PBNS_OK && owner == NULL);

  /* Destruction ends the API lifetime: there is intentionally no accessor
   * invocation with the released handle. */
  assert(helper_calls == calls_before_destroy);
}

int main(void) {
  test_rejected_arguments_zero_output();
  test_state_and_exact_complete_region();
  test_no_helper_call_after_successful_destroy();
  return 0;
}
