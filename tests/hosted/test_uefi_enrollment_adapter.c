#include "PbnsEnrollmentClientLib.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define TEST_IDENTITY_MAGIC UINT32_C(0x6964656e)
#define TEST_PUBLIC_MAGIC UINT32_C(0x7075626b)

struct PBNS_TLS_UEFI_TRANSPORT {
  uint32_t marker;
};

static PBNS_ENROLLMENT_CLIENT_ADAPTER *expected_adapter;
static const pbns_identity *expected_identity;
static const pbns_deployment_public_key *expected_recipient;
static const pbns_deployment_public_key *expected_signer;
static size_t public_calls;
static size_t reset_calls;
static size_t fail_public_call;
static size_t tls_create_calls;
static size_t tls_destroy_calls;
static size_t tls_destroy_failures;
static pbns_status tls_create_status = PBNS_OK;
static pbns_transport expected_lower;
static struct PBNS_TLS_UEFI_TRANSPORT fake_tls = {.marker =
                                                      UINT32_C(0x746c7301)};
static const pbns_transport_ops TLS_OPS = {0};

static bool all_zero(const void *value, size_t length) {
  const uint8_t *bytes = value;
  for (size_t index = 0U; index < length; ++index) {
    if (bytes[index] != 0U) {
      return false;
    }
  }
  return true;
}

pbns_status pbns_cose_key_from_identity(pbns_cose_key *key,
                                        const pbns_identity *identity) {
  assert(expected_adapter != NULL);
  assert(key == &expected_adapter->IdentityKey);
  assert(identity == expected_identity);
  *key = (pbns_cose_key){
      .magic = TEST_IDENTITY_MAGIC, .identity = identity, .native = key};
  memset(key->owned_secret, 0x5a, sizeof(key->owned_secret));
  return PBNS_OK;
}

pbns_status pbns_cose_key_from_p256_public(pbns_cose_key *key, pbns_view x,
                                           pbns_view y) {
  ++public_calls;
  const pbns_deployment_public_key *expected =
      public_calls == 1U ? expected_recipient : expected_signer;
  assert(expected != NULL);
  assert(key == (public_calls == 1U ? &expected_adapter->RecipientKey
                                    : &expected_adapter->SignerKey));
  assert(x.ptr == expected->x.ptr && x.len == expected->x.len);
  assert(y.ptr == expected->y.ptr && y.len == expected->y.len);
  if (public_calls == fail_public_call) {
    return PBNS_ERR_CRYPTO;
  }
  *key = (pbns_cose_key){.magic = TEST_PUBLIC_MAGIC, .native = key};
  return PBNS_OK;
}

void pbns_cose_key_reset(pbns_cose_key *key) {
  ++reset_calls;
  memset(key, 0, sizeof(*key));
}

pbns_status EFIAPI
PbnsTlsTransportCreate(EFI_BOOT_SERVICES *boot_services, pbns_transport lower,
                       const pbns_tls_client_config *config,
                       const PBNS_TPM_RANDOM_SOURCE *tpm_random,
                       PBNS_TLS_UEFI_TRANSPORT **result) {
  ++tls_create_calls;
  assert(boot_services != NULL && config != NULL && tpm_random != NULL &&
         tpm_random->Fill != NULL && result != NULL);
  assert(lower.ops == expected_lower.ops &&
         lower.context == expected_lower.context);
  *result = NULL;
  if (tls_create_status != PBNS_OK) {
    return tls_create_status;
  }
  *result = &fake_tls;
  return PBNS_OK;
}

pbns_transport EFIAPI
PbnsTlsTransportAsTransport(PBNS_TLS_UEFI_TRANSPORT *transport) {
  assert(transport == &fake_tls);
  return (pbns_transport){.ops = &TLS_OPS, .context = transport};
}

pbns_status EFIAPI PbnsTlsTransportDestroy(PBNS_TLS_UEFI_TRANSPORT *transport) {
  assert(transport == &fake_tls);
  ++tls_destroy_calls;
  return tls_destroy_calls <= tls_destroy_failures ? PBNS_ERR_IO : PBNS_OK;
}

static EFI_STATUS EFIAPI fake_random(void *context, UINTN size, UINT8 *output) {
  (void)context;
  assert(size > 0U && output != NULL);
  memset(output, 0xa5, size);
  return EFI_SUCCESS;
}

static void reset_fixture(void) {
  expected_adapter = NULL;
  expected_identity = NULL;
  expected_recipient = NULL;
  expected_signer = NULL;
  public_calls = 0U;
  reset_calls = 0U;
  fail_public_call = 0U;
  tls_create_calls = 0U;
  tls_destroy_calls = 0U;
  tls_destroy_failures = 0U;
  tls_create_status = PBNS_OK;
  expected_lower = (pbns_transport){0};
}

static void test_init_constructs_every_key_at_final_address(void) {
  reset_fixture();
  pbns_identity identity = {0};
  uint8_t recipient_x[32] = {1U};
  uint8_t recipient_y[32] = {2U};
  uint8_t signer_x[32] = {3U};
  uint8_t signer_y[32] = {4U};
  pbns_deployment_public_key recipient = {
      .kid = {(const uint8_t *)"recipient", 9U},
      .x = {recipient_x, sizeof(recipient_x)},
      .y = {recipient_y, sizeof(recipient_y)},
  };
  pbns_deployment_public_key signer = {
      .kid = {(const uint8_t *)"signer", 6U},
      .x = {signer_x, sizeof(signer_x)},
      .y = {signer_y, sizeof(signer_y)},
  };
  PBNS_ENROLLMENT_CLIENT_ADAPTER adapter = {0};
  expected_adapter = &adapter;
  expected_identity = &identity;
  expected_recipient = &recipient;
  expected_signer = &signer;

  assert(PbnsEnrollmentClientAdapterInit(&adapter, &identity, &recipient,
                                         &signer) == EFI_SUCCESS);
  assert(adapter.Initialized);
  assert(adapter.IdentityKey.native == &adapter.IdentityKey);
  assert(adapter.RecipientKey.native == &adapter.RecipientKey);
  assert(adapter.SignerKey.native == &adapter.SignerKey);
  assert(adapter.Identity == &identity);
  assert(PbnsEnrollmentClientAdapterInit(&adapter, &identity, &recipient,
                                         &signer) == EFI_INVALID_PARAMETER);

  PbnsEnrollmentClientAdapterReset(&adapter);
  assert(reset_calls == 3U);
  assert(all_zero(&adapter, sizeof(adapter)));
  PbnsEnrollmentClientAdapterReset(&adapter);
  assert(reset_calls == 3U);
}

static void test_partial_init_failure_clears_all_owned_keys(void) {
  reset_fixture();
  pbns_identity identity = {0};
  uint8_t coordinate[32] = {1U};
  pbns_deployment_public_key recipient = {
      .kid = {(const uint8_t *)"recipient", 9U},
      .x = {coordinate, sizeof(coordinate)},
      .y = {coordinate, sizeof(coordinate)},
  };
  pbns_deployment_public_key signer = recipient;
  PBNS_ENROLLMENT_CLIENT_ADAPTER adapter = {0};
  expected_adapter = &adapter;
  expected_identity = &identity;
  expected_recipient = &recipient;
  expected_signer = &signer;
  fail_public_call = 2U;

  assert(PbnsEnrollmentClientAdapterInit(&adapter, &identity, &recipient,
                                         &signer) == EFI_SECURITY_VIOLATION);
  assert(reset_calls == 3U);
  assert(all_zero(&adapter, sizeof(adapter)));
}

static void test_tls_open_never_returns_the_raw_transport(void) {
  reset_fixture();
  EFI_BOOT_SERVICES boot_services = {0};
  pbns_transport_ops lower_ops = {0};
  uint32_t raw_context = UINT32_C(0x72617701);
  expected_lower = (pbns_transport){.ops = &lower_ops, .context = &raw_context};
  pbns_tls_client_config config = {0};
  PBNS_TPM_RANDOM_SOURCE random = {.Fill = fake_random, .Context = NULL};
  PBNS_TLS_UEFI_TRANSPORT *tls = NULL;
  pbns_transport broker_transport = {0};

  assert(PbnsEnrollmentClientTlsOpen(&boot_services, expected_lower, &config,
                                     &random, &tls,
                                     &broker_transport) == PBNS_OK);
  assert(tls_create_calls == 1U && tls == &fake_tls);
  assert(broker_transport.ops == &TLS_OPS && broker_transport.context == tls);
  assert(broker_transport.ops != expected_lower.ops ||
         broker_transport.context != expected_lower.context);

  const size_t create_calls = tls_create_calls;
  broker_transport = (pbns_transport){0};
  assert(PbnsEnrollmentClientTlsOpen(&boot_services, expected_lower, &config,
                                     &random, &tls,
                                     &broker_transport) == PBNS_ERR_STATE);
  assert(tls == &fake_tls && tls_create_calls == create_calls);

  tls_create_status = PBNS_ERR_ENTROPY;
  tls = NULL;
  broker_transport = (pbns_transport){.ops = &TLS_OPS, .context = &fake_tls};
  assert(PbnsEnrollmentClientTlsOpen(&boot_services, expected_lower, &config,
                                     &random, &tls,
                                     &broker_transport) == PBNS_ERR_ENTROPY);
  assert(tls == NULL && broker_transport.ops == NULL &&
         broker_transport.context == NULL);
}

static void test_tls_destroy_is_bounded_and_invalidates_success(void) {
  reset_fixture();
  PBNS_TLS_UEFI_TRANSPORT *tls = &fake_tls;
  tls_destroy_failures = 2U;
  assert(PbnsEnrollmentClientTlsDestroy(&tls) == PBNS_OK);
  assert(tls_destroy_calls == 3U && tls == NULL);

  tls = &fake_tls;
  tls_destroy_calls = 0U;
  tls_destroy_failures = 3U;
  assert(PbnsEnrollmentClientTlsDestroy(&tls) == PBNS_ERR_IO);
  assert(tls_destroy_calls == 3U && tls == &fake_tls);
}

int main(void) {
  test_init_constructs_every_key_at_final_address();
  test_partial_init_failure_clears_all_owned_keys();
  test_tls_open_never_returns_the_raw_transport();
  test_tls_destroy_is_bounded_and_invalidates_success();
  return 0;
}
