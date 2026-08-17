#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include "PbnsIdentityRecord.h"
#include "PbnsSoftwareIdentity.h"
#include "pbns/identity.h"

typedef struct test_store {
  uint8_t bytes[PBNS_IDENTITY_RECORD_MAX_SIZE];
  size_t length;
  uint32_t attributes;
  size_t reads;
  size_t writes;
  size_t removes;
  bool exists;
  bool fail_write;
  bool corrupt_readback;
} test_store;

typedef struct test_memory {
  size_t allocations;
  size_t releases;
  bool fail_allocation;
} test_memory;

typedef struct test_random {
  size_t calls;
  bool fail;
} test_random;

typedef struct test_environment {
  pbns_software_identity_environment value;
  test_store store;
  test_memory memory;
  test_random random;
} test_environment;

static pbns_status store_read(void *context, pbns_buffer output,
                              size_t *written, uint32_t *attributes) {
  test_store *store = context;
  store->reads++;
  *written = 0U;
  *attributes = 0U;
  if (!store->exists) {
    return PBNS_ERR_STATE;
  }
  if (output.cap < store->length) {
    return PBNS_ERR_LIMIT;
  }
  memcpy(output.ptr, store->bytes, store->length);
  if (store->corrupt_readback &&
      store->length > PBNS_IDENTITY_RECORD_HEADER_SIZE) {
    output.ptr[PBNS_IDENTITY_RECORD_HEADER_SIZE] ^= 1U;
  }
  *written = store->length;
  *attributes = store->attributes;
  return PBNS_OK;
}

static pbns_status store_write(void *context, pbns_view value,
                               uint32_t attributes) {
  test_store *store = context;
  store->writes++;
  if (store->fail_write) {
    return PBNS_ERR_IO;
  }
  assert(value.len <= sizeof(store->bytes));
  memcpy(store->bytes, value.ptr, value.len);
  store->length = value.len;
  store->attributes = attributes;
  store->exists = true;
  return PBNS_OK;
}

static pbns_status store_remove(void *context) {
  test_store *store = context;
  store->removes++;
  memset(store->bytes, 0, sizeof(store->bytes));
  store->length = 0U;
  store->attributes = 0U;
  store->exists = false;
  return PBNS_OK;
}

static void *test_allocate(void *context, size_t size) {
  test_memory *memory = context;
  if (memory->fail_allocation) {
    return NULL;
  }
  memory->allocations++;
  return calloc(1U, size);
}

static void test_release(void *context, void *value, size_t size) {
  test_memory *memory = context;
  memory->releases++;
  if (value != NULL) {
    memset(value, 0, size);
    free(value);
  }
}

static pbns_status test_random_fill(void *state, pbns_buffer output) {
  const pbns_identity_random_state *random_state = state;
  test_random *random = random_state->pointer_alignment;
  assert(random != NULL);
  random->calls++;
  if (random->fail || RAND_bytes(output.ptr, (int)output.cap) != 1) {
    return PBNS_ERR_ENTROPY;
  }
  return PBNS_OK;
}

static void initialize_environment(test_environment *environment) {
  *environment = (test_environment){0};
  environment->value.store = (pbns_identity_store){
      .read = store_read,
      .write = store_write,
      .remove = store_remove,
      .context = &environment->store,
  };
  environment->value.memory = (pbns_identity_memory){
      .allocate = test_allocate,
      .release = test_release,
      .context = &environment->memory,
  };
  environment->value.random_fill = test_random_fill;
  environment->value.random_state.pointer_alignment = &environment->random;
}

static bool contains_bytes(pbns_view haystack, pbns_view needle) {
  if (needle.len == 0U || needle.len > haystack.len) {
    return false;
  }
  for (size_t offset = 0U; offset <= haystack.len - needle.len; ++offset) {
    if (memcmp(haystack.ptr + offset, needle.ptr, needle.len) == 0) {
      return true;
    }
  }
  return false;
}

static bool private_scalar_from_der(pbns_view der, uint8_t scalar[32]) {
  const unsigned char *cursor = der.ptr;
  EVP_PKEY *key = d2i_AutoPrivateKey(NULL, &cursor, (long)der.len);
  BIGNUM *value = NULL;
  const bool ok =
      key != NULL && cursor == der.ptr + der.len &&
      EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &value) == 1 &&
      value != NULL && BN_num_bytes(value) <= 32 &&
      BN_bn2binpad(value, scalar, 32) == 32;
  BN_clear_free(value);
  EVP_PKEY_free(key);
  return ok;
}

static EVP_PKEY *public_key_from_cose(pbns_view cose) {
  assert(cose.len == 75U);
  static const uint8_t prefix[] = {0xa4, 0x01, 0x02, 0x20,
                                   0x01, 0x21, 0x58, 0x20};
  assert(memcmp(cose.ptr, prefix, sizeof(prefix)) == 0);
  assert(cose.ptr[40] == 0x22 && cose.ptr[41] == 0x58 && cose.ptr[42] == 0x20);
  uint8_t point[65] = {0x04};
  memcpy(point + 1U, cose.ptr + 8U, 32U);
  memcpy(point + 33U, cose.ptr + 43U, 32U);
  char group[] = "prime256v1";
  OSSL_PARAM parameters[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0U),
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, point,
                                        sizeof(point)),
      OSSL_PARAM_construct_end(),
  };
  EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
  EVP_PKEY *key = NULL;
  assert(context != NULL);
  assert(EVP_PKEY_fromdata_init(context) == 1);
  assert(EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY, parameters) ==
         1);
  EVP_PKEY_CTX_free(context);
  return key;
}

static bool verify_raw(EVP_PKEY *key, pbns_view digest, pbns_view signature) {
  assert(signature.len == 64U);
  BIGNUM *r = BN_bin2bn(signature.ptr, 32, NULL);
  BIGNUM *s = BN_bin2bn(signature.ptr + 32U, 32, NULL);
  ECDSA_SIG *ecdsa = ECDSA_SIG_new();
  assert(r != NULL && s != NULL && ecdsa != NULL);
  assert(ECDSA_SIG_set0(ecdsa, r, s) == 1);
  const int der_length = i2d_ECDSA_SIG(ecdsa, NULL);
  uint8_t der[80] = {0};
  unsigned char *cursor = der;
  assert(der_length > 0 && (size_t)der_length <= sizeof(der));
  assert(i2d_ECDSA_SIG(ecdsa, &cursor) == der_length);
  EVP_PKEY_CTX *verify = EVP_PKEY_CTX_new(key, NULL);
  assert(verify != NULL && EVP_PKEY_verify_init(verify) == 1);
  assert(EVP_PKEY_CTX_set_signature_md(verify, EVP_sha256()) == 1);
  const bool valid = EVP_PKEY_verify(verify, der, (size_t)der_length,
                                     digest.ptr, digest.len) == 1;
  EVP_PKEY_CTX_free(verify);
  ECDSA_SIG_free(ecdsa);
  return valid;
}

static void identity_values(pbns_identity *identity, uint8_t public_key[128],
                            size_t *public_length, uint8_t fingerprint[32]) {
  assert(pbns_identity_assurance_level(identity) == PBNS_IDENTITY_SOFTWARE);
  assert(pbns_identity_public_cose_key(identity,
                                       (pbns_buffer){public_key, 0U, 128U},
                                       public_length) == PBNS_OK);
  assert(pbns_identity_fingerprint(
             identity, (pbns_buffer){fingerprint, 0U, 32U}) == PBNS_OK);
}

static void test_create_reopen_sign_reset(void) {
  test_environment environment;
  initialize_environment(&environment);
  pbns_identity created = {0};
  assert(pbns_software_identity_create(&environment.value, &created) ==
         PBNS_OK);
  assert(environment.store.exists);
  assert(environment.store.attributes == PBNS_IDENTITY_VARIABLE_ATTRIBUTES);
  assert(environment.store.writes == 1U);
  assert(environment.store.reads >= 2U);

  uint8_t created_public[128] = {0};
  uint8_t created_fingerprint[32] = {0};
  size_t created_public_length = 0U;
  identity_values(&created, created_public, &created_public_length,
                  created_fingerprint);
  uint8_t expected_fingerprint[32] = {0};
  unsigned int expected_fingerprint_length = 0U;
  assert(EVP_Digest(created_public, created_public_length, expected_fingerprint,
                    &expected_fingerprint_length, EVP_sha256(), NULL) == 1);
  assert(expected_fingerprint_length == sizeof(expected_fingerprint));
  assert(memcmp(created_fingerprint, expected_fingerprint,
                sizeof(created_fingerprint)) == 0);
  pbns_identity_record persisted = {0};
  assert(pbns_identity_record_decode(
             (pbns_view){environment.store.bytes, environment.store.length},
             &persisted) == PBNS_OK);
  uint8_t private_scalar[32] = {0};
  assert(private_scalar_from_der(persisted.private_der, private_scalar));
  assert(!contains_bytes((pbns_view){created_public, created_public_length},
                         (pbns_view){private_scalar, sizeof(private_scalar)}));
  assert(!contains_bytes(
      (pbns_view){created_fingerprint, sizeof(created_fingerprint)},
      (pbns_view){private_scalar, sizeof(private_scalar)}));
  OPENSSL_cleanse(private_scalar, sizeof(private_scalar));
  uint8_t digest[32] = {1};
  uint8_t wrong_digest[32] = {2};
  uint8_t signature[64] = {0};
  size_t signature_length = 0U;
  assert(pbns_identity_sign(&created, (pbns_view){digest, sizeof(digest)},
                            (pbns_buffer){signature, 0U, sizeof(signature)},
                            &signature_length) == PBNS_OK);
  EVP_PKEY *verification_key =
      public_key_from_cose((pbns_view){created_public, created_public_length});
  assert(verify_raw(verification_key, (pbns_view){digest, sizeof(digest)},
                    (pbns_view){signature, signature_length}));
  assert(!verify_raw(verification_key,
                     (pbns_view){wrong_digest, sizeof(wrong_digest)},
                     (pbns_view){signature, signature_length}));
  environment.random.fail = true;
  assert(pbns_identity_sign(&created, (pbns_view){digest, sizeof(digest)},
                            (pbns_buffer){signature, 0U, sizeof(signature)},
                            &signature_length) == PBNS_ERR_ENTROPY);
  environment.random.fail = false;
  EVP_PKEY_free(verification_key);
  assert(pbns_software_identity_create(&environment.value,
                                       &(pbns_identity){0}) == PBNS_ERR_STATE);
  pbns_identity_close(&created);

  pbns_identity reopened = {0};
  assert(pbns_software_identity_open(&environment.value, &reopened) == PBNS_OK);
  uint8_t reopened_public[128] = {0};
  uint8_t reopened_fingerprint[32] = {0};
  size_t reopened_public_length = 0U;
  identity_values(&reopened, reopened_public, &reopened_public_length,
                  reopened_fingerprint);
  assert(reopened_public_length == created_public_length);
  assert(memcmp(reopened_public, created_public, created_public_length) == 0);
  assert(memcmp(reopened_fingerprint, created_fingerprint, 32U) == 0);
  pbns_identity_close(&reopened);
  assert(environment.memory.allocations == environment.memory.releases);

  assert(pbns_software_identity_reset(&environment.value) == PBNS_OK);
  assert(!environment.store.exists && environment.store.removes == 1U);
  assert(pbns_software_identity_open(&environment.value, &reopened) ==
         PBNS_ERR_STATE);
}

static void test_create_failures_leave_no_identity(void) {
  test_environment environment;
  initialize_environment(&environment);
  pbns_identity identity = {0};

  environment.random.fail = true;
  assert(pbns_software_identity_create(&environment.value, &identity) ==
         PBNS_ERR_ENTROPY);
  assert(!environment.store.exists);
  environment.random.fail = false;

  environment.memory.fail_allocation = true;
  assert(pbns_software_identity_create(&environment.value, &identity) ==
         PBNS_ERR_RESOURCE);
  assert(!environment.store.exists);
  environment.memory.fail_allocation = false;

  environment.store.fail_write = true;
  assert(pbns_software_identity_create(&environment.value, &identity) ==
         PBNS_ERR_IO);
  assert(!environment.store.exists);
  environment.store.fail_write = false;

  environment.store.corrupt_readback = true;
  assert(pbns_software_identity_create(&environment.value, &identity) ==
         PBNS_ERR_AUTHENTICATION);
  assert(!environment.store.exists);
  assert(environment.store.removes == 2U);
  assert(pbns_identity_assurance_level(&identity) == PBNS_IDENTITY_INVALID);
  assert(environment.memory.allocations == environment.memory.releases);
}

static void replace_record(test_environment *environment, pbns_view private_der,
                           pbns_view public_key, pbns_view fingerprint) {
  uint8_t encoded[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
  size_t written = 0U;
  assert(pbns_identity_record_encode(
             private_der, public_key, fingerprint,
             (pbns_buffer){encoded, 0U, sizeof(encoded)}, &written) == PBNS_OK);
  memcpy(environment->store.bytes, encoded, written);
  environment->store.length = written;
}

static void test_open_rejects_attributes_and_bound_fields(void) {
  test_environment environment;
  initialize_environment(&environment);
  pbns_identity identity = {0};
  assert(pbns_software_identity_create(&environment.value, &identity) ==
         PBNS_OK);
  pbns_identity_close(&identity);
  uint8_t original[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
  memcpy(original, environment.store.bytes, environment.store.length);
  const size_t original_length = environment.store.length;

  environment.store.attributes |= UINT32_C(4);
  assert(pbns_software_identity_open(&environment.value, &identity) ==
         PBNS_ERR_AUTHENTICATION);
  environment.store.attributes = PBNS_IDENTITY_VARIABLE_ATTRIBUTES;

  environment.store.bytes[PBNS_IDENTITY_RECORD_HEADER_SIZE] ^= 1U;
  assert(pbns_software_identity_open(&environment.value, &identity) ==
         PBNS_ERR_CRC);
  memcpy(environment.store.bytes, original, original_length);

  pbns_identity_record record = {0};
  assert(pbns_identity_record_decode((pbns_view){original, original_length},
                                     &record) == PBNS_OK);
  uint8_t changed_public[PBNS_IDENTITY_PUBLIC_COSE_MAX] = {0};
  memcpy(changed_public, record.public_cose_key.ptr,
         record.public_cose_key.len);
  changed_public[8] ^= 1U;
  replace_record(&environment, record.private_der,
                 (pbns_view){changed_public, record.public_cose_key.len},
                 record.fingerprint);
  assert(pbns_software_identity_open(&environment.value, &identity) ==
         PBNS_ERR_AUTHENTICATION);

  uint8_t changed_fingerprint[PBNS_IDENTITY_FINGERPRINT_SIZE] = {0};
  memcpy(changed_fingerprint, record.fingerprint.ptr, record.fingerprint.len);
  changed_fingerprint[0] ^= 1U;
  replace_record(&environment, record.private_der, record.public_cose_key,
                 (pbns_view){changed_fingerprint, sizeof(changed_fingerprint)});
  assert(pbns_software_identity_open(&environment.value, &identity) ==
         PBNS_ERR_AUTHENTICATION);

  memcpy(environment.store.bytes, original, original_length);
  environment.store.length = original_length;
  environment.store.bytes[5] = 2U;
  assert(pbns_software_identity_open(&environment.value, &identity) ==
         PBNS_ERR_VERSION);
  assert(environment.memory.allocations == environment.memory.releases);
}

static void test_argument_contracts(void) {
  test_environment environment;
  initialize_environment(&environment);
  pbns_identity identity = {0};
  assert(pbns_software_identity_create(NULL, &identity) == PBNS_ERR_ARGUMENT);
  assert(pbns_software_identity_create(&environment.value, NULL) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_software_identity_open(NULL, &identity) == PBNS_ERR_ARGUMENT);
  assert(pbns_software_identity_reset(NULL) == PBNS_ERR_ARGUMENT);
  environment.value.random_fill = NULL;
  assert(pbns_software_identity_create(&environment.value, &identity) ==
         PBNS_ERR_ARGUMENT);
}

int main(void) {
  test_create_reopen_sign_reset();
  test_create_failures_leave_no_identity();
  test_open_rejects_attributes_and_bound_fields();
  test_argument_contracts();
  return 0;
}
