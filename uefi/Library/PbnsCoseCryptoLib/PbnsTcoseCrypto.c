#include <Library/MemoryAllocationLib.h>
#include <Library/PbnsCoseCryptoLib.h>

#include "PbnsCoseCryptoInternal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/nist_kw.h"
#include "mbedtls/private_access.h"
#include "mbedtls/sha256.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_crypto.h"

#define PBNS_ES256_SIGNATURE_SIZE 64U
#define PBNS_SHA256_SIZE 32U
#define PBNS_SEC1_P256_SIZE 65U
#define PBNS_AES128_KEY_SIZE 16U
#define PBNS_GCM_TAG_SIZE 16U
#define PBNS_GCM_NONCE_SIZE 12U

typedef struct pbns_cose_symmetric_key {
  size_t length;
  uint8_t bytes[PBNS_AES128_KEY_SIZE];
} pbns_cose_symmetric_key;

static const pbns_identity *active_random_identity;

static void secure_zero(void *memory, size_t length) {
  volatile uint8_t *bytes = memory;
  for (size_t index = 0U; index < length; ++index) {
    bytes[index] = 0U;
  }
}

static const pbns_cose_key *key_context(struct t_cose_key native,
                                        pbns_cose_key_kind kind) {
  const pbns_cose_key *key = native.key.ptr;
  if (key == NULL || key->magic != PBNS_COSE_KEY_MAGIC || key->kind != kind ||
      key->native.key.ptr != key) {
    return NULL;
  }
  return key;
}

bool t_cose_crypto_is_algorithm_supported(int32_t cose_algorithm_id) {
  return cose_algorithm_id == T_COSE_ALGORITHM_ES256 ||
         cose_algorithm_id == T_COSE_ALGORITHM_SHA_256 ||
         cose_algorithm_id == T_COSE_ALGORITHM_A128GCM ||
         cose_algorithm_id == T_COSE_ALGORITHM_A128KW ||
         cose_algorithm_id == T_COSE_ALGORITHM_ECDH_ES_A128KW;
}

enum t_cose_err_t t_cose_crypto_sig_size(int32_t cose_algorithm_id,
                                         struct t_cose_key signing_key,
                                         size_t *sig_size) {
  if (sig_size == NULL) {
    return T_COSE_ERR_INVALID_ARGUMENT;
  }
  *sig_size = 0U;
  if (cose_algorithm_id != T_COSE_ALGORITHM_ES256) {
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
  }
  if (key_context(signing_key, PBNS_COSE_KEY_IDENTITY) == NULL) {
    return T_COSE_ERR_WRONG_TYPE_OF_KEY;
  }
  *sig_size = PBNS_ES256_SIGNATURE_SIZE;
  return T_COSE_SUCCESS;
}

enum t_cose_err_t t_cose_crypto_sign(int32_t cose_algorithm_id,
                                     struct t_cose_key signing_key,
                                     void *crypto_context,
                                     struct q_useful_buf_c hash_to_sign,
                                     struct q_useful_buf signature_buffer,
                                     struct q_useful_buf_c *signature) {
  (void)crypto_context;
  if (signature == NULL || hash_to_sign.ptr == NULL ||
      hash_to_sign.len != PBNS_SHA256_SIZE) {
    return T_COSE_ERR_INVALID_ARGUMENT;
  }
  *signature = NULLUsefulBufC;
  if (cose_algorithm_id != T_COSE_ALGORITHM_ES256) {
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
  }
  const pbns_cose_key *key = key_context(signing_key, PBNS_COSE_KEY_IDENTITY);
  if (key == NULL || key->identity == NULL) {
    return T_COSE_ERR_WRONG_TYPE_OF_KEY;
  }
  if (signature_buffer.ptr == NULL ||
      signature_buffer.len < PBNS_ES256_SIGNATURE_SIZE) {
    return T_COSE_ERR_SIG_BUFFER_SIZE;
  }
  size_t written = 0U;
  const pbns_status status = pbns_identity_sign(
      key->identity, (pbns_view){hash_to_sign.ptr, hash_to_sign.len},
      (pbns_buffer){signature_buffer.ptr, 0U, signature_buffer.len}, &written);
  if (status != PBNS_OK || written != PBNS_ES256_SIGNATURE_SIZE) {
    return T_COSE_ERR_SIG_FAIL;
  }
  *signature =
      (struct q_useful_buf_c){signature_buffer.ptr, PBNS_ES256_SIGNATURE_SIZE};
  return T_COSE_SUCCESS;
}

enum t_cose_err_t t_cose_crypto_sign_restart(
    bool started, int32_t cose_algorithm_id, struct t_cose_key signing_key,
    void *crypto_context, struct q_useful_buf_c hash_to_sign,
    struct q_useful_buf signature_buffer, struct q_useful_buf_c *signature) {
  if (started) {
    return T_COSE_ERR_UNSUPPORTED;
  }
  return t_cose_crypto_sign(cose_algorithm_id, signing_key, crypto_context,
                            hash_to_sign, signature_buffer, signature);
}

enum t_cose_err_t t_cose_crypto_verify(int32_t cose_algorithm_id,
                                       struct t_cose_key verification_key,
                                       void *crypto_context,
                                       struct q_useful_buf_c hash_to_verify,
                                       struct q_useful_buf_c signature) {
  (void)crypto_context;
  if (cose_algorithm_id != T_COSE_ALGORITHM_ES256) {
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
  }
  const pbns_cose_key *key =
      key_context(verification_key, PBNS_COSE_KEY_P256_PUBLIC);
  if (key == NULL) {
    return T_COSE_ERR_WRONG_TYPE_OF_KEY;
  }
  if (hash_to_verify.ptr == NULL || hash_to_verify.len != PBNS_SHA256_SIZE ||
      signature.ptr == NULL || signature.len != PBNS_ES256_SIGNATURE_SIZE) {
    return T_COSE_ERR_INVALID_ARGUMENT;
  }

  uint8_t sec1[PBNS_SEC1_P256_SIZE] = {0};
  sec1[0] = 0x04U;
  memcpy(sec1 + 1U, key->x, sizeof(key->x));
  memcpy(sec1 + 1U + sizeof(key->x), key->y, sizeof(key->y));
  mbedtls_ecp_group group;
  mbedtls_ecp_point point;
  mbedtls_mpi r;
  mbedtls_mpi s;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&point);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
  if (result == 0) {
    result = mbedtls_ecp_point_read_binary(&group, &point, sec1, sizeof(sec1));
  }
  if (result == 0) {
    result = mbedtls_mpi_read_binary(&r, signature.ptr,
                                     PBNS_COSE_P256_COORDINATE_SIZE);
  }
  if (result == 0) {
    result = mbedtls_mpi_read_binary(
        &s, (const uint8_t *)signature.ptr + PBNS_COSE_P256_COORDINATE_SIZE,
        PBNS_COSE_P256_COORDINATE_SIZE);
  }
  if (result == 0) {
    result = mbedtls_ecdsa_verify(&group, hash_to_verify.ptr,
                                  hash_to_verify.len, &point, &r, &s);
  }
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  mbedtls_ecp_point_free(&point);
  mbedtls_ecp_group_free(&group);
  memset(sec1, 0, sizeof(sec1));
  return result == 0 ? T_COSE_SUCCESS : T_COSE_ERR_SIG_VERIFY;
}

enum t_cose_err_t t_cose_crypto_sign_eddsa(struct t_cose_key signing_key,
                                           void *crypto_context,
                                           struct q_useful_buf_c tbs,
                                           struct q_useful_buf signature_buffer,
                                           struct q_useful_buf_c *signature) {
  (void)signing_key;
  (void)crypto_context;
  (void)tbs;
  (void)signature_buffer;
  if (signature != NULL) {
    *signature = NULLUsefulBufC;
  }
  return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}

enum t_cose_err_t t_cose_crypto_verify_eddsa(struct t_cose_key verification_key,
                                             void *crypto_context,
                                             struct q_useful_buf_c tbs,
                                             struct q_useful_buf_c signature) {
  (void)verification_key;
  (void)crypto_context;
  (void)tbs;
  (void)signature;
  return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}

enum t_cose_err_t t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
                                           int32_t cose_hash_alg_id) {
  if (hash_ctx == NULL) {
    return T_COSE_ERR_INVALID_ARGUMENT;
  }
  hash_ctx->context.ptr = NULL;
  hash_ctx->status = -1;
  if (cose_hash_alg_id != T_COSE_ALGORITHM_SHA_256) {
    return T_COSE_ERR_UNSUPPORTED_HASH;
  }
  mbedtls_sha256_context *context = AllocateZeroPool(sizeof(*context));
  if (context == NULL) {
    return T_COSE_ERR_INSUFFICIENT_MEMORY;
  }
  mbedtls_sha256_init(context);
  const int result = mbedtls_sha256_starts(context, 0);
  if (result != 0) {
    mbedtls_sha256_free(context);
    FreePool(context);
    return T_COSE_ERR_HASH_GENERAL_FAIL;
  }
  hash_ctx->context.ptr = context;
  hash_ctx->status = 0;
  return T_COSE_SUCCESS;
}

void t_cose_crypto_hash_update(struct t_cose_crypto_hash *hash_ctx,
                               struct q_useful_buf_c data_to_hash) {
  if (hash_ctx == NULL || hash_ctx->status != 0 ||
      hash_ctx->context.ptr == NULL || data_to_hash.ptr == NULL) {
    return;
  }
  hash_ctx->status = mbedtls_sha256_update(hash_ctx->context.ptr,
                                           data_to_hash.ptr, data_to_hash.len);
}

enum t_cose_err_t
t_cose_crypto_hash_finish(struct t_cose_crypto_hash *hash_ctx,
                          struct q_useful_buf buffer_to_hold_result,
                          struct q_useful_buf_c *hash_result) {
  if (hash_ctx == NULL || hash_result == NULL) {
    return T_COSE_ERR_INVALID_ARGUMENT;
  }
  *hash_result = NULLUsefulBufC;
  mbedtls_sha256_context *context = hash_ctx->context.ptr;
  if (context == NULL) {
    return T_COSE_ERR_HASH_GENERAL_FAIL;
  }
  enum t_cose_err_t error = T_COSE_ERR_HASH_GENERAL_FAIL;
  if (hash_ctx->status == 0) {
    if (buffer_to_hold_result.ptr == NULL ||
        buffer_to_hold_result.len < PBNS_SHA256_SIZE) {
      error = T_COSE_ERR_HASH_BUFFER_SIZE;
    } else if (mbedtls_sha256_finish(context, buffer_to_hold_result.ptr) == 0) {
      *hash_result =
          (struct q_useful_buf_c){buffer_to_hold_result.ptr, PBNS_SHA256_SIZE};
      error = T_COSE_SUCCESS;
    }
  }
  mbedtls_sha256_free(context);
  memset(context, 0, sizeof(*context));
  FreePool(context);
  hash_ctx->context.ptr = NULL;
  hash_ctx->status = -1;
  return error;
}

pbns_status pbns_cose_crypto_random_begin(const pbns_identity *identity) {
  if (identity == NULL || identity->ops == NULL ||
      identity->ops->random == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (active_random_identity != NULL) {
    return PBNS_ERR_BUSY;
  }
  active_random_identity = identity;
  return PBNS_OK;
}

void pbns_cose_crypto_random_end(void) { active_random_identity = NULL; }

int pbns_cose_crypto_random_callback(void *context, unsigned char *output,
                                     size_t length) {
  const pbns_identity *identity = context;
  if (identity == NULL) {
    identity = active_random_identity;
  }
  if (identity == NULL || output == NULL || length == 0U) {
    return -1;
  }
  return pbns_identity_random(identity, (pbns_buffer){output, 0U, length}) ==
                 PBNS_OK
             ? 0
             : -1;
}

static pbns_status private_key_allocate(pbns_cose_key *key) {
  if (key == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  mbedtls_ecp_keypair *pair = AllocateZeroPool(sizeof(*pair));
  if (pair == NULL) {
    return PBNS_ERR_RESOURCE;
  }
  mbedtls_ecp_keypair_init(pair);
  const int result = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, pair,
                                         pbns_cose_crypto_random_callback, NULL);
  if (result != 0) {
    mbedtls_ecp_keypair_free(pair);
    secure_zero(pair, sizeof(*pair));
    FreePool(pair);
    return result == MBEDTLS_ERR_ECP_RANDOM_FAILED ? PBNS_ERR_ENTROPY
                                                   : PBNS_ERR_CRYPTO;
  }
  key->magic = PBNS_COSE_KEY_MAGIC;
  key->kind = PBNS_COSE_KEY_P256_PRIVATE;
  key->backend = pair;
  key->owns_backend = true;
  key->native.key.ptr = key;
  return PBNS_OK;
}

pbns_status pbns_cose_crypto_private_generate(pbns_cose_key *key) {
  if (key == NULL || active_random_identity == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  memset(key, 0, sizeof(*key));
  return private_key_allocate(key);
}

pbns_status pbns_cose_crypto_private_export(const pbns_cose_key *private_key,
                                            pbns_cose_key *public_key) {
  if (private_key == NULL || public_key == NULL ||
      key_context(private_key->native, PBNS_COSE_KEY_P256_PRIVATE) == NULL ||
      private_key->backend == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  const mbedtls_ecp_keypair *pair = private_key->backend;
  uint8_t x[PBNS_COSE_P256_COORDINATE_SIZE] = {0};
  uint8_t y[PBNS_COSE_P256_COORDINATE_SIZE] = {0};
  const int x_result = mbedtls_mpi_write_binary(
      &pair->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), x, sizeof(x));
  const int y_result = mbedtls_mpi_write_binary(
      &pair->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), y, sizeof(y));
  const pbns_status status = x_result == 0 && y_result == 0
                                 ? pbns_cose_key_from_p256_public(
                                       public_key, (pbns_view){x, sizeof(x)},
                                       (pbns_view){y, sizeof(y)})
                                 : PBNS_ERR_CRYPTO;
  secure_zero(y, sizeof(y));
  secure_zero(x, sizeof(x));
  return status;
}

void pbns_cose_crypto_key_release(pbns_cose_key *key) {
  if (key == NULL) {
    return;
  }
  const bool owns_self = key->magic == PBNS_COSE_KEY_MAGIC && key->owns_self;
  if (key->magic == PBNS_COSE_KEY_MAGIC && key->owns_backend &&
      key->backend != NULL) {
    if (key->kind == PBNS_COSE_KEY_P256_PRIVATE) {
      mbedtls_ecp_keypair *pair = key->backend;
      mbedtls_ecp_keypair_free(pair);
      secure_zero(pair, sizeof(*pair));
      FreePool(pair);
    } else if (key->kind == PBNS_COSE_KEY_SYMMETRIC) {
      pbns_cose_symmetric_key *symmetric = key->backend;
      secure_zero(symmetric, sizeof(*symmetric));
      FreePool(symmetric);
    }
  }
  secure_zero(key, sizeof(*key));
  if (owns_self) {
    FreePool(key);
  }
}

static pbns_cose_key *key_allocate_owned(void) {
  pbns_cose_key *key = AllocateZeroPool(sizeof(*key));
  if (key != NULL) {
    key->owns_self = true;
  }
  return key;
}

static const pbns_cose_symmetric_key *
symmetric_key_context(struct t_cose_key native) {
  const pbns_cose_key *key = key_context(native, PBNS_COSE_KEY_SYMMETRIC);
  if (key == NULL || key->backend == NULL) {
    return NULL;
  }
  const pbns_cose_symmetric_key *symmetric = key->backend;
  return symmetric->length == PBNS_AES128_KEY_SIZE ? symmetric : NULL;
}

enum t_cose_err_t t_cose_crypto_generate_ec_key(int32_t cose_ec_curve_id,
                                                struct t_cose_key *key) {
  if (key == NULL || cose_ec_curve_id != T_COSE_ELLIPTIC_CURVE_P_256) {
    return T_COSE_ERR_UNSUPPORTED_ELLIPTIC_CURVE_ALG;
  }
  pbns_cose_key *owned = key_allocate_owned();
  if (owned == NULL) {
    return T_COSE_ERR_INSUFFICIENT_MEMORY;
  }
  const pbns_status status = pbns_cose_crypto_private_generate(owned);
  if (status != PBNS_OK) {
    secure_zero(owned, sizeof(*owned));
    FreePool(owned);
    return status == PBNS_ERR_ENTROPY ? T_COSE_ERR_RNG_FAILED
                                      : T_COSE_ERR_KEY_GENERATION_FAILED;
  }
  owned->owns_self = true;
  *key = owned->native;
  return T_COSE_SUCCESS;
}

enum t_cose_err_t t_cose_crypto_get_random(struct q_useful_buf buffer,
                                           size_t number,
                                           struct q_useful_buf_c *random) {
  if (random == NULL || buffer.ptr == NULL || number == 0U ||
      number > buffer.len) {
    return T_COSE_ERR_INVALID_ARGUMENT;
  }
  *random = NULLUsefulBufC;
  if (pbns_cose_crypto_random_callback(NULL, buffer.ptr, number) != 0) {
    return T_COSE_ERR_RNG_FAILED;
  }
  *random = (struct q_useful_buf_c){buffer.ptr, number};
  return T_COSE_SUCCESS;
}

enum t_cose_err_t
t_cose_crypto_make_symmetric_key_handle(int32_t cose_algorithm_id,
                                        struct q_useful_buf_c symmetric_key,
                                        struct t_cose_key *key_handle) {
  if (key_handle == NULL || symmetric_key.ptr == NULL ||
      symmetric_key.len != PBNS_AES128_KEY_SIZE) {
    return T_COSE_ERR_WRONG_TYPE_OF_KEY;
  }
  if (cose_algorithm_id != T_COSE_ALGORITHM_A128KW &&
      cose_algorithm_id != T_COSE_ALGORITHM_A128GCM) {
    return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
  }
  pbns_cose_key *owned = key_allocate_owned();
  pbns_cose_symmetric_key *backend = AllocateZeroPool(sizeof(*backend));
  if (owned == NULL || backend == NULL) {
    if (backend != NULL) {
      FreePool(backend);
    }
    if (owned != NULL) {
      FreePool(owned);
    }
    return T_COSE_ERR_INSUFFICIENT_MEMORY;
  }
  backend->length = symmetric_key.len;
  memcpy(backend->bytes, symmetric_key.ptr, symmetric_key.len);
  owned->magic = PBNS_COSE_KEY_MAGIC;
  owned->kind = PBNS_COSE_KEY_SYMMETRIC;
  owned->backend = backend;
  owned->owns_backend = true;
  owned->owns_self = true;
  owned->native.key.ptr = owned;
  *key_handle = owned->native;
  return T_COSE_SUCCESS;
}

enum t_cose_err_t
t_cose_crypto_export_symmetric_key(struct t_cose_key key,
                                   struct q_useful_buf key_buffer,
                                   struct q_useful_buf_c *key_bytes) {
  const pbns_cose_symmetric_key *symmetric = symmetric_key_context(key);
  if (symmetric == NULL || key_bytes == NULL) {
    return T_COSE_ERR_WRONG_TYPE_OF_KEY;
  }
  *key_bytes = NULLUsefulBufC;
  if (key_buffer.ptr == NULL || key_buffer.len < symmetric->length) {
    return T_COSE_ERR_TOO_SMALL;
  }
  memcpy(key_buffer.ptr, symmetric->bytes, symmetric->length);
  *key_bytes = (struct q_useful_buf_c){key_buffer.ptr, symmetric->length};
  return T_COSE_SUCCESS;
}

void t_cose_crypto_free_symmetric_key(struct t_cose_key key) {
  pbns_cose_key *context = key.key.ptr;
  if (key_context(key, PBNS_COSE_KEY_SYMMETRIC) != NULL) {
    pbns_cose_crypto_key_release(context);
  }
}

static int public_point_from_key(struct t_cose_key native,
                                 mbedtls_ecp_group *group,
                                 mbedtls_ecp_point *point) {
  if (group == NULL || point == NULL ||
      mbedtls_ecp_group_load(group, MBEDTLS_ECP_DP_SECP256R1) != 0) {
    return -1;
  }
  const pbns_cose_key *public_key =
      key_context(native, PBNS_COSE_KEY_P256_PUBLIC);
  if (public_key != NULL) {
    uint8_t sec1[PBNS_SEC1_P256_SIZE] = {0};
    sec1[0] = 0x04U;
    memcpy(sec1 + 1U, public_key->x, sizeof(public_key->x));
    memcpy(sec1 + 1U + sizeof(public_key->x), public_key->y,
           sizeof(public_key->y));
    const int result =
        mbedtls_ecp_point_read_binary(group, point, sec1, sizeof(sec1));
    secure_zero(sec1, sizeof(sec1));
    return result;
  }
  const pbns_cose_key *private_key =
      key_context(native, PBNS_COSE_KEY_P256_PRIVATE);
  if (private_key == NULL || private_key->backend == NULL) {
    return -1;
  }
  const mbedtls_ecp_keypair *pair = private_key->backend;
  return mbedtls_ecp_copy(point, &pair->MBEDTLS_PRIVATE(Q));
}

enum t_cose_err_t t_cose_crypto_ecdh(struct t_cose_key private_key,
                                     struct t_cose_key public_key,
                                     struct q_useful_buf shared_key_buf,
                                     struct q_useful_buf_c *shared_key) {
  const pbns_cose_key *private_context =
      key_context(private_key, PBNS_COSE_KEY_P256_PRIVATE);
  if (private_context == NULL || private_context->backend == NULL ||
      shared_key == NULL) {
    return T_COSE_ERR_WRONG_TYPE_OF_KEY;
  }
  *shared_key = NULLUsefulBufC;
  if (shared_key_buf.ptr == NULL ||
      shared_key_buf.len < PBNS_COSE_P256_COORDINATE_SIZE) {
    return T_COSE_ERR_TOO_SMALL;
  }
  const mbedtls_ecp_keypair *pair = private_context->backend;
  mbedtls_ecp_group group;
  mbedtls_ecp_point point;
  mbedtls_mpi secret;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&point);
  mbedtls_mpi_init(&secret);
  int result = public_point_from_key(public_key, &group, &point);
  if (result == 0) {
    result = mbedtls_ecdh_compute_shared(
        &group, &secret, &point, &pair->MBEDTLS_PRIVATE(d),
        pbns_cose_crypto_random_callback, NULL);
  }
  if (result == 0) {
    result = mbedtls_mpi_write_binary(&secret, shared_key_buf.ptr,
                                      PBNS_COSE_P256_COORDINATE_SIZE);
  }
  mbedtls_mpi_free(&secret);
  mbedtls_ecp_point_free(&point);
  mbedtls_ecp_group_free(&group);
  if (result != 0) {
    secure_zero(shared_key_buf.ptr, PBNS_COSE_P256_COORDINATE_SIZE);
    return result == MBEDTLS_ERR_ECP_RANDOM_FAILED ? T_COSE_ERR_RNG_FAILED
                                                   : T_COSE_ERR_FAIL;
  }
  *shared_key = (struct q_useful_buf_c){shared_key_buf.ptr,
                                        PBNS_COSE_P256_COORDINATE_SIZE};
  return T_COSE_SUCCESS;
}

enum t_cose_err_t t_cose_crypto_hkdf(int32_t cose_hash_algorithm_id,
                                     struct q_useful_buf_c salt,
                                     struct q_useful_buf_c ikm,
                                     struct q_useful_buf_c info,
                                     struct q_useful_buf okm_buffer) {
  if (cose_hash_algorithm_id != T_COSE_ALGORITHM_SHA_256) {
    return T_COSE_ERR_UNSUPPORTED_HASH;
  }
  if ((salt.ptr == NULL && salt.len != 0U) || ikm.ptr == NULL ||
      ikm.len == 0U || (info.ptr == NULL && info.len != 0U) ||
      okm_buffer.ptr == NULL || okm_buffer.len == 0U) {
    return T_COSE_ERR_INVALID_ARGUMENT;
  }
  const mbedtls_md_info_t *info_sha256 =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (info_sha256 == NULL) {
    return T_COSE_ERR_UNSUPPORTED_HASH;
  }
  return mbedtls_hkdf(info_sha256, salt.ptr, salt.len, ikm.ptr, ikm.len,
                      info.ptr, info.len, okm_buffer.ptr, okm_buffer.len) == 0
             ? T_COSE_SUCCESS
             : T_COSE_ERR_HKDF_FAIL;
}

enum t_cose_err_t
t_cose_crypto_kw_wrap(int32_t cose_algorithm_id, struct t_cose_key kek,
                      struct q_useful_buf_c plaintext,
                      struct q_useful_buf ciphertext_buffer,
                      struct q_useful_buf_c *ciphertext_result) {
  const pbns_cose_symmetric_key *symmetric = symmetric_key_context(kek);
  if (cose_algorithm_id != T_COSE_ALGORITHM_A128KW) {
    return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
  }
  if (symmetric == NULL || plaintext.ptr == NULL || ciphertext_result == NULL ||
      plaintext.len < 16U || plaintext.len > SIZE_MAX - 8U ||
      plaintext.len % 8U != 0U) {
    return T_COSE_ERR_WRONG_TYPE_OF_KEY;
  }
  *ciphertext_result = NULLUsefulBufC;
  if (ciphertext_buffer.ptr == NULL ||
      ciphertext_buffer.len < plaintext.len + 8U) {
    return T_COSE_ERR_TOO_SMALL;
  }
  mbedtls_nist_kw_context context;
  mbedtls_nist_kw_init(&context);
  size_t written = 0U;
  int result =
      mbedtls_nist_kw_setkey(&context, MBEDTLS_CIPHER_ID_AES, symmetric->bytes,
                             (unsigned int)(PBNS_AES128_KEY_SIZE * 8U), 1);
  if (result == 0) {
    result = mbedtls_nist_kw_wrap(&context, MBEDTLS_KW_MODE_KW, plaintext.ptr,
                                  plaintext.len, ciphertext_buffer.ptr,
                                  &written, ciphertext_buffer.len);
  }
  mbedtls_nist_kw_free(&context);
  if (result != 0 || written != plaintext.len + 8U) {
    secure_zero(ciphertext_buffer.ptr, ciphertext_buffer.len);
    return T_COSE_ERR_KW_FAILED;
  }
  *ciphertext_result = (struct q_useful_buf_c){ciphertext_buffer.ptr, written};
  return T_COSE_SUCCESS;
}

enum t_cose_err_t
t_cose_crypto_kw_unwrap(int32_t cose_algorithm_id, struct t_cose_key kek,
                        struct q_useful_buf_c ciphertext,
                        struct q_useful_buf plaintext_buffer,
                        struct q_useful_buf_c *plaintext_result) {
  const pbns_cose_symmetric_key *symmetric = symmetric_key_context(kek);
  if (cose_algorithm_id != T_COSE_ALGORITHM_A128KW) {
    return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
  }
  if (symmetric == NULL || ciphertext.ptr == NULL || plaintext_result == NULL ||
      ciphertext.len < 24U || ciphertext.len % 8U != 0U) {
    return T_COSE_ERR_WRONG_TYPE_OF_KEY;
  }
  *plaintext_result = NULLUsefulBufC;
  if (plaintext_buffer.ptr == NULL ||
      plaintext_buffer.len < ciphertext.len - 8U) {
    return T_COSE_ERR_TOO_SMALL;
  }
  mbedtls_nist_kw_context context;
  mbedtls_nist_kw_init(&context);
  size_t written = 0U;
  int result =
      mbedtls_nist_kw_setkey(&context, MBEDTLS_CIPHER_ID_AES, symmetric->bytes,
                             (unsigned int)(PBNS_AES128_KEY_SIZE * 8U), 0);
  if (result == 0) {
    result = mbedtls_nist_kw_unwrap(
        &context, MBEDTLS_KW_MODE_KW, ciphertext.ptr, ciphertext.len,
        plaintext_buffer.ptr, &written, plaintext_buffer.len);
  }
  mbedtls_nist_kw_free(&context);
  if (result != 0 || written != ciphertext.len - 8U) {
    secure_zero(plaintext_buffer.ptr, plaintext_buffer.len);
    return T_COSE_ERR_DATA_AUTH_FAILED;
  }
  *plaintext_result = (struct q_useful_buf_c){plaintext_buffer.ptr, written};
  return T_COSE_SUCCESS;
}

enum t_cose_err_t t_cose_crypto_aead_encrypt(
    int32_t cose_algorithm_id, struct t_cose_key key,
    struct q_useful_buf_c nonce, struct q_useful_buf_c aad,
    struct q_useful_buf_c plaintext, struct q_useful_buf ciphertext_buffer,
    struct q_useful_buf_c *ciphertext) {
  if (cose_algorithm_id != T_COSE_ALGORITHM_A128GCM) {
    return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
  }
  if (ciphertext == NULL) {
    return T_COSE_ERR_INVALID_ARGUMENT;
  }
  *ciphertext = NULLUsefulBufC;
  if (ciphertext_buffer.ptr == NULL) {
    if (plaintext.len > SIZE_MAX - PBNS_GCM_TAG_SIZE) {
      return T_COSE_ERR_TOO_SMALL;
    }
    ciphertext->len = plaintext.len + PBNS_GCM_TAG_SIZE;
    return T_COSE_SUCCESS;
  }
  const pbns_cose_symmetric_key *symmetric = symmetric_key_context(key);
  if (symmetric == NULL || nonce.ptr == NULL ||
      nonce.len != PBNS_GCM_NONCE_SIZE || (aad.ptr == NULL && aad.len != 0U) ||
      (plaintext.ptr == NULL && plaintext.len != 0U) ||
      plaintext.len > SIZE_MAX - PBNS_GCM_TAG_SIZE ||
      ciphertext_buffer.len < plaintext.len + PBNS_GCM_TAG_SIZE) {
    return T_COSE_ERR_INVALID_ARGUMENT;
  }
  mbedtls_gcm_context context;
  mbedtls_gcm_init(&context);
  int result =
      mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, symmetric->bytes,
                         (unsigned int)(PBNS_AES128_KEY_SIZE * 8U));
  if (result == 0) {
    result = mbedtls_gcm_crypt_and_tag(
        &context, MBEDTLS_GCM_ENCRYPT, plaintext.len, nonce.ptr, nonce.len,
        aad.ptr, aad.len, plaintext.ptr, ciphertext_buffer.ptr,
        PBNS_GCM_TAG_SIZE, (uint8_t *)ciphertext_buffer.ptr + plaintext.len);
  }
  mbedtls_gcm_free(&context);
  if (result != 0) {
    secure_zero(ciphertext_buffer.ptr, ciphertext_buffer.len);
    return T_COSE_ERR_ENCRYPT_FAIL;
  }
  *ciphertext = (struct q_useful_buf_c){ciphertext_buffer.ptr,
                                        plaintext.len + PBNS_GCM_TAG_SIZE};
  return T_COSE_SUCCESS;
}

enum t_cose_err_t t_cose_crypto_aead_decrypt(
    int32_t cose_algorithm_id, struct t_cose_key key,
    struct q_useful_buf_c nonce, struct q_useful_buf_c aad,
    struct q_useful_buf_c ciphertext, struct q_useful_buf plaintext_buffer,
    struct q_useful_buf_c *plaintext) {
  if (cose_algorithm_id != T_COSE_ALGORITHM_A128GCM) {
    return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
  }
  const pbns_cose_symmetric_key *symmetric = symmetric_key_context(key);
  if (symmetric == NULL || nonce.ptr == NULL ||
      nonce.len != PBNS_GCM_NONCE_SIZE || (aad.ptr == NULL && aad.len != 0U) ||
      ciphertext.ptr == NULL || ciphertext.len < PBNS_GCM_TAG_SIZE ||
      plaintext_buffer.ptr == NULL ||
      plaintext_buffer.len < ciphertext.len - PBNS_GCM_TAG_SIZE ||
      plaintext == NULL) {
    return T_COSE_ERR_INVALID_ARGUMENT;
  }
  *plaintext = NULLUsefulBufC;
  const size_t plaintext_length = ciphertext.len - PBNS_GCM_TAG_SIZE;
  mbedtls_gcm_context context;
  mbedtls_gcm_init(&context);
  int result =
      mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, symmetric->bytes,
                         (unsigned int)(PBNS_AES128_KEY_SIZE * 8U));
  if (result == 0) {
    result = mbedtls_gcm_auth_decrypt(
        &context, plaintext_length, nonce.ptr, nonce.len, aad.ptr, aad.len,
        (const uint8_t *)ciphertext.ptr + plaintext_length, PBNS_GCM_TAG_SIZE,
        ciphertext.ptr, plaintext_buffer.ptr);
  }
  mbedtls_gcm_free(&context);
  if (result != 0) {
    secure_zero(plaintext_buffer.ptr, plaintext_buffer.len);
    return T_COSE_ERR_DATA_AUTH_FAILED;
  }
  *plaintext = (struct q_useful_buf_c){plaintext_buffer.ptr, plaintext_length};
  return T_COSE_SUCCESS;
}

enum t_cose_err_t t_cose_crypto_non_aead_encrypt(
    int32_t cose_algorithm_id, struct t_cose_key key,
    struct q_useful_buf_c nonce, struct q_useful_buf_c plaintext,
    struct q_useful_buf ciphertext_buffer, struct q_useful_buf_c *ciphertext) {
  (void)cose_algorithm_id;
  (void)key;
  (void)nonce;
  (void)plaintext;
  (void)ciphertext_buffer;
  if (ciphertext != NULL) {
    *ciphertext = NULLUsefulBufC;
  }
  return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
}

enum t_cose_err_t t_cose_crypto_non_aead_decrypt(
    int32_t cose_algorithm_id, struct t_cose_key key,
    struct q_useful_buf_c nonce, struct q_useful_buf_c ciphertext,
    struct q_useful_buf plaintext_buffer, struct q_useful_buf_c *plaintext) {
  (void)cose_algorithm_id;
  (void)key;
  (void)nonce;
  (void)ciphertext;
  (void)plaintext_buffer;
  if (plaintext != NULL) {
    *plaintext = NULLUsefulBufC;
  }
  return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
}

enum t_cose_err_t t_cose_crypto_import_ec2_pubkey(
    int32_t cose_ec_curve_id, struct q_useful_buf_c x_coord,
    struct q_useful_buf_c y_coord, bool y_bool, struct t_cose_key *key_handle) {
  const bool compressed = y_coord.ptr == NULL && y_coord.len == 0U;
  if (cose_ec_curve_id != T_COSE_ELLIPTIC_CURVE_P_256 || x_coord.ptr == NULL ||
      x_coord.len != PBNS_COSE_P256_COORDINATE_SIZE ||
      (!compressed && (y_coord.ptr == NULL ||
                       y_coord.len != PBNS_COSE_P256_COORDINATE_SIZE)) ||
      key_handle == NULL) {
    return T_COSE_ERR_PRIVATE_KEY_IMPORT_FAILED;
  }
  uint8_t sec1[PBNS_SEC1_P256_SIZE] = {0};
  sec1[0] = compressed ? (uint8_t)(y_bool ? 0x03U : 0x02U) : 0x04U;
  memcpy(sec1 + 1U, x_coord.ptr, x_coord.len);
  size_t sec1_length = 1U + x_coord.len;
  if (!compressed) {
    memcpy(sec1 + sec1_length, y_coord.ptr, y_coord.len);
    sec1_length += y_coord.len;
  }
  mbedtls_ecp_group group;
  mbedtls_ecp_point point;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&point);
  int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
  if (result == 0) {
    result = mbedtls_ecp_point_read_binary(&group, &point, sec1, sec1_length);
  }
  if (result == 0) {
    result = mbedtls_ecp_check_pubkey(&group, &point);
  }
  uint8_t y[PBNS_COSE_P256_COORDINATE_SIZE] = {0};
  if (result == 0) {
    result = mbedtls_mpi_write_binary(&point.MBEDTLS_PRIVATE(Y), y, sizeof(y));
  }
  mbedtls_ecp_point_free(&point);
  mbedtls_ecp_group_free(&group);
  secure_zero(sec1, sizeof(sec1));
  if (result != 0) {
    secure_zero(y, sizeof(y));
    return T_COSE_ERR_PRIVATE_KEY_IMPORT_FAILED;
  }
  pbns_cose_key *owned = key_allocate_owned();
  if (owned == NULL) {
    secure_zero(y, sizeof(y));
    return T_COSE_ERR_INSUFFICIENT_MEMORY;
  }
  const pbns_status status = pbns_cose_key_from_p256_public(
      owned, (pbns_view){x_coord.ptr, x_coord.len}, (pbns_view){y, sizeof(y)});
  secure_zero(y, sizeof(y));
  if (status != PBNS_OK) {
    FreePool(owned);
    return T_COSE_ERR_PRIVATE_KEY_IMPORT_FAILED;
  }
  owned->owns_self = true;
  *key_handle = owned->native;
  return T_COSE_SUCCESS;
}

enum t_cose_err_t t_cose_crypto_export_ec2_key(struct t_cose_key key_handle,
                                               int32_t *curve,
                                               struct q_useful_buf x_coord_buf,
                                               struct q_useful_buf_c *x_coord,
                                               struct q_useful_buf y_coord_buf,
                                               struct q_useful_buf_c *y_coord,
                                               bool *y_bool) {
  if (curve == NULL || x_coord == NULL || y_coord == NULL || y_bool == NULL ||
      x_coord_buf.ptr == NULL ||
      x_coord_buf.len < PBNS_COSE_P256_COORDINATE_SIZE ||
      y_coord_buf.ptr == NULL ||
      y_coord_buf.len < PBNS_COSE_P256_COORDINATE_SIZE) {
    return T_COSE_ERR_TOO_SMALL;
  }
  uint8_t x[PBNS_COSE_P256_COORDINATE_SIZE] = {0};
  uint8_t y[PBNS_COSE_P256_COORDINATE_SIZE] = {0};
  const pbns_cose_key *public_key =
      key_context(key_handle, PBNS_COSE_KEY_P256_PUBLIC);
  int result = -1;
  if (public_key != NULL) {
    memcpy(x, public_key->x, sizeof(x));
    memcpy(y, public_key->y, sizeof(y));
    result = 0;
  } else {
    const pbns_cose_key *private_key =
        key_context(key_handle, PBNS_COSE_KEY_P256_PRIVATE);
    if (private_key != NULL && private_key->backend != NULL) {
      const mbedtls_ecp_keypair *pair = private_key->backend;
      result = mbedtls_mpi_write_binary(
          &pair->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), x, sizeof(x));
      if (result == 0) {
        result = mbedtls_mpi_write_binary(
            &pair->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), y, sizeof(y));
      }
    }
  }
  if (result != 0) {
    secure_zero(y, sizeof(y));
    secure_zero(x, sizeof(x));
    return T_COSE_ERR_KEY_EXPORT_FAILED;
  }
  memcpy(x_coord_buf.ptr, x, sizeof(x));
  memcpy(y_coord_buf.ptr, y, sizeof(y));
  *curve = T_COSE_ELLIPTIC_CURVE_P_256;
  *x_coord = (struct q_useful_buf_c){x_coord_buf.ptr, sizeof(x)};
  *y_coord = (struct q_useful_buf_c){y_coord_buf.ptr, sizeof(y)};
  *y_bool = false;
  secure_zero(y, sizeof(y));
  secure_zero(x, sizeof(x));
  return T_COSE_SUCCESS;
}

void t_cose_crypto_free_ec_key(struct t_cose_key key_handle) {
  pbns_cose_key *context = key_handle.key.ptr;
  if (key_context(key_handle, PBNS_COSE_KEY_P256_PUBLIC) != NULL ||
      key_context(key_handle, PBNS_COSE_KEY_P256_PRIVATE) != NULL) {
    pbns_cose_crypto_key_release(context);
  }
}
