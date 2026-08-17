#include "PbnsSoftwareIdentity.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "PbnsIdentityRecord.h"
#include "mbedtls/asn1.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "qcbor/qcbor.h"

#define PBNS_P256_COORDINATE_SIZE 32U
#define PBNS_ES256_DER_SIGNATURE_MAX 80U
#define PBNS_ES256_RAW_SIGNATURE_SIZE 64U

_Static_assert(PBNS_IDENTITY_RECORD_MAX_SIZE <= 1024U,
               "identity record exceeds the stack bound");

typedef struct pbns_software_identity_context {
  mbedtls_pk_context key;
  pbns_software_identity_environment environment;
  uint8_t public_cose_key[PBNS_IDENTITY_PUBLIC_COSE_MAX];
  size_t public_cose_key_length;
  uint8_t fingerprint[PBNS_IDENTITY_FINGERPRINT_SIZE];
} pbns_software_identity_context;

static void secure_zero(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  while (length > 0U) {
    *bytes = 0U;
    ++bytes;
    --length;
  }
}

static bool
environment_is_valid(const pbns_software_identity_environment *environment) {
  return environment != NULL && environment->store.read != NULL &&
         environment->store.write != NULL &&
         environment->store.remove != NULL &&
         environment->store.context != NULL &&
         environment->memory.allocate != NULL &&
         environment->memory.release != NULL &&
         environment->memory.context != NULL &&
         environment->random_fill != NULL;
}

static bool identity_is_empty(const pbns_identity *identity) {
  return identity != NULL && identity->ops == NULL &&
         identity->context == NULL &&
         identity->assurance == PBNS_IDENTITY_INVALID;
}

static bool constant_time_equal(const uint8_t *first, const uint8_t *second,
                                size_t length) {
  uint8_t difference = 0U;
  for (size_t index = 0U; index < length; ++index) {
    difference |= (uint8_t)(first[index] ^ second[index]);
  }
  return difference == 0U;
}

static int mbedtls_random(void *context, unsigned char *output, size_t length) {
  pbns_software_identity_context *identity = context;
  const pbns_status status = identity->environment.random_fill(
      identity->environment.random_state.bytes,
      (pbns_buffer){output, 0U, length});
  return status == PBNS_OK ? 0 : MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
}

static bool key_is_p256_private(const mbedtls_pk_context *key) {
  if (!mbedtls_pk_can_do(key, MBEDTLS_PK_ECDSA)) {
    return false;
  }
  mbedtls_ecp_keypair *ec = mbedtls_pk_ec(*key);
  return ec != NULL &&
         ec->MBEDTLS_PRIVATE(grp).id == MBEDTLS_ECP_DP_SECP256R1 &&
         mbedtls_mpi_cmp_int(&ec->MBEDTLS_PRIVATE(d), 0) > 0;
}

static pbns_status encode_public_key(pbns_software_identity_context *identity) {
  mbedtls_ecp_keypair *ec = mbedtls_pk_ec(identity->key);
  if (ec == NULL || ec->MBEDTLS_PRIVATE(grp).id != MBEDTLS_ECP_DP_SECP256R1) {
    return PBNS_ERR_CRYPTO;
  }
  uint8_t x[PBNS_P256_COORDINATE_SIZE] = {0};
  uint8_t y[PBNS_P256_COORDINATE_SIZE] = {0};
  if (mbedtls_mpi_write_binary(&ec->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), x,
                               sizeof(x)) != 0 ||
      mbedtls_mpi_write_binary(&ec->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), y,
                               sizeof(y)) != 0) {
    secure_zero(x, sizeof(x));
    secure_zero(y, sizeof(y));
    return PBNS_ERR_CRYPTO;
  }

  QCBOREncodeContext encoder = {0};
  UsefulBufC encoded = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){identity->public_cose_key,
                                         sizeof(identity->public_cose_key)});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddInt64ToMapN(&encoder, 1, 2);
  QCBOREncode_AddInt64ToMapN(&encoder, -1, 1);
  QCBOREncode_AddBytesToMapN(&encoder, -2, (UsefulBufC){x, sizeof(x)});
  QCBOREncode_AddBytesToMapN(&encoder, -3, (UsefulBufC){y, sizeof(y)});
  QCBOREncode_CloseMap(&encoder);
  const QCBORError error = QCBOREncode_Finish(&encoder, &encoded);
  secure_zero(x, sizeof(x));
  secure_zero(y, sizeof(y));
  if (error != QCBOR_SUCCESS || encoded.len == 0U ||
      encoded.len > sizeof(identity->public_cose_key)) {
    return PBNS_ERR_CRYPTO;
  }
  identity->public_cose_key_length = encoded.len;
  if (mbedtls_sha256(identity->public_cose_key,
                     identity->public_cose_key_length, identity->fingerprint,
                     0) != 0) {
    return PBNS_ERR_CRYPTO;
  }
  return PBNS_OK;
}

static pbns_status parse_raw_signature(uint8_t *der, size_t der_length,
                                       pbns_buffer output) {
  unsigned char *cursor = der;
  const unsigned char *end = der + der_length;
  size_t sequence_length = 0U;
  mbedtls_mpi r;
  mbedtls_mpi s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  int result =
      mbedtls_asn1_get_tag(&cursor, end, &sequence_length,
                           MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (result == 0 && sequence_length == (size_t)(end - cursor)) {
    result = mbedtls_asn1_get_mpi(&cursor, end, &r);
  }
  if (result == 0) {
    result = mbedtls_asn1_get_mpi(&cursor, end, &s);
  }
  if (result == 0 && cursor == end && mbedtls_mpi_bitlen(&r) <= 256U &&
      mbedtls_mpi_bitlen(&s) <= 256U) {
    result =
        mbedtls_mpi_write_binary(&r, output.ptr, PBNS_P256_COORDINATE_SIZE);
    if (result == 0) {
      result =
          mbedtls_mpi_write_binary(&s, output.ptr + PBNS_P256_COORDINATE_SIZE,
                                   PBNS_P256_COORDINATE_SIZE);
    }
  } else if (result == 0) {
    result = MBEDTLS_ERR_ASN1_INVALID_DATA;
  }
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  return result == 0 ? PBNS_OK : PBNS_ERR_CRYPTO;
}

static pbns_status software_public(void *context, pbns_buffer output,
                                   size_t *written) {
  const pbns_software_identity_context *identity = context;
  if (output.cap < identity->public_cose_key_length) {
    return PBNS_ERR_LIMIT;
  }
  memcpy(output.ptr, identity->public_cose_key,
         identity->public_cose_key_length);
  *written = identity->public_cose_key_length;
  return PBNS_OK;
}

static pbns_status software_fingerprint(void *context, pbns_buffer output) {
  const pbns_software_identity_context *identity = context;
  memcpy(output.ptr, identity->fingerprint, sizeof(identity->fingerprint));
  return PBNS_OK;
}

static pbns_status software_sign(void *context, pbns_view digest,
                                 pbns_buffer signature, size_t *written) {
  pbns_software_identity_context *identity = context;
  uint8_t der[PBNS_ES256_DER_SIGNATURE_MAX] = {0};
  size_t der_length = 0U;
  const int result =
      mbedtls_pk_sign(&identity->key, MBEDTLS_MD_SHA256, digest.ptr, digest.len,
                      der, sizeof(der), &der_length, mbedtls_random, identity);
  if (result != 0) {
    secure_zero(der, sizeof(der));
    return result == MBEDTLS_ERR_ENTROPY_SOURCE_FAILED ? PBNS_ERR_ENTROPY
                                                       : PBNS_ERR_CRYPTO;
  }
  const pbns_status status = parse_raw_signature(der, der_length, signature);
  secure_zero(der, sizeof(der));
  if (status == PBNS_OK) {
    *written = PBNS_ES256_RAW_SIGNATURE_SIZE;
  }
  return status;
}

static pbns_status software_random(void *context, pbns_buffer output) {
  pbns_software_identity_context *identity = context;
  return identity->environment.random_fill(
      identity->environment.random_state.bytes, output);
}

static void software_close(void *context) {
  pbns_software_identity_context *identity = context;
  pbns_identity_memory memory = identity->environment.memory;
  mbedtls_pk_free(&identity->key);
  secure_zero(identity, sizeof(*identity));
  memory.release(memory.context, identity, sizeof(*identity));
}

static const pbns_identity_ops software_ops = {
    .public_cose_key = software_public,
    .fingerprint = software_fingerprint,
    .sign_digest = software_sign,
    .random = software_random,
    .close = software_close,
};

static pbns_software_identity_context *
allocate_context(const pbns_software_identity_environment *environment) {
  pbns_software_identity_context *identity = environment->memory.allocate(
      environment->memory.context, sizeof(pbns_software_identity_context));
  if (identity == NULL) {
    return NULL;
  }
  memset(identity, 0, sizeof(*identity));
  identity->environment = *environment;
  mbedtls_pk_init(&identity->key);
  return identity;
}

static void release_context(pbns_software_identity_context *identity) {
  if (identity != NULL) {
    software_close(identity);
  }
}

static pbns_status finish_identity(pbns_software_identity_context *context,
                                   pbns_identity *identity) {
  const pbns_status status = pbns_identity_open(
      identity, &software_ops, context, PBNS_IDENTITY_SOFTWARE);
  if (status != PBNS_OK) {
    release_context(context);
  }
  return status;
}

static pbns_status
read_record(const pbns_software_identity_environment *environment,
            uint8_t *encoded, size_t *encoded_length) {
  uint32_t attributes = 0U;
  const pbns_status status = environment->store.read(
      environment->store.context,
      (pbns_buffer){encoded, 0U, PBNS_IDENTITY_RECORD_MAX_SIZE}, encoded_length,
      &attributes);
  if (status != PBNS_OK) {
    return status;
  }
  if (*encoded_length == 0U ||
      *encoded_length > PBNS_IDENTITY_RECORD_MAX_SIZE ||
      attributes != PBNS_IDENTITY_VARIABLE_ATTRIBUTES) {
    return PBNS_ERR_AUTHENTICATION;
  }
  return PBNS_OK;
}

pbns_status pbns_software_identity_create(
    const pbns_software_identity_environment *environment,
    pbns_identity *identity) {
  if (!environment_is_valid(environment) || !identity_is_empty(identity)) {
    return PBNS_ERR_ARGUMENT;
  }
  uint8_t existing[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
  size_t existing_length = 0U;
  uint32_t existing_attributes = 0U;
  pbns_status status = environment->store.read(
      environment->store.context, (pbns_buffer){existing, 0U, sizeof(existing)},
      &existing_length, &existing_attributes);
  secure_zero(existing, sizeof(existing));
  if (status == PBNS_OK || status == PBNS_ERR_LIMIT) {
    return PBNS_ERR_STATE;
  }
  if (status != PBNS_ERR_STATE) {
    return status;
  }

  pbns_software_identity_context *context = allocate_context(environment);
  if (context == NULL) {
    return PBNS_ERR_RESOURCE;
  }
  const mbedtls_pk_info_t *key_info =
      mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
  if (key_info == NULL || mbedtls_pk_setup(&context->key, key_info) != 0) {
    release_context(context);
    return PBNS_ERR_CRYPTO;
  }
  if (mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(context->key),
                          mbedtls_random, context) != 0) {
    release_context(context);
    return PBNS_ERR_ENTROPY;
  }
  status = encode_public_key(context);
  if (status != PBNS_OK) {
    release_context(context);
    return status;
  }

  uint8_t private_der[PBNS_IDENTITY_PRIVATE_DER_MAX] = {0};
  const int private_length =
      mbedtls_pk_write_key_der(&context->key, private_der, sizeof(private_der));
  uint8_t encoded[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
  size_t encoded_length = 0U;
  if (private_length <= 0 || (size_t)private_length > sizeof(private_der)) {
    status = PBNS_ERR_CRYPTO;
  } else {
    const uint8_t *private_start =
        private_der + sizeof(private_der) - (size_t)private_length;
    status = pbns_identity_record_encode(
        (pbns_view){private_start, (size_t)private_length},
        (pbns_view){context->public_cose_key, context->public_cose_key_length},
        (pbns_view){context->fingerprint, sizeof(context->fingerprint)},
        (pbns_buffer){encoded, 0U, sizeof(encoded)}, &encoded_length);
  }
  if (status == PBNS_OK) {
    status = environment->store.write(environment->store.context,
                                      (pbns_view){encoded, encoded_length},
                                      PBNS_IDENTITY_VARIABLE_ATTRIBUTES);
  }
  if (status == PBNS_OK) {
    uint8_t readback[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
    size_t readback_length = 0U;
    const pbns_status read_status =
        read_record(environment, readback, &readback_length);
    if (read_status != PBNS_OK || readback_length != encoded_length ||
        !constant_time_equal(readback, encoded, encoded_length)) {
      status = PBNS_ERR_AUTHENTICATION;
    }
    secure_zero(readback, sizeof(readback));
  }
  secure_zero(private_der, sizeof(private_der));
  secure_zero(encoded, sizeof(encoded));
  if (status != PBNS_OK) {
    (void)environment->store.remove(environment->store.context);
    release_context(context);
    return status;
  }
  return finish_identity(context, identity);
}

pbns_status pbns_software_identity_open(
    const pbns_software_identity_environment *environment,
    pbns_identity *identity) {
  if (!environment_is_valid(environment) || !identity_is_empty(identity)) {
    return PBNS_ERR_ARGUMENT;
  }
  uint8_t encoded[PBNS_IDENTITY_RECORD_MAX_SIZE] = {0};
  size_t encoded_length = 0U;
  pbns_status status = read_record(environment, encoded, &encoded_length);
  pbns_identity_record record = {0};
  if (status == PBNS_OK) {
    status = pbns_identity_record_decode((pbns_view){encoded, encoded_length},
                                         &record);
  }
  pbns_software_identity_context *context = NULL;
  if (status == PBNS_OK) {
    context = allocate_context(environment);
    if (context == NULL) {
      status = PBNS_ERR_RESOURCE;
    }
  }
  if (status == PBNS_OK &&
      mbedtls_pk_parse_key(&context->key, record.private_der.ptr,
                           record.private_der.len, NULL, 0U, mbedtls_random,
                           context) != 0) {
    status = PBNS_ERR_CRYPTO;
  }
  if (status == PBNS_OK && !key_is_p256_private(&context->key)) {
    status = PBNS_ERR_CRYPTO;
  }
  if (status == PBNS_OK) {
    status = encode_public_key(context);
  }
  if (status == PBNS_OK &&
      (record.public_cose_key.len != context->public_cose_key_length ||
       !constant_time_equal(record.public_cose_key.ptr,
                            context->public_cose_key,
                            context->public_cose_key_length) ||
       !constant_time_equal(record.fingerprint.ptr, context->fingerprint,
                            sizeof(context->fingerprint)))) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  secure_zero(encoded, sizeof(encoded));
  if (status != PBNS_OK) {
    release_context(context);
    return status;
  }
  return finish_identity(context, identity);
}

pbns_status pbns_software_identity_reset(
    const pbns_software_identity_environment *environment) {
  if (!environment_is_valid(environment)) {
    return PBNS_ERR_ARGUMENT;
  }
  return environment->store.remove(environment->store.context);
}
