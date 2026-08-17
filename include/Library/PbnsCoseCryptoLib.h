#ifndef PBNS_COSE_CRYPTO_LIB_H
#define PBNS_COSE_CRYPTO_LIB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/identity.h"
#include "pbns/status.h"
#include "t_cose/t_cose_key.h"

#define PBNS_COSE_P256_COORDINATE_SIZE 32U
#define PBNS_COSE_RECIPIENT_KEY_ID_MAX_SIZE 64U
#define PBNS_COSE_EXTERNAL_AAD_MAX_SIZE 256U
#define PBNS_COSE_MESSAGE_MAX_SIZE ((size_t)64U * 1024U)
#define PBNS_COSE_ATTESTATION_MESSAGE_MAX_SIZE                              \
  ((size_t)4U * 1024U * 1024U + (size_t)64U * 1024U + (size_t)8960U)
#define PBNS_COSE_ENCRYPT_OVERHEAD_RESERVE 256U
#define PBNS_COSE_KEY_MAGIC UINT32_C(0x50434f53)

typedef enum pbns_cose_key_kind {
  PBNS_COSE_KEY_INVALID = 0,
  PBNS_COSE_KEY_IDENTITY = 1,
  PBNS_COSE_KEY_P256_PUBLIC = 2,
  PBNS_COSE_KEY_P256_PRIVATE = 3,
  PBNS_COSE_KEY_SYMMETRIC = 4
} pbns_cose_key_kind;

typedef struct pbns_cose_key {
  uint32_t magic;
  pbns_cose_key_kind kind;
  const pbns_identity *identity;
  uint8_t x[PBNS_COSE_P256_COORDINATE_SIZE];
  uint8_t y[PBNS_COSE_P256_COORDINATE_SIZE];
  void *backend;
  bool owns_backend;
  bool owns_self;
  struct t_cose_key native;
} pbns_cose_key;

pbns_status pbns_cose_key_from_identity(pbns_cose_key *key,
                                        const pbns_identity *identity);
pbns_status pbns_cose_key_from_p256_public(pbns_cose_key *key, pbns_view x,
                                           pbns_view y);
pbns_status pbns_cose_p256_key_generate(pbns_cose_key *private_key,
                                        const pbns_identity *random_identity);
pbns_status pbns_cose_p256_key_export_public(const pbns_cose_key *private_key,
                                             pbns_cose_key *public_key);
void pbns_cose_key_reset(pbns_cose_key *key);

pbns_status pbns_cose_uefi_sign1_sign(const pbns_cose_key *key,
                                      pbns_view payload, pbns_view external_aad,
                                      pbns_buffer output, size_t *written);

/* A carga devolvida referencia a mensagem COSE fornecida pelo chamador. */
pbns_status pbns_cose_uefi_sign1_verify(const pbns_cose_key *key,
                                        pbns_view message,
                                        pbns_view external_aad,
                                        pbns_view *payload);
pbns_status pbns_cose_uefi_sign1_verify_profile(
    const pbns_cose_key *key, pbns_view message, pbns_view external_aad,
    pbns_view expected_kid, pbns_view *payload);

pbns_status pbns_cose_uefi_encrypt_for_recipient(
    const pbns_identity *random_identity, const pbns_cose_key *recipient_key,
    pbns_view recipient_key_id, pbns_view plaintext, pbns_view external_aad,
    pbns_buffer output, size_t *written);
pbns_status pbns_cose_uefi_attestation_encrypt_for_recipient(
    const pbns_identity *random_identity, const pbns_cose_key *recipient_key,
    pbns_view recipient_key_id, pbns_view plaintext, pbns_view external_aad,
    pbns_buffer output, size_t *written);
pbns_status pbns_cose_uefi_decrypt_for_recipient(
    const pbns_identity *random_identity, const pbns_cose_key *recipient_key,
    pbns_view recipient_key_id, pbns_view message, pbns_view external_aad,
    pbns_buffer plaintext, size_t *written);

#endif
