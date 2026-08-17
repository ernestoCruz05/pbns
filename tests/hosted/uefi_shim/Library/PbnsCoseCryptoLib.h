#ifndef PBNS_TEST_COSE_CRYPTO_LIB_H
#define PBNS_TEST_COSE_CRYPTO_LIB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/identity.h"
#include "pbns/status.h"

#define PBNS_COSE_ATTESTATION_MESSAGE_MAX_SIZE \
  ((size_t)4U * 1024U * 1024U + (size_t)64U * 1024U + (size_t)8960U)

typedef struct pbns_cose_key {
  uint32_t magic;
  const pbns_identity *identity;
  const struct pbns_cose_key *native;
  uint8_t owned_secret[32];
} pbns_cose_key;

pbns_status pbns_cose_key_from_identity(pbns_cose_key *key,
                                        const pbns_identity *identity);
pbns_status pbns_cose_key_from_p256_public(pbns_cose_key *key, pbns_view x,
                                            pbns_view y);
void pbns_cose_key_reset(pbns_cose_key *key);
pbns_status pbns_cose_uefi_sign1_sign(const pbns_cose_key *key,
                                      pbns_view payload, pbns_view external_aad,
                                      pbns_buffer output, size_t *written);
pbns_status pbns_cose_uefi_sign1_verify(const pbns_cose_key *key,
                                        pbns_view message,
                                        pbns_view external_aad,
                                        pbns_view *payload);
pbns_status pbns_cose_uefi_sign1_verify_profile(
    const pbns_cose_key *key, pbns_view message, pbns_view external_aad,
    pbns_view expected_kid, pbns_view *payload);
pbns_status pbns_cose_uefi_attestation_encrypt_for_recipient(
    const pbns_identity *random_identity, const pbns_cose_key *recipient_key,
    pbns_view recipient_key_id, pbns_view plaintext, pbns_view external_aad,
    pbns_buffer output, size_t *written);

#endif
