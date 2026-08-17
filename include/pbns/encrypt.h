#ifndef PBNS_ENCRYPT_H
#define PBNS_ENCRYPT_H

#include "pbns/crypto.h"

#define PBNS_COSE_ALG_ES256 (-7)
#define PBNS_COSE_ALG_ECDH_ES_A128KW (-29)
#define PBNS_COSE_ALG_A128GCM 1
#define PBNS_COSE_CURVE_P256 1

#define PBNS_ENCRYPT_MAX_RECIPIENT_KID 64U
#define PBNS_ENCRYPT_MAX_EXTERNAL_AAD 256U
#define PBNS_ENCRYPT_MAX_MESSAGE ((size_t)64U * 1024U)

pbns_status pbns_encrypt_for_recipient(const pbns_crypto *crypto,
                                       pbns_view recipient_kid,
                                       pbns_view plaintext,
                                       pbns_view external_aad,
                                       pbns_buffer output,
                                       size_t *written);

pbns_status pbns_decrypt_for_recipient(const pbns_crypto *crypto,
                                       pbns_view expected_recipient_kid,
                                       pbns_view message,
                                       pbns_view external_aad,
                                       pbns_buffer plaintext,
                                       size_t *written);

#endif
