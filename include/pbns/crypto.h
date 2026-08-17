#ifndef PBNS_CRYPTO_H
#define PBNS_CRYPTO_H

#include "pbns/buffer.h"
#include "pbns/status.h"

typedef struct pbns_crypto pbns_crypto;
typedef struct pbns_crypto_ops pbns_crypto_ops;

struct pbns_crypto_ops {
    pbns_status (*sign1_sign)(void *context,
                              pbns_view payload,
                              pbns_view external_aad,
                              pbns_buffer output,
                              size_t *written);
    pbns_status (*sign1_sign_profile)(void *context,
                                      pbns_view payload,
                                      pbns_view external_aad,
                                      pbns_view kid,
                                      pbns_buffer output,
                                      size_t *written);
    pbns_status (*sign1_verify)(void *context,
                                pbns_view cose,
                                pbns_view external_aad,
                                pbns_view *payload);
    pbns_status (*sign1_verify_profile)(void *context,
                                        pbns_view cose,
                                        pbns_view external_aad,
                                        pbns_view expected_kid,
                                        pbns_view *payload);
    pbns_status (*encrypt_for_recipient)(void *context,
                                         pbns_view recipient_kid,
                                         pbns_view plaintext,
                                         pbns_view external_aad,
                                         pbns_buffer output,
                                         size_t *written);
    pbns_status (*decrypt_for_recipient)(void *context,
                                         pbns_view expected_recipient_kid,
                                         pbns_view message,
                                         pbns_view external_aad,
                                         pbns_buffer plaintext,
                                         size_t *written);
};

struct pbns_crypto {
    const pbns_crypto_ops *ops;
    void *context;
};

/* O identificador OpenSSL é emprestado e tem de sobreviver ao adaptador. */
pbns_status pbns_crypto_openssl_wrap(pbns_crypto *crypto, void *key_handle);
void pbns_crypto_reset(pbns_crypto *crypto);

pbns_status pbns_sign1_sign(const pbns_crypto *crypto,
                            pbns_view payload,
                            pbns_view external_aad,
                            pbns_buffer output,
                            size_t *written);
pbns_status pbns_sign1_sign_profile(const pbns_crypto *crypto,
                                    pbns_view payload,
                                    pbns_view external_aad,
                                    pbns_view kid,
                                    pbns_buffer output,
                                    size_t *written);
/* A carga verificada referencia a mensagem COSE fornecida pelo chamador. */
pbns_status pbns_sign1_verify(const pbns_crypto *crypto,
                              pbns_view cose,
                              pbns_view external_aad,
                              pbns_view *payload);
pbns_status pbns_sign1_verify_profile(const pbns_crypto *crypto,
                                      pbns_view cose,
                                      pbns_view external_aad,
                                      pbns_view expected_kid,
                                      pbns_view *payload);

#endif
