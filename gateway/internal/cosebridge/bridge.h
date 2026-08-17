#ifndef PBNS_COSEBRIDGE_H
#define PBNS_COSEBRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum pbns_cosec_status {
    PBNS_COSEC_OK = 0,
    PBNS_COSEC_INVALID_ARGUMENT = 1,
    PBNS_COSEC_KEY_PROFILE = 2,
    PBNS_COSEC_FORMAT = 3,
    PBNS_COSEC_AUTHENTICATION = 4,
    PBNS_COSEC_CRYPTO = 5,
    PBNS_COSEC_MEMORY = 6,
    PBNS_COSEC_LIMIT = 7
} pbns_cosec_status;

typedef struct pbns_cosec_output {
    uint8_t *data;
    size_t len;
} pbns_cosec_output;

pbns_cosec_status pbns_cosec_encrypt(const uint8_t *public_key_der,
                                     size_t public_key_der_len,
                                     const uint8_t *recipient_kid,
                                     size_t recipient_kid_len,
                                     const uint8_t *plaintext,
                                     size_t plaintext_len,
                                     const uint8_t *external_aad,
                                     size_t external_aad_len,
                                     pbns_cosec_output *output);

pbns_cosec_status pbns_cosec_decrypt_bounded(const uint8_t *private_key_der,
                                             size_t private_key_der_len,
                                             size_t maximum_message_size,
                                             const uint8_t *expected_recipient_kid,
                                             size_t expected_recipient_kid_len,
                                             const uint8_t *message,
                                             size_t message_len,
                                             const uint8_t *external_aad,
                                             size_t external_aad_len,
                                             pbns_cosec_output *output);

pbns_cosec_status pbns_cosec_decrypt(const uint8_t *private_key_der,
                                     size_t private_key_der_len,
                                     const uint8_t *expected_recipient_kid,
                                     size_t expected_recipient_kid_len,
                                     const uint8_t *message,
                                     size_t message_len,
                                     const uint8_t *external_aad,
                                     size_t external_aad_len,
                                     pbns_cosec_output *output);

void pbns_cosec_free(void *allocation);
void pbns_cosec_clear_free(void *allocation, size_t allocation_len);
size_t pbns_cosec_clear_free_count(void);

#ifdef __cplusplus
}
#endif

#endif
