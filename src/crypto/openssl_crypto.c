#include "pbns/crypto.h"
#include "pbns/encrypt.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_encrypt_dec.h"
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_key.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_recipient_dec_esdh.h"
#include "t_cose/t_cose_recipient_enc_esdh.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/t_cose_sign_sign.h"
#include "t_cose/t_cose_signature_sign_main.h"
#include "t_cose/t_cose_standard_constants.h"

static pbns_status map_t_cose_error(enum t_cose_err_t error) {
    switch (error) {
        case T_COSE_SUCCESS:
            return PBNS_OK;
        case T_COSE_ERR_TOO_SMALL:
        case T_COSE_ERR_SIG_BUFFER_SIZE:
        case T_COSE_ERR_INSUFFICIENT_SPACE_FOR_PARAMETERS:
        case T_COSE_ERR_KDF_BUFFER_TOO_SMALL:
        case T_COSE_ERR_KDF_CONTEXT_SIZE:
            return PBNS_ERR_LIMIT;
        case T_COSE_ERR_SIG_VERIFY:
        case T_COSE_ERR_BAD_SHORT_CIRCUIT_KID:
        case T_COSE_ERR_KID_UNMATCHED:
        case T_COSE_ERR_TAMPERING_DETECTED:
        case T_COSE_ERR_DECRYPT_FAIL:
        case T_COSE_ERR_KW_FAILED:
        case T_COSE_ERR_KEY_AGREEMENT_FAIL:
            return PBNS_ERR_AUTHENTICATION;
        case T_COSE_ERR_UNSUPPORTED_SIGNING_ALG:
        case T_COSE_ERR_UNSUPPORTED_HASH:
        case T_COSE_ERR_SHORT_CIRCUIT_SIG_DISABLED:
        case T_COSE_ERR_UNSUPPORTED:
        case T_COSE_ERR_UNSUPPORTED_CONTENT_KEY_DISTRIBUTION_ALG:
        case T_COSE_ERR_UNSUPPORTED_ENCRYPTION_ALG:
        case T_COSE_ERR_UNSUPPORTED_KEY_LENGTH:
        case T_COSE_ERR_UNSUPPORTED_CIPHER_ALG:
        case T_COSE_ERR_UNSUPPORTED_ELLIPTIC_CURVE_ALG:
            return PBNS_ERR_UNSUPPORTED;
        case T_COSE_ERR_SIGN1_FORMAT:
        case T_COSE_ERR_CBOR_NOT_WELL_FORMED:
        case T_COSE_ERR_PARAMETER_CBOR:
        case T_COSE_ERR_NO_ALG_ID:
        case T_COSE_ERR_NO_KID:
        case T_COSE_ERR_SHORT_CIRCUIT_SIG:
        case T_COSE_ERR_CBOR_FORMATTING:
        case T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER:
        case T_COSE_ERR_NON_INTEGER_ALG_ID:
        case T_COSE_ERR_INCORRECTLY_TAGGED:
        case T_COSE_ERR_DUPLICATE_PARAMETER:
        case T_COSE_ERR_PARAMETER_NOT_PROTECTED:
        case T_COSE_ERR_CRIT_PARAMETER:
        case T_COSE_ERR_UNHANDLED_HEADER_PARAMETER:
        case T_COSE_ERR_CBOR_DECODE:
        case T_COSE_ERR_SIGNATURE_FORMAT:
        case T_COSE_ERR_CANT_DETERMINE_MESSAGE_TYPE:
        case T_COSE_ERR_WRONG_COSE_MESSAGE_TYPE:
        case T_COSE_ERR_MESSAGE_FORMAT:
        case T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING:
        case T_COSE_ERR_RECIPIENT_FORMAT:
        case T_COSE_ERR_ENCRYPT_FORMAT:
        case T_COSE_ERR_BAD_IV:
        case T_COSE_ERR_UNPROCESSED_TAG_NUMBERS:
            return PBNS_ERR_FORMAT;
        case T_COSE_ERR_INVALID_ARGUMENT:
        case T_COSE_ERR_INVALID_LENGTH:
            return PBNS_ERR_ARGUMENT;
        case T_COSE_ERR_INSUFFICIENT_MEMORY:
            return PBNS_ERR_RESOURCE;
        case T_COSE_ERR_RNG_FAILED:
            return PBNS_ERR_ENTROPY;
        default:
            return PBNS_ERR_CRYPTO;
    }
}

static pbns_status openssl_sign1_sign(void *context,
                                     pbns_view payload,
                                     pbns_view external_aad,
                                     pbns_buffer output,
                                     size_t *written) {
    struct t_cose_sign_sign_ctx signing = {0};
    struct t_cose_signature_sign_main signer = {0};
    const struct t_cose_key key = {.key.ptr = context};
    struct q_useful_buf_c signed_cose = {0};
    t_cose_sign_sign_init(&signing, T_COSE_OPT_MESSAGE_TYPE_SIGN1);
    t_cose_signature_sign_main_init(&signer, T_COSE_ALGORITHM_ES256);
    t_cose_signature_sign_main_set_signing_key(&signer, key, NULL_Q_USEFUL_BUF_C);
    t_cose_sign_add_signer(&signing, t_cose_signature_sign_from_main(&signer));
    const enum t_cose_err_t error = t_cose_sign_sign(
        &signing,
        (struct q_useful_buf_c){external_aad.ptr, external_aad.len},
        (struct q_useful_buf_c){payload.ptr, payload.len},
        (struct q_useful_buf){output.ptr, output.cap},
        &signed_cose);
    if (error != T_COSE_SUCCESS) {
        return map_t_cose_error(error);
    }
    *written = signed_cose.len;
    return PBNS_OK;
}

static pbns_status openssl_sign1_sign_profile(void *context,
                                             pbns_view payload,
                                             pbns_view external_aad,
                                             pbns_view kid,
                                             pbns_buffer output,
                                             size_t *written) {
    struct t_cose_sign_sign_ctx signing = {0};
    struct t_cose_signature_sign_main signer = {0};
    const struct t_cose_key key = {.key.ptr = context};
    struct q_useful_buf_c signed_cose = {0};
    t_cose_sign_sign_init(&signing, T_COSE_OPT_MESSAGE_TYPE_SIGN1);
    t_cose_signature_sign_main_init(&signer, T_COSE_ALGORITHM_ES256);
    t_cose_signature_sign_main_set_signing_key(&signer, key,
                                                NULL_Q_USEFUL_BUF_C);
    struct t_cose_parameter kid_parameter = t_cose_param_make_kid(
        (struct q_useful_buf_c){kid.ptr, kid.len});
    kid_parameter.in_protected = true;
    t_cose_sign_add_body_header_params(&signing, &kid_parameter);
    t_cose_sign_add_signer(&signing, t_cose_signature_sign_from_main(&signer));
    const enum t_cose_err_t error = t_cose_sign_sign(
        &signing, (struct q_useful_buf_c){external_aad.ptr, external_aad.len},
        (struct q_useful_buf_c){payload.ptr, payload.len},
        (struct q_useful_buf){output.ptr, output.cap}, &signed_cose);
    if (error != T_COSE_SUCCESS) {
        return map_t_cose_error(error);
    }
    *written = signed_cose.len;
    return PBNS_OK;
}

static pbns_status openssl_sign1_verify_profile(void *context,
                                               pbns_view cose,
                                               pbns_view external_aad,
                                               pbns_view expected_kid,
                                               pbns_view *payload) {
    struct t_cose_sign1_verify_ctx verification = {0};
    const struct t_cose_key key = {.key.ptr = context};
    struct q_useful_buf_c verified_payload = {0};
    struct t_cose_parameters parameters = {0};
    t_cose_sign1_verify_init(&verification,
                             T_COSE_OPT_TAG_REQUIRED | T_COSE_OPT_REQUIRE_KID);
    t_cose_sign1_set_verification_key(&verification, key);
    const enum t_cose_err_t error = t_cose_sign1_verify_aad(
        &verification,
        (struct q_useful_buf_c){cose.ptr, cose.len},
        (struct q_useful_buf_c){external_aad.ptr, external_aad.len},
        &verified_payload,
        &parameters);
    if (error != T_COSE_SUCCESS) {
        return map_t_cose_error(error);
    }
    if (parameters.cose_algorithm_id != T_COSE_ALGORITHM_ES256) {
        return PBNS_ERR_UNSUPPORTED;
    }
    if (parameters.kid.len != expected_kid.len ||
        parameters.kid.ptr == NULL ||
        memcmp(parameters.kid.ptr, expected_kid.ptr, expected_kid.len) != 0) {
        return PBNS_ERR_AUTHENTICATION;
    }
    if (cose.len < 2U || cose.ptr[0] != 0xd2U || cose.ptr[1] != 0x84U) {
        return PBNS_ERR_FORMAT;
    }
    *payload = (pbns_view){verified_payload.ptr, verified_payload.len};
    return PBNS_OK;
}

static pbns_status openssl_sign1_verify(void *context,
                                       pbns_view cose,
                                       pbns_view external_aad,
                                       pbns_view *payload) {
    struct t_cose_sign1_verify_ctx verification = {0};
    const struct t_cose_key key = {.key.ptr = context};
    struct q_useful_buf_c verified_payload = {0};
    struct t_cose_parameters parameters = {0};
    t_cose_sign1_verify_init(&verification, T_COSE_OPT_TAG_REQUIRED);
    t_cose_sign1_set_verification_key(&verification, key);
    const enum t_cose_err_t error = t_cose_sign1_verify_aad(
        &verification, (struct q_useful_buf_c){cose.ptr, cose.len},
        (struct q_useful_buf_c){external_aad.ptr, external_aad.len},
        &verified_payload, &parameters);
    if (error != T_COSE_SUCCESS) {
        return map_t_cose_error(error);
    }
    if (parameters.cose_algorithm_id != T_COSE_ALGORITHM_ES256) {
        return PBNS_ERR_UNSUPPORTED;
    }
    *payload = (pbns_view){verified_payload.ptr, verified_payload.len};
    return PBNS_OK;
}

static void wipe_buffer(pbns_buffer buffer) {
    if (buffer.cap > 0U) {
        OPENSSL_cleanse(buffer.ptr, buffer.cap);
    }
}

static bool bytes_equal(struct q_useful_buf_c actual, pbns_view expected) {
    return actual.len == expected.len
           && (actual.len == 0U || memcmp(actual.ptr, expected.ptr, actual.len) == 0);
}

static pbns_status encryption_parameters_match_profile(
    const struct t_cose_parameter *parameters,
    pbns_view expected_recipient_kid,
    const uint64_t tags[T_COSE_MAX_TAGS_TO_RETURN]) {
    bool body_algorithm = false;
    bool body_iv = false;
    bool recipient_algorithm = false;
    bool recipient_kid = false;
    bool ephemeral_key = false;

    for (size_t index = 0U; index < T_COSE_MAX_TAGS_TO_RETURN; ++index) {
        if (tags[index] != UINT64_MAX) {
            return PBNS_ERR_FORMAT;
        }
    }

    for (const struct t_cose_parameter *parameter = parameters;
         parameter != NULL;
         parameter = parameter->next) {
        const bool body = parameter->location.nesting == 0U
                          && parameter->location.index == 0U;
        const bool recipient = parameter->location.nesting == 1U
                               && parameter->location.index == 0U;
        switch (parameter->label) {
            case T_COSE_HEADER_PARAM_ALG:
                if (parameter->value_type != T_COSE_PARAMETER_TYPE_INT64
                    || !parameter->in_protected) {
                    return PBNS_ERR_FORMAT;
                }
                if (body && !body_algorithm) {
                    if (parameter->value.int64 != T_COSE_ALGORITHM_A128GCM) {
                        return PBNS_ERR_UNSUPPORTED;
                    }
                    body_algorithm = true;
                } else if (recipient && !recipient_algorithm) {
                    if (parameter->value.int64 != T_COSE_ALGORITHM_ECDH_ES_A128KW) {
                        return PBNS_ERR_UNSUPPORTED;
                    }
                    recipient_algorithm = true;
                } else {
                    return PBNS_ERR_FORMAT;
                }
                break;
            case T_COSE_HEADER_PARAM_IV:
                if (!body || body_iv || parameter->in_protected
                    || parameter->value_type != T_COSE_PARAMETER_TYPE_BYTE_STRING
                    || parameter->value.string.len != 12U) {
                    return PBNS_ERR_FORMAT;
                }
                body_iv = true;
                break;
            case T_COSE_HEADER_PARAM_KID:
                if (!recipient || recipient_kid || parameter->in_protected
                    || parameter->value_type != T_COSE_PARAMETER_TYPE_BYTE_STRING) {
                    return PBNS_ERR_FORMAT;
                }
                if (!bytes_equal(parameter->value.string, expected_recipient_kid)) {
                    return PBNS_ERR_AUTHENTICATION;
                }
                recipient_kid = true;
                break;
            case T_COSE_HEADER_ALG_PARAM_EPHEMERAL_KEY:
                if (!recipient || ephemeral_key || parameter->in_protected) {
                    return PBNS_ERR_FORMAT;
                }
                ephemeral_key = true;
                break;
            default:
                return PBNS_ERR_FORMAT;
        }
    }

    return body_algorithm && body_iv && recipient_algorithm && recipient_kid && ephemeral_key
               ? PBNS_OK
               : PBNS_ERR_FORMAT;
}

static pbns_status openssl_encrypt_for_recipient(void *context,
                                                 pbns_view recipient_kid,
                                                 pbns_view plaintext,
                                                 pbns_view external_aad,
                                                 pbns_buffer output,
                                                 size_t *written) {
    struct t_cose_encrypt_enc encryption = {0};
    struct t_cose_recipient_enc_esdh recipient = {0};
    const struct t_cose_key key = {.key.ptr = context};
    struct q_useful_buf_c message = {0};
    uint8_t enc_structure[PBNS_ENCRYPT_MAX_EXTERNAL_AAD + 64U] = {0};

    t_cose_encrypt_enc_init(&encryption,
                            T_COSE_OPT_MESSAGE_TYPE_ENCRYPT,
                            T_COSE_ALGORITHM_A128GCM);
    t_cose_encrypt_set_enc_struct_buffer(
        &encryption,
        (struct q_useful_buf){enc_structure, sizeof(enc_structure)});
    t_cose_recipient_enc_esdh_init(&recipient,
                                   T_COSE_ALGORITHM_ECDH_ES_A128KW,
                                   T_COSE_ELLIPTIC_CURVE_P_256);
    t_cose_recipient_enc_esdh_set_key(
        &recipient,
        key,
        (struct q_useful_buf_c){recipient_kid.ptr, recipient_kid.len});
    t_cose_encrypt_add_recipient(&encryption,
                                 (struct t_cose_recipient_enc *)&recipient);

    const enum t_cose_err_t error = t_cose_encrypt_enc(
        &encryption,
        (struct q_useful_buf_c){plaintext.ptr, plaintext.len},
        (struct q_useful_buf_c){external_aad.ptr, external_aad.len},
        (struct q_useful_buf){output.ptr, output.cap},
        &message);
    if (error != T_COSE_SUCCESS) {
        wipe_buffer(output);
        return map_t_cose_error(error);
    }
    *written = message.len;
    return PBNS_OK;
}

static pbns_status openssl_decrypt_for_recipient(void *context,
                                                 pbns_view expected_recipient_kid,
                                                 pbns_view message,
                                                 pbns_view external_aad,
                                                 pbns_buffer plaintext,
                                                 size_t *written) {
    struct t_cose_encrypt_dec_ctx decryption = {0};
    struct t_cose_recipient_dec_esdh recipient = {0};
    const struct t_cose_key key = {.key.ptr = context};
    struct q_useful_buf_c decrypted = {0};
    struct t_cose_parameter *parameters = NULL;
    uint64_t tags[T_COSE_MAX_TAGS_TO_RETURN] = {0};
    uint8_t enc_structure[PBNS_ENCRYPT_MAX_EXTERNAL_AAD + 64U] = {0};

    t_cose_encrypt_dec_init(&decryption, T_COSE_OPT_TAG_REQUIRED);
    t_cose_decrypt_set_enc_struct_buffer(
        &decryption,
        (struct q_useful_buf){enc_structure, sizeof(enc_structure)});
    t_cose_recipient_dec_esdh_init(&recipient);
    t_cose_recipient_dec_esdh_set_key(
        &recipient,
        key,
        (struct q_useful_buf_c){expected_recipient_kid.ptr,
                                expected_recipient_kid.len});
    t_cose_encrypt_dec_add_recipient(&decryption,
                                     (struct t_cose_recipient_dec *)&recipient);

    const enum t_cose_err_t error = t_cose_encrypt_dec_msg(
        &decryption,
        (struct q_useful_buf_c){message.ptr, message.len},
        (struct q_useful_buf_c){external_aad.ptr, external_aad.len},
        (struct q_useful_buf){plaintext.ptr, plaintext.cap},
        &decrypted,
        &parameters,
        tags);
    if (error != T_COSE_SUCCESS) {
        wipe_buffer(plaintext);
        return map_t_cose_error(error);
    }

    const pbns_status profile_status = encryption_parameters_match_profile(
        parameters,
        expected_recipient_kid,
        tags);
    if (profile_status != PBNS_OK || decrypted.ptr != plaintext.ptr
        || decrypted.len > plaintext.cap) {
        wipe_buffer(plaintext);
        return profile_status != PBNS_OK ? profile_status : PBNS_ERR_CRYPTO;
    }

    *written = decrypted.len;
    return PBNS_OK;
}

static const pbns_crypto_ops openssl_ops = {
    .sign1_sign = openssl_sign1_sign,
    .sign1_sign_profile = openssl_sign1_sign_profile,
    .sign1_verify = openssl_sign1_verify,
    .sign1_verify_profile = openssl_sign1_verify_profile,
    .encrypt_for_recipient = openssl_encrypt_for_recipient,
    .decrypt_for_recipient = openssl_decrypt_for_recipient,
};

pbns_status pbns_crypto_openssl_wrap(pbns_crypto *crypto, void *key_handle) {
    if (crypto == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    *crypto = (pbns_crypto){0};
    if (key_handle == NULL) {
        return PBNS_ERR_ARGUMENT;
    }

    EVP_PKEY *const key = key_handle;
    if (EVP_PKEY_is_a(key, "EC") != 1) {
        return PBNS_ERR_UNSUPPORTED;
    }
    char group_name[80] = {0};
    size_t group_name_len = 0U;
    if (EVP_PKEY_get_group_name(key,
                                group_name,
                                sizeof(group_name),
                                &group_name_len) != 1) {
        return PBNS_ERR_CRYPTO;
    }
    if (group_name_len >= sizeof(group_name)
        || (strcmp(group_name, SN_X9_62_prime256v1) != 0
            && strcmp(group_name, "P-256") != 0)) {
        return PBNS_ERR_UNSUPPORTED;
    }

    crypto->ops = &openssl_ops;
    crypto->context = key_handle;
    return PBNS_OK;
}
