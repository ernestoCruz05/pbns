#include "bridge.h"

#include <climits>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <atomic>

#include <cn-cbor/cn-cbor.h>
#include <cose/cose.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>

namespace {

constexpr size_t kMaxRecipientKid = 64U;
constexpr size_t kMaxExternalAad = 256U;
constexpr size_t kMaxMessage = 65536U;
constexpr size_t kMaxAttestationMessage = 4268800U;
constexpr size_t kAesGcmIvSize = 12U;

std::mutex cose_mutex;
const uint8_t empty_byte = 0U;
std::atomic<size_t> clear_free_count{0U};

bool valid_span(const uint8_t *data, size_t len)
{
    return data != nullptr || len == 0U;
}

const uint8_t *nonnull_data(const uint8_t *data, size_t len)
{
    return len == 0U ? &empty_byte : data;
}

bool key_has_p256_profile(EVP_PKEY *key, bool require_private)
{
    if(key == nullptr || EVP_PKEY_is_a(key, "EC") != 1) {
        return false;
    }
    char group_name[80] = {0};
    size_t group_name_len = 0U;
    if(EVP_PKEY_get_group_name(key,
                               group_name,
                               sizeof(group_name),
                               &group_name_len) != 1
       || group_name_len >= sizeof(group_name)
       || (std::strcmp(group_name, SN_X9_62_prime256v1) != 0
           && std::strcmp(group_name, "P-256") != 0)) {
        return false;
    }
    if(!require_private) {
        return true;
    }
    BIGNUM *private_value = nullptr;
    const bool has_private = EVP_PKEY_get_bn_param(
                                 key,
                                 OSSL_PKEY_PARAM_PRIV_KEY,
                                 &private_value)
                             == 1;
    BN_clear_free(private_value);
    return has_private;
}

EVP_PKEY *parse_public_key(const uint8_t *der, size_t der_len)
{
    if(der == nullptr || der_len == 0U || der_len > static_cast<size_t>(LONG_MAX)) {
        return nullptr;
    }
    const unsigned char *cursor = der;
    EVP_PKEY *key = d2i_PUBKEY(nullptr, &cursor, static_cast<long>(der_len));
    if(key == nullptr || cursor != der + der_len || !key_has_p256_profile(key, false)) {
        EVP_PKEY_free(key);
        return nullptr;
    }
    return key;
}

EVP_PKEY *parse_private_key(const uint8_t *der, size_t der_len)
{
    if(der == nullptr || der_len == 0U || der_len > static_cast<size_t>(LONG_MAX)) {
        return nullptr;
    }
    const unsigned char *cursor = der;
    EVP_PKEY *key = d2i_AutoPrivateKey(nullptr, &cursor, static_cast<long>(der_len));
    if(key == nullptr || cursor != der + der_len || !key_has_p256_profile(key, true)) {
        EVP_PKEY_free(key);
        return nullptr;
    }
    return key;
}

bool cbor_integer_equals(const cn_cbor *value, int64_t expected)
{
    if(value == nullptr) {
        return false;
    }
    if(value->type == CN_CBOR_UINT) {
        return expected >= 0 && value->v.uint == static_cast<uint64_t>(expected);
    }
    return value->type == CN_CBOR_INT && value->v.sint == expected;
}

bool cbor_bytes_equal(const cn_cbor *value, const uint8_t *expected, size_t expected_len)
{
    return value != nullptr && value->type == CN_CBOR_BYTES
           && value->length == expected_len
           && (expected_len == 0U || std::memcmp(value->v.bytes, expected, expected_len) == 0);
}

cn_cbor *integer_node(int64_t value, cn_cbor_context *context)
{
    cn_cbor_errback error = {0U, CN_CBOR_NO_ERROR};
    return cn_cbor_int_create(value, context, &error);
}

cn_cbor *bytes_node(const uint8_t *data, size_t len, cn_cbor_context *context)
{
    if(len > static_cast<size_t>(INT_MAX)) {
        return nullptr;
    }
    cn_cbor_errback error = {0U, CN_CBOR_NO_ERROR};
    return cn_cbor_data_create(nonnull_data(data, len),
                               static_cast<int>(len),
                               context,
                               &error);
}

pbns_cosec_status map_cose_error(cose_error error, pbns_cosec_status fallback)
{
    switch(error) {
        case COSE_ERR_OUT_OF_MEMORY:
            return PBNS_COSEC_MEMORY;
        case COSE_ERR_UNKNOWN_ALGORITHM:
        case COSE_ERR_UNSUPPORTED_COSE_TYPE:
        case COSE_ERR_NO_COMPRESSED_POINTS:
            return PBNS_COSEC_KEY_PROFILE;
        case COSE_ERR_NO_RECIPIENT_FOUND:
        case COSE_ERR_DECRYPT_FAILED:
            return PBNS_COSEC_AUTHENTICATION;
        case COSE_ERR_CBOR:
            return PBNS_COSEC_FORMAT;
        case COSE_ERR_CRYPTO_FAIL:
        case COSE_ERR_INTERNAL:
            return PBNS_COSEC_CRYPTO;
        case COSE_ERR_INVALID_PARAMETER:
        case COSE_ERR_INVALID_HANDLE:
        case COSE_ERR_NONE:
            return fallback;
    }
    return fallback;
}

bool encode_tagged_message(HCOSE_ENVELOPED message,
                           cn_cbor_context *context,
                           size_t maximum_message_size,
                           uint8_t **encoded,
                           size_t *encoded_len)
{
    *encoded = nullptr;
    *encoded_len = 0U;
    (void)context;
    const cn_cbor *source = COSE_get_cbor(reinterpret_cast<HCOSE>(message));
    const cn_cbor *tagged = source == nullptr ? nullptr : source->parent;
    if(tagged == nullptr || tagged->type != CN_CBOR_TAG
       || tagged->v.uint != static_cast<uint64_t>(COSE_enveloped_object)
       || tagged->first_child != source || source->next != nullptr) {
        return false;
    }
    uint8_t *result = static_cast<uint8_t *>(std::malloc(maximum_message_size));
    if(result == nullptr) {
        return false;
    }
    const ssize_t written = cn_cbor_encoder_write(result, 0U, maximum_message_size, tagged);
    if(written <= 0 || static_cast<size_t>(written) > maximum_message_size) {
        std::free(result);
        return false;
    }
    *encoded = result;
    *encoded_len = static_cast<size_t>(written);
    return true;
}

bool message_is_exact_encoding(HCOSE_ENVELOPED message,
                               cn_cbor_context *context,
                               const uint8_t *encoded,
                               size_t encoded_len,
                               size_t maximum_message_size)
{
    uint8_t *canonical = nullptr;
    size_t canonical_len = 0U;
    if(!encode_tagged_message(message, context, maximum_message_size, &canonical, &canonical_len)) {
        return false;
    }
    const bool equal = canonical_len == encoded_len
                       && std::memcmp(canonical, encoded, encoded_len) == 0;
    std::free(canonical);
    return equal;
}

bool encrypted_profile_matches(HCOSE_ENVELOPED message,
                               HCOSE_RECIPIENT recipient,
                               const uint8_t *expected_kid,
                               size_t expected_kid_len)
{
    cose_errback error = {COSE_ERR_NONE};
    const cn_cbor *body_algorithm = COSE_Enveloped_map_get_int(
        message,
        COSE_Header_Algorithm,
        COSE_PROTECT_ONLY,
        &error);
    const cn_cbor *iv = COSE_Enveloped_map_get_int(
        message,
        COSE_Header_IV,
        COSE_UNPROTECT_ONLY,
        &error);
    const cn_cbor *recipient_algorithm = COSE_Recipient_map_get_int(
        recipient,
        COSE_Header_Algorithm,
        COSE_PROTECT_ONLY,
        &error);
    const cn_cbor *kid = COSE_Recipient_map_get_int(
        recipient,
        COSE_Header_KID,
        COSE_UNPROTECT_ONLY,
        &error);
    const cn_cbor *ephemeral_key = COSE_Recipient_map_get_int(
        recipient,
        COSE_Header_ECDH_EPK,
        COSE_UNPROTECT_ONLY,
        &error);

    return cbor_integer_equals(body_algorithm, COSE_Algorithm_AES_GCM_128)
           && iv != nullptr && iv->type == CN_CBOR_BYTES && iv->length == kAesGcmIvSize
           && cbor_integer_equals(recipient_algorithm, COSE_Algorithm_ECDH_ES_A128KW)
           && cbor_bytes_equal(kid, expected_kid, expected_kid_len)
           && ephemeral_key != nullptr && ephemeral_key->type == CN_CBOR_MAP;
}

}

extern "C" pbns_cosec_status pbns_cosec_encrypt(
    const uint8_t *public_key_der,
    size_t public_key_der_len,
    const uint8_t *recipient_kid,
    size_t recipient_kid_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *external_aad,
    size_t external_aad_len,
    pbns_cosec_output *output)
{
    if(output == nullptr) {
        return PBNS_COSEC_INVALID_ARGUMENT;
    }
    *output = {nullptr, 0U};
    if(!valid_span(plaintext, plaintext_len) || !valid_span(external_aad, external_aad_len)
       || recipient_kid == nullptr || recipient_kid_len == 0U
       || recipient_kid_len > kMaxRecipientKid || external_aad_len > kMaxExternalAad
       || plaintext_len > kMaxMessage) {
        return PBNS_COSEC_INVALID_ARGUMENT;
    }

    std::lock_guard<std::mutex> lock(cose_mutex);
    cn_cbor_context context = {nullptr, nullptr, nullptr};
    cose_errback error = {COSE_ERR_NONE};
    pbns_cosec_status status = PBNS_COSEC_CRYPTO;
    EVP_PKEY *evp_key = parse_public_key(public_key_der, public_key_der_len);
    HCOSE_KEY cose_key = nullptr;
    HCOSE_ENVELOPED message = nullptr;
    HCOSE_RECIPIENT recipient = nullptr;
    cn_cbor *node = nullptr;
    uint8_t *encoded = nullptr;
    if(evp_key == nullptr) {
        return PBNS_COSEC_KEY_PROFILE;
    }

    cose_key = COSE_KEY_FromEVP(evp_key, nullptr, &context, &error);
    if(cose_key == nullptr) {
        status = map_cose_error(error.err, PBNS_COSEC_KEY_PROFILE);
        goto cleanup;
    }
    message = COSE_Enveloped_Init(COSE_INIT_FLAGS_NONE, &context, &error);
    if(message == nullptr) {
        status = map_cose_error(error.err, PBNS_COSEC_MEMORY);
        goto cleanup;
    }
    node = integer_node(COSE_Algorithm_AES_GCM_128, &context);
    if(node == nullptr
       || !COSE_Enveloped_map_put_int(message,
                                      COSE_Header_Algorithm,
                                      node,
                                      COSE_PROTECT_ONLY,
                                      &error)) {
        status = map_cose_error(error.err, PBNS_COSEC_FORMAT);
        goto cleanup;
    }
    node = nullptr;
    if(!COSE_Enveloped_SetContent(message,
                                  nonnull_data(plaintext, plaintext_len),
                                  plaintext_len,
                                  &error)
       || !COSE_Enveloped_SetExternal(message,
                                      nonnull_data(external_aad, external_aad_len),
                                      external_aad_len,
                                      &error)) {
        status = map_cose_error(error.err, PBNS_COSEC_INVALID_ARGUMENT);
        goto cleanup;
    }

    recipient = COSE_Recipient_Init(COSE_INIT_FLAGS_NONE, &context, &error);
    if(recipient == nullptr) {
        status = map_cose_error(error.err, PBNS_COSEC_MEMORY);
        goto cleanup;
    }
    node = integer_node(COSE_Algorithm_ECDH_ES_A128KW, &context);
    if(node == nullptr
       || !COSE_Recipient_map_put_int(recipient,
                                      COSE_Header_Algorithm,
                                      node,
                                      COSE_PROTECT_ONLY,
                                      &error)) {
        status = map_cose_error(error.err, PBNS_COSEC_FORMAT);
        goto cleanup;
    }
    node = nullptr;
    node = bytes_node(recipient_kid, recipient_kid_len, &context);
    if(node == nullptr
       || !COSE_Recipient_map_put_int(recipient,
                                      COSE_Header_KID,
                                      node,
                                      COSE_UNPROTECT_ONLY,
                                      &error)) {
        status = map_cose_error(error.err, PBNS_COSEC_FORMAT);
        goto cleanup;
    }
    node = nullptr;
    if(!COSE_Recipient_SetKey2(recipient, cose_key, &error)
       || !COSE_Enveloped_AddRecipient(message, recipient, &error)
       || !COSE_Enveloped_encrypt(message, &error)) {
        status = map_cose_error(error.err, PBNS_COSEC_CRYPTO);
        goto cleanup;
    }

    {
        size_t encoded_len = 0U;
        if(!encode_tagged_message(message, &context, kMaxMessage, &encoded, &encoded_len)) {
            status = PBNS_COSEC_FORMAT;
            goto cleanup;
        }
        output->data = encoded;
        output->len = encoded_len;
        encoded = nullptr;
        status = PBNS_COSEC_OK;
    }

cleanup:
    std::free(encoded);
    if(node != nullptr) {
        cn_cbor_free(node, &context);
    }
    if(recipient != nullptr) {
        COSE_Recipient_Free(recipient);
    }
    if(message != nullptr) {
        COSE_Enveloped_Free(message);
    }
    if(cose_key != nullptr) {
        COSE_KEY_Free(cose_key);
    }
    EVP_PKEY_free(evp_key);
    if(status != PBNS_COSEC_OK) {
        std::free(output->data);
        *output = {nullptr, 0U};
    }
    return status;
}

extern "C" pbns_cosec_status pbns_cosec_decrypt_bounded(
    const uint8_t *private_key_der,
    size_t private_key_der_len,
    size_t maximum_message_size,
    const uint8_t *expected_recipient_kid,
    size_t expected_recipient_kid_len,
    const uint8_t *encoded,
    size_t encoded_len,
    const uint8_t *external_aad,
    size_t external_aad_len,
    pbns_cosec_output *output)
{
    if(output == nullptr) {
        return PBNS_COSEC_INVALID_ARGUMENT;
    }
    *output = {nullptr, 0U};
    if(maximum_message_size == 0U || maximum_message_size > kMaxAttestationMessage
       || encoded == nullptr || encoded_len == 0U || encoded_len > maximum_message_size
       || !valid_span(external_aad, external_aad_len)
       || expected_recipient_kid == nullptr || expected_recipient_kid_len == 0U
       || expected_recipient_kid_len > kMaxRecipientKid
       || external_aad_len > kMaxExternalAad) {
        return PBNS_COSEC_INVALID_ARGUMENT;
    }

    std::lock_guard<std::mutex> lock(cose_mutex);
    cn_cbor_context context = {nullptr, nullptr, nullptr};
    cose_errback error = {COSE_ERR_NONE};
    pbns_cosec_status status = PBNS_COSEC_CRYPTO;
    EVP_PKEY *evp_key = parse_private_key(private_key_der, private_key_der_len);
    HCOSE_KEY cose_key = nullptr;
    HCOSE_ENVELOPED message = nullptr;
    HCOSE_RECIPIENT recipient = nullptr;
    uint8_t *plaintext = nullptr;
    if(evp_key == nullptr) {
        return PBNS_COSEC_KEY_PROFILE;
    }

    cose_key = COSE_KEY_FromEVP(evp_key, nullptr, &context, &error);
    if(cose_key == nullptr) {
        status = map_cose_error(error.err, PBNS_COSEC_KEY_PROFILE);
        goto cleanup;
    }
    {
        int type = 0;
        message = reinterpret_cast<HCOSE_ENVELOPED>(COSE_Decode(encoded,
                                                                encoded_len,
                                                                &type,
                                                                COSE_enveloped_object,
                                                                &context,
                                                                &error));
        if(message == nullptr || type != COSE_enveloped_object
           || !message_is_exact_encoding(message, &context, encoded, encoded_len, maximum_message_size)) {
            status = PBNS_COSEC_FORMAT;
            goto cleanup;
        }
    }
    recipient = COSE_Enveloped_GetRecipient(message, 0, &error);
    if(recipient == nullptr) {
        status = PBNS_COSEC_FORMAT;
        goto cleanup;
    }
    {
        HCOSE_RECIPIENT extra = COSE_Enveloped_GetRecipient(message, 1, &error);
        if(extra != nullptr) {
            COSE_Recipient_Free(extra);
            status = PBNS_COSEC_FORMAT;
            goto cleanup;
        }
    }
    if(!encrypted_profile_matches(message,
                                  recipient,
                                  expected_recipient_kid,
                                  expected_recipient_kid_len)) {
        status = PBNS_COSEC_AUTHENTICATION;
        goto cleanup;
    }
    if(!COSE_Enveloped_SetExternal(message,
                                   nonnull_data(external_aad, external_aad_len),
                                   external_aad_len,
                                   &error)
       || !COSE_Recipient_SetKey2(recipient, cose_key, &error)
       || !COSE_Enveloped_decrypt(message, recipient, &error)) {
        status = map_cose_error(error.err, PBNS_COSEC_AUTHENTICATION);
        goto cleanup;
    }

    {
        size_t plaintext_len = 0U;
        const byte *content = COSE_Enveloped_GetContent(
            message,
            &plaintext_len,
            &error);
        if((content == nullptr && plaintext_len != 0U) || plaintext_len > maximum_message_size) {
            status = PBNS_COSEC_FORMAT;
            goto cleanup;
        }
        const size_t allocation_size = plaintext_len == 0U ? 1U : plaintext_len;
        plaintext = static_cast<uint8_t *>(std::malloc(allocation_size));
        if(plaintext == nullptr) {
            status = PBNS_COSEC_MEMORY;
            goto cleanup;
        }
        if(plaintext_len > 0U) {
            std::memcpy(plaintext, content, plaintext_len);
        }
        output->data = plaintext;
        output->len = plaintext_len;
        plaintext = nullptr;
        status = PBNS_COSEC_OK;
    }

cleanup:
    std::free(plaintext);
    if(recipient != nullptr) {
        COSE_Recipient_Free(recipient);
    }
    if(message != nullptr) {
        COSE_Enveloped_Free(message);
    }
    if(cose_key != nullptr) {
        COSE_KEY_Free(cose_key);
    }
    EVP_PKEY_free(evp_key);
    if(status != PBNS_COSEC_OK) {
        std::free(output->data);
        *output = {nullptr, 0U};
    }
    return status;
}

extern "C" pbns_cosec_status pbns_cosec_decrypt(
    const uint8_t *private_key_der,
    size_t private_key_der_len,
    const uint8_t *expected_recipient_kid,
    size_t expected_recipient_kid_len,
    const uint8_t *encoded,
    size_t encoded_len,
    const uint8_t *external_aad,
    size_t external_aad_len,
    pbns_cosec_output *output)
{
    return pbns_cosec_decrypt_bounded(private_key_der, private_key_der_len,
                                      kMaxMessage, expected_recipient_kid,
                                      expected_recipient_kid_len, encoded,
                                      encoded_len, external_aad,
                                      external_aad_len, output);
}

extern "C" void pbns_cosec_free(void *allocation)
{
    std::free(allocation);
}

extern "C" void pbns_cosec_clear_free(void *allocation, size_t allocation_len)
{
    if(allocation != nullptr && allocation_len > 0U) {
        OPENSSL_cleanse(allocation, allocation_len);
        clear_free_count.fetch_add(1U, std::memory_order_relaxed);
    }
    std::free(allocation);
}

extern "C" size_t pbns_cosec_clear_free_count(void)
{
    return clear_free_count.load(std::memory_order_relaxed);
}
