#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "pbns/crypto.h"

static const uint8_t signed_payload[] = {
    0xa9, 0x01, 0x69, 0x70, 0x62, 0x6e, 0x73, 0x2e, 0x74, 0x69, 0x6d, 0x65,
    0x02, 0x01, 0x03, 0x01, 0x04, 0x50, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x05, 0x40,
    0x06, 0x58, 0x20, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
    0x3e, 0x3f, 0x07, 0x19, 0x03, 0xe8, 0x08, 0x18, 0x3c, 0x09, 0x43,
    0xaa, 0xbb, 0xcc,
};

static const uint8_t external_aad[] = "pbns-sign1-v1";

static EVP_PKEY *load_private_key(void) {
    FILE *file = fopen("tests/fixtures/keys/service-signing-test-private.pem", "rb");
    assert(file != NULL);
    EVP_PKEY *const key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    assert(fclose(file) == 0);
    assert(key != NULL);
    return key;
}

static EVP_PKEY *load_public_key(void) {
    FILE *file = fopen("tests/fixtures/keys/service-signing-test-public.pem", "rb");
    assert(file != NULL);
    EVP_PKEY *const key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    assert(fclose(file) == 0);
    assert(key != NULL);
    return key;
}

static size_t read_vector(uint8_t *buffer, size_t capacity) {
    FILE *file = fopen("tests/vectors/sign1-v1.cbor", "rb");
    assert(file != NULL);
    const size_t received = fread(buffer, 1U, capacity, file);
    assert(ferror(file) == 0);
    assert(received < capacity);
    assert(fclose(file) == 0);
    return received;
}

static void assert_payload(pbns_view payload) {
    assert(payload.len == sizeof(signed_payload));
    assert(memcmp(payload.ptr, signed_payload, sizeof(signed_payload)) == 0);
}

typedef struct reported_length_context {
    size_t reported;
    size_t calls;
} reported_length_context;

static pbns_status report_sign_length(void *context, pbns_view payload,
                                      pbns_view aad, pbns_buffer output,
                                      size_t *written) {
    reported_length_context *reported = context;
    (void)payload;
    (void)aad;
    ++reported->calls;
    memset(output.ptr, 0x5a, output.cap);
    *written = reported->reported;
    return PBNS_OK;
}

static pbns_status report_profile_sign_length(
    void *context, pbns_view payload, pbns_view aad, pbns_view kid,
    pbns_buffer output, size_t *written) {
    (void)kid;
    return report_sign_length(context, payload, aad, output, written);
}

static void assert_all_value(const uint8_t *bytes, size_t size,
                             uint8_t expected) {
    for (size_t index = 0U; index < size; ++index) {
        assert(bytes[index] == expected);
    }
}

static void test_rejects_invalid_callback_output_lengths(void) {
    static const pbns_crypto_ops ops = {
        .sign1_sign = report_sign_length,
        .sign1_sign_profile = report_profile_sign_length,
    };
    static const uint8_t payload[] = {0x01U};
    static const uint8_t kid[] = {0x02U};
    uint8_t output[16] = {0};
    reported_length_context context = {0};
    const pbns_crypto crypto = {.ops = &ops, .context = &context};
    const size_t invalid_lengths[] = {0U, sizeof(output) + 1U, SIZE_MAX};

    for (size_t index = 0U;
         index < sizeof(invalid_lengths) / sizeof(invalid_lengths[0]);
         ++index) {
        context.reported = invalid_lengths[index];
        memset(output, 0xa5, sizeof(output));
        size_t written = SIZE_MAX;
        assert(pbns_sign1_sign(
                   &crypto, (pbns_view){payload, sizeof(payload)},
                   (pbns_view){NULL, 0U},
                   (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
               PBNS_ERR_LIMIT);
        assert(written == 0U);
        assert_all_value(output, sizeof(output), 0U);

        memset(output, 0xa5, sizeof(output));
        written = SIZE_MAX;
        assert(pbns_sign1_sign_profile(
                   &crypto, (pbns_view){payload, sizeof(payload)},
                   (pbns_view){NULL, 0U}, (pbns_view){kid, sizeof(kid)},
                   (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
               PBNS_ERR_LIMIT);
        assert(written == 0U);
        assert_all_value(output, sizeof(output), 0U);
    }

    context.reported = sizeof(output);
    memset(output, 0xa5, sizeof(output));
    size_t written = 0U;
    assert(pbns_sign1_sign(
               &crypto, (pbns_view){payload, sizeof(payload)},
               (pbns_view){NULL, 0U},
               (pbns_buffer){output, 0U, sizeof(output)}, &written) == PBNS_OK);
    assert(written == sizeof(output));
    assert_all_value(output, sizeof(output), 0x5aU);

    memset(output, 0xa5, sizeof(output));
    written = 0U;
    assert(pbns_sign1_sign_profile(
               &crypto, (pbns_view){payload, sizeof(payload)},
               (pbns_view){NULL, 0U}, (pbns_view){kid, sizeof(kid)},
               (pbns_buffer){output, 0U, sizeof(output)}, &written) == PBNS_OK);
    assert(written == sizeof(output));
    assert_all_value(output, sizeof(output), 0x5aU);
    assert(context.calls == 8U);
}

static void test_sign_and_verify_with_external_aad(void) {
    EVP_PKEY *const private_key = load_private_key();
    EVP_PKEY *const public_key = load_public_key();
    pbns_crypto signer = {0};
    pbns_crypto verifier = {0};
    assert(pbns_crypto_openssl_wrap(&signer, private_key) == PBNS_OK);
    assert(pbns_crypto_openssl_wrap(&verifier, public_key) == PBNS_OK);

    uint8_t cose[512] = {0};
    size_t written = 0U;
    assert(pbns_sign1_sign(&signer,
                           (pbns_view){signed_payload, sizeof(signed_payload)},
                           (pbns_view){external_aad, sizeof(external_aad) - 1U},
                           (pbns_buffer){cose, 0U, sizeof(cose)},
                           &written) == PBNS_OK);
    assert(written > sizeof(signed_payload));

    pbns_view payload = {0};
    assert(pbns_sign1_verify(&verifier,
                             (pbns_view){cose, written},
                             (pbns_view){external_aad, sizeof(external_aad) - 1U},
                             &payload) == PBNS_OK);
    assert_payload(payload);

    pbns_crypto_reset(&signer);
    pbns_crypto_reset(&verifier);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
}

static void test_rejects_wrong_aad_and_tampered_signature(void) {
    EVP_PKEY *const private_key = load_private_key();
    EVP_PKEY *const public_key = load_public_key();
    pbns_crypto signer = {0};
    pbns_crypto verifier = {0};
    assert(pbns_crypto_openssl_wrap(&signer, private_key) == PBNS_OK);
    assert(pbns_crypto_openssl_wrap(&verifier, public_key) == PBNS_OK);

    uint8_t cose[512] = {0};
    size_t written = 0U;
    assert(pbns_sign1_sign(&signer,
                           (pbns_view){signed_payload, sizeof(signed_payload)},
                           (pbns_view){external_aad, sizeof(external_aad) - 1U},
                           (pbns_buffer){cose, 0U, sizeof(cose)},
                           &written) == PBNS_OK);

    static const uint8_t wrong_aad[] = "pbns-sign1-v2";
    pbns_view payload = {0};
    assert(pbns_sign1_verify(&verifier,
                             (pbns_view){cose, written},
                             (pbns_view){wrong_aad, sizeof(wrong_aad) - 1U},
                             &payload) == PBNS_ERR_AUTHENTICATION);

    cose[written - 1U] ^= UINT8_C(1);
    assert(pbns_sign1_verify(&verifier,
                             (pbns_view){cose, written},
                             (pbns_view){external_aad, sizeof(external_aad) - 1U},
                             &payload) == PBNS_ERR_AUTHENTICATION);

    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
}

static void test_rejects_short_output_and_public_only_signing(void) {
    EVP_PKEY *const private_key = load_private_key();
    EVP_PKEY *const public_key = load_public_key();
    pbns_crypto signer = {0};
    pbns_crypto public_only = {0};
    assert(pbns_crypto_openssl_wrap(&signer, private_key) == PBNS_OK);
    assert(pbns_crypto_openssl_wrap(&public_only, public_key) == PBNS_OK);

    uint8_t cose[512] = {0};
    size_t written = 0U;
    assert(pbns_sign1_sign(&signer,
                           (pbns_view){signed_payload, sizeof(signed_payload)},
                           (pbns_view){external_aad, sizeof(external_aad) - 1U},
                           (pbns_buffer){cose, 0U, sizeof(cose)},
                           &written) == PBNS_OK);
    const size_t required = written;

    written = SIZE_MAX;
    assert(pbns_sign1_sign(&signer,
                           (pbns_view){signed_payload, sizeof(signed_payload)},
                           (pbns_view){external_aad, sizeof(external_aad) - 1U},
                           (pbns_buffer){cose, 0U, required - 1U},
                           &written) == PBNS_ERR_LIMIT);
    assert(written == 0U);

    uint8_t overlapping[512] = {0};
    for (size_t index = 0U; index < sizeof(signed_payload); ++index) {
        overlapping[index] = signed_payload[index];
    }
    assert(pbns_sign1_sign(&signer,
                           (pbns_view){overlapping, sizeof(signed_payload)},
                           (pbns_view){external_aad, sizeof(external_aad) - 1U},
                           (pbns_buffer){overlapping, 0U, sizeof(overlapping)},
                           &written) == PBNS_ERR_ARGUMENT);

    assert(pbns_sign1_sign(&public_only,
                           (pbns_view){signed_payload, sizeof(signed_payload)},
                           (pbns_view){external_aad, sizeof(external_aad) - 1U},
                           (pbns_buffer){cose, 0U, sizeof(cose)},
                           &written) == PBNS_ERR_CRYPTO);

    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
}

static void test_checked_in_vector_verifies(void) {
    EVP_PKEY *const public_key = load_public_key();
    pbns_crypto verifier = {0};
    assert(pbns_crypto_openssl_wrap(&verifier, public_key) == PBNS_OK);
    uint8_t vector[512] = {0};
    const size_t vector_len = read_vector(vector, sizeof(vector));
    pbns_view payload = {0};
    assert(pbns_sign1_verify(&verifier,
                             (pbns_view){vector, vector_len},
                             (pbns_view){external_aad, sizeof(external_aad) - 1U},
                             &payload) == PBNS_OK);
    assert_payload(payload);
    EVP_PKEY_free(public_key);
}

static void test_rejects_non_p256_key(void) {
    EVP_PKEY *const p384_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384");
    assert(p384_key != NULL);
    pbns_crypto crypto = {0};
    assert(pbns_crypto_openssl_wrap(&crypto, p384_key) == PBNS_ERR_UNSUPPORTED);
    assert(crypto.ops == NULL);
    assert(crypto.context == NULL);
    EVP_PKEY_free(p384_key);
}

static void test_invalid_arguments_and_reset(void) {
    EVP_PKEY *const private_key = load_private_key();
    pbns_crypto crypto = {0};
    uint8_t output[512] = {0};
    size_t written = SIZE_MAX;
    pbns_view payload = {0};

    assert(pbns_sign1_sign(&crypto,
                           (pbns_view){signed_payload, sizeof(signed_payload)},
                           (pbns_view){NULL, 0U},
                           (pbns_buffer){output, 0U, sizeof(output)},
                           &written) == PBNS_ERR_ARGUMENT);
    assert(written == 0U);
    assert(pbns_crypto_openssl_wrap(&crypto, private_key) == PBNS_OK);
    pbns_crypto_reset(&crypto);
    assert(pbns_sign1_verify(&crypto,
                             (pbns_view){output, sizeof(output)},
                             (pbns_view){NULL, 0U},
                             &payload) == PBNS_ERR_ARGUMENT);
    pbns_crypto_reset(NULL);
    assert(pbns_crypto_openssl_wrap(NULL, private_key) == PBNS_ERR_ARGUMENT);
    assert(pbns_crypto_openssl_wrap(&crypto, NULL) == PBNS_ERR_ARGUMENT);

    EVP_PKEY_free(private_key);
}

int main(void) {
    test_rejects_invalid_callback_output_lengths();
    test_sign_and_verify_with_external_aad();
    test_rejects_wrong_aad_and_tampered_signature();
    test_rejects_short_output_and_public_only_signing();
    test_checked_in_vector_verifies();
    test_rejects_non_p256_key();
    test_invalid_arguments_and_reset();
    return 0;
}
