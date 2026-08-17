#include "pbns/encrypt.h"
#include "bridge.h"

#include <assert.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <qcbor/qcbor_spiffy_decode.h>

#define VECTOR_PATH "tests/vectors/cose-encrypt-v1/cosec-to-tcose.cbor"
#define TCOSE_VECTOR_PATH "tests/vectors/cose-encrypt-v1/tcose-to-cosec.cbor"
#define PRIVATE_KEY_PATH "tests/fixtures/keys/cose-recipient-test-private.pem"
#define PUBLIC_KEY_PATH "tests/fixtures/keys/cose-recipient-test-public.pem"
#define TEST_BUFFER_SIZE 2048U

static const uint8_t interop_kid[] = "pbns-recipient-v1";
static const uint8_t interop_aad[] = "PBNS-ENCRYPT-INTEROP-v1";
static const uint8_t interop_plaintext[] = "pbns interop payload";

typedef struct {
    size_t body_algorithm;
    size_t ciphertext;
    size_t recipient_algorithm;
    size_t kid;
    size_t ephemeral_x;
} mutation_offsets;

typedef struct {
    const uint8_t *private_der;
    size_t private_der_size;
    const uint8_t *message;
    size_t message_size;
    bool success;
} concurrent_decrypt_case;

static pbns_view literal_view(const uint8_t *data, size_t size)
{
    const pbns_view view = {data, size - 1U};
    return view;
}

static size_t read_file(const char *path, uint8_t *storage, size_t capacity)
{
    FILE *file = fopen(path, "rb");
    assert(file != NULL);
    assert(fseek(file, 0L, SEEK_END) == 0);
    const long end = ftell(file);
    assert(end >= 0L);
    assert((unsigned long)end <= (unsigned long)capacity);
    assert(fseek(file, 0L, SEEK_SET) == 0);
    const size_t size = (size_t)end;
    assert(fread(storage, 1U, size, file) == size);
    assert(fclose(file) == 0);
    return size;
}

static EVP_PKEY *load_public_key(void)
{
    FILE *file = fopen(PUBLIC_KEY_PATH, "rb");
    assert(file != NULL);
    EVP_PKEY *key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    assert(fclose(file) == 0);
    assert(key != NULL);
    return key;
}

static EVP_PKEY *load_private_key_at(const char *path)
{
    FILE *file = fopen(path, "rb");
    assert(file != NULL);
    EVP_PKEY *key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    assert(fclose(file) == 0);
    assert(key != NULL);
    return key;
}

static size_t offset_of(pbns_view encoded, struct q_useful_buf_c bytes)
{
    const uintptr_t begin = (uintptr_t)encoded.ptr;
    assert(encoded.len <= UINTPTR_MAX - begin);
    const uintptr_t end = begin + encoded.len;
    const uintptr_t pointer = (uintptr_t)bytes.ptr;
    assert(pointer >= begin);
    assert(pointer < end);
    assert(bytes.len > 0U);
    assert(bytes.len <= (size_t)(end - pointer));
    return (size_t)(pointer - begin);
}

static mutation_offsets locate_mutations(pbns_view encoded)
{
    QCBORDecodeContext decoder = {0};
    struct q_useful_buf_c body_protected = {0};
    struct q_useful_buf_c ciphertext = {0};
    struct q_useful_buf_c recipient_protected = {0};
    struct q_useful_buf_c kid = {0};
    struct q_useful_buf_c ephemeral_x = {0};

    QCBORDecode_Init(&decoder,
                     (struct q_useful_buf_c){encoded.ptr, encoded.len},
                     QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterArray(&decoder, NULL);
    QCBORDecode_GetByteString(&decoder, &body_protected);
    QCBORDecode_EnterMap(&decoder, NULL);
    QCBORDecode_ExitMap(&decoder);
    QCBORDecode_GetByteString(&decoder, &ciphertext);
    QCBORDecode_EnterArray(&decoder, NULL);
    QCBORDecode_EnterArray(&decoder, NULL);
    QCBORDecode_GetByteString(&decoder, &recipient_protected);
    QCBORDecode_EnterMap(&decoder, NULL);
    QCBORDecode_GetByteStringInMapN(&decoder, 4, &kid);
    QCBORDecode_EnterMapFromMapN(&decoder, -1);
    QCBORDecode_GetByteStringInMapN(&decoder, -2, &ephemeral_x);
    QCBORDecode_ExitMap(&decoder);
    QCBORDecode_ExitMap(&decoder);
    QCBORDecode_ExitArray(&decoder);
    QCBORDecode_ExitArray(&decoder);
    QCBORDecode_ExitArray(&decoder);
    assert(QCBORDecode_Finish(&decoder) == QCBOR_SUCCESS);

    assert(body_protected.len >= 1U);
    assert(recipient_protected.len >= 1U);
    const mutation_offsets offsets = {
        .body_algorithm = offset_of(encoded, body_protected) + body_protected.len - 1U,
        .ciphertext = offset_of(encoded, ciphertext),
        .recipient_algorithm = offset_of(encoded, recipient_protected) +
                               recipient_protected.len - 1U,
        .kid = offset_of(encoded, kid),
        .ephemeral_x = offset_of(encoded, ephemeral_x),
    };
    return offsets;
}

static void assert_decrypt_rejects(const pbns_crypto *crypto,
                                   const uint8_t *message,
                                   size_t message_size,
                                   pbns_view kid,
                                   pbns_view aad)
{
    uint8_t plaintext[TEST_BUFFER_SIZE] = {0};
    memset(plaintext, 0xa5, sizeof(plaintext));
    size_t written = SIZE_MAX;
    const pbns_status status = pbns_decrypt_for_recipient(
        crypto,
        kid,
        (pbns_view){message, message_size},
        aad,
        (pbns_buffer){plaintext, 0U, sizeof(plaintext)},
        &written);
    assert(status != PBNS_OK);
    assert(written == 0U);
    for(size_t index = 0U; index < sizeof(plaintext); ++index) {
        assert(plaintext[index] == 0U);
    }
}

static void test_decrypts_cosec_vector_and_rejects_mutations(void)
{
    uint8_t message[TEST_BUFFER_SIZE] = {0};
    const size_t message_size = read_file(VECTOR_PATH, message, sizeof(message));
    EVP_PKEY *private_key = load_private_key_at(PRIVATE_KEY_PATH);
    pbns_crypto crypto = {0};
    assert(pbns_crypto_openssl_wrap(&crypto, private_key) == PBNS_OK);

    uint8_t plaintext[TEST_BUFFER_SIZE] = {0};
    size_t written = 0U;
    assert(pbns_decrypt_for_recipient(
               &crypto,
               literal_view(interop_kid, sizeof(interop_kid)),
               (pbns_view){message, message_size},
               literal_view(interop_aad, sizeof(interop_aad)),
               (pbns_buffer){plaintext, 0U, sizeof(plaintext)},
               &written) == PBNS_OK);
    assert(written == sizeof(interop_plaintext) - 1U);
    assert(memcmp(plaintext, interop_plaintext, written) == 0);

    const mutation_offsets offsets = locate_mutations((pbns_view){message, message_size});
    const size_t mutation_points[] = {
        offsets.body_algorithm,
        offsets.ciphertext,
        offsets.recipient_algorithm,
        offsets.kid,
        offsets.ephemeral_x,
    };
    for(size_t index = 0U; index < sizeof(mutation_points) / sizeof(mutation_points[0]); ++index) {
        uint8_t mutated[TEST_BUFFER_SIZE] = {0};
        memcpy(mutated, message, message_size);
        mutated[mutation_points[index]] ^= 0x01U;
        assert_decrypt_rejects(&crypto,
                               mutated,
                               message_size,
                               literal_view(interop_kid, sizeof(interop_kid)),
                               literal_view(interop_aad, sizeof(interop_aad)));
    }

    const uint8_t wrong_kid[] = "wrong-recipient";
    const uint8_t wrong_aad[] = "wrong-aad";
    assert_decrypt_rejects(&crypto,
                           message,
                           message_size,
                           literal_view(wrong_kid, sizeof(wrong_kid)),
                           literal_view(interop_aad, sizeof(interop_aad)));
    assert_decrypt_rejects(&crypto,
                           message,
                           message_size,
                           literal_view(interop_kid, sizeof(interop_kid)),
                           literal_view(wrong_aad, sizeof(wrong_aad)));

    pbns_crypto_reset(&crypto);
    EVP_PKEY_free(private_key);
}

static void test_cosec_encrypts_for_tcose(void)
{
    EVP_PKEY *public_key = load_public_key();
    const int der_size = i2d_PUBKEY(public_key, NULL);
    assert(der_size > 0);
    uint8_t public_der[512] = {0};
    assert((size_t)der_size <= sizeof(public_der));
    unsigned char *der_cursor = public_der;
    assert(i2d_PUBKEY(public_key, &der_cursor) == der_size);
    assert((size_t)(der_cursor - public_der) == (size_t)der_size);

    pbns_cosec_output output = {0};
    assert(pbns_cosec_encrypt(
               public_der,
               (size_t)der_size,
               interop_kid,
               sizeof(interop_kid) - 1U,
               interop_plaintext,
               sizeof(interop_plaintext) - 1U,
               interop_aad,
               sizeof(interop_aad) - 1U,
               &output) == PBNS_COSEC_OK);
    assert(output.data != NULL);
    assert(output.len > sizeof(interop_plaintext) - 1U);

    EVP_PKEY *private_key = load_private_key_at(PRIVATE_KEY_PATH);
    pbns_crypto crypto = {0};
    assert(pbns_crypto_openssl_wrap(&crypto, private_key) == PBNS_OK);
    uint8_t plaintext[TEST_BUFFER_SIZE] = {0};
    size_t plaintext_size = 0U;
    assert(pbns_decrypt_for_recipient(
               &crypto,
               literal_view(interop_kid, sizeof(interop_kid)),
               (pbns_view){output.data, output.len},
               literal_view(interop_aad, sizeof(interop_aad)),
               (pbns_buffer){plaintext, 0U, sizeof(plaintext)},
               &plaintext_size) == PBNS_OK);
    assert(plaintext_size == sizeof(interop_plaintext) - 1U);
    assert(memcmp(plaintext, interop_plaintext, plaintext_size) == 0);

    pbns_crypto_reset(&crypto);
    EVP_PKEY_free(private_key);
    pbns_cosec_free(output.data);
    EVP_PKEY_free(public_key);
}

static void test_cosec_decrypts_tcose_vector(void)
{
    uint8_t message[TEST_BUFFER_SIZE] = {0};
    const size_t message_size = read_file(TCOSE_VECTOR_PATH, message, sizeof(message));
    EVP_PKEY *private_key = load_private_key_at(PRIVATE_KEY_PATH);

    const int der_size = i2d_PrivateKey(private_key, NULL);
    assert(der_size > 0);
    uint8_t private_der[512] = {0};
    assert((size_t)der_size <= sizeof(private_der));
    unsigned char *der_cursor = private_der;
    assert(i2d_PrivateKey(private_key, &der_cursor) == der_size);
    assert((size_t)(der_cursor - private_der) == (size_t)der_size);

    pbns_cosec_output output = {0};
    assert(pbns_cosec_decrypt(
               private_der,
               (size_t)der_size,
               interop_kid,
               sizeof(interop_kid) - 1U,
               message,
               message_size,
               interop_aad,
               sizeof(interop_aad) - 1U,
               &output) == PBNS_COSEC_OK);
    assert(output.len == sizeof(interop_plaintext) - 1U);
    assert(memcmp(output.data, interop_plaintext, output.len) == 0);
    pbns_cosec_free(output.data);
    EVP_PKEY_free(private_key);
}

static void *concurrent_decrypt_worker(void *context)
{
    concurrent_decrypt_case *const test_case = context;
    test_case->success = false;
    for(size_t iteration = 0U; iteration < 25U; ++iteration) {
        pbns_cosec_output output = {0};
        const pbns_cosec_status status = pbns_cosec_decrypt(
            test_case->private_der,
            test_case->private_der_size,
            interop_kid,
            sizeof(interop_kid) - 1U,
            test_case->message,
            test_case->message_size,
            interop_aad,
            sizeof(interop_aad) - 1U,
            &output);
        const bool matches = status == PBNS_COSEC_OK
                             && output.len == sizeof(interop_plaintext) - 1U
                             && memcmp(output.data, interop_plaintext, output.len) == 0;
        pbns_cosec_free(output.data);
        if(!matches) {
            return NULL;
        }
    }
    test_case->success = true;
    return NULL;
}

static void test_concurrent_cosec_decryption(void)
{
    uint8_t message[TEST_BUFFER_SIZE] = {0};
    const size_t message_size = read_file(TCOSE_VECTOR_PATH, message, sizeof(message));
    EVP_PKEY *private_key = load_private_key_at(PRIVATE_KEY_PATH);
    const int der_size = i2d_PrivateKey(private_key, NULL);
    assert(der_size > 0);
    uint8_t private_der[512] = {0};
    assert((size_t)der_size <= sizeof(private_der));
    unsigned char *der_cursor = private_der;
    assert(i2d_PrivateKey(private_key, &der_cursor) == der_size);
    assert((size_t)(der_cursor - private_der) == (size_t)der_size);

    pthread_t threads[4] = {0};
    concurrent_decrypt_case cases[4] = {0};
    for(size_t index = 0U; index < 4U; ++index) {
        cases[index] = (concurrent_decrypt_case){
            .private_der = private_der,
            .private_der_size = (size_t)der_size,
            .message = message,
            .message_size = message_size,
        };
        assert(pthread_create(&threads[index], NULL, concurrent_decrypt_worker, &cases[index]) == 0);
    }
    for(size_t index = 0U; index < 4U; ++index) {
        void *thread_result = NULL;
        assert(pthread_join(threads[index], &thread_result) == 0);
        assert(thread_result == NULL);
        assert(cases[index].success);
    }
    EVP_PKEY_free(private_key);
}

static void test_tcose_round_trip_and_bounds(void)
{
    EVP_PKEY *public_key = load_public_key();
    EVP_PKEY *private_key = load_private_key_at(PRIVATE_KEY_PATH);
    pbns_crypto encrypt_crypto = {0};
    pbns_crypto decrypt_crypto = {0};
    assert(pbns_crypto_openssl_wrap(&encrypt_crypto, public_key) == PBNS_OK);
    assert(pbns_crypto_openssl_wrap(&decrypt_crypto, private_key) == PBNS_OK);

    uint8_t message[TEST_BUFFER_SIZE] = {0};
    size_t message_size = 0U;
    assert(pbns_encrypt_for_recipient(
               &encrypt_crypto,
               literal_view(interop_kid, sizeof(interop_kid)),
               literal_view(interop_plaintext, sizeof(interop_plaintext)),
               literal_view(interop_aad, sizeof(interop_aad)),
               (pbns_buffer){message, 0U, sizeof(message)},
               &message_size) == PBNS_OK);
    assert(message_size > sizeof(interop_plaintext));

    uint8_t plaintext[TEST_BUFFER_SIZE] = {0};
    size_t plaintext_size = 0U;
    assert(pbns_decrypt_for_recipient(
               &decrypt_crypto,
               literal_view(interop_kid, sizeof(interop_kid)),
               (pbns_view){message, message_size},
               literal_view(interop_aad, sizeof(interop_aad)),
               (pbns_buffer){plaintext, 0U, sizeof(plaintext)},
               &plaintext_size) == PBNS_OK);
    assert(plaintext_size == sizeof(interop_plaintext) - 1U);
    assert(memcmp(plaintext, interop_plaintext, plaintext_size) == 0);

    size_t written = SIZE_MAX;
    uint8_t short_message[1] = {0xa5U};
    assert(pbns_encrypt_for_recipient(
               &encrypt_crypto,
               literal_view(interop_kid, sizeof(interop_kid)),
               literal_view(interop_plaintext, sizeof(interop_plaintext)),
               literal_view(interop_aad, sizeof(interop_aad)),
               (pbns_buffer){short_message, 0U, sizeof(short_message)},
               &written) == PBNS_ERR_LIMIT);
    assert(written == 0U);
    assert(short_message[0] == 0U);

    written = SIZE_MAX;
    assert(pbns_decrypt_for_recipient(
               &decrypt_crypto,
               literal_view(interop_kid, sizeof(interop_kid)),
               (pbns_view){message, message_size},
               literal_view(interop_aad, sizeof(interop_aad)),
               (pbns_buffer){plaintext, 0U, 1U},
               &written) == PBNS_ERR_LIMIT);
    assert(written == 0U);
    assert(plaintext[0] == 0U);

    uint8_t overlapping[TEST_BUFFER_SIZE] = {0};
    memcpy(overlapping, interop_plaintext, sizeof(interop_plaintext) - 1U);
    written = SIZE_MAX;
    assert(pbns_encrypt_for_recipient(
               &encrypt_crypto,
               literal_view(interop_kid, sizeof(interop_kid)),
               (pbns_view){overlapping, sizeof(interop_plaintext) - 1U},
               literal_view(interop_aad, sizeof(interop_aad)),
               (pbns_buffer){overlapping, 0U, sizeof(overlapping)},
               &written) == PBNS_ERR_ARGUMENT);
    assert(written == 0U);

    memcpy(overlapping, message, message_size);
    written = SIZE_MAX;
    assert(pbns_decrypt_for_recipient(
               &decrypt_crypto,
               literal_view(interop_kid, sizeof(interop_kid)),
               (pbns_view){overlapping, message_size},
               literal_view(interop_aad, sizeof(interop_aad)),
               (pbns_buffer){overlapping, 0U, sizeof(overlapping)},
               &written) == PBNS_ERR_ARGUMENT);
    assert(written == 0U);

    pbns_crypto_reset(&decrypt_crypto);
    pbns_crypto_reset(&encrypt_crypto);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
}

static int encrypt_command(const char *key_path,
                           const char *plaintext,
                           const char *kid,
                           const char *aad)
{
    FILE *file = fopen(key_path, "rb");
    assert(file != NULL);
    EVP_PKEY *public_key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    assert(fclose(file) == 0);
    assert(public_key != NULL);
    pbns_crypto crypto = {0};
    assert(pbns_crypto_openssl_wrap(&crypto, public_key) == PBNS_OK);

    uint8_t message[TEST_BUFFER_SIZE] = {0};
    size_t written = 0U;
    const pbns_status status = pbns_encrypt_for_recipient(
        &crypto,
        (pbns_view){(const uint8_t *)kid, strlen(kid)},
        (pbns_view){(const uint8_t *)plaintext, strlen(plaintext)},
        (pbns_view){(const uint8_t *)aad, strlen(aad)},
        (pbns_buffer){message, 0U, sizeof(message)},
        &written);
    const bool write_ok = status == PBNS_OK && fwrite(message, 1U, written, stdout) == written;
    const bool flush_ok = fflush(stdout) == 0;

    pbns_crypto_reset(&crypto);
    EVP_PKEY_free(public_key);
    return write_ok && flush_ok ? 0 : 1;
}

static int decrypt_command(const char *key_path,
                           const char *message_path,
                           const char *kid,
                           const char *aad)
{
    uint8_t message[TEST_BUFFER_SIZE] = {0};
    const size_t message_size = read_file(message_path, message, sizeof(message));
    EVP_PKEY *private_key = load_private_key_at(key_path);
    pbns_crypto crypto = {0};
    assert(pbns_crypto_openssl_wrap(&crypto, private_key) == PBNS_OK);

    uint8_t plaintext[TEST_BUFFER_SIZE] = {0};
    size_t written = 0U;
    const pbns_status status = pbns_decrypt_for_recipient(
        &crypto,
        (pbns_view){(const uint8_t *)kid, strlen(kid)},
        (pbns_view){message, message_size},
        (pbns_view){(const uint8_t *)aad, strlen(aad)},
        (pbns_buffer){plaintext, 0U, sizeof(plaintext)},
        &written);
    const bool write_ok = status == PBNS_OK && fwrite(plaintext, 1U, written, stdout) == written;
    const bool flush_ok = fflush(stdout) == 0;
    if(status != PBNS_OK) {
        assert(fprintf(stderr, "decrypt status: %s (%d)\n", pbns_status_string(status), status) >= 0);
    }

    pbns_crypto_reset(&crypto);
    EVP_PKEY_free(private_key);
    return write_ok && flush_ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    if(argc == 6 && strcmp(argv[1], "--decrypt") == 0) {
        return decrypt_command(argv[2], argv[3], argv[4], argv[5]);
    }
    if(argc == 6 && strcmp(argv[1], "--encrypt") == 0) {
        return encrypt_command(argv[2], argv[3], argv[4], argv[5]);
    }
    assert(argc == 1);
    test_decrypts_cosec_vector_and_rejects_mutations();
    test_cosec_encrypts_for_tcose();
    test_cosec_decrypts_tcose_vector();
    test_concurrent_cosec_decryption();
    test_tcose_round_trip_and_bounds();
    return 0;
}
