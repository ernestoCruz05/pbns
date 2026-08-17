#include <Uefi.h>

#include <Library/PbnsCoseCryptoLib.h>
#include <Library/UefiLib.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static const uint8_t VECTOR_X[32] = {
    0x18U, 0x4dU, 0x92U, 0x82U, 0xe7U, 0x2fU, 0x5bU, 0x3fU, 0x6eU, 0x0eU, 0xa7U,
    0x3bU, 0x42U, 0xacU, 0x55U, 0xd4U, 0x1fU, 0x18U, 0x58U, 0x8aU, 0xcaU, 0x5cU,
    0xc4U, 0x87U, 0x36U, 0x58U, 0x05U, 0xd5U, 0x78U, 0x2aU, 0xb3U, 0xcaU,
};

static const uint8_t VECTOR_Y[32] = {
    0xeeU, 0x41U, 0x0fU, 0xd3U, 0xafU, 0xa3U, 0x58U, 0x94U, 0xf5U, 0x46U, 0x0dU,
    0x82U, 0x2dU, 0xaaU, 0x3aU, 0x3fU, 0x62U, 0xc6U, 0x1fU, 0x62U, 0x0eU, 0xffU,
    0x4fU, 0x65U, 0xabU, 0x7dU, 0x0eU, 0x31U, 0xb9U, 0x4cU, 0x78U, 0x93U,
};

static const uint8_t VECTOR_COSE[90] = {
    0xd2U, 0x84U, 0x43U, 0xa1U, 0x01U, 0x26U, 0xa0U, 0x50U, 0x70U, 0x62U,
    0x6eU, 0x73U, 0x2dU, 0x74U, 0x69U, 0x6dU, 0x65U, 0x2dU, 0x76U, 0x65U,
    0x63U, 0x74U, 0x6fU, 0x72U, 0x58U, 0x40U, 0x0aU, 0xcdU, 0x37U, 0x55U,
    0xdeU, 0x62U, 0x01U, 0x43U, 0x73U, 0x77U, 0x20U, 0x09U, 0x86U, 0xf6U,
    0x27U, 0x70U, 0x49U, 0xfbU, 0x61U, 0x70U, 0x9fU, 0x81U, 0xd6U, 0x91U,
    0x18U, 0xefU, 0x63U, 0xf9U, 0x31U, 0x12U, 0x01U, 0x44U, 0x1fU, 0x75U,
    0x83U, 0x72U, 0xe0U, 0x83U, 0xd3U, 0xadU, 0xfaU, 0x95U, 0x8fU, 0x0fU,
    0x16U, 0x00U, 0x90U, 0x57U, 0xecU, 0x8dU, 0x85U, 0x62U, 0x44U, 0xe9U,
    0x3aU, 0x4dU, 0x96U, 0x86U, 0x4fU, 0xf6U, 0xf1U, 0xb7U, 0xf4U, 0xf6U,
};

static const uint8_t VECTOR_AAD[] = "PBNS-TIME-ASSERTION-v1-vector";
static const uint8_t VECTOR_PAYLOAD[] = "pbns-time-vector";

static const uint8_t FIXTURE_RECIPIENT_X[32] = {
    0x1dU, 0x73U, 0x97U, 0xc5U, 0xdeU, 0x0cU, 0x79U, 0x6cU, 0x13U, 0xe1U, 0x10U,
    0x39U, 0xa1U, 0xdaU, 0x70U, 0xf0U, 0x73U, 0x5aU, 0xa2U, 0x62U, 0xabU, 0x7fU,
    0xafU, 0x47U, 0x81U, 0xf3U, 0x0bU, 0x2bU, 0x18U, 0x38U, 0x0bU, 0x31U,
};

static const uint8_t FIXTURE_RECIPIENT_Y[32] = {
    0xe3U, 0xf8U, 0x96U, 0xceU, 0xa4U, 0xd5U, 0x2fU, 0x22U, 0xd7U, 0xd4U, 0xbfU,
    0xf7U, 0x1aU, 0x39U, 0x1bU, 0xfeU, 0xe8U, 0x11U, 0xe1U, 0x73U, 0xbfU, 0x20U,
    0x7bU, 0xfeU, 0xdfU, 0x7eU, 0xdcU, 0xcfU, 0x9fU, 0xe5U, 0x7eU, 0x52U,
};

static const uint8_t COSEC_ENCRYPT_VECTOR[170] = {
    0xd8U, 0x60U, 0x84U, 0x43U, 0xa1U, 0x01U, 0x01U, 0xa1U, 0x05U, 0x4cU, 0x16U,
    0x91U, 0x7aU, 0xadU, 0x0dU, 0xa2U, 0xc3U, 0x7eU, 0x5aU, 0xc8U, 0x58U, 0x98U,
    0x58U, 0x26U, 0xf5U, 0xf2U, 0x28U, 0x94U, 0x4aU, 0x8eU, 0x26U, 0x06U, 0xdcU,
    0xb9U, 0xd0U, 0x76U, 0x1fU, 0xc1U, 0x2bU, 0xceU, 0xbbU, 0x30U, 0x1aU, 0x96U,
    0x4cU, 0xcdU, 0x4aU, 0x2eU, 0x55U, 0xfcU, 0x06U, 0x2eU, 0x57U, 0x04U, 0x54U,
    0x4eU, 0x7dU, 0x57U, 0x96U, 0xf8U, 0x1dU, 0x5eU, 0x81U, 0x83U, 0x44U, 0xa1U,
    0x01U, 0x38U, 0x1cU, 0xa2U, 0x04U, 0x58U, 0x1cU, 0x70U, 0x62U, 0x6eU, 0x73U,
    0x2dU, 0x65U, 0x6eU, 0x72U, 0x6fU, 0x6cU, 0x6cU, 0x6dU, 0x65U, 0x6eU, 0x74U,
    0x2dU, 0x72U, 0x65U, 0x63U, 0x69U, 0x70U, 0x69U, 0x65U, 0x6eU, 0x74U, 0x2dU,
    0x76U, 0x31U, 0x20U, 0xa4U, 0x20U, 0x01U, 0x21U, 0x58U, 0x20U, 0x3dU, 0xd1U,
    0x7bU, 0xc4U, 0xa6U, 0xa7U, 0xabU, 0x70U, 0xb2U, 0x5fU, 0x8cU, 0x86U, 0x16U,
    0xd3U, 0x42U, 0x5cU, 0x21U, 0x14U, 0x16U, 0x12U, 0x40U, 0x60U, 0xabU, 0x4fU,
    0x81U, 0xb1U, 0x06U, 0xd1U, 0xcbU, 0xfbU, 0xceU, 0xe7U, 0x22U, 0xf5U, 0x01U,
    0x02U, 0x58U, 0x18U, 0xbcU, 0x61U, 0x1aU, 0xf8U, 0x09U, 0x4cU, 0x73U, 0x2aU,
    0xd0U, 0x68U, 0xe7U, 0x3eU, 0x7bU, 0x32U, 0x71U, 0x18U, 0xdbU, 0x55U, 0x24U,
    0xfaU, 0x3dU, 0x6aU, 0x4aU, 0xb9U,
};

#define VECTOR_SIGNATURE_OFFSET 26U
#define VECTOR_SIGNATURE_SIZE 64U

typedef struct probe_identity_context {
  bool sign_called;
  bool random_fail;
  uint32_t random_state;
} probe_identity_context;

static pbns_status probe_public(void *context, pbns_buffer output,
                                size_t *written) {
  (void)context;
  (void)output;
  (void)written;
  return PBNS_ERR_UNSUPPORTED;
}

static pbns_status probe_fingerprint(void *context, pbns_buffer output) {
  (void)context;
  (void)output;
  return PBNS_ERR_UNSUPPORTED;
}

static pbns_status probe_sign(void *context, pbns_view digest,
                              pbns_buffer signature, size_t *written) {
  probe_identity_context *probe = context;
  if (digest.ptr == NULL || digest.len != 32U || signature.ptr == NULL ||
      signature.cap < VECTOR_SIGNATURE_SIZE || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  memcpy(signature.ptr, VECTOR_COSE + VECTOR_SIGNATURE_OFFSET,
         VECTOR_SIGNATURE_SIZE);
  *written = VECTOR_SIGNATURE_SIZE;
  probe->sign_called = true;
  return PBNS_OK;
}

static pbns_status probe_random(void *context, pbns_buffer output) {
  probe_identity_context *probe = context;
  if (probe == NULL || output.ptr == NULL || output.cap == 0U ||
      output.len > output.cap) {
    return PBNS_ERR_ARGUMENT;
  }
  if (probe->random_fail) {
    return PBNS_ERR_ENTROPY;
  }
  for (size_t index = 0U; index < output.cap; ++index) {
    probe->random_state =
        probe->random_state * UINT32_C(1664525) + UINT32_C(1013904223);
    output.ptr[index] = (uint8_t)(probe->random_state >> 24U);
  }
  return PBNS_OK;
}

static void probe_close(void *context) {
  probe_identity_context *probe = context;
  probe->sign_called = false;
  probe->random_fail = false;
  probe->random_state = 0U;
}

static const pbns_identity_ops PROBE_IDENTITY_OPS = {
    .public_cose_key = probe_public,
    .fingerprint = probe_fingerprint,
    .sign_digest = probe_sign,
    .random = probe_random,
    .close = probe_close,
};

static bool encryption_probe(pbns_identity *identity) {
  static const uint8_t key_id[] = "pbns-enrollment-recipient-v1";
  static const uint8_t plaintext[] = "pbns-enrollment-secret";
  static const uint8_t aad[] = "PBNS-ENROLLMENT-v1";
  static const uint8_t wrong_aad[] = "PBNS-ENROLLMENT-wrong";
  pbns_cose_key private_key = {0};
  pbns_cose_key public_key = {0};
  pbns_cose_key wrong_private_key = {0};
  uint8_t encrypted[1024] = {0};
  uint8_t corrupted[1024] = {0};
  uint8_t decrypted[128] = {0};
  uint8_t overlap[1024] = {0};
  uint8_t too_small[1] = {0};
  size_t encrypted_length = 0U;
  size_t decrypted_length = 0U;
  bool success = false;
  if (pbns_cose_p256_key_generate(&private_key, identity) != PBNS_OK ||
      pbns_cose_p256_key_export_public(&private_key, &public_key) != PBNS_OK) {
    goto cleanup;
  }
  pbns_status status = pbns_cose_uefi_encrypt_for_recipient(
      identity, &public_key, (pbns_view){key_id, sizeof(key_id) - 1U},
      (pbns_view){plaintext, sizeof(plaintext) - 1U},
      (pbns_view){aad, sizeof(aad) - 1U},
      (pbns_buffer){too_small, 0U, sizeof(too_small)}, &encrypted_length);
  if (status != PBNS_ERR_LIMIT || encrypted_length != 0U) {
    goto cleanup;
  }
  memcpy(overlap, plaintext, sizeof(plaintext) - 1U);
  status = pbns_cose_uefi_encrypt_for_recipient(
      identity, &public_key, (pbns_view){key_id, sizeof(key_id) - 1U},
      (pbns_view){overlap, sizeof(plaintext) - 1U},
      (pbns_view){aad, sizeof(aad) - 1U},
      (pbns_buffer){overlap, 0U, sizeof(overlap)}, &encrypted_length);
  if (status != PBNS_ERR_ARGUMENT || encrypted_length != 0U) {
    goto cleanup;
  }
  status = pbns_cose_uefi_decrypt_for_recipient(
      identity, &private_key, (pbns_view){key_id, sizeof(key_id) - 1U},
      (pbns_view){COSEC_ENCRYPT_VECTOR, sizeof(COSEC_ENCRYPT_VECTOR)},
      (pbns_view){aad, sizeof(aad) - 1U},
      (pbns_buffer){decrypted, 0U, sizeof(decrypted)}, &decrypted_length);
  if (status != PBNS_OK || decrypted_length != sizeof(plaintext) - 1U ||
      memcmp(decrypted, plaintext, decrypted_length) != 0) {
    goto cleanup;
  }
  memset(decrypted, 0, sizeof(decrypted));
  decrypted_length = 0U;
  status = pbns_cose_uefi_encrypt_for_recipient(
      identity, &public_key, (pbns_view){key_id, sizeof(key_id) - 1U},
      (pbns_view){plaintext, sizeof(plaintext) - 1U},
      (pbns_view){aad, sizeof(aad) - 1U},
      (pbns_buffer){encrypted, 0U, sizeof(encrypted)}, &encrypted_length);
  if (status != PBNS_OK || encrypted_length == 0U ||
      encrypted_length > sizeof(encrypted)) {
    goto cleanup;
  }
  status = pbns_cose_uefi_decrypt_for_recipient(
      identity, &private_key, (pbns_view){key_id, sizeof(key_id) - 1U},
      (pbns_view){encrypted, encrypted_length},
      (pbns_view){aad, sizeof(aad) - 1U},
      (pbns_buffer){decrypted, 0U, sizeof(decrypted)}, &decrypted_length);
  if (status != PBNS_OK || decrypted_length != sizeof(plaintext) - 1U ||
      memcmp(decrypted, plaintext, decrypted_length) != 0) {
    goto cleanup;
  }
  memset(decrypted, 0, sizeof(decrypted));
  decrypted_length = 0U;
  status = pbns_cose_uefi_decrypt_for_recipient(
      identity, &private_key, (pbns_view){key_id, sizeof(key_id) - 1U},
      (pbns_view){encrypted, encrypted_length},
      (pbns_view){wrong_aad, sizeof(wrong_aad) - 1U},
      (pbns_buffer){decrypted, 0U, sizeof(decrypted)}, &decrypted_length);
  if (status != PBNS_ERR_AUTHENTICATION || decrypted_length != 0U) {
    goto cleanup;
  }
  memcpy(corrupted, encrypted, encrypted_length);
  corrupted[encrypted_length - 1U] ^= UINT8_C(1);
  status = pbns_cose_uefi_decrypt_for_recipient(
      identity, &private_key, (pbns_view){key_id, sizeof(key_id) - 1U},
      (pbns_view){corrupted, encrypted_length},
      (pbns_view){aad, sizeof(aad) - 1U},
      (pbns_buffer){decrypted, 0U, sizeof(decrypted)}, &decrypted_length);
  if (status != PBNS_ERR_AUTHENTICATION || decrypted_length != 0U) {
    goto cleanup;
  }
  if (encrypted_length < 7U || encrypted[0] != 0xd8U || encrypted[1] != 0x60U ||
      encrypted[6] != 0x01U) {
    goto cleanup;
  }
  memcpy(corrupted, encrypted, encrypted_length);
  corrupted[6] = 0x02U;
  status = pbns_cose_uefi_decrypt_for_recipient(
      identity, &private_key, (pbns_view){key_id, sizeof(key_id) - 1U},
      (pbns_view){corrupted, encrypted_length},
      (pbns_view){aad, sizeof(aad) - 1U},
      (pbns_buffer){decrypted, 0U, sizeof(decrypted)}, &decrypted_length);
  if (status == PBNS_OK || decrypted_length != 0U) {
    goto cleanup;
  }
  if (pbns_cose_p256_key_generate(&wrong_private_key, identity) != PBNS_OK) {
    goto cleanup;
  }
  status = pbns_cose_uefi_decrypt_for_recipient(
      identity, &wrong_private_key, (pbns_view){key_id, sizeof(key_id) - 1U},
      (pbns_view){encrypted, encrypted_length},
      (pbns_view){aad, sizeof(aad) - 1U},
      (pbns_buffer){decrypted, 0U, sizeof(decrypted)}, &decrypted_length);
  if (status != PBNS_ERR_AUTHENTICATION || decrypted_length != 0U) {
    goto cleanup;
  }
  probe_identity_context *probe = identity->context;
  if (probe == NULL) {
    goto cleanup;
  }
  probe->random_fail = true;
  status = pbns_cose_uefi_encrypt_for_recipient(
      identity, &public_key, (pbns_view){key_id, sizeof(key_id) - 1U},
      (pbns_view){plaintext, sizeof(plaintext) - 1U},
      (pbns_view){aad, sizeof(aad) - 1U},
      (pbns_buffer){encrypted, 0U, sizeof(encrypted)}, &encrypted_length);
  probe->random_fail = false;
  if (status != PBNS_ERR_ENTROPY || encrypted_length != 0U) {
    goto cleanup;
  }
  success = true;

cleanup:
  pbns_cose_key_reset(&wrong_private_key);
  pbns_cose_key_reset(&public_key);
  pbns_cose_key_reset(&private_key);
  memset(too_small, 0, sizeof(too_small));
  memset(overlap, 0, sizeof(overlap));
  memset(decrypted, 0, sizeof(decrypted));
  memset(corrupted, 0, sizeof(corrupted));
  memset(encrypted, 0, sizeof(encrypted));
  return success;
}

static bool fixture_encryption_probe(pbns_identity *identity) {
  static const uint8_t key_id[] = "pbns-recipient-v1";
  static const uint8_t plaintext[] = "pbns interop payload";
  static const uint8_t aad[] = "PBNS-ENCRYPT-INTEROP-v1";
  if (identity == NULL || identity->context == NULL) {
    return false;
  }
  probe_identity_context *probe = identity->context;
  probe->random_state = UINT32_C(0xc0dec0de);
  pbns_cose_key public_key = {0};
  uint8_t encrypted[512] = {0};
  size_t encrypted_length = 0U;
  bool success = false;
  if (pbns_cose_key_from_p256_public(
          &public_key,
          (pbns_view){FIXTURE_RECIPIENT_X, sizeof(FIXTURE_RECIPIENT_X)},
          (pbns_view){FIXTURE_RECIPIENT_Y, sizeof(FIXTURE_RECIPIENT_Y)}) !=
      PBNS_OK) {
    goto cleanup;
  }
  if (pbns_cose_uefi_encrypt_for_recipient(
          identity, &public_key, (pbns_view){key_id, sizeof(key_id) - 1U},
          (pbns_view){plaintext, sizeof(plaintext) - 1U},
          (pbns_view){aad, sizeof(aad) - 1U},
          (pbns_buffer){encrypted, 0U, sizeof(encrypted)},
          &encrypted_length) != PBNS_OK) {
    goto cleanup;
  }
  Print(L"PBNS UEFI ENCRYPT VECTOR ");
  for (size_t index = 0U; index < encrypted_length; ++index) {
    Print(L"%02x", encrypted[index]);
  }
  Print(L"\r\n");
  success = true;

cleanup:
  pbns_cose_key_reset(&public_key);
  memset(encrypted, 0, sizeof(encrypted));
  return success;
}

EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE image_handle,
                           IN EFI_SYSTEM_TABLE *system_table) {
  (void)image_handle;
  (void)system_table;
  pbns_cose_key key = {0};
  if (pbns_cose_key_from_p256_public(
          &key, (pbns_view){VECTOR_X, sizeof(VECTOR_X)},
          (pbns_view){VECTOR_Y, sizeof(VECTOR_Y)}) != PBNS_OK) {
    Print(L"PBNS COSE PROBE FAIL key\r\n");
    return EFI_SECURITY_VIOLATION;
  }
  pbns_view payload = {0};
  pbns_status status = pbns_cose_uefi_sign1_verify(
      &key, (pbns_view){VECTOR_COSE, sizeof(VECTOR_COSE)},
      (pbns_view){VECTOR_AAD, sizeof(VECTOR_AAD) - 1U}, &payload);
  if (status != PBNS_OK || payload.len != sizeof(VECTOR_PAYLOAD) - 1U ||
      memcmp(payload.ptr, VECTOR_PAYLOAD, payload.len) != 0) {
    pbns_cose_key_reset(&key);
    Print(L"PBNS COSE PROBE FAIL vector\r\n");
    return EFI_SECURITY_VIOLATION;
  }
  probe_identity_context probe_context = {0};
  pbns_identity identity = {0};
  pbns_cose_key signing_key = {0};
  uint8_t generated[256] = {0};
  size_t generated_length = 0U;
  if (pbns_identity_open(&identity, &PROBE_IDENTITY_OPS, &probe_context,
                         PBNS_IDENTITY_SOFTWARE) != PBNS_OK ||
      pbns_cose_key_from_identity(&signing_key, &identity) != PBNS_OK) {
    pbns_identity_close(&identity);
    pbns_cose_key_reset(&signing_key);
    pbns_cose_key_reset(&key);
    Print(L"PBNS COSE PROBE FAIL signing setup\r\n");
    return EFI_SECURITY_VIOLATION;
  }
  status = pbns_cose_uefi_sign1_sign(
      &signing_key, (pbns_view){VECTOR_PAYLOAD, sizeof(VECTOR_PAYLOAD) - 1U},
      (pbns_view){VECTOR_AAD, sizeof(VECTOR_AAD) - 1U},
      (pbns_buffer){generated, 0U, sizeof(generated)}, &generated_length);
  if (status != PBNS_OK || !probe_context.sign_called) {
    pbns_cose_key_reset(&signing_key);
    pbns_identity_close(&identity);
    pbns_cose_key_reset(&key);
    Print(L"PBNS COSE PROBE FAIL signing operation\r\n");
    return EFI_SECURITY_VIOLATION;
  }
  if (generated_length != sizeof(VECTOR_COSE) ||
      memcmp(generated, VECTOR_COSE, sizeof(VECTOR_COSE)) != 0) {
    pbns_cose_key_reset(&signing_key);
    pbns_identity_close(&identity);
    pbns_cose_key_reset(&key);
    Print(L"PBNS COSE PROBE FAIL signing interoperability\r\n");
    return EFI_SECURITY_VIOLATION;
  }
  if (!encryption_probe(&identity) || !fixture_encryption_probe(&identity)) {
    pbns_cose_key_reset(&signing_key);
    pbns_identity_close(&identity);
    pbns_cose_key_reset(&key);
    Print(L"PBNS COSE PROBE FAIL encryption\r\n");
    return EFI_SECURITY_VIOLATION;
  }
  Print(L"PBNS COSE ENCRYPT ROUNDTRIP PASS\r\n");
  Print(L"PBNS COSE ENCRYPT NEGATIVE PASS\r\n");
  pbns_cose_key_reset(&signing_key);
  pbns_identity_close(&identity);
  memset(generated, 0, sizeof(generated));

  static const uint8_t wrong_aad[] = "wrong";
  status = pbns_cose_uefi_sign1_verify(
      &key, (pbns_view){VECTOR_COSE, sizeof(VECTOR_COSE)},
      (pbns_view){wrong_aad, sizeof(wrong_aad) - 1U}, &payload);
  if (status != PBNS_ERR_AUTHENTICATION) {
    pbns_cose_key_reset(&key);
    Print(L"PBNS COSE PROBE FAIL aad\r\n");
    return EFI_SECURITY_VIOLATION;
  }

  uint8_t corrupted[sizeof(VECTOR_COSE)] = {0};
  memcpy(corrupted, VECTOR_COSE, sizeof(corrupted));
  corrupted[sizeof(corrupted) - 1U] ^= 1U;
  status = pbns_cose_uefi_sign1_verify(
      &key, (pbns_view){corrupted, sizeof(corrupted)},
      (pbns_view){VECTOR_AAD, sizeof(VECTOR_AAD) - 1U}, &payload);
  memset(corrupted, 0, sizeof(corrupted));
  if (status != PBNS_ERR_AUTHENTICATION) {
    pbns_cose_key_reset(&key);
    Print(L"PBNS COSE PROBE FAIL corruption\r\n");
    return EFI_SECURITY_VIOLATION;
  }

  uint8_t wrong_x[sizeof(VECTOR_X)] = {0};
  memcpy(wrong_x, VECTOR_X, sizeof(wrong_x));
  wrong_x[0] ^= 1U;
  pbns_cose_key wrong_key = {0};
  if (pbns_cose_key_from_p256_public(
          &wrong_key, (pbns_view){wrong_x, sizeof(wrong_x)},
          (pbns_view){VECTOR_Y, sizeof(VECTOR_Y)}) != PBNS_OK) {
    pbns_cose_key_reset(&key);
    memset(wrong_x, 0, sizeof(wrong_x));
    Print(L"PBNS COSE PROBE FAIL wrong key setup\r\n");
    return EFI_SECURITY_VIOLATION;
  }
  status = pbns_cose_uefi_sign1_verify(
      &wrong_key, (pbns_view){VECTOR_COSE, sizeof(VECTOR_COSE)},
      (pbns_view){VECTOR_AAD, sizeof(VECTOR_AAD) - 1U}, &payload);
  pbns_cose_key_reset(&wrong_key);
  pbns_cose_key_reset(&key);
  memset(wrong_x, 0, sizeof(wrong_x));
  if (status != PBNS_ERR_AUTHENTICATION) {
    Print(L"PBNS COSE PROBE FAIL wrong key\r\n");
    return EFI_SECURITY_VIOLATION;
  }
  Print(L"PBNS COSE SIGN1 VERIFY PASS\r\n");
  return EFI_SUCCESS;
}
