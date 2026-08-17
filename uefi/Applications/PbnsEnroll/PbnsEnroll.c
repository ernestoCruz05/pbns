#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PbnsCoseCryptoLib.h>
#include <Library/PbnsEnrollmentBaselineLib.h>
#include <Library/PbnsIdentityLib.h>
#include <Library/PbnsMeasuredBootLib.h>
#include <Library/PbnsTpmEkCertificateLib.h>
#include <Library/PbnsUefiPlatformLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <PbnsEnrollmentClientLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>

#include <PbnsDeploymentTrust.h>
#include <PbnsEnrollmentTrust.h>
#include <PbnsTpmIdentityLib.h>
#include <PbnsUsbTransportLib.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "mbedtls/sha256.h"
#include "pbns/broker.h"
#include "pbns/enrollment.h"
#include "pbns/enrollment_wire.h"
#include "pbns/identity.h"
#include "pbns/measured_boot.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_spiffy_decode.h"

#define PBNS_ENROLL_BROKER_BUFFER_SIZE PBNS_FRAME_V1_WIRE_MAX
#define PBNS_ENROLL_BROKER_WORKSPACE_SIZE (PBNS_ENROLL_BROKER_BUFFER_SIZE * 4U)
#define PBNS_ENROLL_OBJECT_BUFFER_SIZE PBNS_ENROLLMENT_OBJECT_MAX_SIZE
#define PBNS_ENROLL_AAD_BUFFER_SIZE 192U
#define PBNS_ENROLL_PUBLIC_KEY_BUFFER_SIZE 256U
#define PBNS_ENROLL_TIMEOUT_MS 60000U

typedef struct pbns_enroll_tls_random_context {
  pbns_identity *identity;
} pbns_enroll_tls_random_context;

typedef enum pbns_enroll_identity_mode {
  PBNS_ENROLL_IDENTITY_SOFTWARE = 1,
  PBNS_ENROLL_IDENTITY_TPM = 2,
} pbns_enroll_identity_mode;

typedef struct pbns_enroll_buffers {
  uint8_t *event_log;
  uint8_t *variable_scratch;
  uint8_t *baseline;
  uint8_t *broker;
  uint8_t *object;
  uint8_t *ciphertext;
  uint8_t *envelope;
  uint8_t *wire;
  uint8_t *canonical;
  uint8_t *aad;
  uint8_t *ek_certificate;
} pbns_enroll_buffers;

static void secure_zero(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  if (bytes == NULL) {
    return;
  }
  while (length > 0U) {
    *bytes = 0U;
    ++bytes;
    --length;
  }
}

static BOOLEAN option_is(EFI_HANDLE image_handle, const CHAR16 *expected) {
  EFI_LOADED_IMAGE_PROTOCOL *loaded = NULL;
  if (EFI_ERROR(gBS->HandleProtocol(image_handle, &gEfiLoadedImageProtocolGuid,
                                    (VOID **)&loaded)) ||
      loaded == NULL || loaded->LoadOptions == NULL ||
      loaded->LoadOptionsSize < sizeof(CHAR16)) {
    return FALSE;
  }
  return StrStr((CHAR16 *)loaded->LoadOptions, expected) != NULL;
}

static pbns_status broker_random(void *context, pbns_buffer output) {
  (void)context;
  pbns_request_id request_id = {0};
  if (output.ptr == NULL || output.len != 0U ||
      output.cap != sizeof(request_id.bytes)) {
    return PBNS_ERR_ARGUMENT;
  }
  if (EFI_ERROR(PbnsUefiRandomRequestId(&request_id))) {
    return PBNS_ERR_ENTROPY;
  }
  CopyMem(output.ptr, request_id.bytes, sizeof(request_id.bytes));
  secure_zero(&request_id, sizeof(request_id));
  return PBNS_OK;
}

static pbns_status broker_monotonic(void *context, uint64_t *milliseconds) {
  EFI_SYSTEM_TABLE *system_table = context;
  UINT64 current = 0U;
  if (system_table == NULL || system_table->BootServices == NULL ||
      milliseconds == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  const EFI_STATUS status =
      PbnsUefiMonotonicMs(system_table->BootServices, &current);
  if (EFI_ERROR(status)) {
    return PBNS_ERR_TRANSPORT;
  }
  *milliseconds = (uint64_t)current;
  return PBNS_OK;
}

static const pbns_broker_platform_ops BROKER_PLATFORM_OPS = {
    .random = broker_random,
    .monotonic_ms = broker_monotonic,
};

static EFI_STATUS EFIAPI tls_identity_random_fill(void *context, UINTN size,
                                                  UINT8 *output) {
  const pbns_enroll_tls_random_context *random = context;
  if (random == NULL || random->identity == NULL || output == NULL ||
      size == 0U) {
    return EFI_INVALID_PARAMETER;
  }
  return pbns_identity_random(random->identity,
                              (pbns_buffer){output, 0U, (size_t)size}) ==
                 PBNS_OK
             ? EFI_SUCCESS
             : EFI_DEVICE_ERROR;
}

static EFI_STATUS explicit_identity_choice(EFI_SYSTEM_TABLE *system_table,
                                           pbns_enroll_identity_mode *mode) {
  if (mode == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *mode = 0;
  Print(L"PBNS ENROLL MODE: S=explicit reduced software, T=explicit TPM\r\n");
  while (TRUE) {
    UINTN index = 0U;
    if (EFI_ERROR(
            gBS->WaitForEvent(1U, &system_table->ConIn->WaitForKey, &index))) {
      return EFI_DEVICE_ERROR;
    }
    EFI_INPUT_KEY key = {0};
    if (EFI_ERROR(
            system_table->ConIn->ReadKeyStroke(system_table->ConIn, &key))) {
      continue;
    }
    if (key.UnicodeChar == 's' || key.UnicodeChar == 'S') {
      *mode = PBNS_ENROLL_IDENTITY_SOFTWARE;
      Print(L"PBNS ENROLL SOFTWARE MODE EXPLICIT\r\n");
      return EFI_SUCCESS;
    }
    if (key.UnicodeChar == 't' || key.UnicodeChar == 'T') {
      *mode = PBNS_ENROLL_IDENTITY_TPM;
      Print(L"PBNS ENROLL TPM MODE EXPLICIT\r\n");
      return EFI_SUCCESS;
    }
    return EFI_ABORTED;
  }
}

static EFI_STATUS try_decode_token_str(const CHAR8 *text, UINTN len,
                                         uint8_t token[32]) {
  if (text == NULL || len == 0U || token == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  // Trim leading whitespace
  while (len > 0U && (text[0] == ' ' || text[0] == '\t' || text[0] == '\r' ||
                      text[0] == '\n')) {
    text++;
    len--;
  }
  // Trim trailing whitespace
  while (len > 0U && (text[len - 1U] == ' ' || text[len - 1U] == '\t' ||
                      text[len - 1U] == '\r' || text[len - 1U] == '\n')) {
    len--;
  }
  // Skip prefixes like "enrollment_token=" or "token="
  if (len > 17U && AsciiStrnCmp(text, "enrollment_token=", 17U) == 0) {
    text += 17U;
    len -= 17U;
  } else if (len > 6U && AsciiStrnCmp(text, "token=", 6U) == 0) {
    text += 6U;
    len -= 6U;
  }
  while (len > 0U && (text[0] == ' ' || text[0] == '\t' || text[0] == '\r' ||
                      text[0] == '\n')) {
    text++;
    len--;
  }
  while (len > 0U && (text[len - 1U] == ' ' || text[len - 1U] == '\t' ||
                      text[len - 1U] == '\r' || text[len - 1U] == '\n')) {
    len--;
  }
  if (len != 43U) {
    return EFI_INVALID_PARAMETER;
  }
  CHAR8 encoded[46] = {0};
  for (UINTN i = 0U; i < 43U; ++i) {
    CHAR8 c = text[i];
    if (c == '-') {
      c = '+';
    } else if (c == '_') {
      c = '/';
    }
    encoded[i] = c;
  }
  encoded[43] = '=';
  UINTN token_size = 32U;
  const RETURN_STATUS status = Base64Decode(encoded, 44U, token, &token_size);
  secure_zero(encoded, sizeof(encoded));
  if (RETURN_ERROR(status) || token_size != 32U) {
    secure_zero(token, 32U);
    return EFI_INVALID_PARAMETER;
  }
  return EFI_SUCCESS;
}

static EFI_STATUS read_token_from_file(EFI_HANDLE image_handle,
                                       uint8_t token[32]) {
  if (image_handle == NULL || token == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  EFI_LOADED_IMAGE_PROTOCOL *loaded_image = NULL;
  EFI_STATUS status = gBS->HandleProtocol(
      image_handle, &gEfiLoadedImageProtocolGuid, (VOID **)&loaded_image);
  if (EFI_ERROR(status) || loaded_image == NULL ||
      loaded_image->DeviceHandle == NULL) {
    return EFI_NOT_FOUND;
  }
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = NULL;
  status = gBS->HandleProtocol(loaded_image->DeviceHandle,
                               &gEfiSimpleFileSystemProtocolGuid, (VOID **)&fs);
  if (EFI_ERROR(status) || fs == NULL) {
    return EFI_NOT_FOUND;
  }
  EFI_FILE_PROTOCOL *root = NULL;
  status = fs->OpenVolume(fs, &root);
  if (EFI_ERROR(status) || root == NULL) {
    return EFI_NOT_FOUND;
  }

  CHAR16 candidate_files[][32] = {
      { 't', 'o', 'k', 'e', 'n', '.', 't', 'x', 't', 0 },
      { '\\', 't', 'o', 'k', 'e', 'n', '.', 't', 'x', 't', 0 },
      { 'E', 'F', 'I', '\\', 'B', 'O', 'O', 'T', '\\', 't', 'o', 'k', 'e', 'n', '.', 't', 'x', 't', 0 },
      { '\\', 'E', 'F', 'I', '\\', 'B', 'O', 'O', 'T', '\\', 't', 'o', 'k', 'e', 'n', '.', 't', 'x', 't', 0 }
  };

  for (UINTN i = 0U; i < sizeof(candidate_files) / sizeof(candidate_files[0]);
       ++i) {
    EFI_FILE_PROTOCOL *file = NULL;
    status = root->Open(root, &file, candidate_files[i],
                        EFI_FILE_MODE_READ, 0);
    if (!EFI_ERROR(status) && file != NULL) {
      CHAR8 buf[256] = {0};
      UINTN buf_size = sizeof(buf) - 1U;
      status = file->Read(file, &buf_size, buf);
      file->Close(file);
      if (!EFI_ERROR(status) && buf_size > 0U) {
        if (!EFI_ERROR(try_decode_token_str(buf, buf_size, token))) {
          Print(L"PBNS ENROLL: Successfully loaded token from %s\r\n",
                candidate_files[i]);
          root->Close(root);
          return EFI_SUCCESS;
        }
      }
    }
  }
  root->Close(root);
  return EFI_NOT_FOUND;
}

static EFI_STATUS read_enrollment_token(EFI_HANDLE image_handle,
                                        EFI_SYSTEM_TABLE *system_table,
                                        uint8_t token[32]) {
  if (system_table == NULL || token == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if (!EFI_ERROR(read_token_from_file(image_handle, token))) {
    Print(L"PBNS ENROLL TOKEN ACCEPTED (loaded from token.txt)\r\n");
    return EFI_SUCCESS;
  }

  CHAR8 input_buf[128] = {0};
  UINTN input_len = 0U;
  Print(L"PBNS ENROLL TOKEN: Enter token (or place token.txt on USB):\r\n> ");

  while (TRUE) {
    UINTN index = 0U;
    if (EFI_ERROR(
            gBS->WaitForEvent(1U, &system_table->ConIn->WaitForKey, &index))) {
      secure_zero(input_buf, sizeof(input_buf));
      return EFI_DEVICE_ERROR;
    }
    EFI_INPUT_KEY key = {0};
    if (EFI_ERROR(
            system_table->ConIn->ReadKeyStroke(system_table->ConIn, &key))) {
      continue;
    }

    // Submit on Enter
    if (key.UnicodeChar == L'\r' || key.UnicodeChar == L'\n') {
      Print(L"\r\n");
      if (input_len == 0U) {
        Print(L"> ");
        continue;
      }
      EFI_STATUS decode_status =
          try_decode_token_str(input_buf, input_len, token);
      if (!EFI_ERROR(decode_status)) {
        secure_zero(input_buf, sizeof(input_buf));
        Print(L"PBNS ENROLL TOKEN ACCEPTED\r\n");
        return EFI_SUCCESS;
      }
      Print(L"Invalid token format (length %d, expected 43 base64url chars). "
            L"Try again:\r\n> ",
            (INT32)input_len);
      input_len = 0U;
      secure_zero(input_buf, sizeof(input_buf));
      continue;
    }

    // Backspace
    if (key.UnicodeChar == 0x08 || key.UnicodeChar == 0x7F ||
        key.ScanCode == SCAN_DELETE) {
      if (input_len > 0U) {
        --input_len;
        input_buf[input_len] = 0;
        Print(L"\b \b");
      }
      continue;
    }

    // Valid Base64URL characters (a-z, A-Z, 0-9, -, _)
    if ((key.UnicodeChar >= L'a' && key.UnicodeChar <= L'z') ||
        (key.UnicodeChar >= L'A' && key.UnicodeChar <= L'Z') ||
        (key.UnicodeChar >= L'0' && key.UnicodeChar <= L'9') ||
        key.UnicodeChar == L'-' || key.UnicodeChar == L'_') {
      if (input_len < sizeof(input_buf) - 2U) {
        input_buf[input_len] = (CHAR8)key.UnicodeChar;
        ++input_len;
        Print(L"%c", key.UnicodeChar);
      }
      continue;
    }
    // Silently ignore any other non-printable/modifier key
  }
}

static EFI_STATUS print_enrollment_token_id(const uint8_t token[32]) {
  static const CHAR16 hex[] = L"0123456789abcdef";
  uint8_t digest[32] = {0};
  CHAR16 identifier[65] = {0};
  if (token == NULL || mbedtls_sha256(token, 32U, digest, 0) != 0) {
    secure_zero(digest, sizeof(digest));
    secure_zero(identifier, sizeof(identifier));
    return EFI_DEVICE_ERROR;
  }
  for (size_t index = 0U; index < sizeof(digest); ++index) {
    identifier[index * 2U] = hex[digest[index] >> 4U];
    identifier[(index * 2U) + 1U] = hex[digest[index] & 0x0fU];
  }
  Print(L"PBNS ENROLL TOKEN ID %s\r\n", identifier);
  secure_zero(digest, sizeof(digest));
  secure_zero(identifier, sizeof(identifier));
  return EFI_SUCCESS;
}

static pbns_status extract_sign1_payload(pbns_view message,
                                         pbns_view expected_key_id,
                                         pbns_view *payload) {
  if (message.ptr == NULL || message.len == 0U || expected_key_id.ptr == NULL ||
      expected_key_id.len == 0U || payload == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *payload = (pbns_view){0};
  QCBORDecodeContext decoder = {0};
  UsefulBufC protected_headers = {0};
  UsefulBufC decoded_payload = {0};
  UsefulBufC signature = {0};
  QCBORDecode_Init(&decoder, (UsefulBufC){message.ptr, message.len},
                   QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterArray(&decoder, NULL);
  QCBORDecode_GetByteString(&decoder, &protected_headers);
  QCBORDecode_EnterMap(&decoder, NULL);
  QCBORDecode_ExitMap(&decoder);
  QCBORDecode_GetByteString(&decoder, &decoded_payload);
  QCBORDecode_GetByteString(&decoder, &signature);
  QCBORDecode_ExitArray(&decoder);
  if (QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS ||
      protected_headers.len == 0U || decoded_payload.len == 0U ||
      signature.len != 64U) {
    return PBNS_ERR_FORMAT;
  }

  int64_t algorithm = 0;
  UsefulBufC key_id = {0};
  QCBORDecode_Init(&decoder, protected_headers, QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterMap(&decoder, NULL);
  QCBORDecode_GetInt64InMapN(&decoder, 1, &algorithm);
  QCBORDecode_GetByteStringInMapN(&decoder, 4, &key_id);
  QCBORDecode_ExitMap(&decoder);
  if (QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS || algorithm != -7 ||
      key_id.len != expected_key_id.len ||
      CompareMem(key_id.ptr, expected_key_id.ptr, key_id.len) != 0) {
    return PBNS_ERR_AUTHENTICATION;
  }
  uint8_t canonical[96] = {0};
  QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){canonical, sizeof(canonical)});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddInt64ToMapN(&encoder, 1, -7);
  QCBOREncode_AddBytesToMapN(
      &encoder, 4, (UsefulBufC){expected_key_id.ptr, expected_key_id.len});
  QCBOREncode_CloseMap(&encoder);
  UsefulBufC canonical_headers = {0};
  if (QCBOREncode_Finish(&encoder, &canonical_headers) != QCBOR_SUCCESS ||
      canonical_headers.len != protected_headers.len ||
      CompareMem(canonical_headers.ptr, protected_headers.ptr,
                 protected_headers.len) != 0) {
    secure_zero(canonical, sizeof(canonical));
    return PBNS_ERR_AUTHENTICATION;
  }
  secure_zero(canonical, sizeof(canonical));
  *payload = (pbns_view){decoded_payload.ptr, decoded_payload.len};
  return PBNS_OK;
}

static pbns_status enrollment_exchange(pbns_broker *broker, uint64_t operation,
                                       pbns_view object, pbns_buffer wire,
                                       pbns_buffer canonical,
                                       pbns_view *response_object,
                                       UINT64 *elapsed_ms,
                                       EFI_SYSTEM_TABLE *system_table) {
  if (broker == NULL || response_object == NULL || elapsed_ms == NULL ||
      system_table == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *response_object = (pbns_view){0};
  *elapsed_ms = 0U;
  pbns_enrollment_wire_object request = {
      .operation = operation,
      .object = object,
  };
  size_t wire_size = 0U;
  pbns_status status =
      pbns_enrollment_wire_object_encode(&request, wire, &wire_size);
  if (status != PBNS_OK) {
    return status;
  }
  UINT64 started = 0U;
  UINT64 finished = 0U;
  if (EFI_ERROR(PbnsUefiMonotonicMs(system_table->BootServices, &started))) {
    return PBNS_ERR_STATE;
  }
  pbns_broker_response response = {0};
  for (size_t attempt = 0U; attempt < 2U; ++attempt) {
    status = pbns_broker_request(broker, PBNS_SERVICE_ENROLLMENT,
                                 (pbns_view){wire.ptr, wire_size},
                                 PBNS_ENROLL_TIMEOUT_MS, &response);
    if (status == PBNS_OK) {
      break;
    }
    if (attempt != 0U ||
        (status != PBNS_ERR_TIMEOUT && status != PBNS_ERR_TRANSPORT &&
         status != PBNS_ERR_IO)) {
      return status;
    }
  }
  if (EFI_ERROR(PbnsUefiMonotonicMs(system_table->BootServices, &finished))) {
    return PBNS_ERR_STATE;
  }
  if (finished < started || response.frame.service != PBNS_SERVICE_ENROLLMENT ||
      response.frame.type != PBNS_MESSAGE_RESPONSE) {
    return PBNS_ERR_STATE;
  }
  pbns_enrollment_wire_object decoded = {0};
  status = pbns_enrollment_wire_object_decode(response.payload, operation,
                                              canonical, &decoded);
  if (status != PBNS_OK) {
    return status;
  }
  *elapsed_ms = finished - started;
  *response_object = decoded.object;
  return PBNS_OK;
}

static bool allocate_buffers(pbns_enroll_buffers *buffers,
                             bool require_ek_certificate) {
  if (buffers == NULL) {
    return false;
  }
  *buffers = (pbns_enroll_buffers){0};
  buffers->event_log = AllocatePool(PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE);
  buffers->variable_scratch =
      AllocatePool(PBNS_BASELINE_VARIABLE_SCRATCH_MAX_SIZE);
  buffers->baseline = AllocatePool(PBNS_ENROLLMENT_BASELINE_MAX_SIZE);
  buffers->broker = AllocatePool(PBNS_ENROLL_BROKER_WORKSPACE_SIZE);
  buffers->object = AllocatePool(PBNS_ENROLL_OBJECT_BUFFER_SIZE);
  buffers->ciphertext = AllocatePool(PBNS_ENROLL_OBJECT_BUFFER_SIZE);
  buffers->envelope = AllocatePool(PBNS_ENROLL_OBJECT_BUFFER_SIZE);
  buffers->wire = AllocatePool(PBNS_ENROLL_OBJECT_BUFFER_SIZE);
  buffers->canonical = AllocatePool(PBNS_ENROLL_OBJECT_BUFFER_SIZE);
  buffers->aad = AllocatePool(PBNS_ENROLL_AAD_BUFFER_SIZE);
  if (require_ek_certificate) {
    buffers->ek_certificate = AllocatePool(PBNS_TPM_EK_CERTIFICATE_MAX_SIZE);
  }
  return buffers->event_log != NULL && buffers->variable_scratch != NULL &&
         buffers->baseline != NULL && buffers->broker != NULL &&
         buffers->object != NULL && buffers->ciphertext != NULL &&
         buffers->envelope != NULL && buffers->wire != NULL &&
         buffers->canonical != NULL && buffers->aad != NULL &&
         (!require_ek_certificate || buffers->ek_certificate != NULL);
}

static void free_buffer(uint8_t **buffer, size_t size) {
  if (buffer != NULL && *buffer != NULL) {
    secure_zero(*buffer, size);
    FreePool(*buffer);
    *buffer = NULL;
  }
}

static void free_buffers(pbns_enroll_buffers *buffers) {
  if (buffers == NULL) {
    return;
  }
  free_buffer(&buffers->ek_certificate, PBNS_TPM_EK_CERTIFICATE_MAX_SIZE);
  free_buffer(&buffers->aad, PBNS_ENROLL_AAD_BUFFER_SIZE);
  free_buffer(&buffers->canonical, PBNS_ENROLL_OBJECT_BUFFER_SIZE);
  free_buffer(&buffers->wire, PBNS_ENROLL_OBJECT_BUFFER_SIZE);
  free_buffer(&buffers->envelope, PBNS_ENROLL_OBJECT_BUFFER_SIZE);
  free_buffer(&buffers->ciphertext, PBNS_ENROLL_OBJECT_BUFFER_SIZE);
  free_buffer(&buffers->object, PBNS_ENROLL_OBJECT_BUFFER_SIZE);
  free_buffer(&buffers->broker, PBNS_ENROLL_BROKER_WORKSPACE_SIZE);
  free_buffer(&buffers->baseline, PBNS_ENROLLMENT_BASELINE_MAX_SIZE);
  free_buffer(&buffers->variable_scratch,
              PBNS_BASELINE_VARIABLE_SCRATCH_MAX_SIZE);
  free_buffer(&buffers->event_log, PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE);
}

EFI_STATUS EFIAPI UefiMain(EFI_HANDLE image_handle,
                           EFI_SYSTEM_TABLE *system_table) {
  EFI_STATUS result = EFI_SECURITY_VIOLATION;
  bool operational_failure = true;
  pbns_enroll_buffers buffers = {0};
  pbns_identity *identity = NULL;
  pbns_enroll_tls_random_context *tls_random_context = NULL;
  pbns_tpm_capability_result tpm_capabilities = {0};
  PBNS_ENROLLMENT_CLIENT_ADAPTER adapter = {0};
  pbns_usb_transport *usb_transport = NULL;
  PBNS_TLS_UEFI_TRANSPORT *tls_transport = NULL;
  pbns_transport broker_transport = {0};
  PBNS_TPM_RANDOM_SOURCE tls_random = {0};
  pbns_broker broker = {0};
  bool broker_ready = false;
  pbns_enrollment enrollment = {0};
  uint8_t token[32] = {0};
  uint8_t identity_public[PBNS_ENROLL_PUBLIC_KEY_BUFFER_SIZE] = {0};
  size_t identity_public_size = 0U;
  uint8_t fingerprint[PBNS_ENROLLMENT_DIGEST_SIZE] = {0};
  uint8_t random[PBNS_ENROLLMENT_REQUEST_ID_SIZE + PBNS_ENROLLMENT_NONCE_SIZE] =
      {0};
  size_t baseline_size = 0U;
  size_t event_count = 0U;
  uint32_t update_counter = 0U;
  uint8_t baseline_digest[PBNS_ENROLLMENT_DIGEST_SIZE] = {0};
  uint8_t ek_public[PBNS_TPM_ENROLLMENT_PUBLIC_MAX_SIZE] = {0};
  uint8_t ak_public[PBNS_TPM_ENROLLMENT_PUBLIC_MAX_SIZE] = {0};
  uint8_t ak_name[PBNS_TPM_ENROLLMENT_NAME_MAX_SIZE] = {0};
  uint8_t identity_tpm_public[PBNS_TPM_ENROLLMENT_PUBLIC_MAX_SIZE] = {0};
  uint8_t activated_credential[64] = {0};
  uint8_t certify_attestation[2048] = {0};
  uint8_t certify_signature[512] = {0};
  uint8_t certify_digest[32] = {0};
  pbns_tpm_enrollment_public tpm_public = {
      .EkPublic = {ek_public, 0U, sizeof(ek_public)},
      .AkPublic = {ak_public, 0U, sizeof(ak_public)},
      .AkName = {ak_name, 0U, sizeof(ak_name)},
      .IdentityPublic = {identity_tpm_public, 0U, sizeof(identity_tpm_public)},
  };
  PBNS_ENROLLMENT_BASELINE_TIMINGS baseline_timings = {0};
  UINT64 total_started = 0U;
  UINT64 total_finished = 0U;
  UINT64 baseline_started = 0U;
  UINT64 baseline_finished = 0U;
  UINT64 init_crypto_started = 0U;
  UINT64 init_crypto_finished = 0U;
  UINT64 proof_crypto_started = 0U;
  UINT64 proof_crypto_finished = 0U;
  UINT64 begin_exchange_ms = 0U;
  UINT64 complete_exchange_ms = 0U;

  if (system_table == NULL || system_table->BootServices == NULL ||
      system_table->ConIn == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  const BOOLEAN software_create = option_is(image_handle, L"software-create");
  const BOOLEAN software_open = option_is(image_handle, L"software");
  const BOOLEAN tpm_create = option_is(image_handle, L"tpm-create");
  const BOOLEAN tpm_open = option_is(image_handle, L"tpm");
  const BOOLEAN interactive_choice =
      !software_create && !software_open && !tpm_create && !tpm_open;
  pbns_enroll_identity_mode identity_mode = (tpm_create || tpm_open)
                                                ? PBNS_ENROLL_IDENTITY_TPM
                                                : PBNS_ENROLL_IDENTITY_SOFTWARE;
  if (interactive_choice &&
      EFI_ERROR(explicit_identity_choice(system_table, &identity_mode))) {
    Print(L"PBNS ENROLL FAIL explicit identity mode required\r\n");
    return EFI_ABORTED;
  }
  if (!allocate_buffers(&buffers, identity_mode == PBNS_ENROLL_IDENTITY_TPM)) {
    Print(L"PBNS ENROLL FAIL allocation\r\n");
    result = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }
  if (identity_mode == PBNS_ENROLL_IDENTITY_TPM) {
    tpm_public.EkCertificate = (pbns_buffer){buffers.ek_certificate, 0U,
                                             PBNS_TPM_EK_CERTIFICATE_MAX_SIZE};
  }
  identity = AllocateZeroPool(sizeof(*identity));
  tls_random_context = AllocateZeroPool(sizeof(*tls_random_context));
  if (identity == NULL || tls_random_context == NULL) {
    Print(L"PBNS ENROLL FAIL identity allocation\r\n");
    result = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }
  EFI_STATUS status = EFI_UNSUPPORTED;
  if (identity_mode == PBNS_ENROLL_IDENTITY_TPM) {
    status = tpm_create ? PbnsTpmIdentityCreate(identity, &tpm_capabilities)
                        : PbnsTpmIdentityOpen(identity, &tpm_capabilities);
    if (interactive_choice && status == EFI_NOT_FOUND) {
      status = PbnsTpmIdentityCreate(identity, &tpm_capabilities);
    }
  } else {
    status = software_create ? PbnsSoftwareIdentityCreate(NULL, identity)
                             : PbnsSoftwareIdentityOpen(NULL, identity);
    if (interactive_choice && status == EFI_NOT_FOUND) {
      status = PbnsSoftwareIdentityCreate(NULL, identity);
    }
  }
  if (EFI_ERROR(status)) {
    Print(L"PBNS ENROLL FAIL identity status=%r\r\n", status);
    result = status;
    goto Cleanup;
  }
  const pbns_identity_assurance expected_identity_assurance =
      identity_mode == PBNS_ENROLL_IDENTITY_TPM
          ? PBNS_IDENTITY_TPM_UNVERIFIED_EK
          : PBNS_IDENTITY_SOFTWARE;
  if (pbns_identity_assurance_level(identity) != expected_identity_assurance ||
      pbns_identity_public_cose_key(
          identity, (pbns_buffer){identity_public, 0U, sizeof(identity_public)},
          &identity_public_size) != PBNS_OK ||
      pbns_identity_fingerprint(
          identity, (pbns_buffer){fingerprint, 0U, sizeof(fingerprint)}) !=
          PBNS_OK ||
      pbns_identity_random(
          identity, (pbns_buffer){random, 0U, sizeof(random)}) != PBNS_OK ||
      EFI_ERROR(PbnsEnrollmentClientAdapterInit(
          &adapter, identity, &PBNS_ENROLLMENT_TRUST.recipient,
          &PBNS_ENROLLMENT_TRUST.signer))) {
    Print(L"PBNS ENROLL FAIL identity or key setup\r\n");
    goto Cleanup;
  }
  if (identity_mode == PBNS_ENROLL_IDENTITY_TPM &&
      EFI_ERROR(PbnsTpmIdentityEnrollmentPublic(identity, &tpm_public))) {
    Print(L"PBNS ENROLL FAIL TPM public evidence\r\n");
    goto Cleanup;
  }
  status = read_enrollment_token(image_handle, system_table, token);
  if (EFI_ERROR(status)) {
    Print(L"PBNS ENROLL FAIL token input status=%r\r\n", status);
    result = status;
    goto Cleanup;
  }
  status = print_enrollment_token_id(token);
  if (EFI_ERROR(status)) {
    Print(L"PBNS ENROLL FAIL token identifier status=%r\r\n", status);
    result = status;
    goto Cleanup;
  }
  if (EFI_ERROR(
          PbnsUefiMonotonicMs(system_table->BootServices, &total_started)) ||
      EFI_ERROR(
          PbnsUefiMonotonicMs(system_table->BootServices, &baseline_started))) {
    result = EFI_DEVICE_ERROR;
    goto Cleanup;
  }
  status = PbnsEnrollmentBaselineCapture(
      system_table, (pbns_view){fingerprint, sizeof(fingerprint)},
      (pbns_buffer){buffers.event_log, 0U,
                    PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE},
      (pbns_buffer){buffers.variable_scratch, 0U,
                    PBNS_BASELINE_VARIABLE_SCRATCH_MAX_SIZE},
      (pbns_buffer){buffers.baseline, 0U, PBNS_ENROLLMENT_BASELINE_MAX_SIZE},
      &baseline_size, baseline_digest, &event_count, &update_counter,
      &baseline_timings);
  if (EFI_ERROR(status) || baseline_size == 0U || event_count == 0U ||
      EFI_ERROR(PbnsUefiMonotonicMs(system_table->BootServices,
                                    &baseline_finished)) ||
      baseline_finished < baseline_started) {
    Print(L"PBNS ENROLL FAIL baseline status=%r\r\n", status);
    result = EFI_ERROR(status) ? status : EFI_COMPROMISED_DATA;
    goto Cleanup;
  }

  pbns_enrollment_software_init init = {0};
  init.context.stage = PBNS_ENROLLMENT_STAGE_INIT;
  init.context.sequence = 0U;
  init.context.key_id = PBNS_ENROLLMENT_TRUST.recipient.kid;
  CopyMem(init.context.request_id, random, sizeof(init.context.request_id));
  CopyMem(init.context.host_fingerprint, fingerprint,
          sizeof(init.context.host_fingerprint));
  CopyMem(init.context.nonce, random + sizeof(init.context.request_id),
          sizeof(init.context.nonce));
  CopyMem(init.host_nonce, init.context.nonce, sizeof(init.host_nonce));
  CopyMem(init.token, token, sizeof(init.token));
  init.identity_cose_key = (pbns_view){identity_public, identity_public_size};
  CopyMem(init.initial_evidence_digest, baseline_digest,
          sizeof(init.initial_evidence_digest));

  size_t init_size = 0U;
  uint8_t init_digest[PBNS_ENROLLMENT_DIGEST_SIZE] = {0};
  size_t aad_size = 0U;
  size_t ciphertext_size = 0U;
  size_t envelope_size = 0U;
  if (EFI_ERROR(PbnsUefiMonotonicMs(system_table->BootServices,
                                    &init_crypto_started))) {
    Print(L"PBNS ENROLL FAIL init clock\r\n");
    goto Cleanup;
  }
  pbns_enrollment_tpm_init tpm_init = {0};
  pbns_status init_encode_status = PBNS_ERR_STATE;
  if (identity_mode == PBNS_ENROLL_IDENTITY_TPM) {
    tpm_init.context = init.context;
    CopyMem(tpm_init.token, token, sizeof(tpm_init.token));
    tpm_init.ek_public =
        (pbns_view){tpm_public.EkPublic.ptr, tpm_public.EkPublic.len};
    tpm_init.ak_public =
        (pbns_view){tpm_public.AkPublic.ptr, tpm_public.AkPublic.len};
    tpm_init.ak_name =
        (pbns_view){tpm_public.AkName.ptr, tpm_public.AkName.len};
    tpm_init.ek_certificate =
        (pbns_view){tpm_public.EkCertificate.ptr, tpm_public.EkCertificate.len};
    tpm_init.identity_cose_key = init.identity_cose_key;
    CopyMem(tpm_init.initial_evidence_digest, baseline_digest,
            sizeof(tpm_init.initial_evidence_digest));
    CopyMem(tpm_init.host_nonce, init.host_nonce, sizeof(tpm_init.host_nonce));
    tpm_init.identity_tpm_public = (pbns_view){tpm_public.IdentityPublic.ptr,
                                               tpm_public.IdentityPublic.len};
    init_encode_status = pbns_enrollment_tpm_init_encode(
        &tpm_init,
        (pbns_buffer){buffers.object, 0U, PBNS_ENROLL_OBJECT_BUFFER_SIZE},
        &init_size);
  } else {
    init_encode_status = pbns_enrollment_software_init_encode(
        &init,
        (pbns_buffer){buffers.object, 0U, PBNS_ENROLL_OBJECT_BUFFER_SIZE},
        &init_size);
  }
  const pbns_enrollment_assurance enrollment_assurance =
      identity_mode == PBNS_ENROLL_IDENTITY_TPM
          ? PBNS_ENROLLMENT_ASSURANCE_TPM
          : PBNS_ENROLLMENT_ASSURANCE_SOFTWARE;
  if (init_encode_status != PBNS_OK ||
      mbedtls_sha256(buffers.object, init_size, init_digest, 0) != 0 ||
      pbns_enrollment_init(&enrollment, enrollment_assurance,
                           init.context.request_id, init.host_nonce,
                           init_digest, baseline_digest) != PBNS_OK ||
      pbns_enrollment_envelope_aad(
          init.context.request_id, init.host_nonce, init.context.key_id,
          (pbns_buffer){buffers.aad, 0U, PBNS_ENROLL_AAD_BUFFER_SIZE},
          &aad_size) != PBNS_OK ||
      pbns_cose_uefi_encrypt_for_recipient(
          identity, &adapter.RecipientKey, init.context.key_id,
          (pbns_view){buffers.object, init_size},
          (pbns_view){buffers.aad, aad_size},
          (pbns_buffer){buffers.ciphertext, 0U, PBNS_ENROLL_OBJECT_BUFFER_SIZE},
          &ciphertext_size) != PBNS_OK) {
    Print(L"PBNS ENROLL FAIL init cryptography\r\n");
    goto Cleanup;
  }
  secure_zero(token, sizeof(token));
  secure_zero(init.token, sizeof(init.token));
  secure_zero(tpm_init.token, sizeof(tpm_init.token));
  secure_zero(buffers.object, init_size);
  pbns_enrollment_encrypted_envelope encrypted_init = {
      .recipient_key_id = init.context.key_id,
      .ciphertext = {buffers.ciphertext, ciphertext_size},
  };
  CopyMem(encrypted_init.request_id, init.context.request_id,
          sizeof(encrypted_init.request_id));
  CopyMem(encrypted_init.host_nonce, init.host_nonce,
          sizeof(encrypted_init.host_nonce));
  if (pbns_enrollment_envelope_encode(
          &encrypted_init,
          (pbns_buffer){buffers.envelope, 0U, PBNS_ENROLL_OBJECT_BUFFER_SIZE},
          &envelope_size) != PBNS_OK ||
      EFI_ERROR(PbnsUefiMonotonicMs(system_table->BootServices,
                                    &init_crypto_finished)) ||
      init_crypto_finished < init_crypto_started) {
    Print(L"PBNS ENROLL FAIL init envelope\r\n");
    goto Cleanup;
  }
  Print(L"PBNS ENROLL INIT ENCRYPTION CHECKPOINT PASS\r\n");

  if (pbns_usb_transport_create(system_table->BootServices, &usb_transport) !=
      PBNS_OK) {
    Print(L"PBNS ENROLL FAIL CDC0 unavailable\r\n");
    result = EFI_NOT_FOUND;
    goto Cleanup;
  }
  tls_random_context->identity = identity;
  tls_random = (PBNS_TPM_RANDOM_SOURCE){
      .Fill = tls_identity_random_fill,
      .Context = tls_random_context,
  };
  const pbns_status tls_status = PbnsEnrollmentClientTlsOpen(
      system_table->BootServices,
      pbns_usb_transport_as_transport(usb_transport),
      &PBNS_DEPLOYMENT_TRUST.tls, &tls_random, &tls_transport,
      &broker_transport);
  if (tls_status != PBNS_OK || tls_transport == NULL) {
    Print(L"PBNS ENROLL FAIL TLS 1.2 status=%d\r\n", (INT32)tls_status);
    result = tls_status == PBNS_ERR_ENTROPY ? EFI_SECURITY_VIOLATION
                                            : EFI_DEVICE_ERROR;
    goto Cleanup;
  }
  if (pbns_broker_init(
          &broker, broker_transport,
          (pbns_broker_platform){&BROKER_PLATFORM_OPS, system_table},
          (pbns_broker_storage){
              .encoded = {buffers.broker, 0U, PBNS_ENROLL_BROKER_BUFFER_SIZE},
              .raw_scratch = {buffers.broker + PBNS_ENROLL_BROKER_BUFFER_SIZE,
                              0U, PBNS_ENROLL_BROKER_BUFFER_SIZE},
              .receive = {buffers.broker +
                              (PBNS_ENROLL_BROKER_BUFFER_SIZE * 2U),
                          0U, PBNS_ENROLL_BROKER_BUFFER_SIZE},
              .decoded = {buffers.broker +
                              (PBNS_ENROLL_BROKER_BUFFER_SIZE * 3U),
                          0U, PBNS_ENROLL_BROKER_BUFFER_SIZE},
          }) != PBNS_OK) {
    Print(L"PBNS ENROLL FAIL broker setup\r\n");
    goto Cleanup;
  }
  broker_ready = true;

  pbns_view signed_challenge = {0};
  pbns_status pbns_result = enrollment_exchange(
      &broker, 1U, (pbns_view){buffers.envelope, envelope_size},
      (pbns_buffer){buffers.wire, 0U, PBNS_ENROLL_OBJECT_BUFFER_SIZE},
      (pbns_buffer){buffers.canonical, 0U, PBNS_ENROLL_OBJECT_BUFFER_SIZE},
      &signed_challenge, &begin_exchange_ms, system_table);
  secure_zero(buffers.ciphertext, ciphertext_size);
  if (pbns_result != PBNS_OK) {
    Print(L"PBNS ENROLL FAIL begin exchange status=%d\r\n", pbns_result);
    goto Cleanup;
  }

  pbns_view challenge_payload = {0};
  pbns_enrollment_challenge_object challenge = {0};
  pbns_view verified_payload = {0};
  const uint64_t expected_flow = identity_mode == PBNS_ENROLL_IDENTITY_TPM
                                     ? PBNS_ENROLLMENT_FLOW_TPM
                                     : PBNS_ENROLLMENT_FLOW_SOFTWARE;
  if (extract_sign1_payload(signed_challenge, PBNS_ENROLLMENT_TRUST.signer.kid,
                            &challenge_payload) != PBNS_OK ||
      pbns_enrollment_challenge_decode(
          challenge_payload, PBNS_ENROLLMENT_TRUST.signer.kid,
          (pbns_buffer){buffers.canonical, 0U, PBNS_ENROLL_OBJECT_BUFFER_SIZE},
          &challenge) != PBNS_OK ||
      challenge.flow != expected_flow ||
      pbns_enrollment_challenge_aad(
          &challenge,
          (pbns_buffer){buffers.aad, 0U, PBNS_ENROLL_AAD_BUFFER_SIZE},
          &aad_size) != PBNS_OK ||
      pbns_cose_uefi_sign1_verify(&adapter.SignerKey, signed_challenge,
                                  (pbns_view){buffers.aad, aad_size},
                                  &verified_payload) != PBNS_OK ||
      verified_payload.ptr != challenge_payload.ptr ||
      verified_payload.len != challenge_payload.len ||
      pbns_enrollment_accept_challenge(
          &enrollment, challenge.host_nonce, challenge.server_nonce,
          challenge.init_digest, true) != PBNS_OK) {
    Print(L"PBNS ENROLL FAIL challenge verification\r\n");
    goto Cleanup;
  }

  UINTN activated_size = 0U;
  UINTN certify_attestation_size = 0U;
  UINTN certify_signature_size = 0U;
  if (identity_mode == PBNS_ENROLL_IDENTITY_TPM) {
    static const uint8_t certify_prefix[] = "PBNS-ENROLLMENT-CERTIFY-v1";
    size_t certify_input_size = 0U;
    CopyMem(buffers.aad + certify_input_size, certify_prefix,
            sizeof(certify_prefix) - 1U);
    certify_input_size += sizeof(certify_prefix) - 1U;
    CopyMem(buffers.aad + certify_input_size, init.context.request_id,
            sizeof(init.context.request_id));
    certify_input_size += sizeof(init.context.request_id);
    CopyMem(buffers.aad + certify_input_size, challenge.server_nonce,
            sizeof(challenge.server_nonce));
    certify_input_size += sizeof(challenge.server_nonce);
    CopyMem(buffers.aad + certify_input_size, init_digest, sizeof(init_digest));
    certify_input_size += sizeof(init_digest);
    CopyMem(buffers.aad + certify_input_size, baseline_digest,
            sizeof(baseline_digest));
    certify_input_size += sizeof(baseline_digest);
    if (challenge.credential_blob.len == 0U ||
        challenge.encrypted_secret.len == 0U ||
        mbedtls_sha256(buffers.aad, certify_input_size, certify_digest, 0) !=
            0) {
      secure_zero(buffers.aad, PBNS_ENROLL_AAD_BUFFER_SIZE);
      Print(L"PBNS ENROLL FAIL TPM challenge material\r\n");
      goto Cleanup;
    }
    UINT32 activation_command = 0U;
    EFI_STATUS activation_status = PbnsTpmIdentityActivateCredential(
        identity, challenge.credential_blob, challenge.encrypted_secret,
        (pbns_buffer){activated_credential, 0U, sizeof(activated_credential)},
        &activated_size, &activation_command);
    if (EFI_ERROR(activation_status) || activated_size != 32U) {
      if (!EFI_ERROR(activation_status)) {
        activation_status = EFI_COMPROMISED_DATA;
      }
      secure_zero(buffers.aad, PBNS_ENROLL_AAD_BUFFER_SIZE);
      Print(L"PBNS ENROLL FAIL TPM activation status=%r command=0x%08x\r\n",
            activation_status, activation_command);
      result = activation_status;
      goto Cleanup;
    }
    Print(L"PBNS ENROLL TPM ACTIVATION CHECKPOINT PASS\r\n");
    UINT32 certification_command = 0U;
    EFI_STATUS certification_status = PbnsTpmIdentityCertify(
        identity, (pbns_view){certify_digest, sizeof(certify_digest)},
        (pbns_buffer){certify_attestation, 0U, sizeof(certify_attestation)},
        &certify_attestation_size,
        (pbns_buffer){certify_signature, 0U, sizeof(certify_signature)},
        &certify_signature_size, &certification_command);
    if (EFI_ERROR(certification_status) || certify_attestation_size == 0U ||
        certify_signature_size == 0U) {
      if (!EFI_ERROR(certification_status)) {
        certification_status = EFI_COMPROMISED_DATA;
      }
      secure_zero(buffers.aad, PBNS_ENROLL_AAD_BUFFER_SIZE);
      Print(L"PBNS ENROLL FAIL TPM certification status=%r command=0x%08x\r\n",
            certification_status, certification_command);
      result = certification_status;
      goto Cleanup;
    }
    Print(L"PBNS ENROLL TPM CERTIFICATION CHECKPOINT PASS\r\n");
    secure_zero(buffers.aad, PBNS_ENROLL_AAD_BUFFER_SIZE);
    secure_zero(certify_digest, sizeof(certify_digest));
  }

  pbns_enrollment_software_proof proof = {0};
  proof.context.stage = PBNS_ENROLLMENT_STAGE_PROOF;
  proof.context.sequence = 1U;
  proof.context.key_id = PBNS_ENROLLMENT_TRUST.recipient.kid;
  CopyMem(proof.context.request_id, init.context.request_id,
          sizeof(proof.context.request_id));
  CopyMem(proof.context.host_fingerprint, fingerprint,
          sizeof(proof.context.host_fingerprint));
  CopyMem(proof.context.nonce, init.host_nonce, sizeof(proof.context.nonce));
  CopyMem(proof.server_nonce, challenge.server_nonce,
          sizeof(proof.server_nonce));
  CopyMem(proof.init_digest, init_digest, sizeof(proof.init_digest));
  CopyMem(proof.baseline_digest, baseline_digest,
          sizeof(proof.baseline_digest));
  proof.baseline_evidence = (pbns_view){buffers.baseline, baseline_size};

  size_t proof_size = 0U;
  size_t signed_proof_size = 0U;
  pbns_enrollment_tpm_proof tpm_proof = {0};
  if (EFI_ERROR(PbnsUefiMonotonicMs(system_table->BootServices,
                                    &proof_crypto_started))) {
    Print(L"PBNS ENROLL FAIL proof clock\r\n");
    goto Cleanup;
  }
  pbns_status proof_encode_status = PBNS_ERR_STATE;
  pbns_status proof_aad_status = PBNS_ERR_STATE;
  if (identity_mode == PBNS_ENROLL_IDENTITY_TPM) {
    tpm_proof.context = proof.context;
    CopyMem(tpm_proof.server_nonce, proof.server_nonce,
            sizeof(tpm_proof.server_nonce));
    CopyMem(tpm_proof.init_digest, proof.init_digest,
            sizeof(tpm_proof.init_digest));
    tpm_proof.activated_credential =
        (pbns_view){activated_credential, activated_size};
    tpm_proof.certify_attestation =
        (pbns_view){certify_attestation, certify_attestation_size};
    tpm_proof.certify_signature =
        (pbns_view){certify_signature, certify_signature_size};
    CopyMem(tpm_proof.baseline_digest, proof.baseline_digest,
            sizeof(tpm_proof.baseline_digest));
    tpm_proof.baseline_evidence = proof.baseline_evidence;
    proof_encode_status = pbns_enrollment_tpm_proof_encode(
        &tpm_proof,
        (pbns_buffer){buffers.object, 0U, PBNS_ENROLL_OBJECT_BUFFER_SIZE},
        &proof_size);
    proof_aad_status = pbns_enrollment_tpm_proof_aad(
        &tpm_proof, (pbns_buffer){buffers.aad, 0U, PBNS_ENROLL_AAD_BUFFER_SIZE},
        &aad_size);
  } else {
    proof_encode_status = pbns_enrollment_software_proof_encode(
        &proof,
        (pbns_buffer){buffers.object, 0U, PBNS_ENROLL_OBJECT_BUFFER_SIZE},
        &proof_size);
    proof_aad_status = pbns_enrollment_proof_aad(
        &proof, (pbns_buffer){buffers.aad, 0U, PBNS_ENROLL_AAD_BUFFER_SIZE},
        &aad_size);
  }
  if (proof_encode_status != PBNS_OK || proof_aad_status != PBNS_OK ||
      pbns_cose_uefi_sign1_sign(
          &adapter.IdentityKey, (pbns_view){buffers.object, proof_size},
          (pbns_view){buffers.aad, aad_size},
          (pbns_buffer){buffers.ciphertext, 0U, PBNS_ENROLL_OBJECT_BUFFER_SIZE},
          &signed_proof_size) != PBNS_OK ||
      pbns_enrollment_prepare_proof(&enrollment, proof.server_nonce,
                                    proof.init_digest, proof.baseline_digest,
                                    identity_mode == PBNS_ENROLL_IDENTITY_TPM,
                                    true) != PBNS_OK ||
      pbns_enrollment_envelope_aad(
          proof.context.request_id, proof.context.nonce, proof.context.key_id,
          (pbns_buffer){buffers.aad, 0U, PBNS_ENROLL_AAD_BUFFER_SIZE},
          &aad_size) != PBNS_OK) {
    Print(L"PBNS ENROLL FAIL proof signing\r\n");
    goto Cleanup;
  }
  ciphertext_size = 0U;
  if (pbns_cose_uefi_encrypt_for_recipient(
          identity, &adapter.RecipientKey, proof.context.key_id,
          (pbns_view){buffers.ciphertext, signed_proof_size},
          (pbns_view){buffers.aad, aad_size},
          (pbns_buffer){buffers.envelope, 0U, PBNS_ENROLL_OBJECT_BUFFER_SIZE},
          &ciphertext_size) != PBNS_OK) {
    Print(L"PBNS ENROLL FAIL proof encryption\r\n");
    goto Cleanup;
  }
  secure_zero(buffers.object, proof_size);
  secure_zero(buffers.ciphertext, signed_proof_size);
  pbns_enrollment_encrypted_envelope encrypted_proof = {
      .recipient_key_id = proof.context.key_id,
      .ciphertext = {buffers.envelope, ciphertext_size},
  };
  CopyMem(encrypted_proof.request_id, proof.context.request_id,
          sizeof(encrypted_proof.request_id));
  CopyMem(encrypted_proof.host_nonce, proof.context.nonce,
          sizeof(encrypted_proof.host_nonce));
  size_t proof_envelope_size = 0U;
  if (pbns_enrollment_envelope_encode(
          &encrypted_proof,
          (pbns_buffer){buffers.object, 0U, PBNS_ENROLL_OBJECT_BUFFER_SIZE},
          &proof_envelope_size) != PBNS_OK ||
      EFI_ERROR(PbnsUefiMonotonicMs(system_table->BootServices,
                                    &proof_crypto_finished)) ||
      proof_crypto_finished < proof_crypto_started) {
    Print(L"PBNS ENROLL FAIL proof envelope\r\n");
    goto Cleanup;
  }

  pbns_view signed_receipt = {0};
  pbns_result = enrollment_exchange(
      &broker, 2U, (pbns_view){buffers.object, proof_envelope_size},
      (pbns_buffer){buffers.wire, 0U, PBNS_ENROLL_OBJECT_BUFFER_SIZE},
      (pbns_buffer){buffers.canonical, 0U, PBNS_ENROLL_OBJECT_BUFFER_SIZE},
      &signed_receipt, &complete_exchange_ms, system_table);
  secure_zero(buffers.envelope, ciphertext_size);
  secure_zero(buffers.object, proof_envelope_size);
  if (pbns_result != PBNS_OK) {
    Print(L"PBNS ENROLL FAIL complete exchange status=%d\r\n", pbns_result);
    goto Cleanup;
  }

  pbns_view receipt_payload = {0};
  pbns_enrollment_receipt_object receipt = {0};
  static const uint8_t software_assurance[] = "software";
  static const uint8_t tpm_unverified_assurance[] = "tpm-unverified-ek";
  static const uint8_t tpm_verified_assurance[] = "tpm-verified";
  const pbns_view expected_receipt_assurance =
      identity_mode == PBNS_ENROLL_IDENTITY_TPM
          ? (tpm_public.EkCertificate.len > 0U
                 ? (pbns_view){tpm_verified_assurance,
                               sizeof(tpm_verified_assurance) - 1U}
                 : (pbns_view){tpm_unverified_assurance,
                               sizeof(tpm_unverified_assurance) - 1U})
          : (pbns_view){software_assurance, sizeof(software_assurance) - 1U};
  if (extract_sign1_payload(signed_receipt, PBNS_ENROLLMENT_TRUST.signer.kid,
                            &receipt_payload) != PBNS_OK ||
      pbns_enrollment_receipt_decode(
          receipt_payload, PBNS_ENROLLMENT_TRUST.signer.kid,
          (pbns_buffer){buffers.canonical, 0U, PBNS_ENROLL_OBJECT_BUFFER_SIZE},
          &receipt) != PBNS_OK ||
      CompareMem(receipt.context.request_id, init.context.request_id,
                 sizeof(receipt.context.request_id)) != 0 ||
      CompareMem(receipt.context.nonce, init.host_nonce,
                 sizeof(receipt.context.nonce)) != 0 ||
      CompareMem(receipt.context.host_fingerprint, fingerprint,
                 sizeof(receipt.context.host_fingerprint)) != 0 ||
      CompareMem(receipt.fingerprint, fingerprint,
                 sizeof(receipt.fingerprint)) != 0 ||
      CompareMem(receipt.baseline_digest, baseline_digest,
                 sizeof(receipt.baseline_digest)) != 0 ||
      receipt.assurance.len != expected_receipt_assurance.len ||
      CompareMem(receipt.assurance.ptr, expected_receipt_assurance.ptr,
                 expected_receipt_assurance.len) != 0 ||
      pbns_enrollment_receipt_aad(
          &receipt, challenge.server_nonce,
          (pbns_buffer){buffers.aad, 0U, PBNS_ENROLL_AAD_BUFFER_SIZE},
          &aad_size) != PBNS_OK ||
      pbns_cose_uefi_sign1_verify(&adapter.SignerKey, signed_receipt,
                                  (pbns_view){buffers.aad, aad_size},
                                  &verified_payload) != PBNS_OK ||
      verified_payload.ptr != receipt_payload.ptr ||
      verified_payload.len != receipt_payload.len ||
      pbns_enrollment_complete(&enrollment, receipt.context.request_id,
                               challenge.server_nonce, true) != PBNS_OK ||
      EFI_ERROR(
          PbnsUefiMonotonicMs(system_table->BootServices, &total_finished)) ||
      total_finished < total_started) {
    Print(L"PBNS ENROLL FAIL receipt verification\r\n");
    goto Cleanup;
  }

  if (identity_mode == PBNS_ENROLL_IDENTITY_TPM) {
    Print(expected_receipt_assurance.ptr == tpm_verified_assurance
              ? L"PBNS ENROLL ASSURANCE tpm-verified\r\n"
              : L"PBNS ENROLL ASSURANCE tpm-unverified-ek\r\n");
  } else {
    Print(L"PBNS ENROLL ASSURANCE software-reduced\r\n");
  }
  Print(L"PBNS ENROLL BASELINE BYTES %u\r\n", (UINT32)baseline_size);
  Print(L"PBNS ENROLL BASELINE EVENTS %u\r\n", (UINT32)event_count);
  Print(L"PBNS ENROLL BASELINE LOCAL MS %Lu\r\n",
        baseline_finished - baseline_started);
  Print(L"PBNS ENROLL INIT CRYPTO MS %Lu\r\n",
        init_crypto_finished - init_crypto_started);
  Print(L"PBNS ENROLL BEGIN EXCHANGE MS %Lu\r\n", begin_exchange_ms);
  Print(L"PBNS ENROLL PROOF CRYPTO MS %Lu\r\n",
        proof_crypto_finished - proof_crypto_started);
  Print(L"PBNS ENROLL COMPLETE EXCHANGE MS %Lu\r\n", complete_exchange_ms);
  Print(L"PBNS ENROLL TOTAL MS %Lu\r\n", total_finished - total_started);
  Print(identity_mode == PBNS_ENROLL_IDENTITY_TPM
            ? L"PBNS ENROLL TPM CHECKPOINT PASS fingerprint_prefix="
              L"%02x%02x%02x%02x\r\n"
            : L"PBNS ENROLL SOFTWARE CHECKPOINT PASS fingerprint_prefix="
              L"%02x%02x%02x%02x\r\n",
        fingerprint[0], fingerprint[1], fingerprint[2], fingerprint[3]);
  result = EFI_SUCCESS;
  operational_failure = false;

Cleanup:
  secure_zero(token, sizeof(token));
  secure_zero(random, sizeof(random));
  secure_zero(identity_public, sizeof(identity_public));
  secure_zero(fingerprint, sizeof(fingerprint));
  secure_zero(baseline_digest, sizeof(baseline_digest));
  secure_zero(ek_public, sizeof(ek_public));
  secure_zero(ak_public, sizeof(ak_public));
  secure_zero(ak_name, sizeof(ak_name));
  secure_zero(identity_tpm_public, sizeof(identity_tpm_public));
  secure_zero(activated_credential, sizeof(activated_credential));
  secure_zero(certify_attestation, sizeof(certify_attestation));
  secure_zero(certify_signature, sizeof(certify_signature));
  secure_zero(certify_digest, sizeof(certify_digest));
  secure_zero(&tpm_capabilities, sizeof(tpm_capabilities));
  pbns_enrollment_reset(&enrollment);
  if (broker_ready) {
    pbns_broker_reset(&broker);
  }
  secure_zero(&broker, sizeof(broker));
  secure_zero(&broker_transport, sizeof(broker_transport));

  pbns_status tls_cleanup_status = PBNS_OK;
  if (tls_transport != NULL) {
    tls_cleanup_status = PbnsEnrollmentClientTlsDestroy(&tls_transport);
    if (tls_transport != NULL && !operational_failure) {
      result = EFI_DEVICE_ERROR;
    }
  }
  if (tls_transport == NULL) {
    pbns_usb_transport_destroy(usb_transport);
    usb_transport = NULL;
  }

  PbnsEnrollmentClientAdapterReset(&adapter);
  secure_zero(&tls_random, sizeof(tls_random));
  if (tls_transport == NULL) {
    if (identity != NULL) {
      pbns_identity_close(identity);
      secure_zero(identity, sizeof(*identity));
      FreePool(identity);
      identity = NULL;
    }
    if (tls_random_context != NULL) {
      secure_zero(tls_random_context, sizeof(*tls_random_context));
      FreePool(tls_random_context);
      tls_random_context = NULL;
    }
  }
  secure_zero(&tls_cleanup_status, sizeof(tls_cleanup_status));
  free_buffers(&buffers);
  return result;
}
