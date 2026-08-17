#ifndef PBNS_ATTESTATION_H
#define PBNS_ATTESTATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/crypto.h"
#include "pbns/encrypt.h"
#include "pbns/frame.h"
#include "pbns/inventory.h"
#include "pbns/measured_boot.h"
#include "pbns/trusted_time.h"

#define PBNS_ATTESTATION_DOMAIN "PBNS-ATTESTATION-v1"
#define PBNS_ATTESTATION_CHALLENGE_AAD_DOMAIN \
  "PBNS-ATTESTATION-CHALLENGE-SIGN-v1"
#define PBNS_ATTESTATION_SIGN_AAD_DOMAIN "PBNS-ATTESTATION-SIGN-v1"
#define PBNS_ATTESTATION_ENCRYPT_AAD_DOMAIN "PBNS-ATTESTATION-ENCRYPT-v1"
#define PBNS_ATTESTATION_QUALIFYING_DOMAIN "PBNS-ATTESTATION-v1"
#define PBNS_ATTESTATION_PROTOCOL_VERSION UINT64_C(1)
#define PBNS_ATTESTATION_NONCE_SIZE 32U
#define PBNS_ATTESTATION_DIGEST_SIZE 32U
#define PBNS_ATTESTATION_AK_NAME_MAX_SIZE 128U
#define PBNS_ATTESTATION_AK_REFERENCE_MAX_SIZE 4096U
#define PBNS_ATTESTATION_QUOTE_MAX_SIZE 4096U
#define PBNS_ATTESTATION_QUOTE_SIGNATURE_MAX_SIZE 1024U
#define PBNS_ATTESTATION_CHALLENGE_MAX_SIZE 4096U
#define PBNS_ATTESTATION_AAD_MAX_SIZE 256U
#define PBNS_ATTESTATION_SIGNED_OVERHEAD_MAX_SIZE 256U
#define PBNS_ATTESTATION_EVIDENCE_OVERHEAD_MAX_SIZE 8192U
#define PBNS_ATTESTATION_EVIDENCE_MAX_SIZE                              \
  (PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE +                             \
   PBNS_INVENTORY_ENCODED_MAX_SIZE +                                   \
   PBNS_ATTESTATION_EVIDENCE_OVERHEAD_MAX_SIZE)
#define PBNS_ATTESTATION_SIGNED_MAX_SIZE                                \
  (PBNS_ATTESTATION_EVIDENCE_MAX_SIZE +                                \
   PBNS_ATTESTATION_SIGNED_OVERHEAD_MAX_SIZE)
#define PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE                             \
  (PBNS_ATTESTATION_SIGNED_MAX_SIZE + 512U)
#define PBNS_ATTESTATION_SELECTION_WORKSPACE_SIZE                       \
  ((size_t)PBNS_MEASURED_BOOT_SELECTION_MAX_COUNT *                    \
   PBNS_MEASURED_BOOT_CANONICAL_ITEM_SIZE)

typedef struct pbns_attestation_challenge_expected {
  pbns_request_id request_id;
  uint8_t host_fingerprint[PBNS_INVENTORY_DIGEST_SIZE];
  uint8_t verifier_nonce[PBNS_ATTESTATION_NONCE_SIZE];
  pbns_view recipient_kid;
  pbns_view challenge_kid;
} pbns_attestation_challenge_expected;

typedef struct pbns_attestation_challenge {
  pbns_request_id request_id;
  uint8_t host_fingerprint[PBNS_INVENTORY_DIGEST_SIZE];
  uint8_t verifier_nonce[PBNS_ATTESTATION_NONCE_SIZE];
  pbns_measured_boot_selection_item
      selection_items[PBNS_MEASURED_BOOT_SELECTION_MAX_COUNT];
  size_t selection_count;
  uint8_t recipient_kid[PBNS_ENCRYPT_MAX_RECIPIENT_KID];
  size_t recipient_kid_len;
  uint64_t issued_at_ns;
  uint64_t expiry_ns;
  bool consumed;
} pbns_attestation_challenge;

typedef struct pbns_attestation_challenge_workspace {
  pbns_buffer canonical;
  pbns_buffer aad;
} pbns_attestation_challenge_workspace;

typedef pbns_status (*pbns_attestation_sha256_fn)(
    void *context, pbns_view input,
    uint8_t digest[PBNS_ATTESTATION_DIGEST_SIZE]);
typedef pbns_status (*pbns_attestation_consume_fn)(
    void *context, const pbns_request_id *request_id,
    const uint8_t verifier_nonce[PBNS_ATTESTATION_NONCE_SIZE]);
typedef pbns_status (*pbns_attestation_quote_fn)(
    void *context, pbns_measured_boot_selection selection,
    const uint8_t qualifying_data[PBNS_ATTESTATION_DIGEST_SIZE],
    pbns_buffer quote, size_t *quote_size, pbns_buffer signature,
    size_t *signature_size);
typedef pbns_status (*pbns_attestation_send_data_fn)(
    void *context, const pbns_request_id *request_id, uint32_t sequence,
    pbns_view payload, bool final_record);

typedef struct pbns_attestation_workspace {
  pbns_buffer inventory;
  pbns_buffer selection;
  pbns_buffer quote;
  pbns_buffer quote_signature;
  pbns_buffer evidence;
  pbns_buffer signed_evidence;
  pbns_buffer ciphertext;
  pbns_buffer aad;
} pbns_attestation_workspace;

typedef struct pbns_attestation_submission {
  const pbns_inventory_report *inventory_report;
  const pbns_measured_boot_evidence *measured_boot;
  pbns_view ak_name;
  pbns_view ak_reference;
  const pbns_crypto *host_signer;
  const pbns_crypto *recipient_encrypter;
  pbns_attestation_sha256_fn sha256;
  pbns_attestation_quote_fn quote;
  pbns_attestation_consume_fn consume;
  pbns_attestation_send_data_fn send_data;
  /* Saída exacta de 32 bytes. É limpa somente após toda validação de
   * descritores/sobreposição e, então, em toda falha de chamada válida; não
   * pode sobrepor entradas/workspace. */
  pbns_buffer evidence_digest;
  void *sha256_context;
  void *quote_context;
  void *consume_context;
  void *send_context;
  /* Exact caller-owned regions beginning at each non-NULL callback/crypto
   * context. A NULL context requires an empty region. These bounds make
   * evidence_digest alias validation mechanical before any byte is wiped. */
  pbns_view host_signer_context_region;
  pbns_view recipient_encrypter_context_region;
  pbns_view sha256_context_region;
  pbns_view quote_context_region;
  pbns_view consume_context_region;
  pbns_view send_context_region;
} pbns_attestation_submission;

pbns_status pbns_attestation_challenge_encode(
    const pbns_attestation_challenge *challenge, pbns_buffer output,
    size_t *written);
pbns_status pbns_attestation_challenge_aad(
    const pbns_attestation_challenge_expected *expected, pbns_buffer output,
    size_t *written);
pbns_status pbns_attestation_accept_challenge(
    const pbns_crypto *verifier, pbns_view signed_challenge,
    const pbns_attestation_challenge_expected *expected,
    const pbns_time_interval *trusted_time,
    pbns_attestation_challenge_workspace *workspace,
    pbns_attestation_challenge *challenge);
pbns_status pbns_attestation_qualifying_data(
    pbns_attestation_sha256_fn sha256, void *sha256_context,
    const pbns_request_id *request_id,
    const uint8_t verifier_nonce[PBNS_ATTESTATION_NONCE_SIZE],
    const uint8_t report_digest[PBNS_ATTESTATION_DIGEST_SIZE],
    const uint8_t selection_digest[PBNS_ATTESTATION_DIGEST_SIZE],
    const uint8_t event_log_digest[PBNS_ATTESTATION_DIGEST_SIZE],
    pbns_buffer scratch,
    uint8_t qualifying_data[PBNS_ATTESTATION_DIGEST_SIZE]);
pbns_status pbns_attestation_sign_aad(
    const pbns_attestation_challenge *challenge, pbns_view ak_name,
    pbns_buffer output, size_t *written);
pbns_status pbns_attestation_encrypt_aad(
    const pbns_attestation_challenge *challenge, pbns_buffer output,
    size_t *written);
pbns_status pbns_attestation_encrypt_message(
    const pbns_crypto *crypto, pbns_view recipient_kid, pbns_view plaintext,
    pbns_view external_aad, pbns_buffer output, size_t *written);
pbns_status pbns_attestation_submit(
    pbns_attestation_challenge *challenge,
    const pbns_attestation_submission *submission,
    pbns_attestation_workspace *workspace);
void pbns_attestation_challenge_reset(pbns_attestation_challenge *challenge);

#endif
