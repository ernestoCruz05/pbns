#include "pbns/enrollment.h"
#include "pbns/enrollment_wire.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "qcbor/qcbor_spiffy_decode.h"

static void fill(uint8_t *output, size_t length, uint8_t value) {
  memset(output, value, length);
}

static pbns_enrollment make_context(pbns_enrollment_assurance assurance) {
  pbns_enrollment context = {0};
  uint8_t request_id[PBNS_ENROLLMENT_REQUEST_ID_SIZE] = {0};
  uint8_t host_nonce[PBNS_ENROLLMENT_NONCE_SIZE] = {0};
  uint8_t init_digest[PBNS_ENROLLMENT_DIGEST_SIZE] = {0};
  uint8_t baseline_digest[PBNS_ENROLLMENT_DIGEST_SIZE] = {0};
  fill(request_id, sizeof(request_id), 0x11U);
  fill(host_nonce, sizeof(host_nonce), 0x22U);
  fill(init_digest, sizeof(init_digest), 0x33U);
  fill(baseline_digest, sizeof(baseline_digest), 0x44U);
  assert(pbns_enrollment_init(&context, assurance, request_id, host_nonce,
                              init_digest, baseline_digest) == PBNS_OK);
  return context;
}

static void valid_challenge(pbns_enrollment *context,
                            uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE]) {
  fill(server_nonce, PBNS_ENROLLMENT_NONCE_SIZE, 0x55U);
  assert(pbns_enrollment_accept_challenge(context, context->host_nonce,
                                          server_nonce, context->init_digest,
                                          true) == PBNS_OK);
  assert(context->state == PBNS_ENROLLMENT_CHALLENGE_VERIFIED);
}

static void test_software_flow(void) {
  pbns_enrollment context = make_context(PBNS_ENROLLMENT_ASSURANCE_SOFTWARE);
  uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE] = {0};
  valid_challenge(&context, server_nonce);
  assert(pbns_enrollment_prepare_proof(
             &context, server_nonce, context.init_digest,
             context.baseline_digest, false, true) == PBNS_OK);
  assert(context.state == PBNS_ENROLLMENT_PROOF_READY);
  assert(context.assurance == PBNS_ENROLLMENT_ASSURANCE_SOFTWARE);
  assert(pbns_enrollment_complete(&context, context.request_id, server_nonce,
                                  true) == PBNS_OK);
  assert(context.state == PBNS_ENROLLMENT_COMPLETE);
  assert(pbns_enrollment_complete(&context, context.request_id, server_nonce,
                                  true) == PBNS_ERR_STATE);
  pbns_enrollment_reset(&context);
  assert(context.state == PBNS_ENROLLMENT_INIT);
  for (size_t index = 0U; index < sizeof(context); ++index) {
    assert(((const uint8_t *)&context)[index] == 0U);
  }
}

static void test_tpm_requires_activation(void) {
  pbns_enrollment context = make_context(PBNS_ENROLLMENT_ASSURANCE_TPM);
  uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE] = {0};
  valid_challenge(&context, server_nonce);
  assert(pbns_enrollment_prepare_proof(
             &context, server_nonce, context.init_digest,
             context.baseline_digest, false, true) == PBNS_ERR_AUTHENTICATION);
  assert(context.state == PBNS_ENROLLMENT_FAILED);
  assert(context.assurance == PBNS_ENROLLMENT_ASSURANCE_TPM);

  context = make_context(PBNS_ENROLLMENT_ASSURANCE_TPM);
  valid_challenge(&context, server_nonce);
  assert(pbns_enrollment_prepare_proof(
             &context, server_nonce, context.init_digest,
             context.baseline_digest, true, true) == PBNS_OK);
  assert(context.assurance == PBNS_ENROLLMENT_ASSURANCE_TPM);
}

static void test_challenge_context_failures(void) {
  pbns_enrollment context = make_context(PBNS_ENROLLMENT_ASSURANCE_SOFTWARE);
  uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE] = {0};
  fill(server_nonce, sizeof(server_nonce), 0x55U);
  uint8_t changed[PBNS_ENROLLMENT_DIGEST_SIZE] = {0};
  memcpy(changed, context.init_digest, sizeof(changed));
  changed[0] ^= 1U;
  assert(pbns_enrollment_accept_challenge(&context, context.host_nonce,
                                          server_nonce, changed,
                                          true) == PBNS_ERR_AUTHENTICATION);
  assert(context.state == PBNS_ENROLLMENT_FAILED);

  context = make_context(PBNS_ENROLLMENT_ASSURANCE_SOFTWARE);
  assert(pbns_enrollment_accept_challenge(&context, context.host_nonce,
                                          server_nonce, context.init_digest,
                                          false) == PBNS_ERR_AUTHENTICATION);
  assert(context.state == PBNS_ENROLLMENT_FAILED);

  context = make_context(PBNS_ENROLLMENT_ASSURANCE_SOFTWARE);
  uint8_t zero_nonce[PBNS_ENROLLMENT_NONCE_SIZE] = {0};
  assert(pbns_enrollment_accept_challenge(&context, context.host_nonce,
                                          zero_nonce, context.init_digest,
                                          true) == PBNS_ERR_ARGUMENT);
  assert(context.state == PBNS_ENROLLMENT_INIT);
}

static void test_proof_and_receipt_context_failures(void) {
  pbns_enrollment context = make_context(PBNS_ENROLLMENT_ASSURANCE_SOFTWARE);
  uint8_t server_nonce[PBNS_ENROLLMENT_NONCE_SIZE] = {0};
  valid_challenge(&context, server_nonce);
  uint8_t changed[PBNS_ENROLLMENT_DIGEST_SIZE] = {0};
  memcpy(changed, context.baseline_digest, sizeof(changed));
  changed[31] ^= 1U;
  assert(pbns_enrollment_prepare_proof(&context, server_nonce,
                                       context.init_digest, changed, false,
                                       true) == PBNS_ERR_AUTHENTICATION);
  assert(context.state == PBNS_ENROLLMENT_FAILED);

  context = make_context(PBNS_ENROLLMENT_ASSURANCE_SOFTWARE);
  valid_challenge(&context, server_nonce);
  assert(pbns_enrollment_prepare_proof(
             &context, server_nonce, context.init_digest,
             context.baseline_digest, false, false) == PBNS_ERR_AUTHENTICATION);
  assert(context.state == PBNS_ENROLLMENT_FAILED);

  context = make_context(PBNS_ENROLLMENT_ASSURANCE_SOFTWARE);
  valid_challenge(&context, server_nonce);
  assert(pbns_enrollment_prepare_proof(
             &context, server_nonce, context.init_digest,
             context.baseline_digest, false, true) == PBNS_OK);
  assert(pbns_enrollment_complete(&context, context.request_id, server_nonce,
                                  false) == PBNS_ERR_AUTHENTICATION);
  assert(context.state == PBNS_ENROLLMENT_FAILED);
}

static pbns_enrollment_common_context
make_common(uint64_t stage, uint64_t sequence, pbns_view key_id) {
  pbns_enrollment_common_context context = {
      .stage = stage,
      .sequence = sequence,
      .key_id = key_id,
  };
  fill(context.request_id, sizeof(context.request_id), 0x11U);
  fill(context.host_fingerprint, sizeof(context.host_fingerprint), 0x22U);
  fill(context.nonce, sizeof(context.nonce), 0x33U);
  return context;
}

static void test_enrollment_wire_objects(void) {
  static const uint8_t recipient_key_id[] = "recipient-1";
  static const uint8_t signing_key_id[] = "signer-1";
  static const uint8_t identity_key[] = {0xa4U, 0x01U, 0x02U, 0x20U};
  static const uint8_t baseline[] = "baseline-evidence";
  uint8_t first[4096] = {0};
  uint8_t second[4096] = {0};
  uint8_t scratch[4096] = {0};
  size_t first_size = 0U;
  size_t second_size = 0U;

  pbns_enrollment_software_init init = {
      .context = make_common(
          PBNS_ENROLLMENT_STAGE_INIT, 0U,
          (pbns_view){recipient_key_id, sizeof(recipient_key_id) - 1U}),
      .identity_cose_key = {identity_key, sizeof(identity_key)},
  };
  fill(init.token, sizeof(init.token), 0x44U);
  fill(init.initial_evidence_digest, sizeof(init.initial_evidence_digest),
       0x55U);
  memcpy(init.host_nonce, init.context.nonce, sizeof(init.host_nonce));
  assert(pbns_enrollment_software_init_encode(
             &init, (pbns_buffer){first, 0U, sizeof(first)}, &first_size) ==
         PBNS_OK);
  assert(first_size > sizeof(init.token));
  assert(pbns_enrollment_software_init_encode(
             &init, (pbns_buffer){second, 0U, sizeof(second)}, &second_size) ==
         PBNS_OK);
  assert(first_size == second_size && memcmp(first, second, first_size) == 0);
  assert(pbns_enrollment_software_init_encode(
             &init, (pbns_buffer){second, 0U, first_size - 1U}, &second_size) ==
         PBNS_ERR_LIMIT);

  static const uint8_t tpm_public[] = {0x00U, 0x23U, 0x00U, 0x0bU};
  static const uint8_t tpm_name[] = {0x00U, 0x0bU, 0x44U, 0x55U};
  static const uint8_t ek_certificate[] = {0x30U, 0x01U, 0x00U};
  pbns_enrollment_tpm_init tpm_init = {
      .context = init.context,
      .ek_public = {tpm_public, sizeof(tpm_public)},
      .ak_public = {tpm_public, sizeof(tpm_public)},
      .ak_name = {tpm_name, sizeof(tpm_name)},
      .ek_certificate = {ek_certificate, sizeof(ek_certificate)},
      .identity_cose_key = init.identity_cose_key,
      .identity_tpm_public = {tpm_public, sizeof(tpm_public)},
  };
  memcpy(tpm_init.token, init.token, sizeof(tpm_init.token));
  memcpy(tpm_init.initial_evidence_digest, init.initial_evidence_digest,
         sizeof(tpm_init.initial_evidence_digest));
  memcpy(tpm_init.host_nonce, init.host_nonce, sizeof(tpm_init.host_nonce));
  pbns_enrollment_tpm_init empty_chain = tpm_init;
  empty_chain.ek_certificate = (pbns_view){0};
  assert(pbns_enrollment_tpm_init_encode(
             &empty_chain, (pbns_buffer){second, 0U, sizeof(second)},
             &second_size) == PBNS_OK);
  QCBORDecodeContext empty_chain_decoder = {0};
  QCBORItem empty_chain_item = {0};
  QCBORDecode_Init(&empty_chain_decoder, (UsefulBufC){second, second_size},
                   QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterMap(&empty_chain_decoder, NULL);
  QCBORDecode_EnterArrayFromMapN(&empty_chain_decoder, 12);
  assert(QCBORDecode_GetNext(&empty_chain_decoder, &empty_chain_item) ==
         QCBOR_ERR_NO_MORE_ITEMS);
  QCBORDecode_ExitArray(&empty_chain_decoder);
  QCBORDecode_ExitMap(&empty_chain_decoder);
  assert(QCBORDecode_Finish(&empty_chain_decoder) == QCBOR_SUCCESS);

  assert(pbns_enrollment_tpm_init_encode(
             &tpm_init, (pbns_buffer){first, 0U, sizeof(first)}, &first_size) ==
         PBNS_OK);
  QCBORDecodeContext certificate_decoder = {0};
  UsefulBufC decoded_certificate = {0};
  QCBORDecode_Init(&certificate_decoder, (UsefulBufC){first, first_size},
                   QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterMap(&certificate_decoder, NULL);
  QCBORDecode_EnterArrayFromMapN(&certificate_decoder, 12);
  QCBORDecode_GetByteString(&certificate_decoder, &decoded_certificate);
  QCBORDecode_ExitArray(&certificate_decoder);
  QCBORDecode_ExitMap(&certificate_decoder);
  assert(QCBORDecode_Finish(&certificate_decoder) == QCBOR_SUCCESS);
  assert(decoded_certificate.len == sizeof(ek_certificate));
  assert(memcmp(decoded_certificate.ptr, ek_certificate,
                sizeof(ek_certificate)) == 0);
  tpm_init.ek_certificate.len = PBNS_ENROLLMENT_PUBLIC_KEY_MAX_SIZE + 1U;
  assert(pbns_enrollment_tpm_init_encode(
             &tpm_init, (pbns_buffer){first, 0U, sizeof(first)}, &first_size) ==
         PBNS_ERR_FORMAT);
  tpm_init.ek_certificate.len = sizeof(ek_certificate);

  pbns_enrollment_challenge_object challenge = {
      .context =
          make_common(PBNS_ENROLLMENT_STAGE_CHALLENGE, 0U,
                      (pbns_view){signing_key_id, sizeof(signing_key_id) - 1U}),
      .flow = PBNS_ENROLLMENT_FLOW_SOFTWARE,
  };
  memcpy(challenge.host_nonce, init.host_nonce, sizeof(challenge.host_nonce));
  fill(challenge.server_nonce, sizeof(challenge.server_nonce), 0x66U);
  fill(challenge.init_digest, sizeof(challenge.init_digest), 0x77U);
  assert(pbns_enrollment_challenge_encode(
             &challenge, (pbns_buffer){first, 0U, sizeof(first)},
             &first_size) == PBNS_OK);
  pbns_enrollment_challenge_object decoded_challenge = {0};
  assert(pbns_enrollment_challenge_decode(
             (pbns_view){first, first_size},
             (pbns_view){signing_key_id, sizeof(signing_key_id) - 1U},
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded_challenge) == PBNS_OK);
  assert(decoded_challenge.flow == PBNS_ENROLLMENT_FLOW_SOFTWARE);
  assert(memcmp(decoded_challenge.server_nonce, challenge.server_nonce,
                sizeof(challenge.server_nonce)) == 0);
  assert(pbns_enrollment_challenge_decode(
             (pbns_view){first, first_size},
             (pbns_view){recipient_key_id, sizeof(recipient_key_id) - 1U},
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded_challenge) == PBNS_ERR_AUTHENTICATION);

  pbns_enrollment_software_proof proof = {
      .context = make_common(
          PBNS_ENROLLMENT_STAGE_PROOF, 1U,
          (pbns_view){recipient_key_id, sizeof(recipient_key_id) - 1U}),
      .baseline_evidence = {baseline, sizeof(baseline) - 1U},
  };
  memcpy(proof.server_nonce, challenge.server_nonce,
         sizeof(proof.server_nonce));
  memcpy(proof.init_digest, challenge.init_digest, sizeof(proof.init_digest));
  fill(proof.baseline_digest, sizeof(proof.baseline_digest), 0x88U);
  assert(pbns_enrollment_software_proof_encode(
             &proof, (pbns_buffer){first, 0U, sizeof(first)}, &first_size) ==
         PBNS_OK);
  static const uint8_t activation[] = {1U, 2U, 3U};
  static const uint8_t attestation[] = {4U, 5U, 6U};
  static const uint8_t tpm_signature[] = {7U, 8U, 9U};
  pbns_enrollment_tpm_proof tpm_proof = {
      .context = proof.context,
      .activated_credential = {activation, sizeof(activation)},
      .certify_attestation = {attestation, sizeof(attestation)},
      .certify_signature = {tpm_signature, sizeof(tpm_signature)},
      .baseline_evidence = proof.baseline_evidence,
  };
  memcpy(tpm_proof.server_nonce, proof.server_nonce,
         sizeof(tpm_proof.server_nonce));
  memcpy(tpm_proof.init_digest, proof.init_digest,
         sizeof(tpm_proof.init_digest));
  memcpy(tpm_proof.baseline_digest, proof.baseline_digest,
         sizeof(tpm_proof.baseline_digest));
  assert(pbns_enrollment_tpm_proof_encode(
             &tpm_proof, (pbns_buffer){first, 0U, sizeof(first)},
             &first_size) == PBNS_OK);
  assert(pbns_enrollment_tpm_proof_aad(
             &tpm_proof, (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &second_size) == PBNS_OK);

  pbns_enrollment_receipt_object receipt = {
      .context =
          make_common(PBNS_ENROLLMENT_STAGE_RECEIPT, 2U,
                      (pbns_view){signing_key_id, sizeof(signing_key_id) - 1U}),
      .assurance = {(const uint8_t *)"software", 8U},
      .enrolled_at_unix = INT64_C(1900000000),
      .key_id = {signing_key_id, sizeof(signing_key_id) - 1U},
  };
  fill(receipt.fingerprint, sizeof(receipt.fingerprint), 0x22U);
  fill(receipt.baseline_digest, sizeof(receipt.baseline_digest), 0x88U);
  assert(pbns_enrollment_receipt_encode(&receipt,
                                        (pbns_buffer){first, 0U, sizeof(first)},
                                        &first_size) == PBNS_OK);
  pbns_enrollment_receipt_object decoded_receipt = {0};
  assert(pbns_enrollment_receipt_decode(
             (pbns_view){first, first_size},
             (pbns_view){signing_key_id, sizeof(signing_key_id) - 1U},
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded_receipt) == PBNS_OK);
  assert(decoded_receipt.enrolled_at_unix == receipt.enrolled_at_unix);

  static const uint8_t ciphertext[] = {0xd8U, 0x60U, 0x01U, 0x02U};
  pbns_enrollment_encrypted_envelope envelope = {
      .recipient_key_id = {recipient_key_id, sizeof(recipient_key_id) - 1U},
      .ciphertext = {ciphertext, sizeof(ciphertext)},
  };
  memcpy(envelope.request_id, init.context.request_id,
         sizeof(envelope.request_id));
  memcpy(envelope.host_nonce, init.host_nonce, sizeof(envelope.host_nonce));
  assert(pbns_enrollment_envelope_encode(
             &envelope, (pbns_buffer){first, 0U, sizeof(first)}, &first_size) ==
         PBNS_OK);
  pbns_enrollment_encrypted_envelope decoded_envelope = {0};
  assert(pbns_enrollment_envelope_decode(
             (pbns_view){first, first_size},
             (pbns_view){recipient_key_id, sizeof(recipient_key_id) - 1U},
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded_envelope) == PBNS_OK);
  assert(decoded_envelope.ciphertext.len == sizeof(ciphertext));

  pbns_enrollment_wire_object wire = {
      .operation = 1U,
      .object = {first, first_size},
  };
  assert(pbns_enrollment_wire_object_encode(
             &wire, (pbns_buffer){second, 0U, sizeof(second)}, &second_size) ==
         PBNS_OK);
  pbns_enrollment_wire_object decoded_wire = {0};
  assert(pbns_enrollment_wire_object_decode(
             (pbns_view){second, second_size}, 1U,
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded_wire) == PBNS_OK);
  assert(decoded_wire.object.len == first_size);

  size_t aad_size = 0U;
  assert(
      pbns_enrollment_envelope_aad(
          envelope.request_id, envelope.host_nonce, envelope.recipient_key_id,
          (pbns_buffer){scratch, 0U, sizeof(scratch)}, &aad_size) == PBNS_OK);
  assert(aad_size > sizeof(envelope.request_id) + sizeof(envelope.host_nonce));
  assert(pbns_enrollment_challenge_aad(
             &challenge, (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &aad_size) == PBNS_OK);
  assert(pbns_enrollment_proof_aad(&proof,
                                   (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                   &aad_size) == PBNS_OK);
  assert(
      pbns_enrollment_receipt_aad(&receipt, challenge.server_nonce,
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &aad_size) == PBNS_OK);
}

static void test_token_input_requires_enter_and_ignores_scan_keys(void) {
  uint8_t token_text[PBNS_ENROLLMENT_TOKEN_TEXT_SIZE] = {0};
  fill(token_text, sizeof(token_text), (uint8_t)'A');
  pbns_enrollment_token_input input = {0};
  pbns_enrollment_token_input_action action = PBNS_ENROLLMENT_TOKEN_CONTINUE;
  assert(pbns_enrollment_token_input_key(&input, 0U, &action) == PBNS_OK);
  assert(input.length == 0U && action == PBNS_ENROLLMENT_TOKEN_CONTINUE);
  for (size_t index = 0U; index < sizeof(token_text); ++index) {
    assert(pbns_enrollment_token_input_key(&input, token_text[index],
                                           &action) == PBNS_OK);
    assert(action == PBNS_ENROLLMENT_TOKEN_CONTINUE);
  }
  assert(input.length == sizeof(token_text));
  assert(memcmp(input.text, token_text, sizeof(token_text)) == 0);
  assert(pbns_enrollment_token_input_key(&input, 0U, &action) == PBNS_OK);
  assert(input.length == sizeof(token_text));
  assert(pbns_enrollment_token_input_key(&input, 13U, &action) == PBNS_OK);
  assert(action == PBNS_ENROLLMENT_TOKEN_SUBMIT);
  assert(pbns_enrollment_token_input_key(&input, 'A', &action) ==
         PBNS_ERR_FORMAT);
}

static void test_init_rejects_implicit_or_empty_assurance(void) {
  pbns_enrollment context = {0};
  uint8_t request_id[PBNS_ENROLLMENT_REQUEST_ID_SIZE] = {0};
  uint8_t nonce[PBNS_ENROLLMENT_NONCE_SIZE] = {0};
  uint8_t digest[PBNS_ENROLLMENT_DIGEST_SIZE] = {0};
  fill(request_id, sizeof(request_id), 1U);
  fill(nonce, sizeof(nonce), 2U);
  fill(digest, sizeof(digest), 3U);
  assert(pbns_enrollment_init(&context, PBNS_ENROLLMENT_ASSURANCE_INVALID,
                              request_id, nonce, digest,
                              digest) == PBNS_ERR_ARGUMENT);
  memset(request_id, 0, sizeof(request_id));
  assert(pbns_enrollment_init(&context, PBNS_ENROLLMENT_ASSURANCE_SOFTWARE,
                              request_id, nonce, digest,
                              digest) == PBNS_ERR_ARGUMENT);
}

int main(void) {
  test_software_flow();
  test_tpm_requires_activation();
  test_challenge_context_failures();
  test_proof_and_receipt_context_failures();
  test_enrollment_wire_objects();
  test_token_input_requires_enter_and_ignores_scan_keys();
  test_init_rejects_implicit_or_empty_assurance();
  return 0;
}
