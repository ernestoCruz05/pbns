#include "pbns/encrypt.h"

#include <stdbool.h>
#include <stdint.h>

static bool view_is_valid(pbns_view view)
{
    return view.ptr != NULL || view.len == 0U;
}

static bool output_is_valid(pbns_buffer output)
{
    return output.len == 0U && (output.ptr != NULL || output.cap == 0U);
}

static bool ranges_overlap(pbns_view input, pbns_buffer output)
{
    if(input.len == 0U || output.cap == 0U) {
        return false;
    }
    const uintptr_t input_start = (uintptr_t)input.ptr;
    const uintptr_t output_start = (uintptr_t)output.ptr;
    if(input.len > UINTPTR_MAX - input_start || output.cap > UINTPTR_MAX - output_start) {
        return true;
    }
    const uintptr_t input_end = input_start + input.len;
    const uintptr_t output_end = output_start + output.cap;
    return input_start < output_end && output_start < input_end;
}

static bool common_arguments_are_valid(const pbns_crypto *crypto,
                                       pbns_view recipient_kid,
                                       pbns_view external_aad,
                                       pbns_buffer output)
{
    return crypto != NULL && crypto->ops != NULL && crypto->context != NULL
           && view_is_valid(recipient_kid) && recipient_kid.len > 0U
           && recipient_kid.len <= PBNS_ENCRYPT_MAX_RECIPIENT_KID
           && view_is_valid(external_aad)
           && external_aad.len <= PBNS_ENCRYPT_MAX_EXTERNAL_AAD
           && output_is_valid(output) && output.cap <= PBNS_ENCRYPT_MAX_MESSAGE;
}

pbns_status pbns_encrypt_for_recipient(const pbns_crypto *crypto,
                                       pbns_view recipient_kid,
                                       pbns_view plaintext,
                                       pbns_view external_aad,
                                       pbns_buffer output,
                                       size_t *written)
{
    if(written == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    *written = 0U;
    if(!common_arguments_are_valid(crypto, recipient_kid, external_aad, output)
       || crypto->ops->encrypt_for_recipient == NULL || !view_is_valid(plaintext)
       || plaintext.len > PBNS_ENCRYPT_MAX_MESSAGE) {
        return PBNS_ERR_ARGUMENT;
    }
    if(ranges_overlap(recipient_kid, output) || ranges_overlap(plaintext, output)
       || ranges_overlap(external_aad, output)) {
        return PBNS_ERR_ARGUMENT;
    }
    return crypto->ops->encrypt_for_recipient(crypto->context,
                                               recipient_kid,
                                               plaintext,
                                               external_aad,
                                               output,
                                               written);
}

pbns_status pbns_decrypt_for_recipient(const pbns_crypto *crypto,
                                       pbns_view expected_recipient_kid,
                                       pbns_view message,
                                       pbns_view external_aad,
                                       pbns_buffer plaintext,
                                       size_t *written)
{
    if(written == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    *written = 0U;
    if(!common_arguments_are_valid(crypto,
                                   expected_recipient_kid,
                                   external_aad,
                                   plaintext)
       || crypto->ops->decrypt_for_recipient == NULL || !view_is_valid(message)
       || message.len == 0U || message.len > PBNS_ENCRYPT_MAX_MESSAGE) {
        return PBNS_ERR_ARGUMENT;
    }
    if(ranges_overlap(expected_recipient_kid, plaintext)
       || ranges_overlap(message, plaintext) || ranges_overlap(external_aad, plaintext)) {
        return PBNS_ERR_ARGUMENT;
    }
    return crypto->ops->decrypt_for_recipient(crypto->context,
                                               expected_recipient_kid,
                                               message,
                                               external_aad,
                                               plaintext,
                                               written);
}
