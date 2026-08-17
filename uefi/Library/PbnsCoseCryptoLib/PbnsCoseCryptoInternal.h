#ifndef PBNS_COSE_CRYPTO_INTERNAL_H
#define PBNS_COSE_CRYPTO_INTERNAL_H

#include <Library/PbnsCoseCryptoLib.h>

#include <stddef.h>
#include <stdint.h>

pbns_status pbns_cose_crypto_random_begin(const pbns_identity *identity);
void pbns_cose_crypto_random_end(void);
int pbns_cose_crypto_random_callback(void *context, unsigned char *output,
                                     size_t length);
pbns_status pbns_cose_crypto_private_generate(pbns_cose_key *key);
pbns_status pbns_cose_crypto_private_export(const pbns_cose_key *private_key,
                                            pbns_cose_key *public_key);
void pbns_cose_crypto_key_release(pbns_cose_key *key);

#endif
