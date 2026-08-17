#include "mbedtls/build_info.h"

#if !defined(PBNS_MBEDTLS_CONFIG_H)
#error "hosted mbedTLS consumer is not using the PBNS config"
#endif
#if !defined(MBEDTLS_SSL_PROTO_TLS1_2)
#error "PBNS requires TLS 1.2"
#endif
#if !defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
#error "PBNS requires ECDHE-ECDSA"
#endif
#if MBEDTLS_MPI_MAX_SIZE != 32
#error "PBNS requires the bounded MPI size"
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#error "PBNS hosted consumer unexpectedly enables TLS 1.3"
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
#error "PBNS hosted consumer unexpectedly enables renegotiation"
#endif
#if !defined(MBEDTLS_SSL_ALPN)
#error "PBNS hosted consumer requires ALPN"
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
#error "PBNS hosted consumer unexpectedly enables session tickets"
#endif
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#error "PBNS hosted consumer unexpectedly enables DTLS connection IDs"
#endif

int main(void) { return 0; }
