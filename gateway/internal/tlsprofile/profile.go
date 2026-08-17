package tlsprofile

import "crypto/tls"

var approvedTLS12CipherSuites = [...]uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

func TLS12CipherSuites() []uint16 {
	return append([]uint16(nil), approvedTLS12CipherSuites[:]...)
}

func ValidTLS12CipherSuites(cipherSuites []uint16) bool {
	if len(cipherSuites) == 0 {
		return false
	}
	for _, configured := range cipherSuites {
		approved := false
		for _, candidate := range approvedTLS12CipherSuites {
			if configured == candidate {
				approved = true
				break
			}
		}
		if !approved {
			return false
		}
	}
	return true
}
