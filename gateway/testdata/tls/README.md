# TEST ONLY TLS identity

The gateway TLS tests use the public artifact certificate and private key under `pbns/tests/fixtures/keys/tls-gateway-test-*`. They identify `pbns-gateway.test` and provide no deployment trust or confidentiality.

The companion `.sha256` file is the lowercase SHA-256 digest of the certificate's DER `SubjectPublicKeyInfo`. Release and evaluation configurations must use separately generated gateway credentials and the evaluated Pico must pin the corresponding deployment SPKI.
