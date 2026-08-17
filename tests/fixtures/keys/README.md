# TEST ONLY cryptographic keys

The PEM files in this directory are public PBNS artifact fixtures. They provide repeatable ES256 and COSE_Encrypt interoperability tests and offer no confidentiality or deployment trust.

Release configurations must reject these keys. Production and evaluation service keys are generated separately and are never committed to the repository.

`tests/vectors/sign1-v1.cbor` signs the canonical `pbns.time` common-context fixture with external AAD `pbns-sign1-v1`. ECDSA signing is randomized, so the checked-in message is a fixed verification vector rather than a byte-reproducible signature-generation oracle.

The `cose-recipient-test-*` pair is the P-256 recipient used by both directions under `tests/vectors/cose-encrypt-v1/`. Its private key is test-only public artifact material.

The distinct `enrollment-recipient-test-*` and `enrollment-signing-test-*` pairs exercise role-separated encrypted enrollment. Their private keys are intentionally public test fixtures and must be copied to mode `0600` files before a local gateway test run.

The distinct `recovery-policy-test-*` P-256 pair signs only canonical TPM recovery-version policy vectors. Its private key is intentionally public test material and must be copied to a mode-`0600` runtime file before CLI tests.

The distinct `recovery-manifest-test-*` P-256 pair signs only disposable live-recovery manifests. Its private key is intentionally public test material, provides no confidentiality or deployment trust, and must be copied to a mode-`0600` runtime file before gateway use.

The `tls-gateway-test-*` files identify `pbns-gateway.test` for TLS-only listener tests. The private key is public fixture material, and the `.sha256` file pins the certificate's DER `SubjectPublicKeyInfo`.

The RSA `uki-secureboot-test-*` pair identifies only disposable recovery-image fixtures. Its private key is intentionally public test material, is absent from production trust stores, and must be copied to a mode-`0600` runtime file before signing. Release configuration must reject its SHA-256 certificate fingerprint `2C:A0:2D:42:49:A2:E4:3D:EE:A5:9E:BA:8D:6D:D7:EC:0E:5F:25:CB:22:C3:FD:42:83:8F:74:63:65:EC:88:25`.
