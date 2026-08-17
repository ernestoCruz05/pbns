# Recovery test data

Recovery publication tests create artifacts, repositories, keys, and manifests in private temporary directories. No deployment artifact or private key is checked in here.

The shared canonical manifest vectors are under `pbns/tests/vectors/recovery-manifest-v1/`. Their signing key is an intentionally public test fixture and must never be configured for deployment.

A valid recovery manifest authenticates only artifact selection, size, digest, validity, and rollback-policy inputs. It never authorizes PE/COFF execution; Secure Boot validation remains a separate mandatory decision at `LoadImage`/`StartImage`.
