# EK manufacturer-root fixtures

No manufacturer EK root is bundled in this directory. Production and evaluation
runs must supply an explicitly reviewed trust store outside the repository.

Enrollment with an absent or unverifiable EK certificate chain is recorded only
as `tpm-unverified-ek`. It is never upgraded to `tpm-verified` automatically.
The tests generate an ephemeral private root and leaf certificate in memory;
no test private key is stored here.
