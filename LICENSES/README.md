# Retained third-party licenses

`bootstrap.sh --sync-licenses` copies the license text from each exact dependency revision into this directory and verifies its SHA-256 digest against `pbns/dependencies.lock`.

Generated retained copies are committed with the dependency submodules. Project code remains separate from third-party source and preserves upstream notices and comments. Reviewed compatibility changes are stored as patch files under `pbns/patches/` and applied only to ignored generated build copies; pinned submodule worktrees remain unchanged.

The OVMF test also uses the build-only `iasl` package `20190215.0.0` declared by the pinned EDK II `OvmfPkg/PlatformCI/iasl_ext_dep.yaml`. `integration/qemu/bootstrap-iasl.sh` verifies NuGet package SHA-256 `0f207af637358f32c93f09f3df12056452964e6a5242de484508e91d352946cb` and extracted executable SHA-256 `9dc25808684701d5a009a9e984385a7b5d36fbd1e398810028c5d163b7553dff`. The package is downloaded into ignored `.deps` state and is neither linked into PBNS artifacts nor redistributed here; its upstream licensing reference is <https://www.acpica.org/Licensing>.

Go module license copies are retained directly from the exact `go.mod` versions:

```text
c15d721c37e277a11584547de6d618541501f7aa10c4e32a945a4f9ff36cb0f6  go_bbolt.txt
78cad457d5ea7318230f3d969d4cdf29cef45524a1fc8ca3a97646da1ad7a841  go_fxamacker_cbor.txt
cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30  go_google_attestation.txt
cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30  go_google_tpm.txt
1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5  go_veraison_cose.txt
a555f1194fdac34da70fb416968f7e2217b02352c26c1eac2fa45fcb4290ae8d  go_x448_float16.txt
911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad  go_x_sys.txt
18c1bf4b1ba1fb2c4ffa7398c234d83c0d55475298e470ae1e5e3a8a8bd2e448  tpm2_tss.txt
```
