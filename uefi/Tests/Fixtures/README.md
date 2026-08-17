# Disposable UEFI loader fixtures

These applications and generated images test launcher behavior without touching an installed operating-system loader.

- `missing` contains no image.
- `truncated` preserves the DOS, PE, optional, and section headers but ends inside section data.
- `untrusted` is a valid `ReturnSuccess.efi` signed only by the public `TEST ONLY` recovery-image fixture key. That key is not present in the default OVMF trust database.
- `return-error` accepts only the UTF-16 load options `load-error`, `device-error`, and `aborted`; any missing or malformed value returns `EFI_ABORTED`.
- `return-success` returns `EFI_SUCCESS`, which is an unexpected return from a normal loader.

`pbns/integration/qemu/make-loader-fixtures.sh` creates the complete tree under ignored disposable integration state. None of these files is an installed loader or a production signing artifact.
