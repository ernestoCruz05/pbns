# PBNS recovery image policy

This directory defines the **source policy** for a RAM-backed recovery Unified Kernel Image (UKI). It is not a general rescue environment or installer.

## Security boundary

- UEFI must first authenticate the complete PE/COFF image through platform Secure Boot. A valid PBNS recovery manifest alone does not authorize execution.
- The initramfs mounts only proc, sysfs, devtmpfs, and tmpfs. It does not mount persistent filesystems, consume host fstab entries, activate swap/resume, or start networking.
- Every discovered block device is made read-only both by an early hook and a udev rule.
- `pbns-write-enable` is a local, per-device exception. It displays model, size, and canonical path, then requires the exact path to be typed. Its audit record exists only below the RAM-backed `/run/pbns`.
- The evaluated recovery path never invokes `pbns-write-enable`.

The initramfs does not provide arbitrary PBNS RPC, remote commands, plugins, or a general pre-boot agent.

## Build prerequisites

Equivalent package layouts are acceptable, but the build requires:

- dracut;
- systemd `ukify` and `linuxx64.efi.stub`;
- `sbsigntools` (`sbverify`);
- OpenSSL;
- an explicit Linux kernel version and readable kernel image.

Example:

```bash
mkdir -m 0700 -p pbns/integration/state/recovery-build
./pbns/recovery/build-initramfs.sh \
  --kernel-version "$(uname -r)" \
  --kernel-image "/boot/vmlinuz-$(uname -r)" \
  --output pbns/integration/state/recovery-build/pbns-recovery.img
SOURCE_DATE_EPOCH=0 ./pbns/recovery/build-uki.sh \
  --kernel "/boot/vmlinuz-$(uname -r)" \
  --initrd pbns/integration/state/recovery-build/pbns-recovery.img \
  --output pbns/integration/state/recovery-build/PBNSRecovery.efi
./pbns/recovery/test-policy.sh \
  pbns/integration/state/recovery-build/PBNSRecovery.efi
```

Both builders refuse to replace outputs. The UKI manifest records SHA-256 for the kernel, initramfs, command line, OS release, EFI stub, test certificate, and signed output.

## Signing-key status

`build-uki.sh` accepts only the central `TEST ONLY` fixture whose SHA-256 certificate fingerprint is:

```text
2C:A0:2D:42:49:A2:E4:3D:EE:A5:9E:BA:8D:6D:D7:EC:0E:5F:25:CB:22:C3:FD:42:83:8F:74:63:65:EC:88:25
```

The public fixture key is copied to a temporary mode-`0600` file and removed after signing. Release mode rejects the fixture. No deployment signing key belongs in this repository.

## Evidence classification

Static policy tests establish source-level constraints only. A successful local build and `sbverify` inspection establish an artifact checkpoint. QEMU/OVMF execution and physical-platform execution are separate evidence classes and must not be inferred from source or artifact inspection.
