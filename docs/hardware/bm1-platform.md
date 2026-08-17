# PBNS Bare-Metal Platform (BM-1) Specification & Verification

## 1. Platform Specification

The PBNS physical bare-metal evaluation is performed on the **BM-1** reference host system:

| Parameter | Specification |
|:---|:---|
| **Architecture** | x86-64 |
| **Processor** | AMD Ryzen Processor |
| **Firmware Vendor** | American Megatrends Inc. (AMI) |
| **Firmware Version** | Aptio V UEFI 2.7+ (Release Build) |
| **Secure Boot** | Enabled (Active Vendor Key Policy Enforcement) |
| **Setup Mode** | Disabled |
| **TPM Implementation** | AMD Platform Firmware TPM 2.0 (fTPM) |
| **TPM Specification** | TPM 2.0 (Family 2.0, Level 00, Revision 1.59) |
| **PCR Bank** | SHA-256 (Evaluated PCRs: 0, 2, 4, 7) |
| **Wireless Bridge** | Raspberry Pi Pico W (RP2040 + Infineon CYW43439) |
| **Host-Bridge Link** | Standard USB 2.0 Full-Speed CDC-ACM (12 Mbps) |

---

## 2. Security Preconditions & Invariants

1. **Active Secure Boot Enforcement**:
   - Secure Boot is permanently active. All executing PE/COFF binaries must be signed by keys enrolled in the platform `db`.
   - Streaming recovery images are loaded via memory-source `gBS->LoadImage` and `gBS->StartImage`. Unsigned or untrusted recovery UKIs fail closed with `EFI_SECURITY_VIOLATION`.

2. **Disk Immutability**:
   - The PBNS recovery path streams the Unified Kernel Image (UKI) directly into RAM pages allocated via `gBS->AllocatePages`.
   - The primary host block devices remain unmodified and unmounted during pre-boot operations.

3. **TPM 2.0 Remote Attestation**:
   - The host UEFI client accesses the platform fTPM via standard `EFI_TCG2_PROTOCOL`.
   - PCR quotes are generated across banks [0, 2, 4, 7] with fresh server-provided nonces, bound to the Attestation Key (AK), and encrypted using COSE_Encrypt before transmission over TLS.

---

## 3. Evaluation Records

All physical trials and console recordings are preserved in:
- `eval/raw/bare-metal/platform-redacted.json`
- `eval/raw/bare-metal/signed-uki-accepted.log`
- `eval/raw/bare-metal/untrusted-uki-rejected.log`
- `eval/raw/bare-metal/attestation.log`
- `eval/raw/bare-metal/pico-absent-boots.jsonl`
