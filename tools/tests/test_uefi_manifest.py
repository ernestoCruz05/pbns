import json
import pathlib
import re
import unittest


class UefiManifestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pbns_root = pathlib.Path(__file__).parents[2]
        self.core_manifest = self.pbns_root / "src" / "core" / "PbnsCoreLib.inf"
        self.package_dsc = self.pbns_root / "PbnsPkg.dsc"
        self.qcbor_manifest = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsQcborLib"
            / "PbnsQcborLib.inf"
        )
        self.probe_inf = (
            self.pbns_root
            / "uefi"
            / "Applications"
            / "PbnsProbe"
            / "PbnsProbe.inf"
        )
        self.identity_dir = (
            self.pbns_root / "uefi" / "Library" / "PbnsIdentityLib"
        )
        self.tcose_manifest = (
            self.pbns_root / "uefi" / "Library" / "PbnsTCoseLib" / "PbnsTCoseLib.inf"
        )
        self.cose_adapter_dir = (
            self.pbns_root / "uefi" / "Library" / "PbnsCoseCryptoLib"
        )
        self.tss2_mu_manifest = (
            self.pbns_root / "uefi" / "Library" / "Tss2MuLib" / "Tss2MuLib.inf"
        )
        self.tss2_sys_manifest = (
            self.pbns_root / "uefi" / "Library" / "Tss2SysLib" / "Tss2SysLib.inf"
        )

    def test_every_portable_core_source_appears_once(self) -> None:
        manifest = self.core_manifest.read_text(encoding="utf-8")
        sources = sorted((self.pbns_root / "src" / "core").glob("*.c"))
        self.assertGreater(len(sources), 0)
        manifest_sources = [
            line.strip()
            for line in manifest.splitlines()
            if line.strip().endswith(".c")
        ]
        for source in sources:
            with self.subTest(source=source.name):
                self.assertEqual(manifest_sources.count(source.name), 1)
        self.assertNotIn("pbns/src/core", manifest)

    def test_pinned_qcbor_sources_have_an_edk_library_instance(self) -> None:
        manifest = self.qcbor_manifest.read_text(encoding="utf-8")
        package = (self.pbns_root / "PbnsPkg.dec").read_text(encoding="utf-8")
        platform = self.package_dsc.read_text(encoding="utf-8")
        core = self.core_manifest.read_text(encoding="utf-8")
        for source in (
            "qcbor_encode.c",
            "ieee754.c",
            "qcbor_decode.c",
            "qcbor_err_to_str.c",
            "UsefulBuf.c",
        ):
            self.assertEqual(manifest.count(source), 1)
        self.assertIn("USEFULBUF_DISABLE_ALL_FLOAT", manifest)
        self.assertIn("-fno-lto", manifest)
        self.assertIn("PbnsQcborLib", package)
        self.assertIn("PbnsQcborLib", platform)
        self.assertIn("PbnsQcborLib", core)

    def test_package_is_x64_debug_release_without_networkpkg(self) -> None:
        dsc = self.package_dsc.read_text(encoding="utf-8")
        probe = self.probe_inf.read_text(encoding="utf-8")
        self.assertRegex(dsc, r"(?m)^\s*SUPPORTED_ARCHITECTURES\s*=\s*X64\s*$")
        self.assertRegex(dsc, r"(?m)^\s*BUILD_TARGETS\s*=\s*DEBUG\|RELEASE\s*$")
        self.assertIn("PbnsProbe.inf", dsc)
        self.assertIn("PbnsCoreLib", probe)
        self.assertIn("PbnsUefiPlatformLib", probe)
        self.assertNotIn("NetworkPkg", dsc)
        self.assertNotIn("NetworkPkg", probe)

    def test_scripts_pin_edk2_and_emit_probe_path(self) -> None:
        bootstrap = (self.pbns_root / "tools" / "bootstrap-edk2.sh").read_text(
            encoding="utf-8"
        )
        build = (self.pbns_root / "tools" / "build-uefi.sh").read_text(
            encoding="utf-8"
        )
        for marker in (
            "b03a21a63e3bd001f52c527e5a57feddb53a690b",
            "submodule update --init --recursive",
            "submodule_status=",
            "TcgTpmPkg/Library/TpmLib/TPM/external/wolfssl",
            "BaseTools",
        ):
            self.assertIn(marker, bootstrap)
        for marker in (
            "PBNS_EDK2_DIR",
            "PACKAGES_PATH",
            "PbnsPkg.dsc",
            "PBNS_BUILD_TARGET",
            "BUILD_TARGET=${PBNS_BUILD_TARGET:-DEBUG}",
            "-a X64",
            '-b "$BUILD_TARGET"',
            "-t GCC",
            "for application in PbnsProbe PbnsIdentityProbe PbnsCoseProbe "
            "PbnsTlsProbe PbnsTime PbnsTimeLive PbnsBaseline PbnsAttest "
            "PbnsEnroll PBNSLauncher "
            "PBNSRecovery PbnsBootSetup",
            "${application}.efi",
            "GenFw",
            "-z -r",
            "UEFI BUILD PASS",
        ):
            self.assertIn(marker, build)

    def test_launcher_components_are_network_free_and_separately_configured(
        self,
    ) -> None:
        launcher = (
            self.pbns_root
            / "uefi"
            / "Applications"
            / "PBNSLauncher"
            / "PBNSLauncher.c"
        ).read_text(encoding="utf-8")
        launcher_inf = (
            self.pbns_root
            / "uefi"
            / "Applications"
            / "PBNSLauncher"
            / "PBNSLauncher.inf"
        ).read_text(encoding="utf-8")
        setup = (
            self.pbns_root
            / "uefi"
            / "Applications"
            / "PbnsBootSetup"
            / "PbnsBootSetup.c"
        ).read_text(encoding="utf-8")
        config = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsBootConfigLib"
            / "PbnsBootConfigLib.c"
        ).read_text(encoding="utf-8")
        platform = self.package_dsc.read_text(encoding="utf-8")
        for marker in (
            "pbns_launcher_run",
            "LoadImage",
            "StartImage",
            "PbnsBootConfigRead",
        ):
            self.assertIn(marker, launcher)
        for forbidden in (
            "PbnsUsb",
            "pbns_broker",
            "NetworkPkg",
            "PbnsCoreLib",
            "PbnsQcborLib",
            "Tss2MuLib",
            "TRUSTED_TIME",
            "RECOVERY_ARTIFACT",
        ):
            self.assertNotIn(forbidden, launcher)
            self.assertNotIn(forbidden, launcher_inf)
        for marker in (
            "EfiBootManagerGetLoadOptions",
            "EfiBootManagerAddLoadOptionVariable",
            "PbnsBootConfigWrite",
        ):
            self.assertIn(marker, setup)
        self.assertIn("EFI_VARIABLE_BOOTSERVICE_ACCESS", config)
        self.assertNotIn("EFI_VARIABLE_RUNTIME_ACCESS", config)
        self.assertIn("PBNSLauncher.inf", platform)
        self.assertIn("PbnsBootSetup.inf", platform)

    def test_normal_boot_fixture_emits_only_the_exact_success_marker(self) -> None:
        fixture = (
            self.pbns_root
            / "uefi"
            / "Tests"
            / "Fixtures"
            / "ReturnSuccess"
            / "ReturnSuccess.c"
        ).read_text(encoding="utf-8")
        manifest = (
            self.pbns_root
            / "uefi"
            / "Tests"
            / "Fixtures"
            / "ReturnSuccess"
            / "ReturnSuccess.inf"
        ).read_text(encoding="utf-8")
        self.assertIn('Print(L"PBNS NORMAL FIXTURE PASS\\r\\n");', fixture)
        self.assertEqual(fixture.count("PBNS NORMAL FIXTURE"), 1)
        self.assertIn("return EFI_SUCCESS;", fixture)
        self.assertIn("UefiLib", manifest)
        for forbidden in ("PbnsUsb", "pbns_broker", "SetVariable", "GetVariable"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, fixture)
                self.assertNotIn(forbidden, manifest)

    def test_recovery_application_is_ram_only_and_secureboot_gated(self) -> None:
        application_dir = (
            self.pbns_root / "uefi" / "Applications" / "PBNSRecovery"
        )
        library_dir = (
            self.pbns_root / "uefi" / "Library" / "PbnsRecoveryClientLib"
        )
        combined = "".join(
            path.read_text(encoding="utf-8")
            for path in (
                application_dir / "PBNSRecovery.c",
                application_dir / "PBNSRecovery.inf",
                library_dir / "PbnsRecoveryClientLib.c",
                library_dir / "PbnsRecoveryClientLib.h",
                library_dir / "PbnsRecoveryClientLib.inf",
            )
        )
        for required in (
            "PBNS_RECOVERY_STATE_CONFIRM",
            "PBNS_RECOVERY_STATE_TIME",
            "PBNS_RECOVERY_STATE_MANIFEST",
            "PBNS_RECOVERY_STATE_ALLOCATE",
            "PBNS_RECOVERY_STATE_STREAM",
            "PBNS_RECOVERY_STATE_DIGEST",
            "PBNS_RECOVERY_STATE_LOAD_VERIFY",
            "PBNS_RECOVERY_STATE_ADVANCE_VERSION",
            "PBNS_RECOVERY_STATE_START",
            "PBNS_RECOVERY_STATE_FAILED",
            "SecureBoot",
            "SetupMode",
            "AllocatePages",
            "EfiLoaderData",
            "LoadImage",
            "StartImage",
            "UnloadImage",
            "FreePages",
        ):
            with self.subTest(required=required):
                self.assertIn(required, combined)
        for forbidden in (
            "EFI_SIMPLE_FILE_SYSTEM_PROTOCOL",
            "FileProtocol",
            "EFI_FILE_PROTOCOL",
            "Write(",
            "SetTime",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, combined)

    def test_recovery_confirmation_terminates_valid_mode_selection(self) -> None:
        source = (
            self.pbns_root
            / "uefi"
            / "Applications"
            / "PBNSRecovery"
            / "PBNSRecovery.c"
        ).read_text(encoding="utf-8")
        confirm = source[
            source.index("static pbns_status Confirm") : source.index(
                "static pbns_status PlatformReady"
            )
        ]
        newline = 'Print(L"\\r\\n");'
        first_newline = confirm.index(newline)
        mode_branch = confirm.index("if (key.UnicodeChar == L'T'")
        acceptance = confirm.index("*Accepted = true;")
        second_newline = confirm.index(newline, mode_branch)

        self.assertEqual(confirm.count(newline), 2)
        self.assertLess(first_newline, mode_branch)
        self.assertLess(mode_branch, second_newline)
        self.assertLess(second_newline, acceptance)
        self.assertRegex(
            confirm[mode_branch:acceptance],
            re.compile(
                r"else \{\s+return PBNS_OK;\s+\}\s+"
                r'Print\(L"\\r\\n"\);\s*$',
                re.DOTALL,
            ),
        )

    def test_recovery_application_exposes_only_ordered_nonsecret_markers(
        self,
    ) -> None:
        source = (
            self.pbns_root
            / "uefi"
            / "Applications"
            / "PBNSRecovery"
            / "PBNSRecovery.c"
        ).read_text(encoding="utf-8")
        markers = tuple(re.findall(r'L"(PBNS RECOVERY [^"]*)"', source))
        for required in (
            "PBNS RECOVERY MEMORY LOAD BEGIN size=%Lu version=%Lu\\r\\n",
            "PBNS RECOVERY MEMORY LOAD PASS\\r\\n",
            "PBNS RECOVERY MEMORY LOAD REJECT status=0x%lx\\r\\n",
            "PBNS RECOVERY ROLLBACK ADVANCE BEGIN current=%Lu target=%Lu\\r\\n",
            "PBNS RECOVERY ROLLBACK ADVANCE PASS\\r\\n",
            "PBNS RECOVERY UNLOAD BEGIN\\r\\n",
            "PBNS RECOVERY UNLOAD PASS\\r\\n",
            "PBNS RECOVERY FREE BEGIN size=%Lu\\r\\n",
            "PBNS RECOVERY FREE PASS\\r\\n",
            "PBNS RECOVERY STARTIMAGE BEGIN\\r\\n",
        ):
            with self.subTest(required=required):
                self.assertIn(required, markers)
        combined = "\n".join(markers).lower()
        for forbidden in (
            "nonce",
            "digest",
            "authorization",
            "private",
            "identity",
            "request_id",
            "host_binding",
            "tpm",
            "%p",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, combined)

        verified_manifest = source[
            source.index("static pbns_status VerifiedManifest") :
            source.index("static pbns_status AllocatePages")
        ]
        load = source[
            source.index("static pbns_status LoadImage") :
            source.index("static pbns_status AdvanceVersion")
        ]
        advance = source[
            source.index("static pbns_status AdvanceVersion") :
            source.index("static pbns_status StartImage")
        ]
        start = source[
            source.index("static pbns_status StartImage") :
            source.index("static pbns_status UnloadImage")
        ]
        unload = source[
            source.index("static pbns_status UnloadImage") :
            source.index("static pbns_status FreePages")
        ]
        free_pages = source[
            source.index("static pbns_status FreePages") :
            source.index("static void StateChanged")
        ]
        self.assertIn("UINT64 TargetVersion;", source)
        self.assertLess(
            verified_manifest.index("PbnsRecoveryServiceManifest("),
            verified_manifest.index("status == PBNS_OK"),
        )
        self.assertLess(
            verified_manifest.index("status == PBNS_OK"),
            verified_manifest.index("uefi->TargetVersion = Plan->target_version"),
        )
        self.assertLess(load.index("MEMORY LOAD BEGIN"), load.index("gBS->LoadImage("))
        self.assertLess(load.index("gBS->LoadImage("), load.index("MEMORY LOAD PASS"))
        self.assertLess(load.index("gBS->LoadImage("), load.index("MEMORY LOAD REJECT"))
        self.assertLess(
            advance.index("ROLLBACK ADVANCE BEGIN"),
            advance.index("PbnsRecoveryServiceAdvanceVersion("),
        )
        self.assertLess(
            advance.index("PbnsRecoveryServiceAdvanceVersion("),
            advance.index("ROLLBACK ADVANCE PASS"),
        )
        self.assertLess(start.index("STARTIMAGE BEGIN"), start.index("gBS->StartImage("))
        self.assertLess(unload.index("UNLOAD BEGIN"), unload.index("gBS->UnloadImage("))
        self.assertLess(unload.index("gBS->UnloadImage("), unload.index("UNLOAD PASS"))
        self.assertLess(free_pages.index("FREE BEGIN"), free_pages.index("gBS->FreePages("))
        self.assertLess(free_pages.index("gBS->FreePages("), free_pages.index("FREE PASS"))

    def test_recovery_application_connects_the_selected_live_service(self) -> None:
        application_dir = (
            self.pbns_root / "uefi" / "Applications" / "PBNSRecovery"
        )
        service_dir = self.pbns_root / "uefi" / "Library" / "PbnsRecoveryServiceLib"
        source = (application_dir / "PBNSRecovery.c").read_text(encoding="utf-8")
        manifest = (application_dir / "PBNSRecovery.inf").read_text(
            encoding="utf-8"
        )
        service = (service_dir / "PbnsRecoveryServiceLib.c").read_text(
            encoding="utf-8"
        )
        normalized = re.sub(r"\s+", "", source)

        self.assertIn("PbnsRecoveryServiceLib.h", source)
        self.assertIn("PbnsRecoveryServiceLib", manifest)
        self.assertRegex(
            source,
            re.compile(
                r"typedef struct PBNS_RECOVERY_UEFI_CONTEXT \{.*?"
                r"EFI_HANDLE ImageHandle;.*?EFI_SYSTEM_TABLE \*SystemTable;.*?"
                r"PBNS_RECOVERY_SERVICE \*Service;.*?"
                r"pbns_recovery_assurance_mode Mode;.*?"
                r"UINT64 TargetVersion;.*?\} PBNS_RECOVERY_UEFI_CONTEXT;",
                re.DOTALL,
            ),
        )
        self.assertIn("Type RECOVER to download a RAM-only recovery image:", source)
        self.assertIn("Select recovery assurance: T/t or S/s:", source)
        self.assertIn("bool overflowed = false;", source)
        self.assertRegex(
            source,
            re.compile(
                r"if \(key\.UnicodeChar >= L' '\) \{.*?"
                r"length \+ 1U < ARRAY_SIZE\(entered\).*?"
                r"else \{\s*overflowed = true;\s*\}",
                re.DOTALL,
            ),
        )
        self.assertIn(
            "if(overflowed||StrCmp(entered,expected)!=0)",
            normalized,
        )
        self.assertLess(
            source.index("if (overflowed || StrCmp(entered, expected) != 0)"),
            source.index("Select recovery assurance: T/t or S/s:"),
        )
        self.assertIn("key.UnicodeChar == L'T'", source)
        self.assertIn("key.UnicodeChar == L't'", source)
        self.assertIn("key.UnicodeChar == L'S'", source)
        self.assertIn("key.UnicodeChar == L's'", source)
        self.assertIn("uefi->Mode = PBNS_RECOVERY_ASSURANCE_T", source)
        self.assertIn("uefi->Mode = PBNS_RECOVERY_ASSURANCE_S", source)
        self.assertRegex(
            source,
            re.compile(
                r"uefi->Mode = PBNS_RECOVERY_ASSURANCE_[TS];.*?\*Accepted = true;",
                re.DOTALL,
            ),
        )

        trusted_time = re.search(
            r"static pbns_status TrustedTime\(void \*Context\) \{(.*?)\n\}",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(trusted_time)
        assert trusted_time is not None
        self.assertIn("uefi->Service == NULL", trusted_time.group(1))
        self.assertEqual(source.count("PbnsRecoveryServiceCreate("), 1)
        self.assertIn(
            "PbnsRecoveryServiceCreate(uefi->SystemTable,uefi->Mode,&uefi->Service)",
            normalized,
        )
        self.assertIn("PbnsRecoveryServiceTrustedTime(uefi->Service)", normalized)
        for callback, delegate in (
            ("VerifiedManifest", "PbnsRecoveryServiceManifest(uefi->Service, Plan)"),
            ("StreamImage", "PbnsRecoveryServiceStream(uefi->Service, Image, Size)"),
            ("ReadVersion", "PbnsRecoveryServiceReadVersion(uefi->Service, Version)"),
            (
                "AdvanceVersion",
                "PbnsRecoveryServiceAdvanceVersion(uefi->Service, CurrentVersion, TargetVersion, Authorization)",
            ),
        ):
            with self.subTest(callback=callback):
                self.assertIn(re.sub(r"\s+", "", delegate), normalized)
        self.assertIn("*Plan = (PBNS_RECOVERY_PLAN){0};", source)
        self.assertIn("*Version = 0U;", source)
        self.assertNotIn("PBNS_ERR_UNIMPLEMENTED", source + service)
        for forbidden in (
            "EFI_SIMPLE_FILE_SYSTEM_PROTOCOL",
            "EFI_FILE_PROTOCOL",
            "FileProtocol",
            "Write(",
            "socket",
            "Tcp",
            "Tls",
            "TpmInitialize",
            "TpmClear",
            "EFI_VARIABLE_RUNTIME_ACCESS",
            "PBNS_RECOVERY_ASSURANCE_T ? PBNS_RECOVERY_ASSURANCE_S",
            "PBNS_RECOVERY_ASSURANCE_S ? PBNS_RECOVERY_ASSURANCE_T",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source + service)

        run_index = source.index("PbnsRecoveryClientRun(&ops, &context, &result)")
        destroy_index = source.index("PbnsRecoveryServiceDestroy(context.Service)")
        self.assertLess(run_index, destroy_index)
        self.assertIn("context = (PBNS_RECOVERY_UEFI_CONTEXT){0};", source)
        self.assertIn("result = (PBNS_RECOVERY_CLIENT_RESULT){0};", source)
        self.assertIn(
            "LoadImage(FALSE,uefi->ImageHandle,NULL,Image.ptr,Image.len,&handle)",
            normalized,
        )

    def test_anti_rollback_tss2_policy_profile(self) -> None:
        directory = (
            self.pbns_root / "uefi" / "Library" / "PbnsAntiRollbackLib"
        )
        tpm_path = directory / "PbnsAntiRollbackTpm.c"
        wire_path = directory / "PbnsRecoveryPolicyWire.c"
        self.assertTrue(tpm_path.is_file())
        self.assertTrue(wire_path.is_file())
        tpm = tpm_path.read_text(encoding="utf-8")
        wire = wire_path.read_text(encoding="utf-8")
        manifest = (directory / "PbnsAntiRollbackLib.inf").read_text(
            encoding="utf-8"
        )
        sys_manifest = self.tss2_sys_manifest.read_text(encoding="utf-8")
        identity = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsTpmIdentityLib"
            / "PbnsTpmIdentityLib.c"
        ).read_text(encoding="utf-8")
        for marker in (
            "Tss2_Sys_StartAuthSession",
            "Tss2_Sys_PolicyNvWritten",
            "Tss2_Sys_PolicyNV",
            "Tss2_Sys_PolicyCpHash",
            "Tss2_Sys_LoadExternal",
            "Tss2_Sys_VerifySignature",
            "Tss2_Sys_PolicyAuthorize",
            "Tss2_Sys_NV_Write_Prepare",
            "Tss2_Sys_GetCpBuffer",
            "Tss2_Sys_NV_Write",
            "Tss2_Sys_NV_Read",
            "Tss2_Sys_NV_ReadPublic",
            "Tss2_Sys_FlushContext",
        ):
            self.assertIn(marker, tpm + sys_manifest)
        self.assertRegex(
            tpm,
            re.compile(
                r"Tss2_Sys_LoadExternal\(.*?TPM2_RH_OWNER", re.DOTALL
            ),
        )
        for source in (
            "Tss2_Sys_LoadExternal.c",
            "Tss2_Sys_PolicyNvWritten.c",
            "Tss2_Sys_VerifySignature.c",
        ):
            self.assertEqual(sys_manifest.count(source), 1)
        for marker in (
            "PBNS-RECOVERY-POLICY-INIT-v1",
            "PBNS-RECOVERY-POLICY-UPDATE-v1",
            "Tss2_MU_TPM2B_PUBLIC_Unmarshal",
            "Tss2_MU_TPMT_SIGNATURE_Unmarshal",
            "QCBORDecode_Finish",
        ):
            self.assertIn(marker, wire)
        for forbidden in (
            "Esys_",
            "Fapi_",
            "Tpm2CommandLib",
            "IndustryStandard/Tpm20.h",
            "/dev/tpm",
            "socket(",
            "TPM2_ST_SESSIONS",
            "Tss2_TctiLdr",
            "NV_Undefine",
        ):
            self.assertNotIn(forbidden, tpm + wire + manifest)
        self.assertNotIn("ensure_nv_index", identity)
        self.assertNotIn("PbnsTpmRecoveryPolicyDigest", identity)

    def test_anti_rollback_nvram_profile(self) -> None:
        directory = (
            self.pbns_root / "uefi" / "Library" / "PbnsAntiRollbackLib"
        )
        self.assertTrue(directory.is_dir())
        source = (directory / "PbnsAntiRollbackNvram.c").read_text(
            encoding="utf-8"
        )
        header = (directory / "PbnsAntiRollbackLib.h").read_text(
            encoding="utf-8"
        )
        manifest = (directory / "PbnsAntiRollbackLib.inf").read_text(
            encoding="utf-8"
        )
        package = (self.pbns_root / "PbnsPkg.dec").read_text(encoding="utf-8")
        platform = self.package_dsc.read_text(encoding="utf-8")
        for marker in (
            "PbnsRecoveryVersion0",
            "PbnsRecoveryVersion1",
            "gPbnsAntiRollbackVariableGuid",
            "EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS",
            "PBNS_ANTI_ROLLBACK_RECORD_SIZE",
            "PbnsAntiRollbackNvramController",
            "GetVariable",
            "SetVariable",
        ):
            self.assertIn(marker, source + header + manifest + package + platform)
        self.assertIn("UefiRuntimeServicesTableLib", manifest)
        self.assertIn("PbnsCoreLib", manifest)
        for forbidden in (
            "EFI_VARIABLE_RUNTIME_ACCESS",
            "AllocatePool",
            "FreePool",
            "Tss2_",
            "Print(",
            "DEBUG(",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("PbnsAntiRollbackLib.inf", platform)

    def test_platform_adapter_owns_only_explicit_pool_allocations(self) -> None:
        header = (
            self.pbns_root / "include" / "Library" / "PbnsUefiPlatformLib.h"
        ).read_text(encoding="utf-8")
        source = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsUefiPlatformLib"
            / "PbnsUefiPlatformLib.c"
        ).read_text(encoding="utf-8")
        manifest = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsUefiPlatformLib"
            / "PbnsUefiPlatformLib.inf"
        ).read_text(encoding="utf-8")
        for marker in ("PbnsUefiAllocatePool", "PbnsUefiFreePool"):
            self.assertIn(marker, header)
            self.assertIn(marker, source)
        self.assertIn("AllocatePool", source)
        self.assertIn("FreePool", source)
        self.assertIn("GetRandomNumber128", source)
        self.assertIn("ZeroMem (RequestId", source)
        self.assertIn("PbnsUefiMonotonicMs", header)
        self.assertIn("EFI_CPU_ARCH_PROTOCOL", source)
        self.assertIn("PbnsUefiClockMath.c", manifest)
        self.assertIn("gEfiCpuArchProtocolGuid", manifest)
        self.assertIn("MemoryAllocationLib", manifest)

    def test_uefi_clock_uses_cpu_arch_protocol_without_timerlib(self) -> None:
        platform_source = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsUefiPlatformLib"
            / "PbnsUefiPlatformLib.c"
        ).read_text(encoding="utf-8")
        platform_manifest = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsUefiPlatformLib"
            / "PbnsUefiPlatformLib.inf"
        ).read_text(encoding="utf-8")
        usb_shim = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsUsbTransportLib"
            / "PbnsUsbIoShim.c"
        ).read_text(encoding="utf-8")
        usb_manifest = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsUsbTransportLib"
            / "PbnsUsbTransportLib.inf"
        ).read_text(encoding="utf-8")
        probe = (
            self.pbns_root / "uefi" / "Applications" / "PbnsProbe" / "PbnsProbe.c"
        ).read_text(encoding="utf-8")
        package = self.package_dsc.read_text(encoding="utf-8")

        for marker in (
            "EFI_CPU_ARCH_PROTOCOL",
            "gEfiCpuArchProtocolGuid",
            "LocateProtocol",
            "GetTimerValue",
            "PbnsUefiClockMath.h",
        ):
            self.assertIn(marker, platform_source + platform_manifest)
        self.assertIn("PbnsUefiClockMath.c", platform_manifest)
        self.assertIn("PbnsUefiMonotonicMs", usb_shim)
        self.assertIn("PbnsUefiPlatformLib", usb_manifest)
        self.assertIn("SystemTable->BootServices", probe)
        for forbidden in (
            "GetPerformanceCounter",
            "GetPerformanceCounterProperties",
            "GetTimeInNanoSecond",
            "BaseCpuTimerLib",
            "TimerLib",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(
                    forbidden,
                    platform_source
                    + platform_manifest
                    + usb_shim
                    + usb_manifest
                    + package,
                )

    def test_usb_transport_targets_only_the_verified_cdc0_interface(self) -> None:
        header = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsUsbTransportLib"
            / "PbnsUsbIoShim.h"
        ).read_text(encoding="utf-8")
        source = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsUsbTransportLib"
            / "PbnsUsbTransportLib.c"
        ).read_text(encoding="utf-8")
        shim = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsUsbTransportLib"
            / "PbnsUsbIoShim.c"
        ).read_text(encoding="utf-8")
        probe = self.probe_inf.read_text(encoding="utf-8")
        for marker in (
            "PBNS_USB_VENDOR_ID",
            "PBNS_USB_PRODUCT_ID",
            "PBNS_USB_CDC_CONTROL_INTERFACE UINT8_C(0)",
            "PBNS_USB_CDC_DATA_INTERFACE UINT8_C(1)",
            "PBNS_USB_CDC_DATA_CLASS",
            "PBNS_USB_ENDPOINT_TRANSFER_BULK",
        ):
            self.assertIn(marker, header)
        self.assertIn("PBNS Proxy v1", source)
        self.assertIn("PBNS_ERR_AMBIGUOUS", source)
        self.assertIn("HandleProtocol", shim)
        self.assertIn("PBNS_USB_CDC_SET_CONTROL_LINE_STATE", shim)
        self.assertIn("PBNS_USB_CONTROL_TIMEOUT_MS", shim)
        self.assertIn("PbnsUsbTransportLib", probe)
        for forbidden in ("NetworkPkg", "BootOrder", "SetVariable"):
            self.assertNotIn(forbidden, source)
            self.assertNotIn(forbidden, shim)

    def test_identity_record_codec_is_bounded_and_fieldwise(self) -> None:
        source = (self.identity_dir / "PbnsIdentityRecord.c").read_text(
            encoding="utf-8"
        )
        header = (self.identity_dir / "PbnsIdentityRecord.h").read_text(
            encoding="utf-8"
        )
        for bound in (
            "PBNS_IDENTITY_PRIVATE_DER_MAX 512U",
            "PBNS_IDENTITY_PUBLIC_COSE_MAX 128U",
            "PBNS_IDENTITY_FINGERPRINT_SIZE 32U",
            "PBNS_IDENTITY_RECORD_HEADER_SIZE 24U",
        ):
            self.assertIn(bound, header)
        self.assertIn("uint8_t crc_input[PBNS_IDENTITY_RECORD_MAX_SIZE]", source)
        self.assertIn("store_u16", source)
        self.assertIn("store_u32", source)
        self.assertIn("load_u16", source)
        self.assertIn("load_u32", source)
        for forbidden in (
            "AllocatePool",
            "malloc(",
            "calloc(",
            "realloc(",
            "#pragma pack",
            "__attribute__((packed))",
            "memcpy(output.ptr, &",
        ):
            self.assertNotIn(forbidden, source)

    def test_software_identity_uses_pinned_mbedtls_and_boot_service_storage(self) -> None:
        manifest = (self.identity_dir / "PbnsIdentityLib.inf").read_text(
            encoding="utf-8"
        )
        backend = (self.identity_dir / "PbnsSoftwareIdentity.c").read_text(
            encoding="utf-8"
        )
        adapter = (self.identity_dir / "PbnsIdentityLib.c").read_text(
            encoding="utf-8"
        )
        platform = self.package_dsc.read_text(encoding="utf-8")
        package = (self.pbns_root / "PbnsPkg.dec").read_text(encoding="utf-8")
        for source in (
            "PbnsIdentityLib.c",
            "PbnsIdentityRecord.c",
            "PbnsRandomPolicy.c",
            "PbnsRandomUefi.c",
            "PbnsSoftwareIdentity.c",
        ):
            self.assertEqual(manifest.count(source), 1)
        self.assertIn("MbedTlsLib", manifest)
        self.assertIn(
            "MbedTlsLib|CryptoPkg/Library/MbedTlsLib/MbedTlsLibFull.inf",
            platform,
        )
        self.assertIn("gPbnsSoftwareIdentityVariableGuid", package)
        for marker in (
            "mbedtls_pk_setup",
            "mbedtls_ecp_gen_key",
            "mbedtls_pk_write_key_der",
            "mbedtls_pk_parse_key",
            "mbedtls_mpi_write_binary",
            "mbedtls_pk_sign",
            "mbedtls_pk_free",
            "mbedtls_sha256",
            "QCBOREncode_AddInt64ToMapN",
            "pbns_identity_record_encode",
            "pbns_identity_record_decode",
            "constant_time_equal(readback, encoded, encoded_length)",
            "secure_zero",
        ):
            self.assertIn(marker, backend)
        self.assertIn('L"PbnsSoftwareIdentity"', adapter)
        self.assertIn("54f8998a", package)
        self.assertIn("EFI_VARIABLE_NON_VOLATILE", adapter)
        self.assertIn("EFI_VARIABLE_BOOTSERVICE_ACCESS", adapter)
        self.assertIn("attributes != PBNS_IDENTITY_VARIABLE_ATTRIBUTES", backend)
        for cose_marker in (
            "&encoder, 1, 2",
            "&encoder, -1, 1",
            "&encoder, -2",
            "&encoder, -3",
        ):
            self.assertIn(cose_marker, backend)
        open_implementation = backend.split(
            "pbns_status pbns_software_identity_open", 1
        )[1]
        self.assertNotIn("pbns_software_identity_create", open_implementation)
        combined = manifest + backend + adapter
        for forbidden in (
            "BaseCryptLib",
            "EcNewByNid",
            "EcGenerateKey",
            "RngLib|",
            "OpenSSL",
            "openssl/",
            "mbedtls_entropy",
            "EFI_VARIABLE_RUNTIME_ACCESS",
            "DEBUG(",
            "Print(",
        ):
            self.assertNotIn(forbidden, combined)

    def test_identity_rng_has_strict_approved_source_priority(self) -> None:
        uefi = (self.identity_dir / "PbnsRandomUefi.c").read_text(encoding="utf-8")
        policy = (self.identity_dir / "PbnsRandomPolicy.c").read_text(
            encoding="utf-8"
        )
        for marker in (
            "EFI_RNG_PROTOCOL",
            "gEfiRngProtocolGuid",
            "LocateProtocol",
            "GetRNG",
            "PBNS_TPM_RANDOM_SOURCE",
            "tpm_source_fill",
        ):
            self.assertIn(marker, uefi)
        self.assertLess(uefi.index("LocateProtocol"), uefi.index("GetRNG"))
        self.assertLess(uefi.index("GetRNG"), uefi.index("tpm_source_fill"))
        self.assertIn("PBNS_ERR_UNSUPPORTED", policy)
        self.assertIn("PBNS_ERR_ENTROPY", policy)
        self.assertIn("memset(output.ptr, 0, output.cap)", policy)
        combined = uefi + policy
        for forbidden in (
            "GetTime",
            "GetPerformanceCounter",
            "RDTSC",
            "MAC",
            "Serial",
            "RandomSeed",
            "mbedtls_entropy",
            "PbnsSoftwareIdentityCreate",
            "EFI_VARIABLE_RUNTIME_ACCESS",
        ):
            self.assertNotIn(forbidden, combined)

    def test_tcose_adapter_is_pinned_bounded_and_identity_backed(self) -> None:
        manifest = self.tcose_manifest.read_text(encoding="utf-8")
        adapter_manifest = (self.cose_adapter_dir / "PbnsCoseCryptoLib.inf").read_text(
            encoding="utf-8"
        )
        adapter = (self.cose_adapter_dir / "PbnsTcoseCrypto.c").read_text(
            encoding="utf-8"
        )
        wrapper = (self.cose_adapter_dir / "PbnsCoseCryptoLib.c").read_text(
            encoding="utf-8"
        )
        expected_sources = {
            "t_cose_sign1_sign.c",
            "t_cose_parameters.c",
            "t_cose_sign1_verify.c",
            "t_cose_util.c",
            "t_cose_key.c",
            "t_cose_sign_sign.c",
            "t_cose_signature_sign_main.c",
            "t_cose_signature_sign_eddsa.c",
            "t_cose_sign_verify.c",
            "t_cose_signature_verify_main.c",
            "t_cose_signature_verify_eddsa.c",
            "t_cose_encrypt_enc.c",
            "t_cose_encrypt_dec.c",
            "t_cose_recipient_dec_keywrap.c",
            "t_cose_recipient_enc_keywrap.c",
            "t_cose_recipient_dec_esdh.c",
            "t_cose_recipient_enc_esdh.c",
            "t_cose_qcbor_gap.c",
            "t_cose_private.c",
        }
        for source in expected_sources:
            with self.subTest(source=source):
                self.assertEqual(manifest.count(source), 1)
        self.assertEqual(manifest.count(".c"), len(expected_sources))
        for marker in (
            "T_COSE_DISABLE_ES384",
            "T_COSE_DISABLE_ES512",
            "T_COSE_DISABLE_PS256",
            "T_COSE_DISABLE_COSE_SIGN",
            "-fno-lto",
        ):
            self.assertIn(marker, manifest + adapter_manifest)
        for marker in (
            "pbns_identity_sign",
            "mbedtls_ecp_point_read_binary",
            "mbedtls_ecdsa_verify",
            "mbedtls_sha256_starts",
            "mbedtls_sha256_update",
            "mbedtls_sha256_finish",
            "AllocateZeroPool",
            "FreePool",
        ):
            self.assertIn(marker, adapter)
        for marker in (
            "t_cose_sign1_sign_aad",
            "t_cose_sign1_verify_aad",
            "pbns_cose_key_from_identity",
            "pbns_cose_key_from_p256_public",
        ):
            self.assertIn(marker, wrapper)
        combined = manifest + adapter_manifest + adapter + wrapper
        for forbidden in (
            "OpenSSL",
            "openssl/",
            "EcGenerateKey",
            "mbedtls_pk_write_key",
            "mbedtls_mpi_exp_mod",
            "mbedtls_mpi_mul_mpi",
            "RandomSeed",
        ):
            self.assertNotIn(forbidden, combined)
        package = (self.pbns_root / "PbnsPkg.dec").read_text(encoding="utf-8")
        platform = self.package_dsc.read_text(encoding="utf-8")
        for library in ("PbnsTCoseLib", "PbnsCoseCryptoLib"):
            self.assertIn(library, package)
            self.assertIn(library, platform)
        self.assertIn("PbnsCoseProbe.inf", platform)

    def test_tcose_encryption_adapter_maps_every_required_primitive(self) -> None:
        manifest = self.tcose_manifest.read_text(encoding="utf-8")
        adapter_manifest = (self.cose_adapter_dir / "PbnsCoseCryptoLib.inf").read_text(
            encoding="utf-8"
        )
        adapter = (self.cose_adapter_dir / "PbnsTcoseCrypto.c").read_text(
            encoding="utf-8"
        )
        wrapper = (self.cose_adapter_dir / "PbnsCoseCryptoLib.c").read_text(
            encoding="utf-8"
        )
        header = (
            self.pbns_root / "include" / "Library" / "PbnsCoseCryptoLib.h"
        ).read_text(encoding="utf-8")
        for source in (
            "t_cose_encrypt_enc.c",
            "t_cose_encrypt_dec.c",
            "t_cose_recipient_enc_esdh.c",
            "t_cose_recipient_dec_esdh.c",
            "t_cose_recipient_enc_keywrap.c",
            "t_cose_recipient_dec_keywrap.c",
        ):
            with self.subTest(source=source):
                self.assertEqual(manifest.count(source), 1)
        self.assertNotIn("T_COSE_DISABLE_KEYWRAP", manifest + adapter_manifest)
        self.assertIn("build/uefi-t-cose/src", manifest + adapter_manifest)
        self.assertNotIn("vendor/t_cose/src", manifest + adapter_manifest)
        preparation = (self.pbns_root / "tools" / "build-uefi.sh").read_text(
            encoding="utf-8"
        )
        zero_patch = (
            self.pbns_root
            / "patches"
            / "t_cose"
            / "0002-zero-transient-encryption-material.patch"
        ).read_text(encoding="utf-8")
        for marker in (
            "0002-zero-transient-encryption-material.patch",
            "PrepareTCose.cmake",
            "t_cose_crypto_secure_zero(cek_buffer)",
        ):
            self.assertIn(marker, preparation + zero_patch)
        for marker in (
            "t_cose_crypto_secure_zero(derived_key_buf)",
            "t_cose_crypto_secure_zero(derived_secret_buf)",
            "t_cose_crypto_secure_zero(kek_buf)",
            "t_cose_crypto_secure_zero(kek_buffer)",
        ):
            self.assertIn(marker, zero_patch)
        platform = self.package_dsc.read_text(encoding="utf-8")
        self.assertIn("MbedTlsLibFull.inf", platform)
        self.assertIn("MBEDTLS_NIST_KW_C", platform)
        self.assertIn("-flto-partition=one", platform)
        for backend in (
            "pbns_identity_random",
            "mbedtls_ecp_gen_key",
            "mbedtls_ecdh_compute_shared",
            "mbedtls_hkdf",
            "mbedtls_nist_kw_wrap",
            "mbedtls_nist_kw_unwrap",
            "mbedtls_gcm_crypt_and_tag",
            "mbedtls_gcm_auth_decrypt",
        ):
            with self.subTest(backend=backend):
                self.assertIn(backend, adapter)
        for operation in (
            "t_cose_crypto_generate_ec_key",
            "t_cose_crypto_get_random",
            "t_cose_crypto_ecdh",
            "t_cose_crypto_hkdf",
            "t_cose_crypto_kw_wrap",
            "t_cose_crypto_kw_unwrap",
            "t_cose_crypto_aead_encrypt",
            "t_cose_crypto_aead_decrypt",
        ):
            with self.subTest(operation=operation):
                self.assertIn(operation, adapter)
        for public_api in (
            "pbns_cose_p256_key_generate",
            "pbns_cose_p256_key_export_public",
            "pbns_cose_uefi_encrypt_for_recipient",
            "pbns_cose_uefi_decrypt_for_recipient",
        ):
            with self.subTest(public_api=public_api):
                self.assertIn(public_api, header)
                self.assertIn(public_api, wrapper + adapter)
        for forbidden in (
            "mbedtls_mpi_exp_mod",
            "mbedtls_mpi_mul_mpi",
            "mbedtls_entropy",
            "RandomSeed",
        ):
            self.assertNotIn(forbidden, adapter + wrapper)

    def test_enrollment_baseline_uses_tcg2_and_tss2_without_raw_platform_ids(self) -> None:
        measured = self.pbns_root / "uefi" / "Library" / "PbnsMeasuredBootLib"
        baseline = self.pbns_root / "uefi" / "Library" / "PbnsEnrollmentBaselineLib"
        probe = self.pbns_root / "uefi" / "Applications" / "PbnsBaseline"
        tpm = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsTpmIdentityLib"
            / "PbnsTpmIdentityLib.c"
        ).read_text(encoding="utf-8")
        combined = "".join(
            path.read_text(encoding="utf-8")
            for path in (
                measured / "PbnsMeasuredBootLib.c",
                measured / "PbnsMeasuredBootUefiAdapter.c",
                measured / "PbnsMeasuredBootLib.inf",
                baseline / "PbnsEnrollmentBaselineLib.c",
                baseline / "PbnsEnrollmentBaselineLib.inf",
                probe / "PbnsBaseline.c",
                probe / "PbnsBaseline.inf",
            )
        )
        for marker in (
            "EFI_TCG2_PROTOCOL",
            "GetEventLog",
            "EFI_TCG2_EVENT_LOG_FORMAT_TCG_2",
            "pbns_measured_boot_locate_event_log_end",
            "PbnsTpmReadBaselinePcrs",
            "Tpm2PcrRead",
            "pbns_enrollment_baseline_encode",
            "PBNS UEFI VARIABLE ABSENT V1",
            "PBNS UEFI VARIABLE PRESENT V1",
            "status == EFI_NOT_FOUND",
            "status != EFI_BUFFER_TOO_SMALL",
            "EFI_ERROR(status)",
            "ZeroMem(scratch.ptr",
            "mbedtls_sha256",
            "PbnsUefiMonotonicMs",
            "EventLogCaptureMs",
            "HashingMs",
            "PcrReadMs",
            "EncodingMs",
            "PBNS BASELINE SOFTWARE CHECKPOINT PASS",
        ):
            self.assertIn(marker, combined + tpm)
        self.assertIn("Tss2_Sys_PCR_Read", tpm)
        for forbidden in (
            "GetPerformanceCounter",
            "GetTimeInNanoSecond",
            "SerialNumber",
            "SystemUuid",
            "MacAddress",
        ):
            self.assertNotIn(forbidden, combined + tpm)
        platform = self.package_dsc.read_text(encoding="utf-8")
        self.assertIn("PbnsBaseline.inf", platform)

    def test_tpm_enrollment_reports_bounded_activation_and_certification_results(
        self,
    ) -> None:
        application = (
            self.pbns_root
            / "uefi"
            / "Applications"
            / "PbnsEnroll"
            / "PbnsEnroll.c"
        ).read_text(encoding="utf-8")
        library = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsTpmIdentityLib"
            / "PbnsTpmIdentityLib.c"
        ).read_text(encoding="utf-8")
        header = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsTpmIdentityLib"
            / "PbnsTpmIdentityLib.h"
        ).read_text(encoding="utf-8")
        for marker in (
            "PBNS ENROLL TPM ACTIVATION CHECKPOINT PASS",
            "PBNS ENROLL FAIL TPM activation status=%r command=0x%08x",
            "PBNS ENROLL TPM CERTIFICATION CHECKPOINT PASS",
            "PBNS ENROLL FAIL TPM certification status=%r command=0x%08x",
        ):
            self.assertIn(marker, application)
        self.assertIn("UINT32 *CommandResult", header)
        self.assertGreaterEqual(library.count("*CommandResult = (UINT32)rc;"), 2)
        for marker in (
            "PBNS_TPM_COMMAND_RETRY_LIMIT",
            "pbns_tpm_command_retryable",
            "gBS->Stall",
        ):
            self.assertIn(marker, library)
        self.assertGreaterEqual(library.count("retry_command_after_delay"), 5)

    def test_tpm_activation_unmarshals_complete_tpm2b_objects_with_tss2_mu(self) -> None:
        source = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsTpmIdentityLib"
            / "PbnsTpmIdentityLib.c"
        ).read_text(encoding="utf-8")
        for marker in (
            "Tss2_MU_TPM2B_ID_OBJECT_Unmarshal",
            "Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal",
            "credential_offset != CredentialBlob.len",
            "secret_offset != Secret.len",
        ):
            self.assertIn(marker, source)

    def test_trusted_time_client_uses_signed_objects_and_cpu_timer_only(self) -> None:
        source = (
            self.pbns_root
            / "uefi"
            / "Library"
            / "PbnsTrustedTimeLib"
            / "PbnsTrustedTimeLib.c"
        ).read_text(encoding="utf-8")
        probe = (
            self.pbns_root / "uefi" / "Applications" / "PbnsTime" / "PbnsTime.c"
        ).read_text(encoding="utf-8")
        live = (
            self.pbns_root
            / "uefi"
            / "Applications"
            / "PbnsTimeLive"
            / "PbnsTimeLive.c"
        ).read_text(encoding="utf-8")
        self.assertIn("#define PBNS_TIME_LIVE_MAX_RTT_MS 20000U", live)
        vector = json.loads(
            (self.pbns_root / "tests" / "vectors" / "trusted-time-v1.json").read_text(
                encoding="utf-8"
            )
        )
        match = re.search(
            r"static const uint8_t TIME_VECTOR_COSE\[245\] = \{(.*?)\};",
            probe,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        assert match is not None
        embedded = bytes(
            int(value, 16) for value in re.findall(r"0x([0-9a-fA-F]{2})U", match.group(1))
        )
        self.assertEqual(embedded.hex(), vector["cose_sign1_hex"])
        for marker in (
            "pbns_identity_random",
            "pbns_cose_uefi_sign1_sign",
            "pbns_broker_request",
            "PBNS_SERVICE_TRUSTED_TIME",
            "pbns_cose_uefi_sign1_verify",
            "PbnsUefiMonotonicMs",
            "PbnsTrustedTimeClientInit",
        ):
            self.assertIn(marker, source)
        for marker in (
            "pbns_trusted_time_query",
            "PbnsTrustedTimeClientInit",
            "PBNS TRUSTED TIME INTERVAL PASS",
            "PbnsUefiMonotonicMs",
        ):
            self.assertIn(marker, probe)
        combined = source + probe + self.package_dsc.read_text(encoding="utf-8")
        for forbidden in (
            "SetTime",
            "gRT->SetTime",
            "GetPerformanceCounter",
            "GetPerformanceCounterProperties",
            "GetTimeInNanoSecond",
            "BaseCpuTimerLib",
            "TimerLib",
        ):
            self.assertNotIn(forbidden, combined)

    def test_tss2_firmware_manifests_are_audited_and_bounded(self) -> None:
        mu = self.tss2_mu_manifest.read_text(encoding="utf-8")
        sys = self.tss2_sys_manifest.read_text(encoding="utf-8")
        expected_mu = {
            "base-types.c",
            "tpm2b-types.c",
            "tpma-types.c",
            "tpml-types.c",
            "tpms-types.c",
            "tpmt-types.c",
            "tpmu-types.c",
        }
        expected_sys = {
            "sysapi_util.c",
            "Tss2_Sys_GetContextSize.c",
            "Tss2_Sys_GetCpBuffer.c",
            "Tss2_Sys_Initialize.c",
            "Tss2_Sys_Finalize.c",
            "Tss2_Sys_Execute.c",
            "Tss2_Sys_SetCmdAuths.c",
            "Tss2_Sys_GetRspAuths.c",
            "Tss2_Sys_CreatePrimary.c",
            "Tss2_Sys_Create.c",
            "Tss2_Sys_Load.c",
            "Tss2_Sys_LoadExternal.c",
            "Tss2_Sys_Sign.c",
            "Tss2_Sys_Certify.c",
            "Tss2_Sys_ActivateCredential.c",
            "Tss2_Sys_GetRandom.c",
            "Tss2_Sys_GetCapability.c",
            "Tss2_Sys_ReadPublic.c",
            "Tss2_Sys_FlushContext.c",
            "Tss2_Sys_NV_DefineSpace.c",
            "Tss2_Sys_NV_ReadPublic.c",
            "Tss2_Sys_NV_Read.c",
            "Tss2_Sys_NV_UndefineSpace.c",
            "Tss2_Sys_NV_Write.c",
            "Tss2_Sys_PCR_Read.c",
            "Tss2_Sys_Quote.c",
            "Tss2_Sys_PolicyAuthorize.c",
            "Tss2_Sys_PolicyCpHash.c",
            "Tss2_Sys_PolicyNV.c",
            "Tss2_Sys_PolicyNvWritten.c",
            "Tss2_Sys_StartAuthSession.c",
            "Tss2_Sys_VerifySignature.c",
        }
        for source in expected_mu:
            with self.subTest(mu_source=source):
                self.assertEqual(mu.count(source), 1)
        for source in expected_sys:
            with self.subTest(sys_source=source):
                self.assertEqual(sys.count(source), 1)
        self.assertEqual(mu.count(".c"), len(expected_mu))
        self.assertEqual(sys.count(".c"), len(expected_sys))
        combined = mu + sys
        for required in (
            "MAXLOGLEVEL=0",
            "-U__linux__",
            "-U__unix__",
            ".deps/tpm2-tss",
        ):
            self.assertIn(required, combined)
        compat_log = (
            self.pbns_root
            / "uefi"
            / "ThirdParty"
            / "Tss2Compat"
            / "util"
            / "log.h"
        ).read_text(encoding="utf-8")
        for macro in ("LOG_ERROR", "LOG_WARNING", "LOG_DEBUG", "LOGBLOB_ERROR"):
            self.assertIn(macro, compat_log)
        for forbidden in (
            "tss2-esys",
            "tss2-fapi",
            "tss2-tcti-device",
            "tss2-tcti-swtpm",
            "dlopen",
            "pkg-config",
            "socket",
            "unistd",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, combined.lower())
        package = (self.pbns_root / "PbnsPkg.dec").read_text(encoding="utf-8")
        platform = self.package_dsc.read_text(encoding="utf-8")
        for library in ("Tss2MuLib", "Tss2SysLib"):
            self.assertIn(library, package)
            self.assertIn(library, platform)

    def test_no_project_translation_unit_mixes_edk_and_tss_tpm_types(self) -> None:
        for path in self.pbns_root.rglob("*"):
            if path.suffix not in {".c", ".h"}:
                continue
            if any(part in {".deps", "build", "vendor"} for part in path.parts):
                continue
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.relative_to(self.pbns_root)):
                self.assertFalse(
                    "IndustryStandard/Tpm20.h" in text
                    and "tss2_tpm2_types.h" in text
                )

    def test_project_does_not_implement_tpm_command_wire_format(self) -> None:
        marshal_allowlist = {
            pathlib.Path("src/core/tpm_profile.c"),
            pathlib.Path("tests/hosted/test_tpm_policy.c"),
            pathlib.Path("uefi/Library/PbnsAntiRollbackLib/PbnsAntiRollbackTpm.c"),
            pathlib.Path("uefi/Library/PbnsAntiRollbackLib/PbnsRecoveryPolicyWire.c"),
            pathlib.Path("uefi/Library/PbnsRecoveryServiceLib/PbnsRecoveryRollbackUefi.c"),
        }
        policy_digest_allowlist = {
            pathlib.Path("uefi/Library/PbnsAntiRollbackLib/PbnsAntiRollbackTpm.c")
        }
        for path in self.pbns_root.rglob("*"):
            if path.suffix not in {".c", ".h"}:
                continue
            if any(part in {".deps", "build", "vendor"} for part in path.parts):
                continue
            relative = path.relative_to(self.pbns_root)
            text = path.read_text(encoding="utf-8")
            if "Tss2_MU_" in text and "_Marshal" in text:
                self.assertIn(relative, marshal_allowlist)
            if relative not in policy_digest_allowlist:
                self.assertNotRegex(text, r"TPM2_CC_[A-Za-z0-9_]+")

    def test_tpm_identity_backend_is_opaque_and_boot_service_only(self) -> None:
        tcti_dir = self.pbns_root / "uefi" / "Library" / "PbnsTss2TctiLib"
        identity_dir = self.pbns_root / "uefi" / "Library" / "PbnsTpmIdentityLib"
        submit = (tcti_dir / "PbnsTpmSubmitUefi.c").read_text(encoding="utf-8")
        tcti = (tcti_dir / "PbnsTss2Tcti.c").read_text(encoding="utf-8")
        backend = (identity_dir / "PbnsTpmIdentityLib.c").read_text(
            encoding="utf-8"
        )
        uefi = (identity_dir / "PbnsTpmIdentityUefi.c").read_text(
            encoding="utf-8"
        )
        storage = (identity_dir / "PbnsTpmStorage.c").read_text(
            encoding="utf-8"
        )
        policy = (identity_dir / "PbnsTpmPolicy.c").read_text(encoding="utf-8")
        manifest = (identity_dir / "PbnsTpmIdentityLib.inf").read_text(
            encoding="utf-8"
        )
        probe = (
            self.pbns_root
            / "uefi"
            / "Applications"
            / "PbnsIdentityProbe"
            / "PbnsIdentityProbe.c"
        ).read_text(encoding="utf-8")
        self.assertIn("EFI_TCG2_PROTOCOL", submit)
        self.assertIn("SubmitCommand", submit)
        self.assertNotIn("tss2_", submit.lower())
        tcti_header = (tcti_dir / "PbnsTss2Tcti.h").read_text(encoding="utf-8")
        self.assertIn("tss2_tcti.h", tcti + tcti_header)
        self.assertNotIn("Tcg2Protocol.h", tcti)
        for command in (
            "Tss2_Sys_Initialize",
            "Tss2_Sys_CreatePrimary",
            "Tss2_Sys_Create",
            "Tss2_Sys_Load",
            "Tss2_Sys_ReadPublic",
            "Tss2_Sys_Sign",
            "Tss2_Sys_Certify",
            "Tss2_Sys_ActivateCredential",
            "Tss2_Sys_GetRandom",
            "Tss2_Sys_FlushContext",
        ):
            self.assertIn(command, backend + policy)
        combined = submit + tcti + backend + uefi + storage + policy + manifest
        for forbidden in (
            "PbnsSoftwareIdentityCreate",
            "EFI_VARIABLE_RUNTIME_ACCESS",
            "DEBUG(",
            "Print(",
            "TPM2_CC_",
        ):
            self.assertNotIn(forbidden, combined)
        self.assertIn("PBNS_TPM_STORAGE_VARIABLE_ATTRIBUTES", uefi)
        self.assertIn("attributes != PBNS_TPM_STORAGE_VARIABLE_ATTRIBUTES", uefi)
        self.assertIn("PbnsTpmIdentityCreate", probe)
        self.assertIn("PbnsTpmIdentityOpen", probe)
        self.assertIn("PbnsTpmIdentityReset", probe)
        for library in ("PbnsTss2TctiLib", "PbnsTpmIdentityLib"):
            self.assertIn(library, manifest + self.package_dsc.read_text(encoding="utf-8"))

    def test_probe_has_no_direct_network_or_authorization_dependency(self) -> None:
        source = (
            self.pbns_root
            / "uefi"
            / "Applications"
            / "PbnsProbe"
            / "PbnsProbe.c"
        ).read_text(encoding="utf-8")
        self.assertIn("PBNS_SERVICE_TRUSTED_TIME", source)
        self.assertIn("pbns_usb_transport_create", source)
        self.assertIn("pbns_broker_request", source)
        self.assertIn("PBNS_ERR_UNIMPLEMENTED", source)
        self.assertIn("PBNS_FRAME_V1_PROTOCOL_VERSION", source)
        self.assertIn("edk2-b03a21a-x64", source)
        self.assertNotIn("Wire[42]", source)
        self.assertNotIn("EFI_UNSUPPORTED", source)
        self.assertIn("EFI_SUCCESS", source)
        for forbidden in (
            "EFI_TCP",
            "EFI_IP4",
            "EFI_IP6",
            "BootOrder",
            "ticket",
            "unlock",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
