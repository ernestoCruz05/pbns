## @file
# PBNS X64 UEFI application build.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

[Defines]
  PLATFORM_NAME                  = PbnsPkg
  PLATFORM_GUID                  = 8be7e835-a3e9-4db1-86e6-d7899c8fa0a6
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x0001001B
  OUTPUT_DIRECTORY               = Build/PbnsPkg
  SUPPORTED_ARCHITECTURES        = X64
  BUILD_TARGETS                  = DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT

!include MdePkg/MdeLibs.dsc.inc

[LibraryClasses]
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLibRepStr/BaseMemoryLibRepStr.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  DxeServicesLib|MdePkg/Library/DxeServicesLib/DxeServicesLib.inf
  DxeServicesTableLib|MdePkg/Library/DxeServicesTableLib/DxeServicesTableLib.inf
  HiiLib|MdeModulePkg/Library/UefiHiiLib/UefiHiiLib.inf
  HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf
  IntrinsicLib|CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  PeCoffGetEntryPointLib|MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
  PerformanceLib|MdePkg/Library/BasePerformanceLibNull/BasePerformanceLibNull.inf
  MbedTlsLib|CryptoPkg/Library/MbedTlsLib/MbedTlsLibFull.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  ReportStatusCodeLib|MdeModulePkg/Library/DxeReportStatusCodeLib/DxeReportStatusCodeLib.inf
  RngLib|MdePkg/Library/BaseRngLib/BaseRngLib.inf
  SortLib|MdeModulePkg/Library/UefiSortLib/UefiSortLib.inf
  Tpm2CommandLib|SecurityPkg/Library/Tpm2CommandLib/Tpm2CommandLib.inf
  Tpm2DeviceLib|SecurityPkg/Library/Tpm2DeviceLibTcg2/Tpm2DeviceLibTcg2.inf
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  UefiBootManagerLib|MdeModulePkg/Library/UefiBootManagerLib/UefiBootManagerLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiHiiServicesLib|MdeModulePkg/Library/UefiHiiServicesLib/UefiHiiServicesLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  VariablePolicyHelperLib|MdeModulePkg/Library/VariablePolicyHelperLib/VariablePolicyHelperLib.inf
  PbnsCoreLib|pbns/src/core/PbnsCoreLib.inf
  PbnsAntiRollbackLib|pbns/uefi/Library/PbnsAntiRollbackLib/PbnsAntiRollbackLib.inf
  PbnsAttestationClientLib|pbns/uefi/Library/PbnsAttestationClientLib/PbnsAttestationClientLib.inf
  PbnsEnrollmentClientLib|pbns/uefi/Library/PbnsEnrollmentClientLib/PbnsEnrollmentClientLib.inf
  PbnsBootConfigLib|pbns/uefi/Library/PbnsBootConfigLib/PbnsBootConfigLib.inf
  PbnsCoseCryptoLib|pbns/uefi/Library/PbnsCoseCryptoLib/PbnsCoseCryptoLib.inf
  PbnsEnrollmentBaselineLib|pbns/uefi/Library/PbnsEnrollmentBaselineLib/PbnsEnrollmentBaselineLib.inf
  PbnsIdentityLib|pbns/uefi/Library/PbnsIdentityLib/PbnsIdentityLib.inf
  PbnsInventoryLib|pbns/uefi/Library/PbnsInventoryLib/PbnsInventoryLib.inf
  PbnsLauncherPolicyLib|pbns/uefi/Library/PbnsLauncherPolicyLib/PbnsLauncherPolicyLib.inf
  PbnsMeasuredBootLib|pbns/uefi/Library/PbnsMeasuredBootLib/PbnsMeasuredBootLib.inf
  PbnsQcborLib|pbns/uefi/Library/PbnsQcborLib/PbnsQcborLib.inf
  PbnsRecoveryClientLib|pbns/uefi/Library/PbnsRecoveryClientLib/PbnsRecoveryClientLib.inf
  PbnsRecoveryServiceLib|pbns/uefi/Library/PbnsRecoveryServiceLib/PbnsRecoveryServiceLib.inf
  PbnsTpmIdentityLib|pbns/uefi/Library/PbnsTpmIdentityLib/PbnsTpmIdentityLib.inf
  PbnsTpmEkCertificateLib|pbns/uefi/Library/PbnsTpmEkCertificateLib/PbnsTpmEkCertificateLib.inf
  PbnsTrustedTimeLib|pbns/uefi/Library/PbnsTrustedTimeLib/PbnsTrustedTimeLib.inf
  PbnsTCoseLib|pbns/uefi/Library/PbnsTCoseLib/PbnsTCoseLib.inf
  PbnsTlsTransportCoreLib|pbns/src/transport/PbnsTlsTransportCoreLib.inf
  PbnsTlsTransportLib|pbns/uefi/Library/PbnsTlsTransportLib/PbnsTlsTransportLib.inf
  PbnsTss2TctiLib|pbns/uefi/Library/PbnsTss2TctiLib/PbnsTss2TctiLib.inf
  PbnsUefiPlatformLib|pbns/uefi/Library/PbnsUefiPlatformLib/PbnsUefiPlatformLib.inf
  PbnsUsbTransportLib|pbns/uefi/Library/PbnsUsbTransportLib/PbnsUsbTransportLib.inf
  Tss2MuLib|pbns/uefi/Library/Tss2MuLib/Tss2MuLib.inf
  Tss2SysLib|pbns/uefi/Library/Tss2SysLib/Tss2SysLib.inf

[BuildOptions]
  GCC:*_*_*_CC_FLAGS = -DMBEDTLS_NIST_KW_C -flto-partition=one

[Components]
  pbns/uefi/Library/PbnsAntiRollbackLib/PbnsAntiRollbackLib.inf
  pbns/uefi/Library/PbnsAttestationClientLib/PbnsAttestationClientLib.inf
  pbns/uefi/Library/PbnsEnrollmentClientLib/PbnsEnrollmentClientLib.inf
  pbns/uefi/Library/PbnsInventoryLib/PbnsInventoryLib.inf
  pbns/uefi/Library/PbnsRecoveryClientLib/PbnsRecoveryClientLib.inf
  pbns/uefi/Library/PbnsRecoveryServiceLib/PbnsRecoveryServiceLib.inf
  pbns/uefi/Applications/PbnsProbe/PbnsProbe.inf
  pbns/uefi/Applications/PbnsIdentityProbe/PbnsIdentityProbe.inf
  pbns/uefi/Applications/PbnsCoseProbe/PbnsCoseProbe.inf
  pbns/uefi/Applications/PbnsTlsProbe/PbnsTlsProbe.inf
  pbns/uefi/Applications/PbnsTime/PbnsTime.inf
  pbns/uefi/Applications/PbnsTimeLive/PbnsTimeLive.inf
  pbns/uefi/Applications/PbnsBaseline/PbnsBaseline.inf
  pbns/uefi/Applications/PbnsAttest/PbnsAttest.inf
  pbns/uefi/Applications/PbnsEnroll/PbnsEnroll.inf
  pbns/uefi/Applications/PBNSLauncher/PBNSLauncher.inf
  pbns/uefi/Applications/PBNSRecovery/PBNSRecovery.inf
  pbns/uefi/Applications/PbnsBootSetup/PbnsBootSetup.inf
  pbns/uefi/Tests/Fixtures/ReturnError/ReturnError.inf
  pbns/uefi/Tests/Fixtures/ReturnSuccess/ReturnSuccess.inf
