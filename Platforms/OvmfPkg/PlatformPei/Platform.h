/** @file
  Platform PEI module include file.

  Copyright (c) 2006 - 2016, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _PLATFORM_PEI_H_INCLUDED_
#define _PLATFORM_PEI_H_INCLUDED_

#include <IndustryStandard/E820.h>
#include <Library/PlatformInitLib.h>

extern EFI_HOB_PLATFORM_INFO  mPlatformInfoHob;

VOID
AddressWidthInitialization (
  IN OUT EFI_HOB_PLATFORM_INFO  *PlatformInfoHob
  );

VOID
Q35TsegMbytesInitialization (
  VOID
  );

VOID
Q35SmramAtDefaultSmbaseInitialization (
  VOID
  );

EFI_STATUS
PublishPeiMemory (
  VOID
  );

UINT32
EFIAPI
PlatformGetSystemMemorySizeBelow4gb (
  IN EFI_HOB_PLATFORM_INFO  *PlatformInfoHob
  );

VOID
EFIAPI
PlatformQemuUc32BaseInitialization (
  IN OUT EFI_HOB_PLATFORM_INFO  *PlatformInfoHob
  );

VOID
InitializeRamRegions (
  IN EFI_HOB_PLATFORM_INFO  *PlatformInfoHob
  );

VOID
MemMapInitialization (
  IN OUT EFI_HOB_PLATFORM_INFO  *PlatformInfoHob
  );

VOID
MiscInitialization (
  IN EFI_HOB_PLATFORM_INFO  *PlatformInfoHob
  );

VOID
BootModeInitialization (
  IN OUT EFI_HOB_PLATFORM_INFO  *PlatformInfoHob
  );

VOID
MaxCpuCountInitialization (
  IN OUT EFI_HOB_PLATFORM_INFO  *PlatformInfoHob
  );

EFI_STATUS
PeiFvInitialization (
  VOID
  );

VOID
MemTypeInfoInitialization (
  VOID
  );

VOID
InstallFeatureControlCallback (
  VOID
  );

VOID
InstallClearCacheCallback (
  VOID
  );

VOID
AmdSevInitialize (
  VOID
  );

VOID
SevInitializeRam (
  VOID
  );

#endif // _PLATFORM_PEI_H_INCLUDED_
