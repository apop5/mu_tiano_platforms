/** @file
  Exercises HashLogExtendEvent through the EDK II TCG PPI.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiPei.h>

#include <Ppi/Tcg.h>

#include <Library/DebugLib.h>
#include <Library/PeiServicesLib.h>

STATIC CONST UINT8  mHashData[]  = "TcgPpiTest hash data";
STATIC CONST UINT8  mEventData[] = "TcgPpiTest event";

EFI_STATUS
EFIAPI
TcgPpiTestEntryPoint (
  IN EFI_PEI_FILE_HANDLE     FileHandle,
  IN CONST EFI_PEI_SERVICES  **PeiServices
  )
{
  EFI_STATUS         Status;
  EDKII_TCG_PPI      *TcgPpi;
  TCG_PCR_EVENT_HDR  TcgEventHdr;

  (VOID)FileHandle;
  (VOID)PeiServices;

  Status = PeiServicesLocatePpi (
             &gEdkiiTcgPpiGuid,
             0,
             NULL,
             (VOID **)&TcgPpi
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "TcgPpiTest: failed to locate TCG PPI: %r\n", Status));
    return EFI_SUCCESS;
  }

  TcgEventHdr.PCRIndex  = 0;
  TcgEventHdr.EventType = EV_POST_CODE;
  TcgEventHdr.EventSize = sizeof (mEventData) - 1;

  Status = TcgPpi->HashLogExtendEvent (
                     TcgPpi,
                     0,
                     (UINT8 *)(UINTN)mHashData,
                     sizeof (mHashData) - 1,
                     &TcgEventHdr,
                     (UINT8 *)(UINTN)mEventData
                     );
  DEBUG ((EFI_ERROR (Status) ? DEBUG_ERROR : DEBUG_INFO, "TcgPpiTest: HashLogExtendEvent %a: %r\n", EFI_ERROR (Status) ? "failed" : "passed", Status));

  return EFI_SUCCESS;
}