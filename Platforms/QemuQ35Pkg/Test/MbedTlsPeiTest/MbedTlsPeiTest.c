/** @file
  Verifies BaseCryptLib hash services exposed through the EDK II Crypto PPI.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiPei.h>

#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>

typedef
UINTN
(EFIAPI *HASH_GET_CONTEXT_SIZE)(
  VOID
  );

typedef
BOOLEAN
(EFIAPI *HASH_INIT)(
  OUT VOID  *HashContext
  );

typedef
BOOLEAN
(EFIAPI *HASH_DUPLICATE)(
  IN  CONST VOID  *HashContext,
  OUT VOID        *NewHashContext
  );

typedef
BOOLEAN
(EFIAPI *HASH_UPDATE)(
  IN OUT VOID        *HashContext,
  IN     CONST VOID  *Data,
  IN     UINTN       DataSize
  );

typedef
BOOLEAN
(EFIAPI *HASH_FINAL)(
  IN OUT VOID   *HashContext,
  OUT    UINT8  *HashValue
  );

typedef
BOOLEAN
(EFIAPI *HASH_ALL)(
  IN  CONST VOID  *Data,
  IN  UINTN       DataSize,
  OUT UINT8       *HashValue
  );

typedef struct {
  CONST CHAR8           *Name;
  HASH_GET_CONTEXT_SIZE GetContextSize;
  HASH_INIT             Init;
  HASH_DUPLICATE        Duplicate;
  HASH_UPDATE           Update;
  HASH_FINAL            Final;
  HASH_ALL              HashAll;
  UINTN                 DigestSize;
  CONST UINT8           *ExpectedDigest;
} HASH_TEST;

STATIC CONST CHAR8  mTestData[] = "abc";

STATIC CONST UINT8  mSha1Digest[SHA1_DIGEST_SIZE] = {
  0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
  0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
  0x9C, 0xD0, 0xD8, 0x9D
};

STATIC CONST UINT8  mSha256Digest[SHA256_DIGEST_SIZE] = {
  0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
  0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
  0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
  0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
};

STATIC CONST UINT8  mSha384Digest[SHA384_DIGEST_SIZE] = {
  0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B,
  0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50, 0x07,
  0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63,
  0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED,
  0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23,
  0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7
};

STATIC CONST UINT8  mSha512Digest[SHA512_DIGEST_SIZE] = {
  0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA,
  0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31,
  0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2,
  0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A,
  0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8,
  0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
  0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
  0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F
};

STATIC CONST HASH_TEST  mHashTests[] = {
  { "SHA-1",   Sha1GetContextSize,   Sha1Init,   Sha1Duplicate,   Sha1Update,   Sha1Final,   Sha1HashAll,   SHA1_DIGEST_SIZE,   mSha1Digest   },
  { "SHA-256", Sha256GetContextSize, Sha256Init, Sha256Duplicate, Sha256Update, Sha256Final, Sha256HashAll, SHA256_DIGEST_SIZE, mSha256Digest },
  { "SHA-384", Sha384GetContextSize, Sha384Init, Sha384Duplicate, Sha384Update, Sha384Final, Sha384HashAll, SHA384_DIGEST_SIZE, mSha384Digest },
  { "SHA-512", Sha512GetContextSize, Sha512Init, Sha512Duplicate, Sha512Update, Sha512Final, Sha512HashAll, SHA512_DIGEST_SIZE, mSha512Digest },
};

STATIC
BOOLEAN
TestHashFamily (
  IN CONST HASH_TEST  *HashTest
  )
{
  VOID     *HashContext;
  VOID     *DuplicateContext;
  UINT8    Digest[SHA512_DIGEST_SIZE];
  UINT8    DuplicateDigest[SHA512_DIGEST_SIZE];
  UINT8    HashAllDigest[SHA512_DIGEST_SIZE];
  UINTN    ContextSize;
  BOOLEAN  Passed;
  BOOLEAN  ContextReady;
  BOOLEAN  DuplicateReady;

  Passed          = TRUE;
  ContextReady    = FALSE;
  DuplicateReady  = FALSE;
  HashContext     = NULL;
  DuplicateContext = NULL;
  ZeroMem (Digest, sizeof (Digest));
  ZeroMem (DuplicateDigest, sizeof (DuplicateDigest));
  ZeroMem (HashAllDigest, sizeof (HashAllDigest));

  ContextSize = HashTest->GetContextSize ();
  if (ContextSize == 0) {
    DEBUG ((DEBUG_ERROR, "MbedTlsPeiTest: %a GetContextSize failed\n", HashTest->Name));
    Passed = FALSE;
  } else {
    HashContext      = AllocatePool (ContextSize);
    DuplicateContext = AllocatePool (ContextSize);
    if ((HashContext == NULL) || (DuplicateContext == NULL)) {
      DEBUG ((DEBUG_ERROR, "MbedTlsPeiTest: %a context allocation failed\n", HashTest->Name));
      Passed = FALSE;
    }
  }

  if ((HashContext != NULL) && (DuplicateContext != NULL)) {
    ContextReady = HashTest->Init (HashContext);
    if (!ContextReady) {
      DEBUG ((DEBUG_ERROR, "MbedTlsPeiTest: %a Init failed\n", HashTest->Name));
      Passed = FALSE;
    }
  }

  if (ContextReady) {
    ContextReady = HashTest->Update (HashContext, mTestData, sizeof (mTestData) - 1);
    if (!ContextReady) {
      DEBUG ((DEBUG_ERROR, "MbedTlsPeiTest: %a Update failed\n", HashTest->Name));
      Passed = FALSE;
    }
  }

  if (ContextReady) {
    DuplicateReady = HashTest->Duplicate (HashContext, DuplicateContext);
    if (!DuplicateReady) {
      DEBUG ((DEBUG_ERROR, "MbedTlsPeiTest: %a Duplicate failed\n", HashTest->Name));
      Passed = FALSE;
    }

    if (!HashTest->Final (HashContext, Digest)) {
      DEBUG ((DEBUG_ERROR, "MbedTlsPeiTest: %a Final failed\n", HashTest->Name));
      Passed = FALSE;
    } else if (CompareMem (Digest, HashTest->ExpectedDigest, HashTest->DigestSize) != 0) {
      DEBUG ((DEBUG_ERROR, "MbedTlsPeiTest: %a Final digest mismatch\n", HashTest->Name));
      Passed = FALSE;
    }
  }

  if (DuplicateReady) {
    if (!HashTest->Final (DuplicateContext, DuplicateDigest)) {
      DEBUG ((DEBUG_ERROR, "MbedTlsPeiTest: %a duplicate Final failed\n", HashTest->Name));
      Passed = FALSE;
    } else if (CompareMem (DuplicateDigest, HashTest->ExpectedDigest, HashTest->DigestSize) != 0) {
      DEBUG ((DEBUG_ERROR, "MbedTlsPeiTest: %a duplicate digest mismatch\n", HashTest->Name));
      Passed = FALSE;
    }
  }

  if (!HashTest->HashAll (mTestData, sizeof (mTestData) - 1, HashAllDigest)) {
    DEBUG ((DEBUG_ERROR, "MbedTlsPeiTest: %a HashAll failed\n", HashTest->Name));
    Passed = FALSE;
  } else if (CompareMem (HashAllDigest, HashTest->ExpectedDigest, HashTest->DigestSize) != 0) {
    DEBUG ((DEBUG_ERROR, "MbedTlsPeiTest: %a HashAll digest mismatch\n", HashTest->Name));
    DUMP_HEX (DEBUG_ERROR, 0, HashAllDigest, HashTest->DigestSize, "Actual:   ");
    DUMP_HEX (DEBUG_ERROR, 0, HashTest->ExpectedDigest, HashTest->DigestSize, "Expected: ");
    Passed = FALSE;
  }

  if (HashContext != NULL) {
    FreePool (HashContext);
  }

  if (DuplicateContext != NULL) {
    FreePool (DuplicateContext);
  }

  DEBUG ((DEBUG_INFO, "MbedTlsPeiTest: %a %a\n", HashTest->Name, Passed ? "passed" : "failed"));
  return Passed;
}

EFI_STATUS
EFIAPI
MbedTlsPeiTestEntryPoint (
  IN EFI_PEI_FILE_HANDLE     FileHandle,
  IN CONST EFI_PEI_SERVICES  **PeiServices
  )
{
  UINTN    Index;
  BOOLEAN  AllPassed;

  (VOID)FileHandle;
  (VOID)PeiServices;

  AllPassed = TRUE;
  for (Index = 0; Index < ARRAY_SIZE (mHashTests); Index++) {
    if (!TestHashFamily (&mHashTests[Index])) {
      AllPassed = FALSE;
    }
  }

  DEBUG ((DEBUG_INFO, "MbedTlsPeiTest: hash tests %a\n", AllPassed ? "passed" : "failed"));
  return EFI_SUCCESS;
}
