/** @file
  WPA3 SAE (Simultaneous Authentication of Equals) Declarations.

  Implements the Dragonfly Key Exchange protocol for WPA3-Personal
  per IEEE 802.11-2020 Section 12.4. Uses the Hunting-and-Pecking
  method to derive the Password Element on ECC Group 19 (P-256).

  Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef WPA_SAE_H_
#define WPA_SAE_H_

#include "WpaCommon.h"

//
// Forward declaration
//
typedef struct _SUPPLICANT_PRIVATE_DATA SUPPLICANT_PRIVATE_DATA;

//
// ECC Group 19 (NIST P-256 / secp256r1)
//
#define SAE_ECC_GROUP        19
#define SAE_PRIME_LEN        32   // 256-bit prime
#define SAE_ORDER_LEN        32   // 256-bit order

//
// NID for secp256r1/prime256v1 in OpenSSL
//
#define CRYPTO_NID_SECP256R1  415

///
/// SAE handshake state
///
typedef enum {
  SaeStateIdle = 0,
  SaeStateCommitSent,
  SaeStateConfirmSent,
  SaeStateAccepted,
  SaeStateFailed
} SAE_STATE;

///
/// SAE session data
///
typedef struct {
  SAE_STATE  State;

  //
  // Local values
  //
  UINT8      OwnScalar[SAE_PRIME_LEN];
  UINT8      OwnElementX[SAE_PRIME_LEN];
  UINT8      OwnElementY[SAE_PRIME_LEN];
  UINT8      OwnRand[SAE_PRIME_LEN];
  UINT8      OwnMask[SAE_PRIME_LEN];

  //
  // Peer values
  //
  UINT8      PeerScalar[SAE_PRIME_LEN];
  UINT8      PeerElementX[SAE_PRIME_LEN];
  UINT8      PeerElementY[SAE_PRIME_LEN];

  //
  // Derived values
  //
  UINT8      Kck[SAE_KCK_LEN];
  UINT8      Pmk[SAE_PMK_LEN];
  UINT16     SendConfirm;   // Counter for own confirm
  UINT16     RecvConfirm;   // Counter from peer confirm

  //
  // Password Element
  //
  BOOLEAN    PweValid;
  UINT8      PweX[SAE_PRIME_LEN];
  UINT8      PweY[SAE_PRIME_LEN];
} SAE_SESSION;

/**
  Initialize SAE session and derive Password Element using Hunting-and-Pecking.

  @param[in]   Private   Supplicant private data with password and MAC addresses.
  @param[out]  Session   SAE session to initialize.

  @retval TRUE   SAE session initialized successfully.
  @retval FALSE  Failed to initialize SAE session.
**/
BOOLEAN
SaeInit (
  IN  SUPPLICANT_PRIVATE_DATA  *Private,
  OUT SAE_SESSION              *Session
  );

/**
  Build SAE Commit message.

  Generates the Commit frame containing the scalar and element
  for the Dragonfly key exchange.

  @param[in]      Private     Supplicant private data.
  @param[in]      Session     SAE session data.
  @param[out]     Buffer      Output buffer for commit frame body.
  @param[in,out]  BufferSize  On input, buffer size. On output, required/used size.

  @retval EFI_SUCCESS           Commit message built.
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small.
  @retval EFI_INVALID_PARAMETER Invalid parameters.
**/
EFI_STATUS
SaeBuildCommit (
  IN     SUPPLICANT_PRIVATE_DATA  *Private,
  IN     SAE_SESSION              *Session,
  OUT    UINT8                    *Buffer,
  IN OUT UINTN                    *BufferSize
  );

/**
  Process a received SAE Commit message from the peer.

  Extracts the peer's scalar and element, then derives the shared secret.

  @param[in]   Private       Supplicant private data.
  @param[in]   Session       SAE session data.
  @param[in]   CommitFrame   Received commit frame body (after auth header).
  @param[in]   FrameLen      Length of commit frame body.

  @retval EFI_SUCCESS           Peer commit processed successfully.
  @retval EFI_INVALID_PARAMETER Invalid frame.
  @retval EFI_SECURITY_VIOLATION Commit validation failed.
**/
EFI_STATUS
SaeProcessCommit (
  IN  SUPPLICANT_PRIVATE_DATA  *Private,
  IN  SAE_SESSION              *Session,
  IN  CONST UINT8              *CommitFrame,
  IN  UINTN                    FrameLen
  );

/**
  Build SAE Confirm message.

  @param[in]      Private     Supplicant private data.
  @param[in]      Session     SAE session data.
  @param[out]     Buffer      Output buffer for confirm frame body.
  @param[in,out]  BufferSize  On input, buffer size. On output, required/used size.

  @retval EFI_SUCCESS           Confirm message built.
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small.
**/
EFI_STATUS
SaeBuildConfirm (
  IN     SUPPLICANT_PRIVATE_DATA  *Private,
  IN     SAE_SESSION              *Session,
  OUT    UINT8                    *Buffer,
  IN OUT UINTN                    *BufferSize
  );

/**
  Process a received SAE Confirm message and verify.

  @param[in]   Private        Supplicant private data.
  @param[in]   Session        SAE session data.
  @param[in]   ConfirmFrame   Received confirm frame body (after auth header).
  @param[in]   FrameLen       Length of confirm frame body.

  @retval EFI_SUCCESS             Confirm verified; PMK is ready.
  @retval EFI_SECURITY_VIOLATION  Confirm verification failed.
**/
EFI_STATUS
SaeProcessConfirm (
  IN  SUPPLICANT_PRIVATE_DATA  *Private,
  IN  SAE_SESSION              *Session,
  IN  CONST UINT8              *ConfirmFrame,
  IN  UINTN                    FrameLen
  );

/**
  Clean up SAE session, zeroing sensitive data.

  @param[in]  Session   SAE session to clean up.
**/
VOID
SaeCleanup (
  IN SAE_SESSION  *Session
  );

#endif // WPA_SAE_H_
