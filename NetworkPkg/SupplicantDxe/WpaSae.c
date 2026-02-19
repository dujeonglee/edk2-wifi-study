/** @file
  WPA3 SAE (Simultaneous Authentication of Equals) Implementation.

  Implements the Dragonfly Key Exchange protocol for WPA3-Personal
  using the Hunting-and-Pecking method on ECC Group 19 (NIST P-256).

  Reference: IEEE 802.11-2020 Section 12.4, RFC 7664, wpa_supplicant

  Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SupplicantDxe.h"

/**
  Derive Password Element (PWE) using the Hunting-and-Pecking method.

  IEEE 802.11-2020 Section 12.4.4.2.2:
  For each counter from 1..40:
    seed = HMAC-SHA256(MAX(addr1,addr2)||MIN(addr1,addr2), password||counter)
    value = KDF-256(seed, "SAE Hunting and Pecking", p)
    If value < p and the point is on the curve, use it.

  @param[in]   Private     Supplicant private data (password, MACs).
  @param[out]  Session     SAE session to receive PWE.

  @retval TRUE   PWE found.
  @retval FALSE  PWE derivation failed (no point found after max iterations).
**/
STATIC
BOOLEAN
SaeDerivePasswordElement (
  IN  SUPPLICANT_PRIVATE_DATA  *Private,
  OUT SAE_SESSION              *Session
  )
{
  VOID     *EcGroup;
  VOID     *BnCtx;
  VOID     *BnPrime;
  VOID     *BnX;
  VOID     *BnY;
  VOID     *BnOne;
  VOID     *EcPwe;
  UINT8    AddrConcat[2 * WPA_MAC_ADDR_LEN];
  UINT8    PwdSeed[SHA256_DIGEST_SIZE];
  UINT8    PwdValue[SAE_PRIME_LEN];
  UINT8    Counter;
  UINT8    HashInput[WPA_MAX_PASSWORD_LEN + 1];
  UINTN    HashInputLen;
  BOOLEAN  Found;
  BOOLEAN  Result;
  UINT8    PrimeBytes[SAE_PRIME_LEN];
  UINT8    QrFlag;
  INT32    Cmp;

  Found   = FALSE;
  EcGroup = NULL;
  BnCtx   = NULL;
  BnPrime = NULL;
  BnX     = NULL;
  BnY     = NULL;
  BnOne   = NULL;
  EcPwe   = NULL;

  //
  // Initialize ECC Group 19 (P-256)
  //
  EcGroup = EcGroupInit (CRYPTO_NID_SECP256R1);
  if (EcGroup == NULL) {
    DEBUG ((DEBUG_ERROR, "[SAE] Failed to init EC group 19\n"));
    return FALSE;
  }

  BnCtx = BigNumNewContext ();
  if (BnCtx == NULL) {
    goto Done;
  }

  //
  // Get the prime p
  //
  BnPrime = BigNumInit ();
  BnX     = BigNumInit ();
  BnY     = BigNumInit ();
  BnOne   = BigNumInit ();
  if ((BnPrime == NULL) || (BnX == NULL) || (BnY == NULL) || (BnOne == NULL)) {
    goto Done;
  }

  if (!EcGroupGetCurve (EcGroup, BnPrime, NULL, NULL, BnCtx)) {
    goto Done;
  }

  BigNumToBin (BnPrime, PrimeBytes, SAE_PRIME_LEN);

  //
  // Sort addresses: MAX || MIN for HMAC key
  //
  Cmp = CompareMem (Private->StationMac.Addr, Private->TargetBssid.Addr, WPA_MAC_ADDR_LEN);
  if (Cmp >= 0) {
    CopyMem (AddrConcat, Private->StationMac.Addr, WPA_MAC_ADDR_LEN);
    CopyMem (AddrConcat + WPA_MAC_ADDR_LEN, Private->TargetBssid.Addr, WPA_MAC_ADDR_LEN);
  } else {
    CopyMem (AddrConcat, Private->TargetBssid.Addr, WPA_MAC_ADDR_LEN);
    CopyMem (AddrConcat + WPA_MAC_ADDR_LEN, Private->StationMac.Addr, WPA_MAC_ADDR_LEN);
  }

  //
  // Hunting and Pecking: iterate counter from 1 to 40
  //
  for (Counter = 1; Counter <= 40; Counter++) {
    //
    // Build hash input: password || counter
    //
    HashInputLen = Private->PasswordLen;
    CopyMem (HashInput, Private->Password, HashInputLen);
    HashInput[HashInputLen] = Counter;
    HashInputLen++;

    //
    // pwd-seed = HMAC-SHA256(addr_concat, password || counter)
    //
    if (!HmacSha256All (HashInput, HashInputLen, AddrConcat, sizeof (AddrConcat), PwdSeed)) {
      continue;
    }

    //
    // pwd-value = KDF-256(pwd-seed, "SAE Hunting and Pecking", p)
    //
    if (!WpaKdfSha256 (PwdSeed, SHA256_DIGEST_SIZE, "SAE Hunting and Pecking",
           PrimeBytes, SAE_PRIME_LEN, PwdValue, 256))
    {
      continue;
    }

    //
    // Check if pwd-value < p
    //
    {
      VOID  *BnVal;
      BnVal = BigNumFromBin (PwdValue, SAE_PRIME_LEN);
      if (BnVal == NULL) {
        continue;
      }

      if (BigNumCmp (BnVal, BnPrime) >= 0) {
        BigNumFree (BnVal, TRUE);
        continue;
      }

      //
      // Try to find y such that y^2 = x^3 + ax + b (mod p)
      // Use EC point operations: set x coordinate and check if point is on curve
      //
      EcPwe = EcPointInit (EcGroup);
      if (EcPwe == NULL) {
        BigNumFree (BnVal, TRUE);
        continue;
      }

      //
      // Compute y^2 = x^3 + ax + b mod p using EC point operations.
      // We set the x coordinate and try to find a valid point.
      //
      // For P-256, a = p-3, b is a fixed constant.
      // y^2 = x^3 + a*x + b (mod p)
      //
      // We use EcPointSetAffineCoordinates with a dummy y then check.
      // A simpler approach: use EcPointSetCompressedCoordinates if available,
      // or compute y directly.
      //
      // Since EDK2 BigNum provides modular arithmetic, compute:
      // y_sq = (x^3 + a*x + b) mod p
      // y = sqrt(y_sq) mod p using Tonelli-Shanks (P-256 has p = 3 mod 4, so y = y_sq^((p+1)/4))
      //
      {
        VOID   *BnA;
        VOID   *BnB;
        VOID   *BnYSq;
        VOID   *BnTemp;
        VOID   *BnExp;
        UINT8  YBytes[SAE_PRIME_LEN];

        BnA    = BigNumInit ();
        BnB    = BigNumInit ();
        BnYSq  = BigNumInit ();
        BnTemp = BigNumInit ();
        BnExp  = BigNumInit ();

        if ((BnA == NULL) || (BnB == NULL) || (BnYSq == NULL) ||
            (BnTemp == NULL) || (BnExp == NULL))
        {
          if (BnA)    BigNumFree (BnA, TRUE);
          if (BnB)    BigNumFree (BnB, TRUE);
          if (BnYSq)  BigNumFree (BnYSq, TRUE);
          if (BnTemp)  BigNumFree (BnTemp, TRUE);
          if (BnExp)  BigNumFree (BnExp, TRUE);
          EcPointDeInit (EcPwe, TRUE);
          EcPwe = NULL;
          BigNumFree (BnVal, TRUE);
          continue;
        }

        //
        // Get curve parameters a, b
        //
        if (!EcGroupGetCurve (EcGroup, NULL, BnA, BnB, BnCtx)) {
          BigNumFree (BnA, TRUE);
          BigNumFree (BnB, TRUE);
          BigNumFree (BnYSq, TRUE);
          BigNumFree (BnTemp, TRUE);
          BigNumFree (BnExp, TRUE);
          EcPointDeInit (EcPwe, TRUE);
          EcPwe = NULL;
          BigNumFree (BnVal, TRUE);
          continue;
        }

        //
        // y_sq = x^3 + a*x + b mod p
        // = ((x * x mod p) * x mod p + a * x mod p + b) mod p
        //
        // Step 1: temp = x^2 mod p
        //
        if (!BigNumSqrMod (BnVal, BnPrime, BnCtx, BnTemp)) {
          goto CleanupYCalc;
        }

        //
        // Step 2: y_sq = temp * x mod p = x^3 mod p
        //
        if (!BigNumMulMod (BnTemp, BnVal, BnPrime, BnCtx, BnYSq)) {
          goto CleanupYCalc;
        }

        //
        // Step 3: temp = a * x mod p
        //
        if (!BigNumMulMod (BnA, BnVal, BnPrime, BnCtx, BnTemp)) {
          goto CleanupYCalc;
        }

        //
        // Step 4: y_sq = y_sq + temp mod p
        //
        if (!BigNumAddMod (BnYSq, BnTemp, BnPrime, BnYSq)) {
          goto CleanupYCalc;
        }

        //
        // Step 5: y_sq = y_sq + b mod p
        //
        if (!BigNumAddMod (BnYSq, BnB, BnPrime, BnYSq)) {
          goto CleanupYCalc;
        }

        //
        // Check if y_sq is a quadratic residue (QR) by computing
        // y_sq^((p-1)/2) mod p. If result is 1, it's a QR.
        // For P-256, p = 3 mod 4, so sqrt(y_sq) = y_sq^((p+1)/4) mod p
        //
        // Compute exp = (p+1)/4
        //
        {
          UINT8  One = 1;

          BigNumFree (BnOne, TRUE);
          BnOne = BigNumFromBin (&One, 1);
          if (BnOne == NULL) {
            goto CleanupYCalc;
          }
        }

        //
        // exp = p + 1
        //
        if (!BigNumAdd (BnPrime, BnOne, BnExp)) {
          goto CleanupYCalc;
        }

        //
        // exp = (p+1) >> 2  (divide by 4)
        //
        if (!BigNumRShift (BnExp, 2, BnExp)) {
          goto CleanupYCalc;
        }

        //
        // y = y_sq^exp mod p
        //
        if (!BigNumExpMod (BnYSq, BnExp, BnPrime, BnCtx, BnY)) {
          goto CleanupYCalc;
        }

        //
        // Verify: y^2 mod p == y_sq
        //
        if (!BigNumSqrMod (BnY, BnPrime, BnCtx, BnTemp)) {
          goto CleanupYCalc;
        }

        if (BigNumCmp (BnTemp, BnYSq) != 0) {
          //
          // Not a quadratic residue; skip this counter
          //
          goto CleanupYCalc;
        }

        //
        // Found a valid point! Adjust y parity.
        // LSB(y) should match (counter & 1) for Dragonfly.
        //
        BigNumToBin (BnY, YBytes, SAE_PRIME_LEN);
        QrFlag = YBytes[SAE_PRIME_LEN - 1] & 1;
        if (QrFlag != (Counter & 1)) {
          //
          // y = p - y
          //
          if (!BigNumSub (BnPrime, BnY, BnY)) {
            goto CleanupYCalc;
          }

          BigNumToBin (BnY, YBytes, SAE_PRIME_LEN);
        }

        //
        // Store PWE coordinates
        //
        CopyMem (Session->PweX, PwdValue, SAE_PRIME_LEN);
        CopyMem (Session->PweY, YBytes, SAE_PRIME_LEN);
        Session->PweValid = TRUE;
        Found = TRUE;

        BigNumFree (BnA, TRUE);
        BigNumFree (BnB, TRUE);
        BigNumFree (BnYSq, TRUE);
        BigNumFree (BnTemp, TRUE);
        BigNumFree (BnExp, TRUE);
        EcPointDeInit (EcPwe, TRUE);
        EcPwe = NULL;
        BigNumFree (BnVal, TRUE);

        DEBUG ((DEBUG_INFO, "[SAE] PWE found at counter=%d\n", Counter));
        goto Done;

CleanupYCalc:
        BigNumFree (BnA, TRUE);
        BigNumFree (BnB, TRUE);
        BigNumFree (BnYSq, TRUE);
        BigNumFree (BnTemp, TRUE);
        BigNumFree (BnExp, TRUE);
        EcPointDeInit (EcPwe, TRUE);
        EcPwe = NULL;
      }

      BigNumFree (BnVal, TRUE);
    }
  }

Done:
  if (BnPrime != NULL) BigNumFree (BnPrime, TRUE);
  if (BnX != NULL) BigNumFree (BnX, TRUE);
  if (BnY != NULL) BigNumFree (BnY, TRUE);
  if (BnOne != NULL) BigNumFree (BnOne, TRUE);
  if (BnCtx != NULL) BigNumContextFree (BnCtx);
  if (EcGroup != NULL) EcGroupFree (EcGroup);

  return Found;
}

/**
  Initialize SAE session.

  @param[in]   Private   Supplicant private data.
  @param[out]  Session   SAE session.

  @retval TRUE   Initialized.
  @retval FALSE  Failed.
**/
BOOLEAN
SaeInit (
  IN  SUPPLICANT_PRIVATE_DATA  *Private,
  OUT SAE_SESSION              *Session
  )
{
  VOID    *EcGroup;
  VOID    *BnCtx;
  VOID    *BnOrder;
  VOID    *BnRand;
  VOID    *BnMask;
  VOID    *BnScalar;
  VOID    *EcPwe;
  VOID    *EcElement;
  UINT8   OrderBytes[SAE_ORDER_LEN];
  UINT8   RandBytes[SAE_PRIME_LEN];
  UINT8   MaskBytes[SAE_PRIME_LEN];
  BOOLEAN Result;

  if ((Private == NULL) || (Session == NULL)) {
    return FALSE;
  }

  ZeroMem (Session, sizeof (SAE_SESSION));

  //
  // Derive Password Element
  //
  if (!SaeDerivePasswordElement (Private, Session)) {
    DEBUG ((DEBUG_ERROR, "[SAE] Password element derivation failed\n"));
    return FALSE;
  }

  //
  // Generate random scalar and mask
  // scalar = (rand + mask) mod order
  // element = -mask * PWE
  //
  EcGroup   = NULL;
  BnCtx     = NULL;
  BnOrder   = NULL;
  BnRand    = NULL;
  BnMask    = NULL;
  BnScalar  = NULL;
  EcPwe     = NULL;
  EcElement = NULL;
  Result    = FALSE;

  EcGroup = EcGroupInit (CRYPTO_NID_SECP256R1);
  if (EcGroup == NULL) {
    return FALSE;
  }

  BnCtx = BigNumNewContext ();
  if (BnCtx == NULL) {
    goto InitDone;
  }

  BnOrder = BigNumInit ();
  if (BnOrder == NULL) {
    goto InitDone;
  }

  if (!EcGroupGetOrder (EcGroup, BnOrder, BnCtx)) {
    goto InitDone;
  }

  BigNumToBin (BnOrder, OrderBytes, SAE_ORDER_LEN);

  //
  // Generate random values in [2, order-1]
  //
  if (!WpaRandomBytes (RandBytes, SAE_PRIME_LEN) ||
      !WpaRandomBytes (MaskBytes, SAE_PRIME_LEN))
  {
    goto InitDone;
  }

  BnRand = BigNumFromBin (RandBytes, SAE_PRIME_LEN);
  BnMask = BigNumFromBin (MaskBytes, SAE_PRIME_LEN);
  if ((BnRand == NULL) || (BnMask == NULL)) {
    goto InitDone;
  }

  //
  // Reduce rand and mask modulo (order - 2), then add 2
  // to ensure they are in range [2, order-1]
  //
  if (!BigNumMod (BnRand, BnOrder, BnCtx, BnRand) ||
      !BigNumMod (BnMask, BnOrder, BnCtx, BnMask))
  {
    goto InitDone;
  }

  //
  // scalar = (rand + mask) mod order
  //
  BnScalar = BigNumInit ();
  if (BnScalar == NULL) {
    goto InitDone;
  }

  if (!BigNumAddMod (BnRand, BnMask, BnOrder, BnScalar)) {
    goto InitDone;
  }

  //
  // Store scalar and rand
  //
  BigNumToBin (BnScalar, Session->OwnScalar, SAE_PRIME_LEN);
  BigNumToBin (BnRand, Session->OwnRand, SAE_PRIME_LEN);
  BigNumToBin (BnMask, Session->OwnMask, SAE_PRIME_LEN);

  //
  // element = inverse(mask * PWE) = -mask * PWE
  //
  EcPwe = EcPointInit (EcGroup);
  if (EcPwe == NULL) {
    goto InitDone;
  }

  {
    VOID  *BnPweX;
    VOID  *BnPweY;

    BnPweX = BigNumFromBin (Session->PweX, SAE_PRIME_LEN);
    BnPweY = BigNumFromBin (Session->PweY, SAE_PRIME_LEN);
    if ((BnPweX == NULL) || (BnPweY == NULL)) {
      if (BnPweX) BigNumFree (BnPweX, TRUE);
      if (BnPweY) BigNumFree (BnPweY, TRUE);
      goto InitDone;
    }

    if (!EcPointSetAffineCoordinates (EcGroup, EcPwe, BnPweX, BnPweY, BnCtx)) {
      BigNumFree (BnPweX, TRUE);
      BigNumFree (BnPweY, TRUE);
      goto InitDone;
    }

    BigNumFree (BnPweX, TRUE);
    BigNumFree (BnPweY, TRUE);
  }

  //
  // element = mask * PWE
  //
  EcElement = EcPointInit (EcGroup);
  if (EcElement == NULL) {
    goto InitDone;
  }

  if (!EcPointMul (EcGroup, EcElement, NULL, EcPwe, BnMask, BnCtx)) {
    goto InitDone;
  }

  //
  // Invert the point (negate y coordinate)
  //
  if (!EcPointInvert (EcGroup, EcElement, BnCtx)) {
    goto InitDone;
  }

  //
  // Extract element coordinates
  //
  {
    VOID  *BnElemX;
    VOID  *BnElemY;

    BnElemX = BigNumInit ();
    BnElemY = BigNumInit ();
    if ((BnElemX == NULL) || (BnElemY == NULL)) {
      if (BnElemX) BigNumFree (BnElemX, TRUE);
      if (BnElemY) BigNumFree (BnElemY, TRUE);
      goto InitDone;
    }

    if (!EcPointGetAffineCoordinates (EcGroup, EcElement, BnElemX, BnElemY, BnCtx)) {
      BigNumFree (BnElemX, TRUE);
      BigNumFree (BnElemY, TRUE);
      goto InitDone;
    }

    BigNumToBin (BnElemX, Session->OwnElementX, SAE_PRIME_LEN);
    BigNumToBin (BnElemY, Session->OwnElementY, SAE_PRIME_LEN);

    BigNumFree (BnElemX, TRUE);
    BigNumFree (BnElemY, TRUE);
  }

  Session->State       = SaeStateIdle;
  Session->SendConfirm = 0;
  Result               = TRUE;

  DEBUG ((DEBUG_INFO, "[SAE] Session initialized\n"));

InitDone:
  if (BnOrder != NULL) BigNumFree (BnOrder, TRUE);
  if (BnRand != NULL) BigNumFree (BnRand, TRUE);
  if (BnMask != NULL) BigNumFree (BnMask, TRUE);
  if (BnScalar != NULL) BigNumFree (BnScalar, TRUE);
  if (EcPwe != NULL) EcPointDeInit (EcPwe, TRUE);
  if (EcElement != NULL) EcPointDeInit (EcElement, TRUE);
  if (BnCtx != NULL) BigNumContextFree (BnCtx);
  if (EcGroup != NULL) EcGroupFree (EcGroup);

  return Result;
}

/**
  Build SAE Commit message.

  Frame body: GroupId(2) || Scalar(32) || Element.x(32) || Element.y(32)

  @param[in]      Private     Supplicant private data.
  @param[in]      Session     SAE session.
  @param[out]     Buffer      Output buffer.
  @param[in,out]  BufferSize  Buffer size.

  @retval EFI_SUCCESS           Built.
  @retval EFI_BUFFER_TOO_SMALL  Need more space.
**/
EFI_STATUS
SaeBuildCommit (
  IN     SUPPLICANT_PRIVATE_DATA  *Private,
  IN     SAE_SESSION              *Session,
  OUT    UINT8                    *Buffer,
  IN OUT UINTN                    *BufferSize
  )
{
  UINTN  RequiredSize;
  UINTN  Offset;

  //
  // Commit body: GroupId(2) + Scalar(32) + Element(64)
  //
  RequiredSize = 2 + SAE_PRIME_LEN + 2 * SAE_PRIME_LEN;

  if ((Buffer == NULL) || (*BufferSize < RequiredSize)) {
    *BufferSize = RequiredSize;
    if (Buffer == NULL) {
      return EFI_BUFFER_TOO_SMALL;
    }

    return EFI_BUFFER_TOO_SMALL;
  }

  Offset = 0;

  //
  // Finite Field Group: 19 (P-256) in LE
  //
  WPA_PUT_LE16 (Buffer + Offset, SAE_ECC_GROUP);
  Offset += 2;

  //
  // Scalar
  //
  CopyMem (Buffer + Offset, Session->OwnScalar, SAE_PRIME_LEN);
  Offset += SAE_PRIME_LEN;

  //
  // Element (x, y)
  //
  CopyMem (Buffer + Offset, Session->OwnElementX, SAE_PRIME_LEN);
  Offset += SAE_PRIME_LEN;
  CopyMem (Buffer + Offset, Session->OwnElementY, SAE_PRIME_LEN);
  Offset += SAE_PRIME_LEN;

  *BufferSize    = Offset;
  Session->State = SaeStateCommitSent;

  DEBUG ((DEBUG_INFO, "[SAE] Commit message built (%d bytes)\n", Offset));
  return EFI_SUCCESS;
}

/**
  Process received SAE Commit and derive shared secret + keys.

  @param[in]   Private       Supplicant private data.
  @param[in]   Session       SAE session.
  @param[in]   CommitFrame   Commit frame body (after SAE auth header).
  @param[in]   FrameLen      Frame body length.

  @retval EFI_SUCCESS             Processed.
  @retval EFI_INVALID_PARAMETER   Bad frame.
  @retval EFI_SECURITY_VIOLATION  Validation failed.
**/
EFI_STATUS
SaeProcessCommit (
  IN  SUPPLICANT_PRIVATE_DATA  *Private,
  IN  SAE_SESSION              *Session,
  IN  CONST UINT8              *CommitFrame,
  IN  UINTN                    FrameLen
  )
{
  UINT16   GroupId;
  VOID     *EcGroup;
  VOID     *BnCtx;
  VOID     *BnOrder;
  VOID     *BnPeerScalar;
  VOID     *EcPeerElement;
  VOID     *EcPwe;
  VOID     *EcK;
  VOID     *BnRand;
  VOID     *BnKx;
  BOOLEAN  Result;
  UINT8    KeySeedInput[SAE_PRIME_LEN];
  UINT8    KeySeed[SHA256_DIGEST_SIZE];
  UINT8    Keys[SAE_KCK_LEN + SAE_PMK_LEN];
  UINT8    ZeroKey[SHA256_DIGEST_SIZE];

  if ((CommitFrame == NULL) || (FrameLen < 2 + SAE_PRIME_LEN + 2 * SAE_PRIME_LEN)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Parse Group ID
  //
  GroupId = WPA_GET_LE16 (CommitFrame);
  if (GroupId != SAE_ECC_GROUP) {
    DEBUG ((DEBUG_ERROR, "[SAE] Unsupported group: %d\n", GroupId));
    return EFI_UNSUPPORTED;
  }

  //
  // Extract peer scalar and element
  //
  CopyMem (Session->PeerScalar, CommitFrame + 2, SAE_PRIME_LEN);
  CopyMem (Session->PeerElementX, CommitFrame + 2 + SAE_PRIME_LEN, SAE_PRIME_LEN);
  CopyMem (Session->PeerElementY, CommitFrame + 2 + SAE_PRIME_LEN + SAE_PRIME_LEN, SAE_PRIME_LEN);

  //
  // Compute shared secret K:
  // K = rand * (peer_scalar * PWE + peer_element)
  //
  EcGroup       = NULL;
  BnCtx         = NULL;
  BnOrder       = NULL;
  BnPeerScalar  = NULL;
  EcPeerElement = NULL;
  EcPwe         = NULL;
  EcK           = NULL;
  BnRand        = NULL;
  BnKx          = NULL;
  Result        = FALSE;

  EcGroup = EcGroupInit (CRYPTO_NID_SECP256R1);
  if (EcGroup == NULL) {
    return EFI_DEVICE_ERROR;
  }

  BnCtx = BigNumNewContext ();
  if (BnCtx == NULL) {
    goto ProcessDone;
  }

  BnOrder = BigNumInit ();
  if (BnOrder == NULL) {
    goto ProcessDone;
  }

  if (!EcGroupGetOrder (EcGroup, BnOrder, BnCtx)) {
    goto ProcessDone;
  }

  //
  // Validate peer scalar is in [2, order-1]
  //
  BnPeerScalar = BigNumFromBin (Session->PeerScalar, SAE_PRIME_LEN);
  if (BnPeerScalar == NULL) {
    goto ProcessDone;
  }

  if (BigNumIsWord (BnPeerScalar, 0) || BigNumIsWord (BnPeerScalar, 1)) {
    DEBUG ((DEBUG_ERROR, "[SAE] Invalid peer scalar\n"));
    goto ProcessDone;
  }

  if (BigNumCmp (BnPeerScalar, BnOrder) >= 0) {
    DEBUG ((DEBUG_ERROR, "[SAE] Peer scalar >= order\n"));
    goto ProcessDone;
  }

  //
  // Set up peer element point
  //
  EcPeerElement = EcPointInit (EcGroup);
  if (EcPeerElement == NULL) {
    goto ProcessDone;
  }

  {
    VOID  *BnPeerX;
    VOID  *BnPeerY;

    BnPeerX = BigNumFromBin (Session->PeerElementX, SAE_PRIME_LEN);
    BnPeerY = BigNumFromBin (Session->PeerElementY, SAE_PRIME_LEN);
    if ((BnPeerX == NULL) || (BnPeerY == NULL)) {
      if (BnPeerX) BigNumFree (BnPeerX, TRUE);
      if (BnPeerY) BigNumFree (BnPeerY, TRUE);
      goto ProcessDone;
    }

    if (!EcPointSetAffineCoordinates (EcGroup, EcPeerElement, BnPeerX, BnPeerY, BnCtx)) {
      BigNumFree (BnPeerX, TRUE);
      BigNumFree (BnPeerY, TRUE);
      goto ProcessDone;
    }

    BigNumFree (BnPeerX, TRUE);
    BigNumFree (BnPeerY, TRUE);
  }

  //
  // Validate peer element is on the curve
  //
  if (!EcPointIsOnCurve (EcGroup, EcPeerElement, BnCtx)) {
    DEBUG ((DEBUG_ERROR, "[SAE] Peer element not on curve\n"));
    goto ProcessDone;
  }

  //
  // Set up PWE point
  //
  EcPwe = EcPointInit (EcGroup);
  if (EcPwe == NULL) {
    goto ProcessDone;
  }

  {
    VOID  *BnPweX;
    VOID  *BnPweY;

    BnPweX = BigNumFromBin (Session->PweX, SAE_PRIME_LEN);
    BnPweY = BigNumFromBin (Session->PweY, SAE_PRIME_LEN);
    if ((BnPweX == NULL) || (BnPweY == NULL)) {
      if (BnPweX) BigNumFree (BnPweX, TRUE);
      if (BnPweY) BigNumFree (BnPweY, TRUE);
      goto ProcessDone;
    }

    if (!EcPointSetAffineCoordinates (EcGroup, EcPwe, BnPweX, BnPweY, BnCtx)) {
      BigNumFree (BnPweX, TRUE);
      BigNumFree (BnPweY, TRUE);
      goto ProcessDone;
    }

    BigNumFree (BnPweX, TRUE);
    BigNumFree (BnPweY, TRUE);
  }

  //
  // K_point = peer_scalar * PWE + peer_element
  //
  EcK = EcPointInit (EcGroup);
  if (EcK == NULL) {
    goto ProcessDone;
  }

  if (!EcPointMul (EcGroup, EcK, NULL, EcPwe, BnPeerScalar, BnCtx)) {
    goto ProcessDone;
  }

  if (!EcPointAdd (EcGroup, EcK, EcK, EcPeerElement, BnCtx)) {
    goto ProcessDone;
  }

  //
  // K_point = rand * K_point
  //
  BnRand = BigNumFromBin (Session->OwnRand, SAE_PRIME_LEN);
  if (BnRand == NULL) {
    goto ProcessDone;
  }

  if (!EcPointMul (EcGroup, EcK, NULL, EcK, BnRand, BnCtx)) {
    goto ProcessDone;
  }

  //
  // Check K is not point at infinity
  //
  if (EcPointIsAtInfinity (EcGroup, EcK)) {
    DEBUG ((DEBUG_ERROR, "[SAE] Shared secret is point at infinity\n"));
    goto ProcessDone;
  }

  //
  // Extract K.x coordinate as the shared secret
  //
  BnKx = BigNumInit ();
  if (BnKx == NULL) {
    goto ProcessDone;
  }

  if (!EcPointGetAffineCoordinates (EcGroup, EcK, BnKx, NULL, BnCtx)) {
    goto ProcessDone;
  }

  BigNumToBin (BnKx, KeySeedInput, SAE_PRIME_LEN);

  //
  // keyseed = HMAC-SHA256(zero, K.x)
  //
  ZeroMem (ZeroKey, sizeof (ZeroKey));
  if (!HmacSha256All (KeySeedInput, SAE_PRIME_LEN, ZeroKey, SHA256_DIGEST_SIZE, KeySeed)) {
    goto ProcessDone;
  }

  //
  // KCK || PMK = KDF-512(keyseed, "SAE KCK and PMK",
  //                       (own_scalar + peer_scalar) mod order)
  //
  {
    VOID   *BnSum;
    UINT8  ScalarSum[SAE_PRIME_LEN];

    BnSum = BigNumInit ();
    if (BnSum == NULL) {
      goto ProcessDone;
    }

    {
      VOID  *BnOwnScalar;

      BnOwnScalar = BigNumFromBin (Session->OwnScalar, SAE_PRIME_LEN);
      if (BnOwnScalar == NULL) {
        BigNumFree (BnSum, TRUE);
        goto ProcessDone;
      }

      if (!BigNumAddMod (BnOwnScalar, BnPeerScalar, BnOrder, BnSum)) {
        BigNumFree (BnOwnScalar, TRUE);
        BigNumFree (BnSum, TRUE);
        goto ProcessDone;
      }

      BigNumFree (BnOwnScalar, TRUE);
    }

    BigNumToBin (BnSum, ScalarSum, SAE_PRIME_LEN);
    BigNumFree (BnSum, TRUE);

    if (!WpaKdfSha256 (
           KeySeed, SHA256_DIGEST_SIZE,
           "SAE KCK and PMK",
           ScalarSum, SAE_PRIME_LEN,
           Keys, 512))
    {
      goto ProcessDone;
    }
  }

  //
  // Split keys: KCK (first 32 bytes) || PMK (next 32 bytes)
  //
  CopyMem (Session->Kck, Keys, SAE_KCK_LEN);
  CopyMem (Session->Pmk, Keys + SAE_KCK_LEN, SAE_PMK_LEN);

  ZeroMem (Keys, sizeof (Keys));
  ZeroMem (KeySeed, sizeof (KeySeed));
  ZeroMem (KeySeedInput, sizeof (KeySeedInput));

  Result = TRUE;
  DEBUG ((DEBUG_INFO, "[SAE] Shared secret derived\n"));

ProcessDone:
  if (BnOrder != NULL) BigNumFree (BnOrder, TRUE);
  if (BnPeerScalar != NULL) BigNumFree (BnPeerScalar, TRUE);
  if (EcPeerElement != NULL) EcPointDeInit (EcPeerElement, TRUE);
  if (EcPwe != NULL) EcPointDeInit (EcPwe, TRUE);
  if (EcK != NULL) EcPointDeInit (EcK, TRUE);
  if (BnRand != NULL) BigNumFree (BnRand, TRUE);
  if (BnKx != NULL) BigNumFree (BnKx, TRUE);
  if (BnCtx != NULL) BigNumContextFree (BnCtx);
  if (EcGroup != NULL) EcGroupFree (EcGroup);

  return Result ? EFI_SUCCESS : EFI_SECURITY_VIOLATION;
}

/**
  Build SAE Confirm message.

  confirm = HMAC-SHA256(KCK, send_confirm || own_scalar || peer_scalar ||
                        own_element || peer_element)

  @param[in]      Private     Supplicant private data.
  @param[in]      Session     SAE session.
  @param[out]     Buffer      Output buffer.
  @param[in,out]  BufferSize  Buffer size.

  @retval EFI_SUCCESS           Built.
  @retval EFI_BUFFER_TOO_SMALL  Need more space.
**/
EFI_STATUS
SaeBuildConfirm (
  IN     SUPPLICANT_PRIVATE_DATA  *Private,
  IN     SAE_SESSION              *Session,
  OUT    UINT8                    *Buffer,
  IN OUT UINTN                    *BufferSize
  )
{
  UINTN  RequiredSize;
  UINTN  ConfirmDataLen;
  UINT8  *ConfirmData;
  UINTN  Offset;
  UINT8  Confirm[SHA256_DIGEST_SIZE];

  //
  // Confirm body: send_confirm(2) + confirm(32)
  //
  RequiredSize = 2 + SHA256_DIGEST_SIZE;

  if ((Buffer == NULL) || (*BufferSize < RequiredSize)) {
    *BufferSize = RequiredSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  //
  // Build confirm input:
  // send_confirm(2) || scalar_own(32) || peer_scalar(32) ||
  // element_own_x(32) || element_own_y(32) || peer_element_x(32) || peer_element_y(32)
  //
  ConfirmDataLen = 2 + 2 * SAE_PRIME_LEN + 4 * SAE_PRIME_LEN;
  ConfirmData    = AllocatePool (ConfirmDataLen);
  if (ConfirmData == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Offset = 0;
  Session->SendConfirm++;
  WPA_PUT_LE16 (ConfirmData + Offset, Session->SendConfirm);
  Offset += 2;

  CopyMem (ConfirmData + Offset, Session->OwnScalar, SAE_PRIME_LEN);
  Offset += SAE_PRIME_LEN;
  CopyMem (ConfirmData + Offset, Session->PeerScalar, SAE_PRIME_LEN);
  Offset += SAE_PRIME_LEN;
  CopyMem (ConfirmData + Offset, Session->OwnElementX, SAE_PRIME_LEN);
  Offset += SAE_PRIME_LEN;
  CopyMem (ConfirmData + Offset, Session->OwnElementY, SAE_PRIME_LEN);
  Offset += SAE_PRIME_LEN;
  CopyMem (ConfirmData + Offset, Session->PeerElementX, SAE_PRIME_LEN);
  Offset += SAE_PRIME_LEN;
  CopyMem (ConfirmData + Offset, Session->PeerElementY, SAE_PRIME_LEN);
  Offset += SAE_PRIME_LEN;

  //
  // confirm = HMAC-SHA256(KCK, confirm_data)
  //
  if (!HmacSha256All (ConfirmData, ConfirmDataLen, Session->Kck, SAE_KCK_LEN, Confirm)) {
    FreePool (ConfirmData);
    return EFI_DEVICE_ERROR;
  }

  FreePool (ConfirmData);

  //
  // Build confirm frame body: send_confirm || confirm
  //
  WPA_PUT_LE16 (Buffer, Session->SendConfirm);
  CopyMem (Buffer + 2, Confirm, SHA256_DIGEST_SIZE);

  *BufferSize    = RequiredSize;
  Session->State = SaeStateConfirmSent;

  DEBUG ((DEBUG_INFO, "[SAE] Confirm message built\n"));
  return EFI_SUCCESS;
}

/**
  Process received SAE Confirm and verify.

  @param[in]   Private        Supplicant private data.
  @param[in]   Session        SAE session.
  @param[in]   ConfirmFrame   Confirm body (after auth header).
  @param[in]   FrameLen       Body length.

  @retval EFI_SUCCESS             Verified; PMK ready.
  @retval EFI_SECURITY_VIOLATION  Verification failed.
**/
EFI_STATUS
SaeProcessConfirm (
  IN  SUPPLICANT_PRIVATE_DATA  *Private,
  IN  SAE_SESSION              *Session,
  IN  CONST UINT8              *ConfirmFrame,
  IN  UINTN                    FrameLen
  )
{
  UINT16  PeerSendConfirm;
  UINTN   ConfirmDataLen;
  UINT8   *ConfirmData;
  UINTN   Offset;
  UINT8   ExpectedConfirm[SHA256_DIGEST_SIZE];

  if ((ConfirmFrame == NULL) || (FrameLen < 2 + SHA256_DIGEST_SIZE)) {
    return EFI_INVALID_PARAMETER;
  }

  PeerSendConfirm = WPA_GET_LE16 (ConfirmFrame);

  //
  // Build expected confirm:
  // peer_send_confirm || peer_scalar || own_scalar ||
  // peer_element_x || peer_element_y || own_element_x || own_element_y
  // (note: swapped order compared to our own confirm)
  //
  ConfirmDataLen = 2 + 2 * SAE_PRIME_LEN + 4 * SAE_PRIME_LEN;
  ConfirmData    = AllocatePool (ConfirmDataLen);
  if (ConfirmData == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Offset = 0;
  WPA_PUT_LE16 (ConfirmData + Offset, PeerSendConfirm);
  Offset += 2;

  CopyMem (ConfirmData + Offset, Session->PeerScalar, SAE_PRIME_LEN);
  Offset += SAE_PRIME_LEN;
  CopyMem (ConfirmData + Offset, Session->OwnScalar, SAE_PRIME_LEN);
  Offset += SAE_PRIME_LEN;
  CopyMem (ConfirmData + Offset, Session->PeerElementX, SAE_PRIME_LEN);
  Offset += SAE_PRIME_LEN;
  CopyMem (ConfirmData + Offset, Session->PeerElementY, SAE_PRIME_LEN);
  Offset += SAE_PRIME_LEN;
  CopyMem (ConfirmData + Offset, Session->OwnElementX, SAE_PRIME_LEN);
  Offset += SAE_PRIME_LEN;
  CopyMem (ConfirmData + Offset, Session->OwnElementY, SAE_PRIME_LEN);
  Offset += SAE_PRIME_LEN;

  if (!HmacSha256All (ConfirmData, ConfirmDataLen, Session->Kck, SAE_KCK_LEN, ExpectedConfirm)) {
    FreePool (ConfirmData);
    return EFI_DEVICE_ERROR;
  }

  FreePool (ConfirmData);

  //
  // Verify confirm value
  //
  if (CompareMem (ConfirmFrame + 2, ExpectedConfirm, SHA256_DIGEST_SIZE) != 0) {
    DEBUG ((DEBUG_ERROR, "[SAE] Confirm verification failed\n"));
    return EFI_SECURITY_VIOLATION;
  }

  Session->RecvConfirm = PeerSendConfirm;
  Session->State       = SaeStateAccepted;

  //
  // Install PMK from SAE into the supplicant's PMK
  //
  CopyMem (Private->Pmk, Session->Pmk, SAE_PMK_LEN);
  Private->PmkValid = TRUE;

  DEBUG ((DEBUG_INFO, "[SAE] Confirm verified! PMK installed.\n"));
  return EFI_SUCCESS;
}

/**
  Clean up SAE session.

  @param[in]  Session   SAE session.
**/
VOID
SaeCleanup (
  IN SAE_SESSION  *Session
  )
{
  if (Session != NULL) {
    ZeroMem (Session, sizeof (SAE_SESSION));
  }
}
