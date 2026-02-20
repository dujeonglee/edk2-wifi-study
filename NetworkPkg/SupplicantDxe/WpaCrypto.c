/** @file
  WPA Cryptographic Primitive Implementations.

  Implements PRF-SHA1, KDF-SHA256, PBKDF2, AES-128-CMAC, AES Key Wrap/Unwrap,
  CCMP (AES-CCM) encrypt/decrypt for WPA2/WPA3-Personal, plus RC4, HMAC-MD5,
  Michael MIC, TKIP, and WEP for WPA1/legacy cipher support.

  Reference: IEEE 802.11-2020, RFC 3394, RFC 4493, wpa_supplicant

  WARNING: TKIP and WEP are cryptographically broken protocols. This
  implementation exists solely for interoperability with legacy deployments.
  Do NOT use TKIP or WEP in new network configurations.

  Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseCryptLib.h>

#include "WpaCrypto.h"

//
// SHA1 digest size
//
#define SHA1_DIGEST_SIZE    20
#define SHA256_DIGEST_SIZE  32

//
// AES Key Wrap default IV (RFC 3394 Section 2.2.3.1)
//
STATIC CONST UINT8  mAesKeyWrapIv[8] = {
  0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
};

//
// AES-CMAC constant Rb for 128-bit block (RFC 4493)
//
#define AES_CMAC_RB  0x87

/**
  Encrypt a single 16-byte block using AES-ECB.
  Implemented using AES-CBC with zero IV on a single block.

  @param[in]   Key     16-byte AES key.
  @param[in]   Input   16-byte input block.
  @param[out]  Output  16-byte output block.

  @retval TRUE   Encryption succeeded.
  @retval FALSE  Encryption failed.
**/
BOOLEAN
WpaAesEncryptBlock (
  IN  CONST UINT8  *Key,
  IN  CONST UINT8  *Input,
  OUT UINT8        *Output
  )
{
  VOID   *AesCtx;
  UINTN  CtxSize;
  UINT8  Iv[AES_BLOCK_SIZE];
  BOOLEAN Result;

  if ((Key == NULL) || (Input == NULL) || (Output == NULL)) {
    return FALSE;
  }

  CtxSize = AesGetContextSize ();
  if (CtxSize == 0) {
    return FALSE;
  }

  AesCtx = AllocatePool (CtxSize);
  if (AesCtx == NULL) {
    return FALSE;
  }

  ZeroMem (Iv, sizeof (Iv));

  Result = AesInit (AesCtx, Key, 128);
  if (Result) {
    Result = AesCbcEncrypt (AesCtx, Input, AES_BLOCK_SIZE, Iv, Output);
  }

  FreePool (AesCtx);
  return Result;
}

/**
  Left-shift a 16-byte value by 1 bit.

  @param[in]   Input    16-byte input.
  @param[out]  Output   16-byte output (may alias Input).
**/
STATIC
VOID
ShiftLeft128 (
  IN  CONST UINT8  *Input,
  OUT UINT8        *Output
  )
{
  UINT8  Overflow;
  INTN   Index;

  Overflow = 0;
  for (Index = AES_BLOCK_SIZE - 1; Index >= 0; Index--) {
    Output[Index] = (UINT8)((Input[Index] << 1) | Overflow);
    Overflow = (Input[Index] & 0x80) ? 1 : 0;
  }
}

/**
  XOR two 16-byte blocks: Output = A ^ B.
**/
STATIC
VOID
Xor128 (
  IN  CONST UINT8  *A,
  IN  CONST UINT8  *B,
  OUT UINT8        *Output
  )
{
  UINTN  Index;

  for (Index = 0; Index < AES_BLOCK_SIZE; Index++) {
    Output[Index] = A[Index] ^ B[Index];
  }
}

/**
  Compute AES-128-CMAC (RFC 4493).

  @param[in]   Key       16-byte AES key.
  @param[in]   Data      Input data.
  @param[in]   DataLen   Length of input data.
  @param[out]  Mac       16-byte output MAC.

  @retval TRUE   CMAC computation succeeded.
  @retval FALSE  CMAC computation failed.
**/
BOOLEAN
WpaAesCmac (
  IN  CONST UINT8  *Key,
  IN  CONST UINT8  *Data,
  IN  UINTN        DataLen,
  OUT UINT8        *Mac
  )
{
  UINT8    L[AES_BLOCK_SIZE];
  UINT8    K1[AES_BLOCK_SIZE];
  UINT8    K2[AES_BLOCK_SIZE];
  UINT8    X[AES_BLOCK_SIZE];
  UINT8    Y[AES_BLOCK_SIZE];
  UINT8    MLast[AES_BLOCK_SIZE];
  UINT8    Pad[AES_BLOCK_SIZE];
  UINTN    NumBlocks;
  UINTN    Index;
  BOOLEAN  Complete;

  if ((Key == NULL) || (Mac == NULL)) {
    return FALSE;
  }

  if ((Data == NULL) && (DataLen > 0)) {
    return FALSE;
  }

  //
  // Generate sub-keys K1 and K2
  //
  ZeroMem (L, sizeof (L));
  if (!WpaAesEncryptBlock (Key, L, L)) {
    return FALSE;
  }

  ShiftLeft128 (L, K1);
  if (L[0] & 0x80) {
    K1[AES_BLOCK_SIZE - 1] ^= AES_CMAC_RB;
  }

  ShiftLeft128 (K1, K2);
  if (K1[0] & 0x80) {
    K2[AES_BLOCK_SIZE - 1] ^= AES_CMAC_RB;
  }

  //
  // Determine number of blocks
  //
  NumBlocks = (DataLen + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
  if (NumBlocks == 0) {
    NumBlocks = 1;
    Complete  = FALSE;
  } else {
    Complete = ((DataLen % AES_BLOCK_SIZE) == 0);
  }

  //
  // Compute M_last
  //
  if (Complete) {
    Xor128 (Data + (NumBlocks - 1) * AES_BLOCK_SIZE, K1, MLast);
  } else {
    ZeroMem (Pad, sizeof (Pad));
    if (DataLen > 0) {
      CopyMem (Pad, Data + (NumBlocks - 1) * AES_BLOCK_SIZE, DataLen % AES_BLOCK_SIZE);
    }

    Pad[DataLen % AES_BLOCK_SIZE] = 0x80;
    Xor128 (Pad, K2, MLast);
  }

  //
  // CBC-MAC computation
  //
  ZeroMem (X, sizeof (X));
  for (Index = 0; Index < NumBlocks - 1; Index++) {
    Xor128 (X, Data + Index * AES_BLOCK_SIZE, Y);
    if (!WpaAesEncryptBlock (Key, Y, X)) {
      return FALSE;
    }
  }

  Xor128 (X, MLast, Y);
  if (!WpaAesEncryptBlock (Key, Y, Mac)) {
    return FALSE;
  }

  return TRUE;
}

/**
  Compute HMAC-SHA1-128 MIC for WPA2-PSK (Key Descriptor Version 2).

  @param[in]   Key       KCK (16 bytes).
  @param[in]   Data      EAPOL frame with MIC field zeroed.
  @param[in]   DataLen   Length of data.
  @param[out]  Mic       16-byte MIC output.

  @retval TRUE   MIC computation succeeded.
  @retval FALSE  MIC computation failed.
**/
BOOLEAN
WpaHmacSha1Mic (
  IN  CONST UINT8  *Key,
  IN  CONST UINT8  *Data,
  IN  UINTN        DataLen,
  OUT UINT8        *Mic
  )
{
  VOID     *HmacCtx;
  UINT8    HashValue[SHA1_DIGEST_SIZE];
  UINTN    HashSize;
  BOOLEAN  Result;

  if ((Key == NULL) || (Data == NULL) || (Mic == NULL)) {
    return FALSE;
  }

  //
  // Use HMAC-SHA256 is not available for SHA1 in BaseCryptLib HMAC APIs,
  // so we use the SHA1 hash-based approach.
  // Actually, BaseCryptLib provides HmacSha256 but not HmacSha1.
  // For WPA2-PSK, we need HMAC-SHA1-128. We implement this using
  // the Sha1 primitives directly.
  //
  HashSize = Sha1GetContextSize ();
  if (HashSize == 0) {
    return FALSE;
  }

  //
  // HMAC-SHA1 implementation using SHA1 primitives:
  // HMAC(K, M) = SHA1((K ^ opad) || SHA1((K ^ ipad) || M))
  //
  {
    VOID   *Sha1Ctx;
    UINT8  KeyBuf[64];
    UINT8  IPad[64];
    UINT8  OPad[64];
    UINT8  InnerHash[SHA1_DIGEST_SIZE];
    UINTN  Index;

    ZeroMem (KeyBuf, sizeof (KeyBuf));
    CopyMem (KeyBuf, Key, WPA_KCK_LEN);

    for (Index = 0; Index < 64; Index++) {
      IPad[Index] = KeyBuf[Index] ^ 0x36;
      OPad[Index] = KeyBuf[Index] ^ 0x5C;
    }

    Sha1Ctx = AllocatePool (HashSize);
    if (Sha1Ctx == NULL) {
      return FALSE;
    }

    //
    // Inner hash: SHA1(ipad || message)
    //
    Result = Sha1Init (Sha1Ctx);
    if (Result) {
      Result = Sha1Update (Sha1Ctx, IPad, 64);
    }

    if (Result) {
      Result = Sha1Update (Sha1Ctx, Data, DataLen);
    }

    if (Result) {
      Result = Sha1Final (Sha1Ctx, InnerHash);
    }

    if (!Result) {
      FreePool (Sha1Ctx);
      return FALSE;
    }

    //
    // Outer hash: SHA1(opad || inner_hash)
    //
    Result = Sha1Init (Sha1Ctx);
    if (Result) {
      Result = Sha1Update (Sha1Ctx, OPad, 64);
    }

    if (Result) {
      Result = Sha1Update (Sha1Ctx, InnerHash, SHA1_DIGEST_SIZE);
    }

    if (Result) {
      Result = Sha1Final (Sha1Ctx, HashValue);
    }

    FreePool (Sha1Ctx);

    if (!Result) {
      return FALSE;
    }

    //
    // Truncate to 128 bits (16 bytes)
    //
    CopyMem (Mic, HashValue, WPA_MIC_LEN);
    return TRUE;
  }
}

/**
  PRF-X using HMAC-SHA1 (IEEE 802.11-2020 Section 12.7.1.2).

  PRF(K, A, B, Len) = HMAC-SHA1(K, A || 0x00 || B || i)
  where i = 0, 1, ... ceil(Len/160)-1

  @param[in]   Key        PMK.
  @param[in]   KeyLen     Length of Key.
  @param[in]   Label      Null-terminated label.
  @param[in]   Data       Concatenated data.
  @param[in]   DataLen    Length of Data.
  @param[out]  Output     Derived key output.
  @param[in]   OutputLen  Desired output length in bytes.

  @retval TRUE   Succeeded.
  @retval FALSE  Failed.
**/
BOOLEAN
WpaPrfSha1 (
  IN  CONST UINT8  *Key,
  IN  UINTN        KeyLen,
  IN  CONST CHAR8  *Label,
  IN  CONST UINT8  *Data,
  IN  UINTN        DataLen,
  OUT UINT8        *Output,
  IN  UINTN        OutputLen
  )
{
  UINTN   LabelLen;
  UINTN   MsgLen;
  UINT8   *Msg;
  UINT8   Counter;
  UINTN   BytesGenerated;
  UINT8   HmacResult[SHA1_DIGEST_SIZE];
  UINTN   CopyLen;
  VOID    *Sha1Ctx;
  UINTN   Sha1CtxSize;
  UINT8   KeyBuf[64];
  UINT8   IPad[64];
  UINT8   OPad[64];
  UINT8   InnerHash[SHA1_DIGEST_SIZE];
  UINTN   Index;
  BOOLEAN Result;

  if ((Key == NULL) || (Label == NULL) || (Data == NULL) || (Output == NULL)) {
    return FALSE;
  }

  LabelLen = AsciiStrLen (Label);

  //
  // Construct message: Label || 0x00 || Data || Counter
  //
  MsgLen = LabelLen + 1 + DataLen + 1;
  Msg    = AllocatePool (MsgLen);
  if (Msg == NULL) {
    return FALSE;
  }

  CopyMem (Msg, Label, LabelLen);
  Msg[LabelLen] = 0x00;
  CopyMem (Msg + LabelLen + 1, Data, DataLen);
  // Counter byte will be set in loop

  //
  // Prepare key for HMAC
  //
  ZeroMem (KeyBuf, sizeof (KeyBuf));
  if (KeyLen <= 64) {
    CopyMem (KeyBuf, Key, KeyLen);
  } else {
    //
    // Key > 64 bytes: hash it first (rare for WPA)
    //
    FreePool (Msg);
    return FALSE;
  }

  for (Index = 0; Index < 64; Index++) {
    IPad[Index] = KeyBuf[Index] ^ 0x36;
    OPad[Index] = KeyBuf[Index] ^ 0x5C;
  }

  Sha1CtxSize = Sha1GetContextSize ();
  Sha1Ctx     = AllocatePool (Sha1CtxSize);
  if (Sha1Ctx == NULL) {
    FreePool (Msg);
    return FALSE;
  }

  BytesGenerated = 0;
  Counter        = 0;

  while (BytesGenerated < OutputLen) {
    Msg[MsgLen - 1] = Counter;

    //
    // HMAC-SHA1(Key, Msg)
    //
    Result = Sha1Init (Sha1Ctx);
    if (Result) {
      Result = Sha1Update (Sha1Ctx, IPad, 64);
    }

    if (Result) {
      Result = Sha1Update (Sha1Ctx, Msg, MsgLen);
    }

    if (Result) {
      Result = Sha1Final (Sha1Ctx, InnerHash);
    }

    if (Result) {
      Result = Sha1Init (Sha1Ctx);
    }

    if (Result) {
      Result = Sha1Update (Sha1Ctx, OPad, 64);
    }

    if (Result) {
      Result = Sha1Update (Sha1Ctx, InnerHash, SHA1_DIGEST_SIZE);
    }

    if (Result) {
      Result = Sha1Final (Sha1Ctx, HmacResult);
    }

    if (!Result) {
      FreePool (Sha1Ctx);
      FreePool (Msg);
      return FALSE;
    }

    CopyLen = OutputLen - BytesGenerated;
    if (CopyLen > SHA1_DIGEST_SIZE) {
      CopyLen = SHA1_DIGEST_SIZE;
    }

    CopyMem (Output + BytesGenerated, HmacResult, CopyLen);
    BytesGenerated += CopyLen;
    Counter++;
  }

  FreePool (Sha1Ctx);
  FreePool (Msg);
  return TRUE;
}

/**
  KDF-X using HMAC-SHA256 (IEEE 802.11-2020 Section 12.7.1.7.2).

  @param[in]   Key         PMK.
  @param[in]   KeyLen      Length of Key.
  @param[in]   Label       Null-terminated label.
  @param[in]   Context     Context data.
  @param[in]   CtxLen      Length of Context.
  @param[out]  Output      Derived key output.
  @param[in]   OutputBits  Desired output length in bits.

  @retval TRUE   Succeeded.
  @retval FALSE  Failed.
**/
BOOLEAN
WpaKdfSha256 (
  IN  CONST UINT8  *Key,
  IN  UINTN        KeyLen,
  IN  CONST CHAR8  *Label,
  IN  CONST UINT8  *Context,
  IN  UINTN        CtxLen,
  OUT UINT8        *Output,
  IN  UINTN        OutputBits
  )
{
  UINTN   LabelLen;
  UINTN   OutputLen;
  UINT16  Iterations;
  UINT16  Counter;
  UINTN   MsgLen;
  UINT8   *Msg;
  UINTN   Offset;
  UINT8   HmacResult[SHA256_DIGEST_SIZE];
  UINTN   CopyLen;
  UINTN   BytesGenerated;

  if ((Key == NULL) || (Label == NULL) || (Context == NULL) || (Output == NULL)) {
    return FALSE;
  }

  LabelLen  = AsciiStrLen (Label);
  OutputLen = (OutputBits + 7) / 8;

  Iterations = (UINT16)((OutputBits + 255) / 256);

  //
  // Message: Counter(LE16) || Label || Context || OutputBits(LE16)
  //
  MsgLen = 2 + LabelLen + CtxLen + 2;
  Msg    = AllocatePool (MsgLen);
  if (Msg == NULL) {
    return FALSE;
  }

  //
  // Set Label and Context (these don't change per iteration)
  //
  CopyMem (Msg + 2, Label, LabelLen);
  CopyMem (Msg + 2 + LabelLen, Context, CtxLen);
  WPA_PUT_LE16 (Msg + 2 + LabelLen + CtxLen, (UINT16)OutputBits);

  BytesGenerated = 0;

  for (Counter = 1; Counter <= Iterations; Counter++) {
    WPA_PUT_LE16 (Msg, Counter);

    if (!HmacSha256All (Msg, MsgLen, Key, KeyLen, HmacResult)) {
      FreePool (Msg);
      return FALSE;
    }

    CopyLen = OutputLen - BytesGenerated;
    if (CopyLen > SHA256_DIGEST_SIZE) {
      CopyLen = SHA256_DIGEST_SIZE;
    }

    CopyMem (Output + BytesGenerated, HmacResult, CopyLen);
    BytesGenerated += CopyLen;
  }

  FreePool (Msg);
  return TRUE;
}

/**
  Derive PMK from passphrase using PBKDF2-SHA1.

  @param[in]   Passphrase   ASCII passphrase.
  @param[in]   Ssid         SSID.
  @param[in]   SsidLen      SSID length.
  @param[out]  Pmk          32-byte PMK output.

  @retval TRUE   Succeeded.
  @retval FALSE  Failed.
**/
BOOLEAN
WpaDerivePmk (
  IN  CONST CHAR8  *Passphrase,
  IN  CONST UINT8  *Ssid,
  IN  UINTN        SsidLen,
  OUT UINT8        *Pmk
  )
{
  UINTN  PassLen;

  if ((Passphrase == NULL) || (Ssid == NULL) || (Pmk == NULL)) {
    return FALSE;
  }

  PassLen = AsciiStrLen (Passphrase);
  if ((PassLen < 8) || (PassLen > WPA_MAX_PASSWORD_LEN)) {
    return FALSE;
  }

  //
  // PMK = PBKDF2(HMAC-SHA1, Passphrase, SSID, 4096, 256)
  //
  return Pkcs5HashPassword (
           PassLen,
           Passphrase,
           SsidLen,
           Ssid,
           WPA2_PBKDF2_ITERATIONS,
           SHA1_DIGEST_SIZE,
           WPA_PMK_LEN,
           Pmk
           );
}

/**
  AES Key Wrap (RFC 3394).

  @param[in]   Kek          16-byte KEK.
  @param[in]   Plaintext    Data to wrap.
  @param[in]   PlainLen     Data length (multiple of 8).
  @param[out]  Ciphertext   Wrapped output (PlainLen + 8).

  @retval TRUE   Succeeded.
  @retval FALSE  Failed.
**/
BOOLEAN
WpaAesKeyWrap (
  IN  CONST UINT8  *Kek,
  IN  CONST UINT8  *Plaintext,
  IN  UINTN        PlainLen,
  OUT UINT8        *Ciphertext
  )
{
  UINT8   *R;
  UINT8   A[8];
  UINT8   B[AES_BLOCK_SIZE];
  UINT8   Input[AES_BLOCK_SIZE];
  UINTN   N;
  UINTN   J;
  UINTN   I;
  UINT64  T;

  if ((Kek == NULL) || (Plaintext == NULL) || (Ciphertext == NULL)) {
    return FALSE;
  }

  if ((PlainLen == 0) || (PlainLen % 8 != 0)) {
    return FALSE;
  }

  N = PlainLen / 8;

  //
  // Initialize: A = IV, R[i] = P[i]
  //
  CopyMem (A, mAesKeyWrapIv, 8);

  R = AllocatePool (PlainLen);
  if (R == NULL) {
    return FALSE;
  }

  CopyMem (R, Plaintext, PlainLen);

  //
  // Wrap: for j = 0 to 5, for i = 1 to n
  //
  T = 0;
  for (J = 0; J < 6; J++) {
    for (I = 0; I < N; I++) {
      T++;

      CopyMem (Input, A, 8);
      CopyMem (Input + 8, R + I * 8, 8);

      if (!WpaAesEncryptBlock (Kek, Input, B)) {
        FreePool (R);
        return FALSE;
      }

      CopyMem (A, B, 8);
      A[7] ^= (UINT8)(T & 0xFF);
      A[6] ^= (UINT8)((T >> 8) & 0xFF);
      A[5] ^= (UINT8)((T >> 16) & 0xFF);
      A[4] ^= (UINT8)((T >> 24) & 0xFF);

      CopyMem (R + I * 8, B + 8, 8);
    }
  }

  CopyMem (Ciphertext, A, 8);
  CopyMem (Ciphertext + 8, R, PlainLen);

  FreePool (R);
  return TRUE;
}

/**
  AES Key Unwrap (RFC 3394).

  @param[in]   Kek          16-byte KEK.
  @param[in]   Ciphertext   Wrapped data.
  @param[in]   CipherLen    Wrapped data length (multiple of 8, >= 16).
  @param[out]  Plaintext    Unwrapped output (CipherLen - 8).

  @retval TRUE   Succeeded and integrity verified.
  @retval FALSE  Failed or integrity check failed.
**/
BOOLEAN
WpaAesKeyUnwrap (
  IN  CONST UINT8  *Kek,
  IN  CONST UINT8  *Ciphertext,
  IN  UINTN        CipherLen,
  OUT UINT8        *Plaintext
  )
{
  UINT8    *R;
  UINT8    A[8];
  UINT8    B[AES_BLOCK_SIZE];
  UINT8    Input[AES_BLOCK_SIZE];
  UINTN    N;
  INTN     J;
  INTN     I;
  UINT64   T;
  VOID     *AesCtx;
  UINTN    CtxSize;
  UINT8    Iv[AES_BLOCK_SIZE];

  if ((Kek == NULL) || (Ciphertext == NULL) || (Plaintext == NULL)) {
    return FALSE;
  }

  if ((CipherLen < 16) || (CipherLen % 8 != 0)) {
    return FALSE;
  }

  N = (CipherLen / 8) - 1;

  //
  // Initialize: A = C[0], R[i] = C[i]
  //
  CopyMem (A, Ciphertext, 8);

  R = AllocatePool (N * 8);
  if (R == NULL) {
    return FALSE;
  }

  CopyMem (R, Ciphertext + 8, N * 8);

  //
  // Set up AES context for decryption
  //
  CtxSize = AesGetContextSize ();
  AesCtx  = AllocatePool (CtxSize);
  if (AesCtx == NULL) {
    FreePool (R);
    return FALSE;
  }

  if (!AesInit (AesCtx, Kek, 128)) {
    FreePool (AesCtx);
    FreePool (R);
    return FALSE;
  }

  //
  // Unwrap: for j = 5 downto 0, for i = n downto 1
  //
  T = (UINT64)N * 6;
  for (J = 5; J >= 0; J--) {
    for (I = (INTN)N - 1; I >= 0; I--) {
      A[7] ^= (UINT8)(T & 0xFF);
      A[6] ^= (UINT8)((T >> 8) & 0xFF);
      A[5] ^= (UINT8)((T >> 16) & 0xFF);
      A[4] ^= (UINT8)((T >> 24) & 0xFF);
      T--;

      CopyMem (Input, A, 8);
      CopyMem (Input + 8, R + I * 8, 8);

      //
      // AES-ECB decrypt: use CBC with zero IV on single block
      //
      ZeroMem (Iv, sizeof (Iv));
      if (!AesCbcDecrypt (AesCtx, Input, AES_BLOCK_SIZE, Iv, B)) {
        FreePool (AesCtx);
        FreePool (R);
        return FALSE;
      }

      CopyMem (A, B, 8);
      CopyMem (R + I * 8, B + 8, 8);
    }
  }

  FreePool (AesCtx);

  //
  // Verify integrity: A must equal the default IV
  //
  if (CompareMem (A, mAesKeyWrapIv, 8) != 0) {
    FreePool (R);
    return FALSE;
  }

  CopyMem (Plaintext, R, N * 8);
  FreePool (R);
  return TRUE;
}

/**
  Construct CCMP nonce (13 bytes) for AES-CCM.
  Nonce = Priority(1) || A2(6) || PN(6)

  @param[in]   Priority  QoS priority.
  @param[in]   A2        Source address (6 bytes).
  @param[in]   Pn        Packet Number (6 bytes).
  @param[out]  Nonce     13-byte nonce output.
**/
STATIC
VOID
CcmpBuildNonce (
  IN  UINT8        Priority,
  IN  CONST UINT8  *A2,
  IN  CONST UINT8  *Pn,
  OUT UINT8        *Nonce
  )
{
  Nonce[0] = Priority;
  CopyMem (Nonce + 1, A2, WPA_MAC_ADDR_LEN);
  CopyMem (Nonce + 7, Pn, CCMP_PN_LEN);
}

/**
  Construct Additional Authentication Data (AAD) for CCMP.
  AAD is constructed from the 802.11 MAC header with mutable fields masked.

  For simplicity, we construct a minimal AAD from the header.

  @param[in]   Header      802.11 header.
  @param[in]   HeaderLen   Header length.
  @param[out]  Aad         AAD output buffer (must be at least HeaderLen + 2 bytes).
  @param[out]  AadLen      AAD output length.
**/
STATIC
VOID
CcmpBuildAad (
  IN  CONST UINT8  *Header,
  IN  UINTN        HeaderLen,
  OUT UINT8        *Aad,
  OUT UINTN        *AadLen
  )
{
  UINT16  FcMasked;

  //
  // AAD consists of the masked Frame Control, A1, A2, masked Sequence Control, A3
  // For simplicity, copy the header and mask mutable fields.
  //
  if (HeaderLen < 24) {
    *AadLen = 0;
    return;
  }

  //
  // AAD format: FC(masked) || A1 || A2 || SC(masked) || A3
  //
  // Mask FC: clear Subtype/Retry/PwrMgt/MoreData/Protected bits
  //
  FcMasked = WPA_GET_LE16 (Header);
  FcMasked &= ~(0x0070 | 0x0800 | 0x1000 | 0x2000 | 0x4000);
  WPA_PUT_LE16 (Aad, FcMasked);

  //
  // A1, A2 (12 bytes from offset 4)
  //
  CopyMem (Aad + 2, Header + 4, 12);

  //
  // Masked Sequence Control: clear sequence number, keep fragment number
  //
  Aad[14] = Header[22] & 0x0F;
  Aad[15] = 0;

  //
  // A3 (6 bytes from offset 16)
  //
  CopyMem (Aad + 16, Header + 16, 6);

  *AadLen = 22;

  //
  // If header has A4 (ToDS and FromDS both set), include it
  //
  if (HeaderLen >= 30 && (Header[1] & 0x03) == 0x03) {
    CopyMem (Aad + 22, Header + 24, 6);
    *AadLen = 28;
  }
}

/**
  AES-CCM core encryption/decryption for CCMP.

  This implements the AES-CCM mode with M=8 (8-byte MIC), L=2.

  @param[in]   Key        16-byte AES key.
  @param[in]   Nonce      13-byte nonce.
  @param[in]   Aad        Additional authenticated data.
  @param[in]   AadLen     AAD length.
  @param[in]   Input      Input data.
  @param[in]   InputLen   Input data length.
  @param[out]  Output     Output data.
  @param[out]  Mic        8-byte MIC (for encryption) or NULL (for decryption verify).
  @param[in]   Encrypt    TRUE for encryption, FALSE for decryption.

  @retval TRUE   Operation succeeded.
  @retval FALSE  Operation failed.
**/
STATIC
BOOLEAN
AesCcmProcess (
  IN  CONST UINT8  *Key,
  IN  CONST UINT8  *Nonce,
  IN  CONST UINT8  *Aad,
  IN  UINTN        AadLen,
  IN  CONST UINT8  *Input,
  IN  UINTN        InputLen,
  OUT UINT8        *Output,
  IN OUT UINT8     *Mic,
  IN  BOOLEAN      Encrypt
  )
{
  UINT8   B[AES_BLOCK_SIZE];
  UINT8   A[AES_BLOCK_SIZE];
  UINT8   S[AES_BLOCK_SIZE];
  UINT8   T[AES_BLOCK_SIZE];
  UINTN   Index;
  UINTN   BlockIndex;
  UINTN   Remaining;
  UINT16  Counter;

  //
  // Construct B0 for CBC-MAC:
  // Flags = 8*((M-2)/2) + (L-1) = 8*3 + 1 = 0x19 (M=8, L=2)
  // If AAD present, set Adata flag: 0x19 | 0x40 = 0x59
  //
  ZeroMem (B, sizeof (B));
  B[0] = 0x19;
  if (AadLen > 0) {
    B[0] |= 0x40;
  }

  CopyMem (B + 1, Nonce, 13);

  //
  // L field: message length in 2 bytes (big-endian)
  //
  if (Encrypt) {
    WPA_PUT_BE16 (B + 14, (UINT16)InputLen);
  } else {
    WPA_PUT_BE16 (B + 14, (UINT16)InputLen);
  }

  //
  // Start CBC-MAC: T = AES(K, B0)
  //
  if (!WpaAesEncryptBlock (Key, B, T)) {
    return FALSE;
  }

  //
  // Process AAD (if present)
  //
  if (AadLen > 0) {
    ZeroMem (B, sizeof (B));
    //
    // AAD length encoding (assuming AadLen < 0xFF00)
    //
    WPA_PUT_BE16 (B, (UINT16)AadLen);
    Remaining = AadLen;
    if (Remaining > 14) {
      Remaining = 14;
    }

    CopyMem (B + 2, Aad, Remaining);

    //
    // XOR and encrypt
    //
    for (Index = 0; Index < AES_BLOCK_SIZE; Index++) {
      T[Index] ^= B[Index];
    }

    if (!WpaAesEncryptBlock (Key, T, T)) {
      return FALSE;
    }

    //
    // Remaining AAD blocks
    //
    BlockIndex = Remaining;
    while (BlockIndex < AadLen) {
      ZeroMem (B, sizeof (B));
      Remaining = AadLen - BlockIndex;
      if (Remaining > AES_BLOCK_SIZE) {
        Remaining = AES_BLOCK_SIZE;
      }

      CopyMem (B, Aad + BlockIndex, Remaining);

      for (Index = 0; Index < AES_BLOCK_SIZE; Index++) {
        T[Index] ^= B[Index];
      }

      if (!WpaAesEncryptBlock (Key, T, T)) {
        return FALSE;
      }

      BlockIndex += Remaining;
    }
  }

  //
  // Process message data for CBC-MAC (using plaintext for both encrypt and decrypt)
  //
  if (Encrypt) {
    //
    // For encryption, CBC-MAC the plaintext
    //
    BlockIndex = 0;
    while (BlockIndex < InputLen) {
      ZeroMem (B, sizeof (B));
      Remaining = InputLen - BlockIndex;
      if (Remaining > AES_BLOCK_SIZE) {
        Remaining = AES_BLOCK_SIZE;
      }

      CopyMem (B, Input + BlockIndex, Remaining);

      for (Index = 0; Index < AES_BLOCK_SIZE; Index++) {
        T[Index] ^= B[Index];
      }

      if (!WpaAesEncryptBlock (Key, T, T)) {
        return FALSE;
      }

      BlockIndex += Remaining;
    }
  }

  //
  // Generate CTR mode keystream and encrypt/decrypt
  //
  // A0 for MIC encryption: Flags = L-1 = 1, then Nonce, then counter = 0
  //
  ZeroMem (A, sizeof (A));
  A[0] = 0x01;  // L-1
  CopyMem (A + 1, Nonce, 13);
  A[14] = 0;
  A[15] = 0;

  //
  // S0 = AES(K, A0) - used to encrypt/decrypt the MIC
  //
  if (!WpaAesEncryptBlock (Key, A, S)) {
    return FALSE;
  }

  //
  // CTR mode for data: counters 1, 2, ...
  //
  Counter    = 1;
  BlockIndex = 0;

  while (BlockIndex < InputLen) {
    A[14] = (UINT8)(Counter >> 8);
    A[15] = (UINT8)(Counter & 0xFF);

    UINT8  Keystream[AES_BLOCK_SIZE];
    if (!WpaAesEncryptBlock (Key, A, Keystream)) {
      return FALSE;
    }

    Remaining = InputLen - BlockIndex;
    if (Remaining > AES_BLOCK_SIZE) {
      Remaining = AES_BLOCK_SIZE;
    }

    for (Index = 0; Index < Remaining; Index++) {
      Output[BlockIndex + Index] = Input[BlockIndex + Index] ^ Keystream[Index];
    }

    BlockIndex += Remaining;
    Counter++;
  }

  if (!Encrypt) {
    //
    // For decryption, CBC-MAC the resulting plaintext
    //
    BlockIndex = 0;
    while (BlockIndex < InputLen) {
      ZeroMem (B, sizeof (B));
      Remaining = InputLen - BlockIndex;
      if (Remaining > AES_BLOCK_SIZE) {
        Remaining = AES_BLOCK_SIZE;
      }

      CopyMem (B, Output + BlockIndex, Remaining);

      for (Index = 0; Index < AES_BLOCK_SIZE; Index++) {
        T[Index] ^= B[Index];
      }

      if (!WpaAesEncryptBlock (Key, T, T)) {
        return FALSE;
      }

      BlockIndex += Remaining;
    }
  }

  //
  // Encrypt/decrypt the MIC using S0
  //
  if (Encrypt) {
    for (Index = 0; Index < CCMP_MIC_LEN; Index++) {
      Mic[Index] = T[Index] ^ S[Index];
    }
  } else {
    //
    // Verify MIC
    //
    for (Index = 0; Index < CCMP_MIC_LEN; Index++) {
      if (Mic[Index] != (T[Index] ^ S[Index])) {
        return FALSE;
      }
    }
  }

  return TRUE;
}

/**
  CCMP encryption.

  @param[in]   Tk           Temporal Key.
  @param[in]   Pn           Packet Number.
  @param[in]   A2           Source address.
  @param[in]   Priority     QoS priority.
  @param[in]   Header       802.11 header.
  @param[in]   HeaderLen    Header length.
  @param[in]   Plaintext    Plaintext.
  @param[in]   PlainLen     Plaintext length.
  @param[out]  Ciphertext   Ciphertext output (PlainLen + CCMP_MIC_LEN).
  @param[out]  CcmpHeader   8-byte CCMP header.

  @retval TRUE   Succeeded.
  @retval FALSE  Failed.
**/
BOOLEAN
WpaCcmpEncrypt (
  IN  CONST UINT8  *Tk,
  IN  CONST UINT8  *Pn,
  IN  CONST UINT8  *A2,
  IN  UINT8        Priority,
  IN  CONST UINT8  *Header,
  IN  UINTN        HeaderLen,
  IN  CONST UINT8  *Plaintext,
  IN  UINTN        PlainLen,
  OUT UINT8        *Ciphertext,
  OUT UINT8        *CcmpHeader
  )
{
  UINT8  Nonce[13];
  UINT8  Aad[32];
  UINTN  AadLen;

  if ((Tk == NULL) || (Pn == NULL) || (A2 == NULL) || (Header == NULL) ||
      (Plaintext == NULL) || (Ciphertext == NULL) || (CcmpHeader == NULL))
  {
    return FALSE;
  }

  //
  // Build CCMP header: PN0 | PN1 | 0 | KeyID<<6|ExtIV | PN2 | PN3 | PN4 | PN5
  //
  CcmpHeader[0] = Pn[5];  // PN0
  CcmpHeader[1] = Pn[4];  // PN1
  CcmpHeader[2] = 0;      // Reserved
  CcmpHeader[3] = 0x20;   // KeyID=0, ExtIV=1
  CcmpHeader[4] = Pn[3];  // PN2
  CcmpHeader[5] = Pn[2];  // PN3
  CcmpHeader[6] = Pn[1];  // PN4
  CcmpHeader[7] = Pn[0];  // PN5

  CcmpBuildNonce (Priority, A2, Pn, Nonce);
  CcmpBuildAad (Header, HeaderLen, Aad, &AadLen);

  return AesCcmProcess (
           Tk,
           Nonce,
           Aad,
           AadLen,
           Plaintext,
           PlainLen,
           Ciphertext,
           Ciphertext + PlainLen,  // MIC appended after ciphertext
           TRUE
           );
}

/**
  CCMP decryption.

  @param[in]   Tk           Temporal Key.
  @param[in]   Pn           Packet Number.
  @param[in]   A2           Source address.
  @param[in]   Priority     QoS priority.
  @param[in]   Header       802.11 header.
  @param[in]   HeaderLen    Header length.
  @param[in]   Ciphertext   Ciphertext with MIC.
  @param[in]   CipherLen    Total ciphertext length (data + MIC).
  @param[out]  Plaintext    Plaintext output.

  @retval TRUE   Decryption and MIC verification succeeded.
  @retval FALSE  Failed.
**/
BOOLEAN
WpaCcmpDecrypt (
  IN  CONST UINT8  *Tk,
  IN  CONST UINT8  *Pn,
  IN  CONST UINT8  *A2,
  IN  UINT8        Priority,
  IN  CONST UINT8  *Header,
  IN  UINTN        HeaderLen,
  IN  CONST UINT8  *Ciphertext,
  IN  UINTN        CipherLen,
  OUT UINT8        *Plaintext
  )
{
  UINT8  Nonce[13];
  UINT8  Aad[32];
  UINTN  AadLen;
  UINTN  DataLen;
  UINT8  Mic[CCMP_MIC_LEN];

  if ((Tk == NULL) || (Pn == NULL) || (A2 == NULL) || (Header == NULL) ||
      (Ciphertext == NULL) || (Plaintext == NULL))
  {
    return FALSE;
  }

  if (CipherLen <= CCMP_MIC_LEN) {
    return FALSE;
  }

  DataLen = CipherLen - CCMP_MIC_LEN;

  CcmpBuildNonce (Priority, A2, Pn, Nonce);
  CcmpBuildAad (Header, HeaderLen, Aad, &AadLen);

  //
  // Extract MIC from end of ciphertext
  //
  CopyMem (Mic, Ciphertext + DataLen, CCMP_MIC_LEN);

  return AesCcmProcess (
           Tk,
           Nonce,
           Aad,
           AadLen,
           Ciphertext,
           DataLen,
           Plaintext,
           Mic,
           FALSE
           );
}

/**
  Generate random bytes.

  @param[out]  Buffer   Output buffer.
  @param[in]   Size     Byte count.

  @retval TRUE   Succeeded.
  @retval FALSE  Failed.
**/
BOOLEAN
WpaRandomBytes (
  OUT UINT8  *Buffer,
  IN  UINTN  Size
  )
{
  if ((Buffer == NULL) || (Size == 0)) {
    return FALSE;
  }

  return RandomBytes (Buffer, Size);
}

// ==========================================================================
// RC4 stream cipher (PKCS#3)
// ==========================================================================

/**
  Initialize RC4 key schedule (KSA).

  @param[out]  Ctx     RC4 context.
  @param[in]   Key     Key bytes.
  @param[in]   KeyLen  Key length in bytes.
**/
VOID
WpaRc4Init (
  OUT WPA_RC4_CTX  *Ctx,
  IN  CONST UINT8  *Key,
  IN  UINTN        KeyLen
  )
{
  UINTN  I;
  UINTN  J;
  UINT8  Tmp;

  ASSERT (Ctx != NULL);
  ASSERT (Key != NULL);
  ASSERT (KeyLen > 0);

  //
  // Identity permutation
  //
  for (I = 0; I < 256; I++) {
    Ctx->S[I] = (UINT8)I;
  }

  //
  // Key Scheduling Algorithm
  //
  J = 0;
  for (I = 0; I < 256; I++) {
    J = (J + Ctx->S[I] + Key[I % KeyLen]) & 0xFF;
    Tmp       = Ctx->S[I];
    Ctx->S[I] = Ctx->S[J];
    Ctx->S[J] = Tmp;
  }

  Ctx->I = 0;
  Ctx->J = 0;
}

/**
  Generate RC4 keystream and XOR with input (PRGA).

  @param[in,out]  Ctx  RC4 context.
  @param[in]      In   Input bytes.
  @param[out]     Out  Output bytes (may alias In).
  @param[in]      Len  Number of bytes to process.
**/
VOID
WpaRc4Process (
  IN OUT WPA_RC4_CTX  *Ctx,
  IN     CONST UINT8  *In,
  OUT    UINT8        *Out,
  IN     UINTN        Len
  )
{
  UINTN  K;
  UINT8  Tmp;
  UINT8  I;
  UINT8  J;

  ASSERT (Ctx != NULL);
  ASSERT ((In != NULL) || (Len == 0));
  ASSERT ((Out != NULL) || (Len == 0));

  I = Ctx->I;
  J = Ctx->J;

  for (K = 0; K < Len; K++) {
    I = (I + 1) & 0xFF;
    J = (J + Ctx->S[I]) & 0xFF;

    Tmp       = Ctx->S[I];
    Ctx->S[I] = Ctx->S[J];
    Ctx->S[J] = Tmp;

    Out[K] = In[K] ^ Ctx->S[(Ctx->S[I] + Ctx->S[J]) & 0xFF];
  }

  Ctx->I = I;
  Ctx->J = J;
}

/**
  Discard the first Skip keystream bytes.

  @param[in,out]  Ctx   RC4 context.
  @param[in]      Skip  Bytes to skip.
**/
VOID
WpaRc4Skip (
  IN OUT WPA_RC4_CTX  *Ctx,
  IN     UINTN        Skip
  )
{
  UINTN  K;
  UINT8  Tmp;
  UINT8  I;
  UINT8  J;

  ASSERT (Ctx != NULL);

  I = Ctx->I;
  J = Ctx->J;

  for (K = 0; K < Skip; K++) {
    I = (I + 1) & 0xFF;
    J = (J + Ctx->S[I]) & 0xFF;

    Tmp       = Ctx->S[I];
    Ctx->S[I] = Ctx->S[J];
    Ctx->S[J] = Tmp;
  }

  Ctx->I = I;
  Ctx->J = J;
}

// ==========================================================================
// HMAC-MD5 (for WPA1 EAPOL-Key MIC, Key Descriptor Version 1)
// ==========================================================================

#define MD5_DIGEST_SIZE   16
#define HMAC_BLOCK_SIZE   64

/**
  Compute HMAC-MD5 (RFC 2104) for the WPA1 EAPOL-Key MIC.

  @param[in]   Key      KCK (16 bytes for WPA1).
  @param[in]   KeyLen   Key length in bytes.
  @param[in]   Data     Input data.
  @param[in]   DataLen  Input data length.
  @param[out]  Mac      16-byte HMAC-MD5 output.

  @retval TRUE   Succeeded.
  @retval FALSE  Failed.
**/
BOOLEAN
WpaHmacMd5Mic (
  IN  CONST UINT8  *Key,
  IN  UINTN        KeyLen,
  IN  CONST UINT8  *Data,
  IN  UINTN        DataLen,
  OUT UINT8        *Mac
  )
{
  VOID     *Md5Ctx;
  UINTN    CtxSize;
  UINT8    KeyBuf[HMAC_BLOCK_SIZE];
  UINT8    IPad[HMAC_BLOCK_SIZE];
  UINT8    OPad[HMAC_BLOCK_SIZE];
  UINT8    InnerHash[MD5_DIGEST_SIZE];
  UINTN    Index;
  BOOLEAN  Result;

  if ((Key == NULL) || (Data == NULL) || (Mac == NULL)) {
    return FALSE;
  }

  CtxSize = Md5GetContextSize ();
  if (CtxSize == 0) {
    return FALSE;
  }

  //
  // HMAC-MD5: HMAC(K, M) = MD5((K ^ opad) || MD5((K ^ ipad) || M))
  // Key is always <= 64 bytes for WPA1 KCK usage
  //
  ZeroMem (KeyBuf, sizeof (KeyBuf));
  if (KeyLen <= HMAC_BLOCK_SIZE) {
    CopyMem (KeyBuf, Key, KeyLen);
  } else {
    //
    // Key > 64 bytes: hash it first (not needed for WPA1 KCK, but handle gracefully)
    //
    return FALSE;
  }

  for (Index = 0; Index < HMAC_BLOCK_SIZE; Index++) {
    IPad[Index] = KeyBuf[Index] ^ 0x36;
    OPad[Index] = KeyBuf[Index] ^ 0x5C;
  }

  Md5Ctx = AllocatePool (CtxSize);
  if (Md5Ctx == NULL) {
    return FALSE;
  }

  //
  // Inner hash: MD5(ipad || message)
  //
  Result = Md5Init (Md5Ctx);
  if (Result) {
    Result = Md5Update (Md5Ctx, IPad, HMAC_BLOCK_SIZE);
  }

  if (Result) {
    Result = Md5Update (Md5Ctx, Data, DataLen);
  }

  if (Result) {
    Result = Md5Final (Md5Ctx, InnerHash);
  }

  if (!Result) {
    FreePool (Md5Ctx);
    return FALSE;
  }

  //
  // Outer hash: MD5(opad || inner_hash)
  //
  Result = Md5Init (Md5Ctx);
  if (Result) {
    Result = Md5Update (Md5Ctx, OPad, HMAC_BLOCK_SIZE);
  }

  if (Result) {
    Result = Md5Update (Md5Ctx, InnerHash, MD5_DIGEST_SIZE);
  }

  if (Result) {
    Result = Md5Final (Md5Ctx, Mac);
  }

  FreePool (Md5Ctx);
  return Result;
}

// ==========================================================================
// Michael MIC (TKIP message integrity code)
// ==========================================================================

//
// Read a 32-bit little-endian word from unaligned memory.
//
STATIC
UINT32
MichaelGetLE32 (
  IN CONST UINT8  *P
  )
{
  return (UINT32)P[0] | ((UINT32)P[1] << 8) |
         ((UINT32)P[2] << 16) | ((UINT32)P[3] << 24);
}

//
// Apply the Michael block function: 1 round of mixing on (l, r).
//
STATIC
VOID
MichaelBlock (
  IN OUT UINT32  *Pl,
  IN OUT UINT32  *Pr
  )
{
  UINT32  L;
  UINT32  R;

  L = *Pl;
  R = *Pr;

  R ^= ((L << 17) | (L >> 15));
  L += R;
  R ^= ((L & 0xFF00FF00UL) >> 8) | ((L & 0x00FF00FFUL) << 8);
  L += R;
  R ^= ((L << 3) | (L >> 29));
  L += R;
  R ^= ((L >> 2) | (L << 30));
  L += R;

  *Pl = L;
  *Pr = R;
}

/**
  Compute the Michael MIC for a TKIP-protected MPDU.

  Michael input: DA || SA || Priority || 0 || 0 || 0 || MSDU
  then padding with 0x5a and zeros to a 4-byte boundary, then 4 zero bytes.

  @param[in]   Key       8-byte Michael key.
  @param[in]   Da        Destination MAC (6 bytes).
  @param[in]   Sa        Source MAC (6 bytes).
  @param[in]   Priority  QoS TID (1 byte; upper 3 bytes are 0).
  @param[in]   Data      MSDU payload.
  @param[in]   DataLen   MSDU length in bytes.
  @param[out]  Mic       8-byte MIC output.
**/
VOID
WpaMichaelMic (
  IN  CONST UINT8  *Key,
  IN  CONST UINT8  *Da,
  IN  CONST UINT8  *Sa,
  IN  UINT8        Priority,
  IN  CONST UINT8  *Data,
  IN  UINTN        DataLen,
  OUT UINT8        *Mic
  )
{
  UINT32  L;
  UINT32  R;
  UINTN   I;
  UINT8   Buf[4];

  //
  // Initialize from key (little-endian)
  //
  L = MichaelGetLE32 (Key);
  R = MichaelGetLE32 (Key + 4);

  //
  // Helper lambda: feed a 4-byte little-endian word
  //
#define MICHAEL_FEED(word) \
  do { L ^= (word); MichaelBlock (&L, &R); } while (0)

  //
  // Feed DA (6 bytes = 1.5 words)
  //
  MICHAEL_FEED (MichaelGetLE32 (Da));
  Buf[0] = Da[4];
  Buf[1] = Da[5];
  Buf[2] = Sa[0];
  Buf[3] = Sa[1];
  MICHAEL_FEED (MichaelGetLE32 (Buf));
  Buf[0] = Sa[2];
  Buf[1] = Sa[3];
  Buf[2] = Sa[4];
  Buf[3] = Sa[5];
  MICHAEL_FEED (MichaelGetLE32 (Buf));

  //
  // Feed Priority || 0 || 0 || 0
  //
  Buf[0] = Priority;
  Buf[1] = 0;
  Buf[2] = 0;
  Buf[3] = 0;
  MICHAEL_FEED (MichaelGetLE32 (Buf));

  //
  // Feed MSDU data in 4-byte blocks
  //
  for (I = 0; I + 4 <= DataLen; I += 4) {
    MICHAEL_FEED (MichaelGetLE32 (Data + I));
  }

  //
  // Padding: remaining bytes || 0x5a || zeros to fill 4 bytes
  //
  {
    UINTN  Rem = DataLen - I;

    ZeroMem (Buf, sizeof (Buf));
    if (Rem > 0) {
      CopyMem (Buf, Data + I, Rem);
    }

    Buf[Rem] = 0x5a;
    MICHAEL_FEED (MichaelGetLE32 (Buf));
    MICHAEL_FEED (0);
  }

#undef MICHAEL_FEED

  //
  // Output MIC (8 bytes, little-endian)
  //
  Mic[0] = (UINT8)(L & 0xFF);
  Mic[1] = (UINT8)((L >> 8) & 0xFF);
  Mic[2] = (UINT8)((L >> 16) & 0xFF);
  Mic[3] = (UINT8)((L >> 24) & 0xFF);
  Mic[4] = (UINT8)(R & 0xFF);
  Mic[5] = (UINT8)((R >> 8) & 0xFF);
  Mic[6] = (UINT8)((R >> 16) & 0xFF);
  Mic[7] = (UINT8)((R >> 24) & 0xFF);
}

// ==========================================================================
// TKIP key mixing (Phase 1 and Phase 2)
// Reference: IEEE 802.11-2020 Section 12.5.2
// ==========================================================================

//
// AES forward S-box (256 bytes). Used by TKIP key mixing.
//
STATIC CONST UINT8  mAesSbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
  0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
  0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
  0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
  0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
  0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
  0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
  0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
  0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
  0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
  0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

//
// TKIP S-box: for 16-bit input x, Sbox(x) = S[x & 0xFF] | (S[x >> 8] << 8)
//
STATIC
UINT16
TkipSbox (
  IN UINT16  Val
  )
{
  return (UINT16)mAesSbox[Val & 0xFF] | ((UINT16)mAesSbox[Val >> 8] << 8);
}

//
// Build a 16-bit big-endian word from two bytes: high || low.
//
#define TKIP_MK16(High, Low)  ((UINT16)(((UINT16)(High) << 8) | (UINT8)(Low)))

//
// Rotate-right 16-bit value by 1 bit.
//
#define TKIP_ROTR1(x)  ((UINT16)(((UINT16)(x) >> 1) | ((UINT16)(x) << 15)))

/**
  TKIP Phase 1 key mixing.

  @param[in]   Tk      First 16 bytes of the TKIP temporal key.
  @param[in]   Ta      Transmitter address (6 bytes).
  @param[in]   Tsc32   Upper 32 bits of the 48-bit TSC.
  @param[out]  Ttak    5 x UINT16 TTAK output.
**/
VOID
WpaTkipPhase1Mix (
  IN  CONST UINT8  *Tk,
  IN  CONST UINT8  *Ta,
  IN  UINT32       Tsc32,
  OUT UINT16       Ttak[5]
  )
{
  UINTN  Iter;
  UINTN  J;

  //
  // Initialize TTAK from TSC (low/high 16-bit halves) and TA bytes.
  //
  Ttak[0] = (UINT16)(Tsc32 & 0xFFFF);
  Ttak[1] = (UINT16)(Tsc32 >> 16);
  Ttak[2] = TKIP_MK16 (Ta[1], Ta[0]);
  Ttak[3] = TKIP_MK16 (Ta[3], Ta[2]);
  Ttak[4] = TKIP_MK16 (Ta[5], Ta[4]);

  for (Iter = 0; Iter < 8; Iter++) {
    J = 2 * (Iter & 1);

    Ttak[0] += TkipSbox (Ttak[4] ^ TKIP_MK16 (Tk[1 + J], Tk[0 + J]));
    Ttak[1] += TkipSbox (Ttak[0] ^ TKIP_MK16 (Tk[5 + J], Tk[4 + J]));
    Ttak[2] += TkipSbox (Ttak[1] ^ TKIP_MK16 (Tk[9 + J], Tk[8 + J]));
    Ttak[3] += TkipSbox (Ttak[2] ^ TKIP_MK16 (Tk[13 + J], Tk[12 + J]));
    Ttak[4] += TkipSbox (Ttak[3] ^ TKIP_MK16 (Tk[1 + J], Tk[0 + J])) + (UINT16)Iter;
  }
}

/**
  TKIP Phase 2 per-packet key mixing.

  @param[in]   Ttak    5 x UINT16 from WpaTkipPhase1Mix.
  @param[in]   Tk      First 16 bytes of the TKIP temporal key.
  @param[in]   Tsc16   Lower 16 bits of the 48-bit TSC.
  @param[out]  Rc4Key  16-byte per-packet RC4 key.
**/
VOID
WpaTkipPhase2Mix (
  IN  CONST UINT16  Ttak[5],
  IN  CONST UINT8   *Tk,
  IN  UINT16        Tsc16,
  OUT UINT8         Rc4Key[16]
  )
{
  UINT16  Ppk[6];
  UINTN   I;

  //
  // Initialize PPK from TTAK; PPK[5] adds the per-frame counter.
  //
  Ppk[0] = Ttak[0];
  Ppk[1] = Ttak[1];
  Ppk[2] = Ttak[2];
  Ppk[3] = Ttak[3];
  Ppk[4] = Ttak[4];
  Ppk[5] = Ttak[4] + Tsc16;

  //
  // Phase 2 mixing: two rounds of S-box lookups with TK.
  //
  Ppk[0] += TkipSbox (Ppk[5] ^ TKIP_MK16 (Tk[1],  Tk[0]));
  Ppk[1] += TkipSbox (Ppk[0] ^ TKIP_MK16 (Tk[3],  Tk[2]));
  Ppk[2] += TkipSbox (Ppk[1] ^ TKIP_MK16 (Tk[5],  Tk[4]));
  Ppk[3] += TkipSbox (Ppk[2] ^ TKIP_MK16 (Tk[7],  Tk[6]));
  Ppk[4] += TkipSbox (Ppk[3] ^ TKIP_MK16 (Tk[9],  Tk[8]));
  Ppk[5] += TkipSbox (Ppk[4] ^ TKIP_MK16 (Tk[11], Tk[10]));

  Ppk[0] += TKIP_ROTR1 (Ppk[5] ^ TKIP_MK16 (Tk[13], Tk[12]));
  Ppk[1] += TKIP_ROTR1 (Ppk[0] ^ TKIP_MK16 (Tk[15], Tk[14]));
  Ppk[2] += TKIP_ROTR1 (Ppk[1]);
  Ppk[3] += TKIP_ROTR1 (Ppk[2]);
  Ppk[4] += TKIP_ROTR1 (Ppk[3]);
  Ppk[5] += TKIP_ROTR1 (Ppk[4]);

  //
  // Build the 16-byte per-packet RC4 key (WEP seed format).
  //   Byte 0: Hi8(Tsc16)
  //   Byte 1: (Hi8(Tsc16) | 0x20) & 0x7f  -- WEP seed byte
  //   Byte 2: Lo8(Tsc16)
  //   Byte 3: Lo8((Ppk[5] ^ Mk16(Tk[1], Tk[0])) >> 1)
  //   Bytes 4-15: Lo8/Hi8 of Ppk[0..5]
  //
  Rc4Key[0] = (UINT8)(Tsc16 >> 8);
  Rc4Key[1] = (UINT8)(((Tsc16 >> 8) | 0x20) & 0x7f);
  Rc4Key[2] = (UINT8)(Tsc16 & 0xFF);
  Rc4Key[3] = (UINT8)((Ppk[5] ^ TKIP_MK16 (Tk[1], Tk[0])) >> 1);

  for (I = 0; I < 6; I++) {
    Rc4Key[4 + 2 * I]     = (UINT8)(Ppk[I] & 0xFF);
    Rc4Key[4 + 2 * I + 1] = (UINT8)(Ppk[I] >> 8);
  }
}

// ==========================================================================
// CRC-32 (IEEE 802.3 / WEP ICV)
// ==========================================================================

/**
  Compute IEEE 802.3 CRC-32 over a buffer.

  @param[in]   Data    Input data.
  @param[in]   Len     Input length in bytes.

  @return CRC-32 value.
**/
STATIC
UINT32
Crc32 (
  IN CONST UINT8  *Data,
  IN UINTN        Len
  )
{
  UINT32  Crc;
  UINTN   I;
  UINT32  J;

  Crc = 0xFFFFFFFFUL;
  for (I = 0; I < Len; I++) {
    Crc ^= Data[I];
    for (J = 0; J < 8; J++) {
      if (Crc & 1U) {
        Crc = (Crc >> 1) ^ 0xEDB88320UL;
      } else {
        Crc >>= 1;
      }
    }
  }

  return ~Crc;
}

// ==========================================================================
// TKIP encrypt / decrypt
// ==========================================================================

/**
  Encrypt one 802.11 MPDU with TKIP.

  @param[in]   Tk         32-byte TKIP temporal key.
  @param[in]   Da         Destination MAC (6 bytes).
  @param[in]   Sa         Transmitter MAC (6 bytes).
  @param[in]   Priority   QoS TID.
  @param[in]   Tsc        48-bit TKIP Sequence Counter.
  @param[in]   Data       Plaintext MSDU.
  @param[in]   DataLen    Plaintext length in bytes.
  @param[out]  Output     TKIP-protected output.
  @param[out]  OutputLen  Output length in bytes.

  @retval EFI_SUCCESS           Succeeded.
  @retval EFI_INVALID_PARAMETER NULL pointer.
  @retval EFI_OUT_OF_RESOURCES  Allocation failure.
**/
EFI_STATUS
WpaTkipEncrypt (
  IN  CONST UINT8  *Tk,
  IN  CONST UINT8  *Da,
  IN  CONST UINT8  *Sa,
  IN  UINT8        Priority,
  IN  UINT64       Tsc,
  IN  CONST UINT8  *Data,
  IN  UINTN        DataLen,
  OUT UINT8        *Output,
  OUT UINTN        *OutputLen
  )
{
  UINT32       Tsc32;
  UINT16       Tsc16;
  UINT16       Ttak[5];
  UINT8        Rc4Key[16];
  UINT8        Mic[TKIP_MIC_LEN];
  UINT32       Icv;
  UINT8        *PlainBuf;
  UINTN        PlainLen;
  WPA_RC4_CTX  Ctx;
  UINT8        *Enc;

  if ((Tk == NULL) || (Da == NULL) || (Sa == NULL) ||
      (Data == NULL) || (Output == NULL) || (OutputLen == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  DEBUG ((DEBUG_WARN,
    "[Supplicant] TKIP is cryptographically broken; use CCMP instead.\n"));

  //
  // Split 48-bit TSC into upper 32 bits and lower 16 bits.
  //
  Tsc16 = (UINT16)(Tsc & 0xFFFF);
  Tsc32 = (UINT32)((Tsc >> 16) & 0xFFFFFFFF);

  //
  // Phase 1 and Phase 2 key mixing to derive per-packet RC4 key.
  //
  WpaTkipPhase1Mix (Tk, Sa, Tsc32, Ttak);
  WpaTkipPhase2Mix (Ttak, Tk, Tsc16, Rc4Key);

  //
  // Compute Michael MIC using TX-MIC key (bytes 16-23 of 32-byte Tk).
  //
  WpaMichaelMic (Tk + WPA_TK_TX_MIC_OFFSET, Da, Sa, Priority, Data, DataLen, Mic);

  //
  // Build plaintext buffer: Data || Michael MIC
  //
  PlainLen = DataLen + TKIP_MIC_LEN;
  PlainBuf = AllocatePool (PlainLen + TKIP_ICV_LEN);
  if (PlainBuf == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (PlainBuf, Data, DataLen);
  CopyMem (PlainBuf + DataLen, Mic, TKIP_MIC_LEN);

  //
  // Compute CRC-32 ICV over (Data || MIC).
  //
  Icv = Crc32 (PlainBuf, PlainLen);
  PlainBuf[PlainLen]     = (UINT8)(Icv & 0xFF);
  PlainBuf[PlainLen + 1] = (UINT8)((Icv >> 8) & 0xFF);
  PlainBuf[PlainLen + 2] = (UINT8)((Icv >> 16) & 0xFF);
  PlainBuf[PlainLen + 3] = (UINT8)((Icv >> 24) & 0xFF);
  PlainLen += TKIP_ICV_LEN;

  //
  // Build TKIP header (8 bytes):
  //   Byte 0: TSC1 = (Tsc >> 8) & 0xFF
  //   Byte 1: WEPSeed = (TSC1 | 0x20) & 0x7F
  //   Byte 2: TSC0 = Tsc & 0xFF
  //   Byte 3: KeyID field with ExtIV flag set (0x20)
  //   Bytes 4-7: TSC2..TSC5 (big-endian, upper 32 bits of TSC as bytes)
  //
  Enc = Output;

  Enc[0] = (UINT8)((Tsc >> 8) & 0xFF);                    // TSC1
  Enc[1] = (UINT8)(((Tsc >> 8) | 0x20) & 0x7F);           // WEPSeed
  Enc[2] = (UINT8)(Tsc & 0xFF);                            // TSC0
  Enc[3] = 0x20;                                           // ExtIV=1, KeyID=0
  Enc[4] = (UINT8)((Tsc >> 16) & 0xFF);                   // TSC2
  Enc[5] = (UINT8)((Tsc >> 24) & 0xFF);                   // TSC3
  Enc[6] = (UINT8)((Tsc >> 32) & 0xFF);                   // TSC4
  Enc[7] = (UINT8)((Tsc >> 40) & 0xFF);                   // TSC5

  //
  // RC4 encrypt the payload.
  //
  WpaRc4Init (&Ctx, Rc4Key, 16);
  WpaRc4Process (&Ctx, PlainBuf, Enc + TKIP_HEADER_LEN, PlainLen);

  FreePool (PlainBuf);

  *OutputLen = TKIP_HEADER_LEN + PlainLen;
  return EFI_SUCCESS;
}

/**
  Decrypt and verify one 802.11 MPDU with TKIP.

  @param[in]   Tk         32-byte TKIP temporal key.
  @param[in]   Da         Destination MAC (6 bytes).
  @param[in]   Sa         Source MAC (6 bytes).
  @param[in]   Priority   QoS TID.
  @param[in]   Data       Input buffer including 8-byte TKIP header.
  @param[in]   DataLen    Total input length.
  @param[out]  Output     Decrypted MSDU (without MIC or ICV).
  @param[out]  OutputLen  MSDU length.

  @retval EFI_SUCCESS           Succeeded.
  @retval EFI_SECURITY_VIOLATION MIC or ICV check failed.
  @retval EFI_INVALID_PARAMETER NULL pointer or bad length.
  @retval EFI_OUT_OF_RESOURCES  Allocation failure.
**/
EFI_STATUS
WpaTkipDecrypt (
  IN  CONST UINT8  *Tk,
  IN  CONST UINT8  *Da,
  IN  CONST UINT8  *Sa,
  IN  UINT8        Priority,
  IN  CONST UINT8  *Data,
  IN  UINTN        DataLen,
  OUT UINT8        *Output,
  OUT UINTN        *OutputLen
  )
{
  UINT64       Tsc;
  UINT32       Tsc32;
  UINT16       Tsc16;
  UINT16       Ttak[5];
  UINT8        Rc4Key[16];
  UINT8        *PlainBuf;
  UINTN        PlainLen;
  UINT32       IcvCalc;
  UINT32       IcvRecv;
  UINT8        MicCalc[TKIP_MIC_LEN];
  UINTN        MsduLen;
  WPA_RC4_CTX  Ctx;

  if ((Tk == NULL) || (Da == NULL) || (Sa == NULL) ||
      (Data == NULL) || (Output == NULL) || (OutputLen == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  if (DataLen < TKIP_HEADER_LEN + TKIP_MIC_LEN + TKIP_ICV_LEN + 1) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Extract TSC from TKIP header:
  //   TSC0 = Data[2], TSC1 = Data[0]
  //   TSC2..TSC5 = Data[4..7]
  //
  Tsc = (UINT64)Data[2]        |        // TSC0
        ((UINT64)Data[0] << 8) |        // TSC1
        ((UINT64)Data[4] << 16) |       // TSC2
        ((UINT64)Data[5] << 24) |       // TSC3
        ((UINT64)Data[6] << 32) |       // TSC4
        ((UINT64)Data[7] << 40);        // TSC5

  Tsc16 = (UINT16)(Tsc & 0xFFFF);
  Tsc32 = (UINT32)((Tsc >> 16) & 0xFFFFFFFF);

  //
  // Phase 1 and Phase 2 key mixing.
  //
  WpaTkipPhase1Mix (Tk, Sa, Tsc32, Ttak);
  WpaTkipPhase2Mix (Ttak, Tk, Tsc16, Rc4Key);

  //
  // RC4 decrypt the ciphertext (everything after the 8-byte TKIP header).
  //
  PlainLen = DataLen - TKIP_HEADER_LEN;
  PlainBuf = AllocatePool (PlainLen);
  if (PlainBuf == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  WpaRc4Init (&Ctx, Rc4Key, 16);
  WpaRc4Process (&Ctx, Data + TKIP_HEADER_LEN, PlainBuf, PlainLen);

  //
  // Verify CRC-32 ICV (last 4 bytes of plaintext).
  //
  MsduLen  = PlainLen - TKIP_MIC_LEN - TKIP_ICV_LEN;
  IcvCalc  = Crc32 (PlainBuf, PlainLen - TKIP_ICV_LEN);
  IcvRecv  = (UINT32)PlainBuf[PlainLen - 4]        |
             ((UINT32)PlainBuf[PlainLen - 3] << 8)  |
             ((UINT32)PlainBuf[PlainLen - 2] << 16) |
             ((UINT32)PlainBuf[PlainLen - 1] << 24);

  if (IcvCalc != IcvRecv) {
    ZeroMem (PlainBuf, PlainLen);
    FreePool (PlainBuf);
    return EFI_SECURITY_VIOLATION;
  }

  //
  // Verify Michael MIC using RX-MIC key (bytes 24-31 of 32-byte Tk).
  //
  WpaMichaelMic (
    Tk + WPA_TK_RX_MIC_OFFSET,
    Da,
    Sa,
    Priority,
    PlainBuf,
    MsduLen,
    MicCalc
    );

  if (CompareMem (MicCalc, PlainBuf + MsduLen, TKIP_MIC_LEN) != 0) {
    ZeroMem (PlainBuf, PlainLen);
    FreePool (PlainBuf);
    return EFI_SECURITY_VIOLATION;
  }

  //
  // Copy the verified MSDU to the output buffer.
  //
  CopyMem (Output, PlainBuf, MsduLen);
  *OutputLen = MsduLen;

  ZeroMem (PlainBuf, PlainLen);
  FreePool (PlainBuf);
  return EFI_SUCCESS;
}

// ==========================================================================
// WEP encrypt / decrypt
// ==========================================================================

/**
  Encrypt a WEP frame.

  @param[in]   Key        WEP key (5 or 13 bytes).
  @param[in]   KeyLen     Key length.
  @param[in]   KeyId      Key index (0-3).
  @param[in]   Data       Plaintext.
  @param[in]   DataLen    Plaintext length.
  @param[out]  Output     WEP-protected output (header + encrypted payload).
  @param[out]  OutputLen  Output length.

  @retval EFI_SUCCESS           Succeeded.
  @retval EFI_INVALID_PARAMETER NULL pointer or bad key length.
  @retval EFI_OUT_OF_RESOURCES  Allocation failure.
**/
EFI_STATUS
WpaWepEncrypt (
  IN  CONST UINT8  *Key,
  IN  UINTN        KeyLen,
  IN  UINT8        KeyId,
  IN  CONST UINT8  *Data,
  IN  UINTN        DataLen,
  OUT UINT8        *Output,
  OUT UINTN        *OutputLen
  )
{
  UINT8        Iv[WEP_IV_LEN];
  UINT8        Rc4Key[WEP_IV_LEN + WEP_MAX_KEY_LEN];
  UINT8        *PlainBuf;
  UINT32       Icv;
  WPA_RC4_CTX  Ctx;

  if ((Key == NULL) || (Data == NULL) || (Output == NULL) || (OutputLen == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((KeyLen != WEP40_KEY_LEN) && (KeyLen != WEP104_KEY_LEN)) {
    return EFI_INVALID_PARAMETER;
  }

  DEBUG ((DEBUG_WARN,
    "[Supplicant] WEP is cryptographically broken; use CCMP instead.\n"));

  //
  // Generate a random 3-byte IV.
  //
  if (!WpaRandomBytes (Iv, WEP_IV_LEN)) {
    return EFI_DEVICE_ERROR;
  }

  //
  // Build WEP header: IV[3] || KeyID[1].
  //
  CopyMem (Output, Iv, WEP_IV_LEN);
  Output[3] = (KeyId & 0x03) << 6;

  //
  // Build RC4 seed: IV || WEP_key.
  //
  CopyMem (Rc4Key, Iv, WEP_IV_LEN);
  CopyMem (Rc4Key + WEP_IV_LEN, Key, KeyLen);

  //
  // Build plaintext with appended ICV: Data || CRC-32(Data).
  //
  PlainBuf = AllocatePool (DataLen + WEP_ICV_LEN);
  if (PlainBuf == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (PlainBuf, Data, DataLen);
  Icv              = Crc32 (Data, DataLen);
  PlainBuf[DataLen]     = (UINT8)(Icv & 0xFF);
  PlainBuf[DataLen + 1] = (UINT8)((Icv >> 8) & 0xFF);
  PlainBuf[DataLen + 2] = (UINT8)((Icv >> 16) & 0xFF);
  PlainBuf[DataLen + 3] = (UINT8)((Icv >> 24) & 0xFF);

  //
  // RC4 encrypt.
  //
  WpaRc4Init (&Ctx, Rc4Key, WEP_IV_LEN + KeyLen);
  WpaRc4Process (&Ctx, PlainBuf, Output + WEP_HEADER_LEN, DataLen + WEP_ICV_LEN);

  FreePool (PlainBuf);

  *OutputLen = WEP_HEADER_LEN + DataLen + WEP_ICV_LEN;
  return EFI_SUCCESS;
}

/**
  Decrypt a WEP frame.

  @param[in]   Key        WEP key (5 or 13 bytes).
  @param[in]   KeyLen     Key length.
  @param[in]   Data       Input buffer including 4-byte WEP header.
  @param[in]   DataLen    Total input length.
  @param[out]  Output     Decrypted plaintext (without header or ICV).
  @param[out]  OutputLen  Plaintext length.

  @retval EFI_SUCCESS           Succeeded.
  @retval EFI_SECURITY_VIOLATION ICV check failed.
  @retval EFI_INVALID_PARAMETER NULL pointer or bad length.
**/
EFI_STATUS
WpaWepDecrypt (
  IN  CONST UINT8  *Key,
  IN  UINTN        KeyLen,
  IN  CONST UINT8  *Data,
  IN  UINTN        DataLen,
  OUT UINT8        *Output,
  OUT UINTN        *OutputLen
  )
{
  UINT8        Rc4Key[WEP_IV_LEN + WEP_MAX_KEY_LEN];
  UINT8        *PlainBuf;
  UINTN        CipherLen;
  UINTN        PlainLen;
  UINT32       IcvCalc;
  UINT32       IcvRecv;
  WPA_RC4_CTX  Ctx;

  if ((Key == NULL) || (Data == NULL) || (Output == NULL) || (OutputLen == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((KeyLen != WEP40_KEY_LEN) && (KeyLen != WEP104_KEY_LEN)) {
    return EFI_INVALID_PARAMETER;
  }

  if (DataLen < WEP_HEADER_LEN + WEP_ICV_LEN + 1) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Build RC4 seed: IV (first 3 bytes of header) || WEP_key.
  //
  CopyMem (Rc4Key, Data, WEP_IV_LEN);
  CopyMem (Rc4Key + WEP_IV_LEN, Key, KeyLen);

  //
  // RC4 decrypt ciphertext (everything after the 4-byte header).
  //
  CipherLen = DataLen - WEP_HEADER_LEN;
  PlainBuf  = AllocatePool (CipherLen);
  if (PlainBuf == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  WpaRc4Init (&Ctx, Rc4Key, WEP_IV_LEN + KeyLen);
  WpaRc4Process (&Ctx, Data + WEP_HEADER_LEN, PlainBuf, CipherLen);

  //
  // Verify CRC-32 ICV (last 4 bytes of plaintext).
  //
  PlainLen = CipherLen - WEP_ICV_LEN;
  IcvCalc  = Crc32 (PlainBuf, PlainLen);
  IcvRecv  = (UINT32)PlainBuf[PlainLen]          |
             ((UINT32)PlainBuf[PlainLen + 1] << 8)  |
             ((UINT32)PlainBuf[PlainLen + 2] << 16) |
             ((UINT32)PlainBuf[PlainLen + 3] << 24);

  if (IcvCalc != IcvRecv) {
    ZeroMem (PlainBuf, CipherLen);
    FreePool (PlainBuf);
    return EFI_SECURITY_VIOLATION;
  }

  CopyMem (Output, PlainBuf, PlainLen);
  *OutputLen = PlainLen;

  ZeroMem (PlainBuf, CipherLen);
  FreePool (PlainBuf);
  return EFI_SUCCESS;
}
