/** @file
  WPA Cryptographic Primitive Implementations.

  Implements PRF-SHA1, KDF-SHA256, PBKDF2, AES-128-CMAC, AES Key Wrap/Unwrap,
  and CCMP (AES-CCM) encrypt/decrypt for WPA2/WPA3-Personal.

  Reference: IEEE 802.11-2020, RFC 3394, RFC 4493, wpa_supplicant

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
