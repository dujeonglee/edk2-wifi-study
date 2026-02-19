/** @file
  WPA Cryptographic Primitive Declarations.

  Provides PRF (HMAC-SHA1), KDF (HMAC-SHA256), AES-128-CMAC, AES Key Wrap/Unwrap,
  CCMP encrypt/decrypt, and PBKDF2 passphrase-to-PMK derivation for WPA2/WPA3-Personal.

  Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef WPA_CRYPTO_H_
#define WPA_CRYPTO_H_

#include "WpaCommon.h"

/**
  PRF-X using HMAC-SHA1 (IEEE 802.11-2020 Section 12.7.1.2).
  Used by WPA2-PSK (AKM Suite 2) for PTK derivation.

  @param[in]   Key        HMAC-SHA1 key (PMK).
  @param[in]   KeyLen     Length of Key in bytes.
  @param[in]   Label      Null-terminated ASCII label string.
  @param[in]   Data       Concatenated data (Min(AA,SPA)||Max(AA,SPA)||Min(ANonce,SNonce)||Max(ANonce,SNonce)).
  @param[in]   DataLen    Length of Data in bytes.
  @param[out]  Output     Output buffer for the derived key.
  @param[in]   OutputLen  Desired output length in bytes.

  @retval TRUE   PRF computation succeeded.
  @retval FALSE  PRF computation failed.
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
  );

/**
  KDF-X using HMAC-SHA256 (IEEE 802.11-2020 Section 12.7.1.7.2).
  Used by WPA3-SAE (AKM Suite 8) and WPA2-PSK-SHA256 (AKM Suite 6) for PTK derivation.

  @param[in]   Key        HMAC-SHA256 key (PMK).
  @param[in]   KeyLen     Length of Key in bytes.
  @param[in]   Label      Null-terminated ASCII label string.
  @param[in]   Context    Context data.
  @param[in]   CtxLen     Length of Context in bytes.
  @param[out]  Output     Output buffer for the derived key.
  @param[in]   OutputBits Desired output length in bits.

  @retval TRUE   KDF computation succeeded.
  @retval FALSE  KDF computation failed.
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
  );

/**
  Derive PMK from passphrase and SSID using PBKDF2-SHA1.
  WPA2-Personal: PMK = PBKDF2(HMAC-SHA1, Passphrase, SSID, 4096, 256).

  @param[in]   Passphrase   Null-terminated ASCII passphrase (8-63 characters).
  @param[in]   Ssid         SSID bytes.
  @param[in]   SsidLen      Length of SSID in bytes.
  @param[out]  Pmk          Output 32-byte PMK buffer.

  @retval TRUE   PMK derivation succeeded.
  @retval FALSE  PMK derivation failed.
**/
BOOLEAN
WpaDerivePmk (
  IN  CONST CHAR8  *Passphrase,
  IN  CONST UINT8  *Ssid,
  IN  UINTN        SsidLen,
  OUT UINT8        *Pmk
  );

/**
  Compute AES-128-CMAC (RFC 4493).
  Used for MIC calculation in WPA3-SAE and WPA2-PSK-SHA256.

  @param[in]   Key       16-byte AES key (KCK).
  @param[in]   Data      Input data.
  @param[in]   DataLen   Length of input data in bytes.
  @param[out]  Mac       16-byte output MAC buffer.

  @retval TRUE   CMAC computation succeeded.
  @retval FALSE  CMAC computation failed.
**/
BOOLEAN
WpaAesCmac (
  IN  CONST UINT8  *Key,
  IN  CONST UINT8  *Data,
  IN  UINTN        DataLen,
  OUT UINT8        *Mac
  );

/**
  Compute HMAC-SHA1-128 for EAPOL-Key MIC (WPA2-PSK, Key Descriptor Version 2).
  Returns the first 16 bytes of the HMAC-SHA1 output.

  @param[in]   Key       KCK (Key Confirmation Key, 16 bytes).
  @param[in]   Data      Input data (EAPOL frame with MIC zeroed).
  @param[in]   DataLen   Length of input data.
  @param[out]  Mic       16-byte output MIC buffer.

  @retval TRUE   MIC computation succeeded.
  @retval FALSE  MIC computation failed.
**/
BOOLEAN
WpaHmacSha1Mic (
  IN  CONST UINT8  *Key,
  IN  CONST UINT8  *Data,
  IN  UINTN        DataLen,
  OUT UINT8        *Mic
  );

/**
  AES Key Wrap (RFC 3394) encryption.
  Used to decrypt GTK from EAPOL-Key message 3 key data.

  @param[in]   Kek          16-byte Key Encryption Key.
  @param[in]   Plaintext    Plaintext to wrap (must be multiple of 8 bytes).
  @param[in]   PlainLen     Length of plaintext in bytes.
  @param[out]  Ciphertext   Output buffer (PlainLen + 8 bytes).

  @retval TRUE   Key wrap succeeded.
  @retval FALSE  Key wrap failed.
**/
BOOLEAN
WpaAesKeyWrap (
  IN  CONST UINT8  *Kek,
  IN  CONST UINT8  *Plaintext,
  IN  UINTN        PlainLen,
  OUT UINT8        *Ciphertext
  );

/**
  AES Key Unwrap (RFC 3394) decryption.
  Used to decrypt GTK from EAPOL-Key message 3 key data.

  @param[in]   Kek          16-byte Key Encryption Key.
  @param[in]   Ciphertext   Wrapped key data (must be multiple of 8 bytes).
  @param[in]   CipherLen    Length of ciphertext in bytes.
  @param[out]  Plaintext    Output buffer (CipherLen - 8 bytes).

  @retval TRUE   Key unwrap succeeded and integrity check passed.
  @retval FALSE  Key unwrap failed or integrity check failed.
**/
BOOLEAN
WpaAesKeyUnwrap (
  IN  CONST UINT8  *Kek,
  IN  CONST UINT8  *Ciphertext,
  IN  UINTN        CipherLen,
  OUT UINT8        *Plaintext
  );

/**
  Encrypt a single 16-byte block using AES-ECB.

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
  );

/**
  CCMP (AES-CCM) encryption for 802.11 data frames.

  @param[in]   Tk           16-byte Temporal Key.
  @param[in]   Pn           6-byte Packet Number.
  @param[in]   A2           Source MAC address (6 bytes).
  @param[in]   Priority     Priority (QoS TID), typically 0.
  @param[in]   Header       802.11 header for AAD construction.
  @param[in]   HeaderLen    Length of the 802.11 header.
  @param[in]   Plaintext    Plaintext MPDU payload.
  @param[in]   PlainLen     Length of plaintext.
  @param[out]  Ciphertext   Output buffer (PlainLen + CCMP_MIC_LEN bytes).
  @param[out]  CcmpHeader   8-byte CCMP header output.

  @retval TRUE   CCMP encryption succeeded.
  @retval FALSE  CCMP encryption failed.
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
  );

/**
  CCMP (AES-CCM) decryption for 802.11 data frames.

  @param[in]   Tk           16-byte Temporal Key.
  @param[in]   Pn           6-byte Packet Number (from CCMP header).
  @param[in]   A2           Source MAC address (6 bytes).
  @param[in]   Priority     Priority (QoS TID), typically 0.
  @param[in]   Header       802.11 header for AAD construction.
  @param[in]   HeaderLen    Length of the 802.11 header.
  @param[in]   Ciphertext   Ciphertext (including 8-byte MIC at end).
  @param[in]   CipherLen    Length of ciphertext including MIC.
  @param[out]  Plaintext    Output buffer (CipherLen - CCMP_MIC_LEN bytes).

  @retval TRUE   CCMP decryption and MIC verification succeeded.
  @retval FALSE  CCMP decryption or MIC verification failed.
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
  );

/**
  Generate cryptographically random bytes.

  @param[out]  Buffer   Output buffer.
  @param[in]   Size     Number of random bytes to generate.

  @retval TRUE   Random generation succeeded.
  @retval FALSE  Random generation failed.
**/
BOOLEAN
WpaRandomBytes (
  OUT UINT8  *Buffer,
  IN  UINTN  Size
  );

#endif // WPA_CRYPTO_H_
