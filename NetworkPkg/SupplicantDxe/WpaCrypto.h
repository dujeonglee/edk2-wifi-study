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

// ==========================================================================
// RC4, HMAC-MD5, Michael MIC, TKIP, and WEP (WPA1/legacy)
// ==========================================================================

///
/// RC4 stream cipher context.
///
typedef struct {
  UINT8    S[256];
  UINT8    I;
  UINT8    J;
} WPA_RC4_CTX;

/**
  Initialize the RC4 key schedule.

  @param[out]  Ctx     RC4 context to initialize.
  @param[in]   Key     Key bytes.
  @param[in]   KeyLen  Length of Key in bytes.
**/
VOID
WpaRc4Init (
  OUT WPA_RC4_CTX  *Ctx,
  IN  CONST UINT8  *Key,
  IN  UINTN        KeyLen
  );

/**
  Generate and XOR RC4 keystream bytes.

  @param[in,out]  Ctx  Initialized RC4 context.
  @param[in]      In   Input buffer (may equal Out for in-place).
  @param[out]     Out  Output buffer.
  @param[in]      Len  Number of bytes to process.
**/
VOID
WpaRc4Process (
  IN OUT WPA_RC4_CTX  *Ctx,
  IN     CONST UINT8  *In,
  OUT    UINT8        *Out,
  IN     UINTN        Len
  );

/**
  Discard (skip) the first Skip bytes of the RC4 keystream.
  Used by TKIP per-packet key generation (skip 256 bytes).

  @param[in,out]  Ctx   Initialized RC4 context.
  @param[in]      Skip  Number of keystream bytes to discard.
**/
VOID
WpaRc4Skip (
  IN OUT WPA_RC4_CTX  *Ctx,
  IN     UINTN        Skip
  );

/**
  Compute HMAC-MD5 for WPA1 EAPOL-Key MIC (Key Descriptor Version 1).
  Returns the full 16-byte HMAC-MD5 output.

  @param[in]   Key      KCK (Key Confirmation Key, 16 bytes).
  @param[in]   KeyLen   Length of Key in bytes (16 for WPA1 KCK).
  @param[in]   Data     EAPOL frame data (MIC field zeroed).
  @param[in]   DataLen  Length of Data in bytes.
  @param[out]  Mac      16-byte output MAC buffer.

  @retval TRUE   HMAC-MD5 computation succeeded.
  @retval FALSE  HMAC-MD5 computation failed.
**/
BOOLEAN
WpaHmacMd5Mic (
  IN  CONST UINT8  *Key,
  IN  UINTN        KeyLen,
  IN  CONST UINT8  *Data,
  IN  UINTN        DataLen,
  OUT UINT8        *Mac
  );

/**
  Compute Michael MIC for TKIP frame integrity.

  @param[in]   Key       8-byte Michael key (TX-MIC or RX-MIC from TK_TKIP).
  @param[in]   Da        Destination MAC address (6 bytes).
  @param[in]   Sa        Source MAC address (6 bytes).
  @param[in]   Priority  QoS priority / TID (0 for non-QoS).
  @param[in]   Data      MSDU payload.
  @param[in]   DataLen   Length of Data in bytes.
  @param[out]  Mic       8-byte Michael MIC output.
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
  );

/**
  TKIP Phase 1 key mixing.
  Produces an 80-bit TTAK from the temporal key, transmitter address, and
  the upper 32 bits of the TKIP Sequence Counter.

  @param[in]   Tk      16-byte TKIP temporal key (first 16 bytes of TK_TKIP).
  @param[in]   Ta      Transmitter address (6 bytes).
  @param[in]   Tsc32   Upper 32 bits of the 48-bit TSC (TSC32:TSC16).
  @param[out]  Ttak    80-bit TKIP-mixed output (5 x UINT16, little-endian).
**/
VOID
WpaTkipPhase1Mix (
  IN  CONST UINT8   *Tk,
  IN  CONST UINT8   *Ta,
  IN  UINT32        Tsc32,
  OUT UINT16        Ttak[5]
  );

/**
  TKIP Phase 2 per-packet key mixing.
  Produces a 16-byte per-packet RC4 key from the TTAK, temporal key, and
  the lower 16 bits of the TSC.

  @param[in]   Ttak    80-bit TTAK from WpaTkipPhase1Mix (5 x UINT16).
  @param[in]   Tk      16-byte TKIP temporal key.
  @param[in]   Tsc16   Lower 16 bits of the 48-bit TSC.
  @param[out]  Rc4Key  16-byte per-packet RC4 key output.
**/
VOID
WpaTkipPhase2Mix (
  IN  CONST UINT16  Ttak[5],
  IN  CONST UINT8   *Tk,
  IN  UINT16        Tsc16,
  OUT UINT8         Rc4Key[16]
  );

/**
  Encrypt one 802.11 MPDU with TKIP.

  The output buffer receives: 8-byte TKIP header || RC4(plaintext || Michael
  MIC || ICV). The caller must supply a buffer at least
  DataLen + TKIP_HEADER_LEN + TKIP_MIC_LEN + TKIP_ICV_LEN bytes large.

  @param[in]   Tk         32-byte TKIP TK (TK[0:16] + TX-MIC[16:24] + RX-MIC[24:32]).
  @param[in]   Da         Destination MAC address (6 bytes).
  @param[in]   Sa         Source (transmitter) MAC address (6 bytes).
  @param[in]   Priority   QoS TID (0 for non-QoS frames).
  @param[in]   Tsc        48-bit TKIP Sequence Counter value.
  @param[in]   Data       Plaintext MSDU payload.
  @param[in]   DataLen    Length of Data in bytes.
  @param[out]  Output     Output buffer (TKIP header + encrypted payload).
  @param[out]  OutputLen  Length of Output in bytes.

  @retval EFI_SUCCESS            Encryption succeeded.
  @retval EFI_INVALID_PARAMETER  NULL pointer argument.
  @retval EFI_OUT_OF_RESOURCES   Internal allocation failure.
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
  );

/**
  Decrypt and verify one 802.11 MPDU received with TKIP.

  @param[in]   Tk         32-byte TKIP TK.
  @param[in]   Da         Destination MAC address (6 bytes).
  @param[in]   Sa         Source MAC address (6 bytes).
  @param[in]   Priority   QoS TID.
  @param[in]   Data       Input buffer including 8-byte TKIP header.
  @param[in]   DataLen    Total input length (must be > TKIP_HEADER_LEN + TKIP_ICV_LEN).
  @param[out]  Output     Decrypted MSDU payload (without Michael MIC or ICV).
  @param[out]  OutputLen  Length of Output in bytes.

  @retval EFI_SUCCESS            Decryption and MIC/ICV verification succeeded.
  @retval EFI_SECURITY_VIOLATION MIC or ICV verification failed.
  @retval EFI_INVALID_PARAMETER  NULL pointer or invalid length.
  @retval EFI_OUT_OF_RESOURCES   Internal allocation failure.
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
  );

/**
  Encrypt a WEP frame.
  Output format: 3-byte IV || 1-byte KeyID || RC4(plaintext || CRC-32).

  @param[in]   Key        WEP key (5 or 13 bytes).
  @param[in]   KeyLen     Length of Key in bytes (WEP40_KEY_LEN or WEP104_KEY_LEN).
  @param[in]   KeyId      Key index (0-3), stored in the KeyID byte.
  @param[in]   Data       Plaintext payload.
  @param[in]   DataLen    Length of Data in bytes.
  @param[out]  Output     Output buffer (DataLen + WEP_HEADER_LEN + WEP_ICV_LEN bytes).
  @param[out]  OutputLen  Length of Output in bytes.

  @retval EFI_SUCCESS            Encryption succeeded.
  @retval EFI_INVALID_PARAMETER  NULL pointer or unsupported key length.
  @retval EFI_OUT_OF_RESOURCES   Internal allocation failure.
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
  );

/**
  Decrypt and verify a WEP frame.

  @param[in]   Key        WEP key (5 or 13 bytes).
  @param[in]   KeyLen     Length of Key in bytes.
  @param[in]   Data       Input buffer including 4-byte WEP header.
  @param[in]   DataLen    Total input length (must be > WEP_HEADER_LEN + WEP_ICV_LEN).
  @param[out]  Output     Decrypted payload (without WEP header or ICV).
  @param[out]  OutputLen  Length of Output in bytes.

  @retval EFI_SUCCESS            Decryption and ICV verification succeeded.
  @retval EFI_SECURITY_VIOLATION ICV check failed.
  @retval EFI_INVALID_PARAMETER  NULL pointer or invalid length.
**/
EFI_STATUS
WpaWepDecrypt (
  IN  CONST UINT8  *Key,
  IN  UINTN        KeyLen,
  IN  CONST UINT8  *Data,
  IN  UINTN        DataLen,
  OUT UINT8        *Output,
  OUT UINTN        *OutputLen
  );

#endif // WPA_CRYPTO_H_
