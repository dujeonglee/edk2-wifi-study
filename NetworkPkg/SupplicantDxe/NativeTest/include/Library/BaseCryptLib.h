/** @file
  BaseCryptLib shim declarations: mirrors the EDK2 BaseCryptLib API surface
  used by WpaCrypto.c.  Implemented in BaseCryptShim.c via OpenSSL.
**/

#ifndef BASE_CRYPT_LIB_SHIM_H_
#define BASE_CRYPT_LIB_SHIM_H_

#include <Uefi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
   AES (CBC mode)
   ======================================================================== */

/**
  Return the size in bytes of the AES context buffer required by AesInit().
**/
UINTN
AesGetContextSize (
  VOID
  );

/**
  Initialise an AES context with the given key.

  @param[out]  AesContext  Caller-allocated buffer of AesGetContextSize() bytes.
  @param[in]   Key         AES key bytes.
  @param[in]   KeyBits     Key size in bits: 128, 192, or 256.
  @retval TRUE   Success.
  @retval FALSE  Failure.
**/
BOOLEAN
AesInit (
  OUT VOID        *AesContext,
  IN  CONST UINT8 *Key,
  IN  UINTN       KeyBits
  );

/**
  AES-CBC encryption.  No padding is applied (InputSize must be a multiple of 16).

  @param[in]   AesContext  Initialised AES context.
  @param[in]   Input       Plaintext buffer.
  @param[in]   InputSize   Length of Input in bytes.
  @param[in]   Ivec        16-byte IV (consumed but NOT updated by this call).
  @param[out]  Output      Ciphertext buffer (same size as Input).
  @retval TRUE   Success.
  @retval FALSE  Failure.
**/
BOOLEAN
AesCbcEncrypt (
  IN  VOID        *AesContext,
  IN  CONST UINT8 *Input,
  IN  UINTN       InputSize,
  IN  CONST UINT8 *Ivec,
  OUT UINT8       *Output
  );

/**
  AES-CBC decryption.  No padding is applied.

  @param[in]   AesContext  Initialised AES context.
  @param[in]   Input       Ciphertext buffer.
  @param[in]   InputSize   Length of Input in bytes.
  @param[in]   Ivec        16-byte IV.
  @param[out]  Output      Plaintext buffer.
  @retval TRUE   Success.
  @retval FALSE  Failure.
**/
BOOLEAN
AesCbcDecrypt (
  IN  VOID        *AesContext,
  IN  CONST UINT8 *Input,
  IN  UINTN       InputSize,
  IN  CONST UINT8 *Ivec,
  OUT UINT8       *Output
  );

/* ========================================================================
   SHA-1
   ======================================================================== */

UINTN
Sha1GetContextSize (
  VOID
  );

BOOLEAN
Sha1Init (
  OUT VOID  *Sha1Context
  );

BOOLEAN
Sha1Update (
  IN OUT VOID        *Sha1Context,
  IN     CONST VOID  *Data,
  IN     UINTN       DataSize
  );

BOOLEAN
Sha1Final (
  IN OUT VOID   *Sha1Context,
  OUT    UINT8  *HashValue
  );

/* ========================================================================
   HMAC-SHA-256 (one-shot)
   ======================================================================== */

/**
  Compute HMAC-SHA-256 in a single call.

  @param[in]   Data       Message data.
  @param[in]   DataSize   Length of Data in bytes.
  @param[in]   Key        HMAC key.
  @param[in]   KeySize    Length of Key in bytes.
  @param[out]  HmacValue  32-byte output buffer.
  @retval TRUE   Success.
  @retval FALSE  Failure.
**/
BOOLEAN
HmacSha256All (
  IN  CONST VOID  *Data,
  IN  UINTN       DataSize,
  IN  CONST UINT8 *Key,
  IN  UINTN       KeySize,
  OUT UINT8       *HmacValue
  );

/* ========================================================================
   PBKDF2-SHA1 (Pkcs5HashPassword)
   ======================================================================== */

/**
  Derive a key from a password using PKCS#5 PBKDF2 with HMAC-SHA1.

  Parameter order matches EDK2 BaseCryptLib exactly.

  @param[in]   PasswordLength  Length of Password in bytes.
  @param[in]   Password        Password (not null-terminated required).
  @param[in]   SaltLength      Length of Salt in bytes.
  @param[in]   Salt            Salt bytes.
  @param[in]   IterationCount  PBKDF2 iteration count.
  @param[in]   DigestSize      PRF output size in bytes (20 for SHA-1).
  @param[in]   KeyLength       Desired output key length in bytes.
  @param[out]  OutKey          Output key buffer.
  @retval TRUE   Success.
  @retval FALSE  Failure.
**/
BOOLEAN
Pkcs5HashPassword (
  IN  UINTN        PasswordLength,
  IN  CONST CHAR8  *Password,
  IN  UINTN        SaltLength,
  IN  CONST UINT8  *Salt,
  IN  UINTN        IterationCount,
  IN  UINTN        DigestSize,
  IN  UINTN        KeyLength,
  OUT UINT8        *OutKey
  );

/* ========================================================================
   Random bytes
   ======================================================================== */

/**
  Fill a buffer with cryptographically random bytes.

  @param[out]  Output  Destination buffer.
  @param[in]   Size    Number of bytes to generate.
  @retval TRUE   Success.
  @retval FALSE  Failure.
**/
BOOLEAN
RandomBytes (
  OUT UINT8  *Output,
  IN  UINTN  Size
  );

/* ========================================================================
   MD5
   ======================================================================== */

UINTN
Md5GetContextSize (
  VOID
  );

BOOLEAN
Md5Init (
  OUT VOID  *Md5Context
  );

BOOLEAN
Md5Update (
  IN OUT VOID        *Md5Context,
  IN     CONST VOID  *Data,
  IN     UINTN       DataSize
  );

BOOLEAN
Md5Final (
  IN OUT VOID   *Md5Context,
  OUT    UINT8  *HashValue
  );

#ifdef __cplusplus
}
#endif

#endif /* BASE_CRYPT_LIB_SHIM_H_ */
