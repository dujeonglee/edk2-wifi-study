/**
  BaseCryptShim.c — OpenSSL 3 implementation of the EDK2 BaseCryptLib API
  surface used by WpaCrypto.c.

  Each function mirrors the signature declared in include/Library/BaseCryptLib.h
  and used by the production source.  The implementation delegates to OpenSSL's
  EVP API (no deprecated low-level functions).
**/

#include <Uefi.h>
#include <Library/BaseCryptLib.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <string.h>
#include <stdlib.h>

/* =========================================================================
   Internal context types
   ========================================================================= */

/** AES context stores the raw key so we can re-init EVP per call. **/
typedef struct {
  UINT8   Key[32];   /* up to 256-bit key */
  UINT32  KeyBits;
} NATIVE_AES_CTX;

/** SHA-1 / MD5 context stores an EVP_MD_CTX pointer. **/
typedef struct {
  EVP_MD_CTX  *Evp;
} NATIVE_DIGEST_CTX;

/* =========================================================================
   AES
   ========================================================================= */

UINTN
AesGetContextSize (
  VOID
  )
{
  return sizeof (NATIVE_AES_CTX);
}

BOOLEAN
AesInit (
  OUT VOID        *AesContext,
  IN  CONST UINT8 *Key,
  IN  UINTN       KeyBits
  )
{
  NATIVE_AES_CTX  *Ctx;

  if ((AesContext == NULL) || (Key == NULL)) {
    return FALSE;
  }

  if ((KeyBits != 128) && (KeyBits != 192) && (KeyBits != 256)) {
    return FALSE;
  }

  Ctx = (NATIVE_AES_CTX *)AesContext;
  memcpy (Ctx->Key, Key, KeyBits / 8);
  Ctx->KeyBits = (UINT32)KeyBits;
  return TRUE;
}

static const EVP_CIPHER *
SelectAesCbc (
  UINT32  KeyBits
  )
{
  switch (KeyBits) {
    case 128: return EVP_aes_128_cbc ();
    case 192: return EVP_aes_192_cbc ();
    case 256: return EVP_aes_256_cbc ();
    default:  return NULL;
  }
}

BOOLEAN
AesCbcEncrypt (
  IN  VOID        *AesContext,
  IN  CONST UINT8 *Input,
  IN  UINTN       InputSize,
  IN  CONST UINT8 *Ivec,
  OUT UINT8       *Output
  )
{
  NATIVE_AES_CTX   *Ctx;
  EVP_CIPHER_CTX   *Evp;
  const EVP_CIPHER *Cipher;
  int               OutLen;
  BOOLEAN           Ok;

  if ((AesContext == NULL) || (Input == NULL) || (Ivec == NULL) || (Output == NULL)) {
    return FALSE;
  }

  Ctx    = (NATIVE_AES_CTX *)AesContext;
  Cipher = SelectAesCbc (Ctx->KeyBits);
  if (Cipher == NULL) {
    return FALSE;
  }

  Evp = EVP_CIPHER_CTX_new ();
  if (Evp == NULL) {
    return FALSE;
  }

  Ok = (EVP_EncryptInit_ex (Evp, Cipher, NULL, Ctx->Key, Ivec) == 1) &&
       (EVP_CIPHER_CTX_set_padding (Evp, 0) == 1) &&
       (EVP_EncryptUpdate (Evp, Output, &OutLen, Input, (int)InputSize) == 1);

  EVP_CIPHER_CTX_free (Evp);
  return Ok;
}

BOOLEAN
AesCbcDecrypt (
  IN  VOID        *AesContext,
  IN  CONST UINT8 *Input,
  IN  UINTN       InputSize,
  IN  CONST UINT8 *Ivec,
  OUT UINT8       *Output
  )
{
  NATIVE_AES_CTX   *Ctx;
  EVP_CIPHER_CTX   *Evp;
  const EVP_CIPHER *Cipher;
  int               OutLen;
  BOOLEAN           Ok;

  if ((AesContext == NULL) || (Input == NULL) || (Ivec == NULL) || (Output == NULL)) {
    return FALSE;
  }

  Ctx    = (NATIVE_AES_CTX *)AesContext;
  Cipher = SelectAesCbc (Ctx->KeyBits);
  if (Cipher == NULL) {
    return FALSE;
  }

  Evp = EVP_CIPHER_CTX_new ();
  if (Evp == NULL) {
    return FALSE;
  }

  Ok = (EVP_DecryptInit_ex (Evp, Cipher, NULL, Ctx->Key, Ivec) == 1) &&
       (EVP_CIPHER_CTX_set_padding (Evp, 0) == 1) &&
       (EVP_DecryptUpdate (Evp, Output, &OutLen, Input, (int)InputSize) == 1);

  EVP_CIPHER_CTX_free (Evp);
  return Ok;
}

/* =========================================================================
   SHA-1
   ========================================================================= */

UINTN
Sha1GetContextSize (
  VOID
  )
{
  return sizeof (NATIVE_DIGEST_CTX);
}

BOOLEAN
Sha1Init (
  OUT VOID  *Sha1Context
  )
{
  NATIVE_DIGEST_CTX  *Ctx;

  if (Sha1Context == NULL) {
    return FALSE;
  }

  Ctx = (NATIVE_DIGEST_CTX *)Sha1Context;

  /* Re-init: free any previous EVP context */
  if (Ctx->Evp != NULL) {
    EVP_MD_CTX_free (Ctx->Evp);
    Ctx->Evp = NULL;
  }

  Ctx->Evp = EVP_MD_CTX_new ();
  if (Ctx->Evp == NULL) {
    return FALSE;
  }

  return EVP_DigestInit_ex (Ctx->Evp, EVP_sha1 (), NULL) == 1;
}

BOOLEAN
Sha1Update (
  IN OUT VOID        *Sha1Context,
  IN     CONST VOID  *Data,
  IN     UINTN       DataSize
  )
{
  NATIVE_DIGEST_CTX  *Ctx;

  if ((Sha1Context == NULL) || (Data == NULL)) {
    return FALSE;
  }

  Ctx = (NATIVE_DIGEST_CTX *)Sha1Context;
  return EVP_DigestUpdate (Ctx->Evp, Data, DataSize) == 1;
}

BOOLEAN
Sha1Final (
  IN OUT VOID   *Sha1Context,
  OUT    UINT8  *HashValue
  )
{
  NATIVE_DIGEST_CTX  *Ctx;
  unsigned int        Len;
  BOOLEAN             Ok;

  if ((Sha1Context == NULL) || (HashValue == NULL)) {
    return FALSE;
  }

  Ctx = (NATIVE_DIGEST_CTX *)Sha1Context;
  Ok  = EVP_DigestFinal_ex (Ctx->Evp, HashValue, &Len) == 1;

  /* Free the EVP context so the buffer can be re-used via Sha1Init() */
  EVP_MD_CTX_free (Ctx->Evp);
  Ctx->Evp = NULL;

  return Ok;
}

/* =========================================================================
   HMAC-SHA-256 (one-shot)
   ========================================================================= */

BOOLEAN
HmacSha256All (
  IN  CONST VOID  *Data,
  IN  UINTN       DataSize,
  IN  CONST UINT8 *Key,
  IN  UINTN       KeySize,
  OUT UINT8       *HmacValue
  )
{
  unsigned int  Len;

  if ((Data == NULL) || (Key == NULL) || (HmacValue == NULL)) {
    return FALSE;
  }

  return HMAC (
           EVP_sha256 (),
           Key,
           (int)KeySize,
           (const unsigned char *)Data,
           DataSize,
           HmacValue,
           &Len
           ) != NULL;
}

/* =========================================================================
   PBKDF2-SHA1  (Pkcs5HashPassword)
   ========================================================================= */

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
  )
{
  (void)DigestSize; /* SHA-1 is implicit in PKCS5_PBKDF2_HMAC_SHA1 */

  if ((Password == NULL) || (Salt == NULL) || (OutKey == NULL)) {
    return FALSE;
  }

  return PKCS5_PBKDF2_HMAC_SHA1 (
           Password,
           (int)PasswordLength,
           Salt,
           (int)SaltLength,
           (int)IterationCount,
           (int)KeyLength,
           OutKey
           ) == 1;
}

/* =========================================================================
   Random bytes
   ========================================================================= */

BOOLEAN
RandomBytes (
  OUT UINT8  *Output,
  IN  UINTN  Size
  )
{
  if ((Output == NULL) || (Size == 0)) {
    return FALSE;
  }

  return RAND_bytes (Output, (int)Size) == 1;
}

/* =========================================================================
   MD5
   ========================================================================= */

UINTN
Md5GetContextSize (
  VOID
  )
{
  return sizeof (NATIVE_DIGEST_CTX);
}

BOOLEAN
Md5Init (
  OUT VOID  *Md5Context
  )
{
  NATIVE_DIGEST_CTX  *Ctx;

  if (Md5Context == NULL) {
    return FALSE;
  }

  Ctx = (NATIVE_DIGEST_CTX *)Md5Context;

  if (Ctx->Evp != NULL) {
    EVP_MD_CTX_free (Ctx->Evp);
    Ctx->Evp = NULL;
  }

  Ctx->Evp = EVP_MD_CTX_new ();
  if (Ctx->Evp == NULL) {
    return FALSE;
  }

  return EVP_DigestInit_ex (Ctx->Evp, EVP_md5 (), NULL) == 1;
}

BOOLEAN
Md5Update (
  IN OUT VOID        *Md5Context,
  IN     CONST VOID  *Data,
  IN     UINTN       DataSize
  )
{
  NATIVE_DIGEST_CTX  *Ctx;

  if ((Md5Context == NULL) || (Data == NULL)) {
    return FALSE;
  }

  Ctx = (NATIVE_DIGEST_CTX *)Md5Context;
  return EVP_DigestUpdate (Ctx->Evp, Data, DataSize) == 1;
}

BOOLEAN
Md5Final (
  IN OUT VOID   *Md5Context,
  OUT    UINT8  *HashValue
  )
{
  NATIVE_DIGEST_CTX  *Ctx;
  unsigned int        Len;
  BOOLEAN             Ok;

  if ((Md5Context == NULL) || (HashValue == NULL)) {
    return FALSE;
  }

  Ctx = (NATIVE_DIGEST_CTX *)Md5Context;
  Ok  = EVP_DigestFinal_ex (Ctx->Evp, HashValue, &Len) == 1;

  EVP_MD_CTX_free (Ctx->Evp);
  Ctx->Evp = NULL;

  return Ok;
}
