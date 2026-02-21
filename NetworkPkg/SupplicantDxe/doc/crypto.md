# SupplicantDxe — Cryptographic Primitives

All primitives are declared in `WpaCrypto.h` and implemented in `WpaCrypto.c`.
They rely on `BaseCryptLib` (OpenSSL backend) for the underlying block cipher and
hash operations.

---

## High-Level Key Derivation

### WpaDerivePmk — PBKDF2-SHA1

```c
BOOLEAN WpaDerivePmk (
  IN  CONST CHAR8  *Passphrase,   // 8–63 char ASCII passphrase
  IN  CONST UINT8  *Ssid,         // SSID bytes
  IN  UINTN        SsidLen,
  OUT UINT8        *Pmk           // 32-byte output
);
```

Computes `PMK = PBKDF2(HMAC-SHA1, passphrase, SSID, 4096, 32)` per
IEEE 802.11-2020 Section 12.4.4.3.2 (WPA2-Personal). Delegates to
`Pkcs5HashPassword()` from `BaseCryptLib`.

### WpaPrfSha1 — PRF-X (HMAC-SHA1)

```c
BOOLEAN WpaPrfSha1 (
  IN  CONST UINT8  *Key,          // PMK (32 bytes)
  IN  UINTN        KeyLen,
  IN  CONST CHAR8  *Label,        // e.g. "Pairwise key expansion"
  IN  CONST UINT8  *Data,         // sorted addresses and nonces (76 bytes)
  IN  UINTN        DataLen,
  OUT UINT8        *Output,
  IN  UINTN        OutputLen      // 48 (CCMP) or 64 (TKIP)
);
```

IEEE 802.11-2020 Section 12.7.1.2.  Iterates HMAC-SHA1 with a counter byte
appended to `Label || 0x00 || Data` until `OutputLen` bytes are produced:

```
for i in 0 .. ceil(OutputLen/20):
    PRF[i] = HMAC-SHA1(Key, Label || 0x00 || Data || i)
Output = PRF[0] || PRF[1] || ... truncated to OutputLen
```

Used by WPA2-PSK for PTK derivation.

### WpaKdfSha256 — KDF-X (HMAC-SHA256)

```c
BOOLEAN WpaKdfSha256 (
  IN  CONST UINT8  *Key,
  IN  UINTN        KeyLen,
  IN  CONST CHAR8  *Label,
  IN  CONST UINT8  *Context,
  IN  UINTN        CtxLen,
  OUT UINT8        *Output,
  IN  UINTN        OutputBits     // in bits, e.g. 384 for 48-byte PTK
);
```

IEEE 802.11-2020 Section 12.7.1.7.2.  Counter-mode HMAC-SHA256:

```
for i in 1 .. ceil(OutputBits/256):
    KDF[i] = HMAC-SHA256(Key, LE16(i) || Label || 0x00 || Context || LE16(OutputBits))
Output = KDF[1] || ... truncated to OutputBits/8 bytes
```

Used by WPA3-SAE and WPA2-PSK-SHA256 for PTK derivation, and by SAE internally
for `KCK || PMK` derivation from the Dragonfly shared secret.

---

## Message Authentication

### WpaAesCmac — AES-128-CMAC (RFC 4493)

```c
BOOLEAN WpaAesCmac (
  IN  CONST UINT8  *Key,     // 16-byte AES key (KCK)
  IN  CONST UINT8  *Data,    // may be NULL for empty message
  IN  UINTN        DataLen,
  OUT UINT8        *Mac      // 16-byte output
);
```

Used as the EAPOL-Key MIC for `KeyDescVersion == 0` (WPA3-SAE, PSK-SHA256),
and internally by SAE for Commit/Confirm authentication.

Algorithm (RFC 4493):
1. Derive subkeys K1, K2 from AES-ECB(Key, 0):
   - K1 = L << 1; if MSB(L) then K1 ^= 0x87
   - K2 = K1 << 1; if MSB(K1) then K2 ^= 0x87
2. Pad last block with K1 (complete) or K2 (incomplete, pad with 0x80..00).
3. CBC-MAC over all blocks: X[i] = AES(Key, X[i-1] ^ M[i]).

### WpaHmacSha1Mic — HMAC-SHA1-128

```c
BOOLEAN WpaHmacSha1Mic (
  IN  CONST UINT8  *Key,     // KCK (16 bytes)
  IN  CONST UINT8  *Data,    // EAPOL frame with MIC field zeroed
  IN  UINTN        DataLen,
  OUT UINT8        *Mic      // 16-byte output (first 16 bytes of HMAC-SHA1)
);
```

Used as the EAPOL-Key MIC for `KeyDescVersion == 2` (WPA2-PSK / CCMP).
Returns the first 16 bytes of HMAC-SHA1(Key, Data).

### WpaHmacMd5Mic — HMAC-MD5

```c
BOOLEAN WpaHmacMd5Mic (
  IN  CONST UINT8  *Key,
  IN  UINTN        KeyLen,
  IN  CONST UINT8  *Data,
  IN  UINTN        DataLen,
  OUT UINT8        *Mac      // 16-byte output
);
```

Used as the EAPOL-Key MIC for `KeyDescVersion == 1` (WPA1 / TKIP).
Full 16-byte HMAC-MD5 output.

---

## Key Wrap

### WpaAesKeyWrap / WpaAesKeyUnwrap — RFC 3394

```c
BOOLEAN WpaAesKeyWrap (
  IN  CONST UINT8  *Kek,          // 16-byte KEK
  IN  CONST UINT8  *Plaintext,    // multiple of 8 bytes
  IN  UINTN        PlainLen,
  OUT UINT8        *Ciphertext    // PlainLen + 8 bytes
);

BOOLEAN WpaAesKeyUnwrap (
  IN  CONST UINT8  *Kek,
  IN  CONST UINT8  *Ciphertext,   // multiple of 8 bytes, ≥ 16 bytes
  IN  UINTN        CipherLen,
  OUT UINT8        *Plaintext     // CipherLen - 8 bytes
);
```

RFC 3394 authenticated key wrap. The 8-byte integrity check value (ICV)
`0xA6A6A6A6A6A6A6A6` is prepended. Six forward wrapping rounds produce
the wrapped output; six reverse rounds (with ICV verification) unwrap.
Used in EAPOL-Key message 3 to protect the GTK for `KeyDescVersion == 2`.

For `KeyDescVersion == 1` (TKIP), RC4 stream encryption is used instead
(see `WpaEapol.c`, key-data decrypt path).

### WpaAesEncryptBlock — AES-ECB Single Block

```c
BOOLEAN WpaAesEncryptBlock (
  IN  CONST UINT8  *Key,      // 16 bytes
  IN  CONST UINT8  *Input,    // 16 bytes
  OUT UINT8        *Output    // 16 bytes
);
```

Low-level primitive used by `WpaAesCmac` and `WpaAesKeyWrap` internals.
Calls `AesEncryptBlock()` from `BaseCryptLib`.

---

## CCMP (AES-CCM) Data Frame Encryption

### WpaCcmpEncrypt / WpaCcmpDecrypt

```c
BOOLEAN WpaCcmpEncrypt (
  IN  CONST UINT8  *Tk,           // 16-byte Temporal Key
  IN  CONST UINT8  *Pn,           // 6-byte Packet Number (monotonic)
  IN  CONST UINT8  *A2,           // transmitter address (6 bytes)
  IN  UINT8        Priority,      // QoS TID, 0 for non-QoS
  IN  CONST UINT8  *Header,       // 802.11 MAC header (for AAD)
  IN  UINTN        HeaderLen,
  IN  CONST UINT8  *Plaintext,
  IN  UINTN        PlainLen,
  OUT UINT8        *Ciphertext,   // PlainLen + 8 bytes (includes MIC)
  OUT UINT8        *CcmpHeader    // 8-byte CCMP header output
);

BOOLEAN WpaCcmpDecrypt (
  IN  CONST UINT8  *Tk,
  IN  CONST UINT8  *Pn,           // extracted from CCMP header
  IN  CONST UINT8  *A2,
  IN  UINT8        Priority,
  IN  CONST UINT8  *Header,
  IN  UINTN        HeaderLen,
  IN  CONST UINT8  *Ciphertext,   // includes 8-byte MIC at end
  IN  UINTN        CipherLen,
  OUT UINT8        *Plaintext     // CipherLen - 8 bytes
);
```

IEEE 802.11-2020 Section 12.5.3 (CCMP).  Internally uses `AesCcmProcess()`:
- **CBC-MAC** over `B0 || AAD || plaintext` for MIC generation.
- **AES-CTR** starting at counter 1 to encrypt plaintext; counter 0 encrypts the MIC.

**CCMP header format** (8 bytes, `WpaCcmpEncrypt` output `CcmpHeader`):

```
Byte 0: PN0  (Pn[5], least-significant byte of PN)
Byte 1: PN1  (Pn[4])
Byte 2: Reserved (0x00)
Byte 3: KeyID<<6 | 0x20  (ExtIV=1, KeyID=0 → 0x20)
Byte 4: PN2  (Pn[3])
Byte 5: PN3  (Pn[2])
Byte 6: PN4  (Pn[1])
Byte 7: PN5  (Pn[0], most-significant byte of PN)
```

The 11-byte CCM nonce is: `Priority || A2[6] || PN[5..0]` (PN in big-endian order).

---

## TKIP Frame Encryption (Legacy WPA1)

### Overview

TKIP provides per-packet key mixing to defend against WEP's static-key weakness.
Each packet uses a different RC4 key derived from the temporal key, transmitter
address, and packet sequence counter (TSC).

TKIP frame layout (output of `WpaTkipEncrypt`):

```
[TKIP Header (8)] [RC4(plaintext || Michael-MIC(8) || CRC-32(4))]
```

Total overhead per MPDU: `+8 (header) +8 (MIC) +4 (ICV) = +20 bytes`.

### WpaTkipPhase1Mix — TTAK derivation

```c
VOID WpaTkipPhase1Mix (
  IN  CONST UINT8   *Tk,       // first 16 bytes of TK_TKIP
  IN  CONST UINT8   *Ta,       // transmitter MAC address (6 bytes)
  IN  UINT32        Tsc32,     // upper 32 bits of TSC (TSC[47:16])
  OUT UINT16        Ttak[5]    // 80-bit intermediate key
);
```

Executed once per 2^16 packets (when the upper 32 bits of TSC change).
8 rounds of S-box substitution and XOR mixing of `TK`, `TA`, and `TSC[47:16]`.

### WpaTkipPhase2Mix — Per-packet RC4 key

```c
VOID WpaTkipPhase2Mix (
  IN  CONST UINT16  Ttak[5],   // from Phase 1
  IN  CONST UINT8   *Tk,
  IN  UINT16        Tsc16,     // lower 16 bits of TSC (TSC[15:0])
  OUT UINT8         Rc4Key[16] // 16-byte per-packet RC4 key
);
```

Executed once per packet. Two additional S-box mixing rounds produce the
16-byte RC4 key used to encrypt this specific MPDU.

### WpaTkipEncrypt / WpaTkipDecrypt

```c
EFI_STATUS WpaTkipEncrypt (
  IN  CONST UINT8  *Tk,        // 32-byte TKIP TK_TKIP
  IN  CONST UINT8  *Da,        // destination MAC
  IN  CONST UINT8  *Sa,        // source (transmitter) MAC
  IN  UINT8        Priority,
  IN  UINT64       Tsc,        // 48-bit counter, monotonically increasing
  IN  CONST UINT8  *Data,      // plaintext MSDU
  IN  UINTN        DataLen,
  OUT UINT8        *Output,    // TKIP header + ciphertext
  OUT UINTN        *OutputLen
);

EFI_STATUS WpaTkipDecrypt (
  IN  CONST UINT8  *Tk,
  IN  CONST UINT8  *Da,
  IN  CONST UINT8  *Sa,
  IN  UINT8        Priority,
  IN  CONST UINT8  *Data,      // includes 8-byte TKIP header
  IN  UINTN        DataLen,
  OUT UINT8        *Output,    // decrypted MSDU payload
  OUT UINTN        *OutputLen
);
```

**Encrypt steps:**
1. Phase 1 key mix: `TTAK = WpaTkipPhase1Mix(TK[0:16], Sa, TSC[47:16])`.
2. Phase 2 key mix: `Rc4Key = WpaTkipPhase2Mix(TTAK, TK, TSC[15:0])`.
3. Compute Michael MIC: `MIC = WpaMichaelMic(TX-MIC, Da, Sa, Priority, Data, DataLen)`.
4. Compute CRC-32 ICV over `Data || MIC`.
5. Build 8-byte TKIP header: `TSC1 || WEPSeed || TSC0 || KeyID|ExtIV || TSC2..TSC5`.
6. Skip first 256 bytes of RC4 keystream (`WpaRc4Skip(&Ctx, 256)`).
7. RC4-encrypt `Data || MIC || ICV`.

**Decrypt steps:**
1. Extract TSC from TKIP header; reconstruct `Tsc32` and `Tsc16`.
2. Phase 1 + Phase 2 key mix.
3. Skip 256 bytes; RC4-decrypt the payload.
4. Verify CRC-32 ICV → `EFI_SECURITY_VIOLATION` on mismatch.
5. Separate MSDU (without MIC and ICV).
6. Verify Michael MIC → `EFI_SECURITY_VIOLATION` on mismatch.

**TK_TKIP layout** (passed as `Tk` parameter):

```
[0:16)  TKIP temporal key (used by Phase 1/2 mixing)
[16:24) TX-MIC key (used by WpaMichaelMic for outgoing frames)
[24:32) RX-MIC key (used by WpaMichaelMic for incoming frames)
```

### WpaMichaelMic — Michael Message Integrity Code

```c
VOID WpaMichaelMic (
  IN  CONST UINT8  *Key,       // 8-byte Michael key
  IN  CONST UINT8  *Da,        // 6 bytes
  IN  CONST UINT8  *Sa,        // 6 bytes
  IN  UINT8        Priority,
  IN  CONST UINT8  *Data,      // MSDU payload (may be NULL for empty)
  IN  UINTN        DataLen,
  OUT UINT8        *Mic        // 8-byte output
);
```

Input to Michael is `DA || SA || Priority || 0x00 || 0x00 || 0x00 || MSDU || padding`.
The block function uses XOR, add-mod-2^32, and rotate-right operations (Feistel-like).

---

## WEP Frame Encryption (Legacy)

### WpaWepEncrypt / WpaWepDecrypt

```c
EFI_STATUS WpaWepEncrypt (
  IN  CONST UINT8  *Key,       // 5 bytes (WEP-40) or 13 bytes (WEP-104)
  IN  UINTN        KeyLen,
  IN  UINT8        KeyId,      // 0–3, stored in header byte 3 bits[7:6]
  IN  CONST UINT8  *Data,
  IN  UINTN        DataLen,
  OUT UINT8        *Output,    // WEP header (4) + RC4(Data || CRC-32)
  OUT UINTN        *OutputLen
);

EFI_STATUS WpaWepDecrypt (
  IN  CONST UINT8  *Key,
  IN  UINTN        KeyLen,
  IN  CONST UINT8  *Data,      // includes 4-byte WEP header
  IN  UINTN        DataLen,
  OUT UINT8        *Output,
  OUT UINTN        *OutputLen
);
```

WEP frame layout: `[IV(3)] [KeyID(1)] [RC4(payload || CRC-32(4))]`.

**Encrypt:** Generate 3-byte random IV; RC4 seed = `IV || Key`; CRC-32 ICV appended
before encryption.

**Decrypt:** Extract IV; RC4 decrypt; verify CRC-32 → `EFI_SECURITY_VIOLATION` on
mismatch.

Supported key lengths: `WEP40_KEY_LEN` (5) and `WEP104_KEY_LEN` (13).
Any other length returns `EFI_INVALID_PARAMETER`.

---

## RC4 Stream Cipher

```c
typedef struct { UINT8 S[256]; UINT8 I; UINT8 J; } WPA_RC4_CTX;

VOID WpaRc4Init    (OUT WPA_RC4_CTX *Ctx, IN CONST UINT8 *Key, IN UINTN KeyLen);
VOID WpaRc4Process (IN OUT WPA_RC4_CTX *Ctx, IN CONST UINT8 *In, OUT UINT8 *Out, IN UINTN Len);
VOID WpaRc4Skip    (IN OUT WPA_RC4_CTX *Ctx, IN UINTN Skip);
```

Standard RC4 KSA (key-scheduling algorithm) in `WpaRc4Init`, PRGA
(pseudo-random generation algorithm) in `WpaRc4Process`. `WpaRc4Skip` discards
`Skip` keystream bytes without producing output — used by TKIP to skip the first
256 bytes (weak-key avoidance).

`WpaRc4Process` is in-place capable (`In == Out`).

---

## Random Bytes

```c
BOOLEAN WpaRandomBytes (OUT UINT8 *Buffer, IN UINTN Size);
```

Wraps `RandomBytes()` from `BaseCryptLib` (OpenSSL `RAND_bytes` in the
firmware CryptoPkg build). Used to generate SNonce and WEP IVs.

---

## Dependency Map

```
BaseCryptLib
  ├── AesEncryptBlock()   ← WpaAesEncryptBlock
  ├── HmacSha1New/Update/Final()  ← WpaHmacSha1Mic, WpaPrfSha1
  ├── HmacSha256New/Update/Final() ← WpaKdfSha256, WpaMichaelMic (via HMAC)
  ├── HmacMd5New/Update/Final()  ← WpaHmacMd5Mic
  ├── Pkcs5HashPassword()  ← WpaDerivePmk
  ├── AesCbcEncrypt()      ← WpaAesCmac (CBC-MAC)
  └── RandomBytes()        ← WpaRandomBytes
```
