# SupplicantDxe — Unit Test Documentation

There are two test build systems:

| Build | Location | Platform | Test runner |
|-------|----------|----------|-------------|
| EDK II host tests | `GoogleTest/` | Ubuntu x86-64 (CI) | GoogleTest binary |
| Native macOS harness | `NativeTest/` | macOS arm64 | Make + GoogleTest |

---

## 1. EDK II Host Tests (Google Test)

### Source Files

| File | Tests |
|------|-------|
| `GoogleTest/SupplicantDxeGoogleTest.cpp` | WpaCrypto primitives + RC4, HMAC-MD5, Michael MIC, TKIP, WEP |
| `GoogleTest/WpaEapolGoogleTest.cpp` | EAPOL 4-Way Handshake state machine |
| `GoogleTest/SupplicantImplGoogleTest.cpp` | `EFI_SUPPLICANT_PROTOCOL` SetData/GetData |

### INF Registration

Tests are declared in `GoogleTest/SupplicantDxeGoogleTest.inf` under `[Sources]` and
registered in `NetworkPkg/Test/NetworkPkgHostTest.dsc`.

### Build & Run

```bash
# Build (from repo root, after . edksetup.sh)
build -p NetworkPkg/Test/NetworkPkgHostTest.dsc -t GCC -a X64 -b NOOPT

# Run all tests
Build/NetworkPkg/NOOPT_GCC/X64/SupplicantDxeGoogleTest

# CI (runs all NetworkPkg host tests including this one)
stuart_ci_build -c .pytool/CISettings.py -p NetworkPkg HostUnitTestCompilerPlugin=run
```

---

## 2. Native macOS Test Harness

Located in `NativeTest/`. Compiles `WpaCrypto.c` and `SupplicantDxeGoogleTest.cpp`
directly against Apple clang, OpenSSL 3 (Homebrew), and GoogleTest (Homebrew).

### Prerequisites

```bash
brew install googletest openssl@3
```

### Build & Run

```bash
cd NetworkPkg/SupplicantDxe/NativeTest
make run          # build SupplicantCryptoTest and execute
make clean        # remove build artifacts
```

All 51 tests pass on macOS arm64. The binary is `SupplicantCryptoTest`.

### Architecture

```
NativeTest/
├── Makefile               Apple clang, links OpenSSL 3 + GoogleTest
├── BaseCryptShim.c        OpenSSL 3 EVP implementation of BaseCryptLib APIs
└── include/
    ├── Uefi.h             EDK II type shims (UINT8, EFI_STATUS, etc.)
    └── Library/
        ├── BaseMemoryLib.h       CopyMem, SetMem, ZeroMem, CompareMem
        ├── MemoryAllocationLib.h AllocatePool, FreePool, AllocateZeroPool
        ├── DebugLib.h            DEBUG() macro → fprintf
        ├── BaseLib.h             AsciiStrLen
        ├── BaseCryptLib.h        prototype stubs
        └── GoogleTestLib.h       includes <gtest/gtest.h>
```

`BaseCryptShim.c` implements the following `BaseCryptLib` APIs using OpenSSL 3 EVP:
- `AesEncryptBlock` — `EVP_CIPHER_CTX` with `EVP_aes_128_ecb()`
- `HmacSha1New/SetKey/Update/Final/Free` — `EVP_MAC` with `HMAC` + `SHA1`
- `HmacSha256New/SetKey/Update/Final/Free` — `HMAC` + `SHA256`
- `HmacMd5New/SetKey/Update/Final/Free` — `HMAC` + `MD5`
- `Pkcs5HashPassword` — `PKCS5_PBKDF2_HMAC` with `EVP_sha1()`
- `Md5HashAll` — `EVP_Digest` with `EVP_md5()`
- `RandomBytes` — `RAND_bytes()`
- `AesCbcEncrypt` — `EVP_CIPHER_CTX` with `EVP_aes_128_cbc()`

---

## 3. Test Catalogue

### SupplicantDxeGoogleTest.cpp

#### WpaAesCmacTest — AES-128-CMAC (RFC 4493)

Uses the RFC 4493 key `2b7e151628aed2a6abf7158809cf4f3c`.

| Test | Description | Expected |
|------|-------------|----------|
| `EmptyMessage` | CMAC of 0-byte message | `bb1d6929e9593728 7fa37d129b756746` |
| `OneBlock` | CMAC of 16-byte message | `070a16b46b4d4144 f79bdd9dd04a287c` |
| `PartialLastBlock` | CMAC of 40-byte message | `dfa66747de9ae630 30ca326114 97c827` |
| `FourBlocks` | CMAC of 64-byte message | `51f0bebf7e3b9d92 fc497417 79363cfe` |
| `NullKeyFails` | NULL key → FALSE | — |
| `NullMacFails` | NULL mac output → FALSE | — |

#### WpaAesKeyWrapTest — AES Key Wrap/Unwrap (RFC 3394)

Uses RFC 3394 Section 4.1 vectors: KEK `000102030405060708090a0b0c0d0e0f`,
plaintext `00112233445566778899aabbccddeeff`.

| Test | Description |
|------|-------------|
| `WrapRfc3394Vector` | Wrap produces `1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5` |
| `UnwrapRfc3394Vector` | Unwrap recovers original plaintext |
| `WrapUnwrapRoundTrip` | 32-byte round-trip with a different key |
| `UnwrapTamperedDataFails` | Single byte flip → FALSE |
| `NullParametersFail` | NULL key/plaintext/ciphertext, zero length, non-8-multiple → FALSE |

#### WpaHmacSha1MicTest

| Test | Description |
|------|-------------|
| `KnownVector` | key `0b0b..0b`, data `"Hi There"` → non-zero, non-all-zero output |
| `DeterministicOutput` | Same inputs produce identical 16-byte MICs |
| `NullParametersFail` | NULL key/data/mic → FALSE |

#### WpaPrfSha1Test

| Test | Description |
|------|-------------|
| `BasicDerivation` | 48-byte output is non-zero and deterministic |
| `DifferentLabelProducesDifferentOutput` | "Label A" vs "Label B" → distinct outputs |
| `NullParametersFail` | NULL key/label/data/output → FALSE |

#### WpaKdfSha256Test

| Test | Description |
|------|-------------|
| `BasicDerivation` | 48-byte output is deterministic |
| `DifferentKeyProducesDifferentOutput` | Different keys → different outputs |
| `NullParametersFail` | NULL parameters → FALSE |

#### WpaAesEncryptBlockTest

| Test | Description | Expected |
|------|-------------|----------|
| `KnownVector` | NIST AES-128 ECB block test | `3ad77bb40d7a3660a89ecaf32466ef97` |
| `NullParametersFail` | NULL inputs → FALSE | — |

#### WpaCcmpTest — CCMP Encrypt/Decrypt

Uses TK `66ed21042f9f26d7115706e40414cf2e`, PN `000000000001`, A2 `020304050607`.

| Test | Description |
|------|-------------|
| `EncryptDecryptRoundTrip` | 32-byte plaintext: encrypt then decrypt recovers original |
| `TamperedCiphertextFails` | Flip byte 5 of ciphertext → decrypt returns FALSE |
| `WrongKeyFails` | Different TK on decrypt → FALSE |
| `CcmpHeaderFormat` | Verifies byte ordering of PN in 8-byte CCMP header: PN0=Pn[5], PN1=Pn[4], byte 3=0x20, PN2-5=Pn[3..0] |
| `NullParametersFail` | NULL any required pointer → FALSE; ciphertext too short (≤ MIC_LEN) → FALSE |

#### WpaRandomBytesTest

| Test | Description |
|------|-------------|
| `ProducesOutput` | Two calls return different 32-byte buffers |
| `NullParametersFail` | NULL buffer or 0 size → FALSE |

#### WpaHelperMacroTest

| Test | Description |
|------|-------------|
| `GetPutBE16` | `WPA_PUT_BE16` stores MSB first; `WPA_GET_BE16` reads back correctly |
| `GetPutBE32` | Same for 32-bit big-endian |
| `GetPutLE16` | `WPA_PUT_LE16` stores LSB first; `WPA_GET_LE16` reads back correctly |

#### WpaRc4Test — RC4 (RFC 6229)

| Test | Description | Expected |
|------|-------------|----------|
| `Rc4BasicVector` | key `0102030405`, 16 output bytes from offset 0 | `b2396305f03dc027ccc3524a0a1118a8` |
| `Rc4SkipVerification` | Skip(16) + 16 bytes == bytes 16-31 without skip | — |
| `Rc4RoundTrip` | Encrypt then decrypt with same key recovers plaintext | — |

#### WpaHmacMd5Test — HMAC-MD5 (RFC 2202)

| Test | Description | Expected |
|------|-------------|----------|
| `Rfc2202Vector1` | key `0b0b..0b`(16), data `"Hi There"` | `9294727a3638bb1c13f48ef8158bfc9d` |
| `Rfc2202Vector2` | key `"Jefe"`, data `"what do ya want for nothing?"` | `750c783e6ab0b503eaa86e310a5db738` |
| `NullKeyFails` | NULL key → FALSE | — |

#### WpaMichaelMicTest

| Test | Description |
|------|-------------|
| `EmptyPayload` | MIC over empty MSDU is non-zero |
| `Deterministic` | Same inputs produce identical 8-byte MIC |
| `DifferentKeys` | Different 8-byte keys produce distinct MICs |

#### WpaTkipKeyMixTest — TKIP Phase 1/2

| Test | Description |
|------|-------------|
| `Phase1Deterministic` | Same TK, TA, TSC32 → identical 80-bit TTAK |
| `Phase1DifferentTsc` | TSC32 0 vs 1 → different TTAK |
| `Phase2Deterministic` | Same TTAK, TK, TSC16 → identical 16-byte RC4 key |
| `Phase2DifferentTsc16` | TSC16 0 vs 1 → different RC4 key |

#### WpaTkipCryptTest — TKIP Encrypt/Decrypt

| Test | Description |
|------|-------------|
| `EncryptDecryptRoundTrip` | 10-byte payload; output length = payload + 8+8+4; round-trip recovers original |
| `TamperDetection` | Flip bit in ciphertext payload → `EFI_SECURITY_VIOLATION` |

Note: The TK in `EncryptDecryptRoundTrip` has TX-MIC == RX-MIC (bytes 16-23 equal
bytes 24-31) so that the loopback test can verify the MIC both ways with the same key.

#### WpaWepCryptTest — WEP Encrypt/Decrypt

| Test | Description |
|------|-------------|
| `Wep40RoundTrip` | 5-byte key; output = payload + 4 (header) + 4 (ICV); round-trip |
| `Wep104RoundTrip` | 13-byte key; round-trip with key ID 2 |
| `TamperDetection` | Flip first byte of ciphertext → `EFI_SECURITY_VIOLATION` |
| `InvalidKeyLengthFails` | 8-byte key → `EFI_INVALID_PARAMETER` for both encrypt and decrypt |

---

### WpaEapolGoogleTest.cpp

Tests the EAPOL 4-Way Handshake state machine. A mock `SUPPLICANT_PRIVATE_DATA`
is constructed inline, with pre-computed PMK and pre-set configuration.

Key test classes and scenarios (representative; file has ~706 lines):

| Test class | Scenarios |
|------------|-----------|
| `WpaDerivePtkTest` | PTK derivation with PSK+CCMP (48-byte), PSK+TKIP (64-byte), SAE (48-byte KDF-SHA256); sorted MAC/nonce ordering |
| `WpaBuildRsnIeTest` | RSN IE field values for PSK+CCMP and SAE+CCMP; minimum IE size |
| `WpaEapolMsg1to2Test` | Full Message 1 → Message 2 round-trip; verifies SNonce in Message 2; verifies MIC |
| `WpaEapolMsg3to4Test` | Full Message 3 → Message 4; verifies MIC; verifies GTK installed; verifies `PtkValid` |
| `WpaEapolGroupKeyTest` | Group Key Message 1 → 2; verifies GTK updated |
| `WpaEapolMicVersionTest` | KeyDescVersion 0, 1, 2 all compute non-identical MICs with same data |
| `WpaEapolResetTest` | After reset: nonces zeroed, `PtkValid=FALSE`, state = `Wpa4WayIdle` |
| `WpaKeyDescVersionTest` | `UpdateKeyDescVersion`: SAE→0, TKIP→1, CCMP→2 |

---

### SupplicantImplGoogleTest.cpp

Tests `SupplicantSetData` and `SupplicantGetData` through a fully initialised
`SUPPLICANT_PRIVATE_DATA` (not a firmware instance — allocated directly in the test).

Key test classes (~685 lines):

| Test class | Scenarios |
|------------|-----------|
| `SupplicantSetDataAkmTest` | SetData for PSK, PSK-SHA256, SAE; verifies `AkmSuiteType`, `KeyDescVersion` |
| `SupplicantSetDataCipherTest` | SetData for CCMP, TKIP, WEP-40, WEP-104; verifies `PairwiseCipherType` |
| `SupplicantSetDataPasswordTest` | Valid 8-63 char password; too-short password; invalidates PMK |
| `SupplicantSetDataSsidTest` | SetData SSID; invalidates PMK; 32-byte max |
| `SupplicantSetDataMacTest` | SetData StationMac and TargetBssid |
| `SupplicantSetDataPmkTest` | Direct PMK install (32 bytes); verifies `PmkValid` |
| `SupplicantSetDataPtkTest` | Direct PTK install (48 and 64 bytes); verifies `PtkValid` |
| `SupplicantSetDataGtkTest` | GTK install at key IDs 1 and 2; verifies storage |
| `SupplicantSetDataWepTest` | WEP-40 (5 bytes) and WEP-104 (13 bytes) key install |
| `SupplicantGetDataSupportedSuites` | Returns 3 AKM suites and 5 cipher suites |
| `SupplicantGetDataPmkTest` | Returns PMK when valid; `EFI_NOT_READY` when not |
| `SupplicantGetDataGtkTest` | Returns GTK by key ID |
| `SupplicantGetDataSizeQuery` | Two-phase pattern: `Data==NULL` returns required size |

---

## 4. Test Coverage Summary

| Component | Test file(s) | Known-vector tests | Round-trip / tamper tests |
|-----------|-------------|-------------------|---------------------------|
| AES-CMAC | `SupplicantDxeGoogleTest.cpp` | 4 RFC 4493 | — |
| AES Key Wrap | same | 1 RFC 3394 | 1 round-trip, 1 tamper |
| HMAC-SHA1-128 | same | 1 known-vector | — |
| PRF-SHA1 | same | — | Determinism, label separation |
| KDF-SHA256 | same | — | Determinism, key separation |
| AES-ECB | same | 1 NIST | — |
| CCMP | same | — | 1 round-trip, 1 tamper, 1 wrong-key |
| CCMP header layout | same | Header byte check | — |
| RC4 | same | 1 RFC 6229 | 1 round-trip, skip verify |
| HMAC-MD5 | same | 2 RFC 2202 | — |
| Michael MIC | same | — | Determinism, key separation |
| TKIP Phase 1/2 | same | — | Determinism, TSC sensitivity |
| TKIP encrypt/decrypt | same | — | 1 round-trip, 1 tamper |
| WEP-40 | same | — | 1 round-trip |
| WEP-104 | same | — | 1 round-trip |
| WEP tamper/invalid key | same | — | 1 tamper, 1 invalid length |
| EAPOL state machine | `WpaEapolGoogleTest.cpp` | — | Full Msg1→4 and group key |
| PTK derivation | same | — | 3 AKM/cipher combinations |
| KeyDescVersion logic | same | — | 3 configurations |
| SetData/GetData | `SupplicantImplGoogleTest.cpp` | — | All DataType values |
