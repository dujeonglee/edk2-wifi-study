# SupplicantDxe — Architecture

## Module Overview

`SupplicantDxe` is a UEFI DXE driver that implements `EFI_SUPPLICANT_PROTOCOL` for
WPA2-Personal (PSK) and WPA3-Personal (SAE) Wi-Fi authentication. Its consumer is
`WifiConnectionManagerDxe`, which calls into the protocol to conduct authentication
and then encrypt/decrypt data frames.

## Source File Map

```
NetworkPkg/SupplicantDxe/
├── SupplicantDxe.inf          EDK II module description
├── SupplicantDxe.h            Private data structure + protocol declarations
├── WpaCommon.h                On-wire constants, structs, helper macros
├── SupplicantDriver.c         Driver entry/unload; installs the protocol
├── SupplicantImpl.c           EFI_SUPPLICANT_PROTOCOL implementation
├── WpaCrypto.h / .c           Cryptographic primitives
├── WpaEapol.h / .c            EAPOL 4-Way and Group Key Handshake
├── WpaSae.h   / .c            SAE (Dragonfly) commit/confirm
├── GoogleTest/
│   ├── SupplicantDxeGoogleTest.cpp   WpaCrypto unit tests
│   ├── WpaEapolGoogleTest.cpp        4-Way Handshake tests
│   └── SupplicantImplGoogleTest.cpp  SetData/GetData protocol tests
└── NativeTest/                       macOS native test harness
    ├── Makefile
    ├── BaseCryptShim.c
    └── include/
```

## INF Summary

| Field | Value |
|-------|-------|
| `BASE_NAME` | `SupplicantDxe` |
| `FILE_GUID` | `A2B45F9E-3C7D-4E1A-B8F6-7D2E5A6C8B01` |
| `MODULE_TYPE` | `DXE_DRIVER` |
| `ENTRY_POINT` | `SupplicantDxeDriverEntryPoint` |
| `UNLOAD_IMAGE` | `SupplicantDxeDriverUnload` |
| Produces | `gEfiSupplicantProtocolGuid` |
| `[Depex]` | `TRUE` (no dependencies) |

Library classes used: `UefiDriverEntryPoint`, `UefiBootServicesTableLib`,
`MemoryAllocationLib`, `BaseMemoryLib`, `BaseLib`, `UefiLib`, `DebugLib`, `BaseCryptLib`.

## SUPPLICANT_PRIVATE_DATA Structure

Defined in `SupplicantDxe.h:80`. The full 154-line structure holds all session state.

```
struct _SUPPLICANT_PRIVATE_DATA {
  UINT32                          Signature;          // 'WPAS'
  EFI_HANDLE                      Handle;
  EFI_SUPPLICANT_PROTOCOL         Supplicant;         // produced protocol

  // --- Configuration (set via SetData) ---
  UINT8   AkmSuiteOui[3];        // typically 00-0F-AC
  UINT8   AkmSuiteType;          // WPA_AKM_SUITE_PSK (2), _PSK_SHA256 (6), _SAE (8)
  UINT8   PairwiseCipherOui[3];
  UINT8   PairwiseCipherType;    // WPA_CIPHER_SUITE_CCMP (4), _TKIP (2), _WEP40 (1), _WEP104 (5)
  UINT8   GroupCipherOui[3];
  UINT8   GroupCipherType;
  CHAR8   Password[64];          // 8-63 char passphrase + NUL
  UINTN   PasswordLen;
  EFI_80211_SSID        TargetSsid;
  EFI_80211_MAC_ADDRESS StationMac;   // SPA / supplicant address
  EFI_80211_MAC_ADDRESS TargetBssid;  // AA  / authenticator address

  // --- PMK ---
  UINT8   Pmk[32];               // Pairwise Master Key
  BOOLEAN PmkValid;

  // --- 4-Way Handshake state ---
  WPA_4WAY_STATE  FourWayState;
  UINT8   ANonce[32];            // AP nonce (from message 1)
  UINT8   SNonce[32];            // station nonce (generated for message 2)
  UINT8   ReplayCounter[8];
  UINT8   PtkRaw[64];            // Raw PTK storage (see layout below)
  BOOLEAN PtkValid;

  // --- Group/IGTK ---
  WPA_GTK_ENTRY   Gtk[4];        // up to 4 GTK entries
  UINT8           GtkCount;
  WPA_IGTK_ENTRY  Igtk[2];       // up to 2 IGTK entries
  UINT8           IgtkCount;
  BOOLEAN         GtkRefreshed;

  // --- Link state ---
  EFI_80211_LINK_STATE             LinkState;
  EFI_EAPOL_SUPPLICANT_PAE_STATE   PaeState;

  // --- SAE (WPA3-Personal) ---
  SAE_SESSION  SaeSession;

  // --- CCMP packet counter ---
  UINT8   TxPn[6];               // monotonically increasing TX packet number

  // --- WEP legacy keys ---
  WPA_WEP_KEY  WepKeys[4];       // 5-byte (WEP-40) or 13-byte (WEP-104)
  UINT8        WepDefaultKeyId;
  BOOLEAN      WepKeysValid;

  // --- Key descriptor version ---
  UINT8   KeyDescVersion;        // 0=AKM-defined, 1=HMAC-MD5+RC4, 2=HMAC-SHA1+AES
};
```

### PtkRaw Layout (`SupplicantDxe.h:44–54`)

`PtkRaw[64]` is a flat byte array holding all PTK sub-keys.
Three accessor macros index into it:

| Macro | Offset | Length | Purpose |
|-------|--------|--------|---------|
| `PTK_KCK(p)` | 0 | 16 | Key Confirmation Key (MIC signing) |
| `PTK_KEK(p)` | 16 | 16 | Key Encryption Key (GTK wrapping) |
| `PTK_TK(p)` | 32 | 16 | Temporal Key (data encryption) |
| — | 48 | 8 | TX-MIC (TKIP only) |
| — | 56 | 8 | RX-MIC (TKIP only) |

For CCMP the PTK is 48 bytes (`PtkRaw[0..47]`); bytes 48–63 are unused.
For TKIP the full 64 bytes are used.

### KeyDescVersion Selection (`WpaEapol.c:UpdateKeyDescVersion`)

| Value | MIC Algorithm | Key Wrap | When Used |
|-------|--------------|----------|-----------|
| `0` | AES-128-CMAC | AES Key Wrap | WPA3-SAE, PSK-SHA256 |
| `1` | HMAC-MD5 | RC4 stream | WPA1 / TKIP |
| `2` | HMAC-SHA1-128 | AES Key Wrap | WPA2-PSK / CCMP |

## Data Flow

```
WiFiConnectionManagerDxe
        │
        │  SetData(AKM, Cipher, Password, SSID, BSSID, MAC)
        ▼
  SupplicantImpl.c
  SupplicantSetData()
        │
        ├── SAE path ──────────────────────────────────────────────┐
        │   BuildResponsePacket(NULL) → SaeInit()                  │
        │   BuildResponsePacket(Commit) → SaeProcessCommit()       │
        │                                 SaeBuildConfirm()        │
        │   SaeProcessConfirm() → PMK installed                    │
        │                                                          │
        └── EAPOL path ────────────────────────────────────────────┘
            BuildResponsePacket(Msg1) → WpaEapolProcessKeyFrame()
              ├── Derive PMK (PBKDF2 if not yet valid)
              ├── Generate SNonce
              ├── WpaDerivePtk() → PtkRaw
              └── Build EAPOL Message 2

            BuildResponsePacket(Msg3) → WpaEapolProcessKeyFrame()
              ├── Verify MIC
              ├── Decrypt key data → GTK + IGTK installed
              └── Build EAPOL Message 4

        ProcessPacket(TX) → WpaCcmpEncrypt(PTK_TK, TxPn++)
        ProcessPacket(RX) → WpaCcmpDecrypt(PTK_TK, PN from header)
```

## Key Derivation Chain

```
Passphrase + SSID
     │
     │ PBKDF2-SHA1 (4096 iter)       [WPA2-PSK]
     ▼
    PMK (32 bytes)
     │
     │ PRF-SHA1  (WPA2-PSK + CCMP → 48 B)
     │ PRF-SHA1  (WPA2-PSK + TKIP → 64 B)
     │ KDF-SHA256 (WPA3/PSK-SHA256 → 48 B)
     ▼
    PTK = KCK(16) || KEK(16) || TK(16) [|| TX-MIC(8) || RX-MIC(8) for TKIP]


Password + addresses
     │
     │ Hunting-and-Pecking (HMAC-SHA256 + ECC P-256)
     ▼
    PWE (Password Element, a point on P-256)
     │
     │ Dragonfly commit exchange
     ▼
    K = rand × (peer_scalar × PWE + peer_element)
     │
     │ HMAC-SHA256 keyseed + KDF-512
     ▼
    KCK (32 B) || PMK (32 B)           [WPA3-SAE]
```

## Module Lifecycle

1. **Entry** (`SupplicantDriver.c:SupplicantDxeDriverEntryPoint`):
   - Allocates `SUPPLICANT_PRIVATE_DATA` with `AllocateZeroPool`.
   - Sets default AKM = PSK, PairwiseCipher = CCMP, GroupCipher = CCMP.
   - Installs `EFI_SUPPLICANT_PROTOCOL` on a new handle.

2. **Operation**: Consumer calls `SetData` to configure, then `BuildResponsePacket`
   repeatedly as authentication frames arrive, then `ProcessPacket` for data.

3. **Unload** (`SupplicantDriver.c:SupplicantDxeDriverUnload`):
   - Uninstalls the protocol.
   - Zeros `PtkRaw`, `Pmk`, `WepKeys` (sensitive material).
   - Frees the private data block.
