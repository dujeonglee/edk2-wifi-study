# SupplicantDxe — EFI_SUPPLICANT_PROTOCOL

Implemented in `SupplicantImpl.c`. The protocol is installed on a new handle in
`SupplicantDriver.c` and consumed by `WifiConnectionManagerDxe`.

```c
typedef struct {
  EFI_SUPPLICANT_BUILD_RESPONSE_PACKET  BuildResponsePacket;
  EFI_SUPPLICANT_PROCESS_PACKET         ProcessPacket;
  EFI_SUPPLICANT_SET_DATA               SetData;
  EFI_SUPPLICANT_GET_DATA               GetData;
} EFI_SUPPLICANT_PROTOCOL;
```

---

## BuildResponsePacket

```c
EFI_STATUS EFIAPI SupplicantBuildResponsePacket (
  IN     EFI_SUPPLICANT_PROTOCOL  *This,
  IN     UINT8                    *RequestBuffer      OPTIONAL,
  IN     UINTN                    RequestBufferSize   OPTIONAL,
  OUT    UINT8                    *Buffer,
  IN OUT UINTN                    *BufferSize
);
```

Dispatches to either the SAE sub-module or the EAPOL sub-module depending on
`AkmSuiteType` and the content of `RequestBuffer`.

### SAE dispatch (`AkmSuiteType == WPA_AKM_SUITE_SAE`)

| `RequestBuffer` | Action |
|----------------|--------|
| `NULL` | `SaeInit()` → generate PWE, scalar, element; build SAE Commit → return Commit frame |
| Commit frame (TransactionSeq == 1) | `SaeProcessCommit()` + `SaeBuildConfirm()` → return Confirm frame |
| Confirm frame (TransactionSeq == 2) | `SaeProcessConfirm()` → installs PMK; returns empty success |

### EAPOL dispatch (WPA2/WPA3 after SAE)

Calls `WpaEapolProcessKeyFrame()` for all EAPOL-Key frames.

| Frame | Action |
|-------|--------|
| 4-Way Message 1 | Generate SNonce, derive PMK (if needed), derive PTK, return Message 2 |
| 4-Way Message 3 | Verify MIC, decrypt key data, install GTK/IGTK, return Message 4 |
| Group Key Message 1 | Verify MIC, decrypt key data, install GTK/IGTK, return Group Key Message 2 |

### Return values

| Code | Meaning |
|------|---------|
| `EFI_SUCCESS` | Response packet is in `Buffer`; `*BufferSize` is the actual length |
| `EFI_BUFFER_TOO_SMALL` | `Buffer` too small; `*BufferSize` set to required size |
| `EFI_INVALID_PARAMETER` | NULL required pointer or bad frame |
| `EFI_NOT_READY` | PMK not yet available or unexpected message sequence |
| `EFI_SECURITY_VIOLATION` | MIC check failed or SAE confirm mismatch |

---

## ProcessPacket

```c
EFI_STATUS EFIAPI SupplicantProcessPacket (
  IN     EFI_SUPPLICANT_PROTOCOL       *This,
  IN OUT EFI_SUPPLICANT_FRAGMENT_DATA  **FragmentTable,
  IN     UINT32                        *FragmentCount,
  IN     EFI_SUPPLICANT_CRYPT_MODE     CryptMode
);
```

Encrypts (TX) or decrypts (RX) a single 802.11 MPDU using CCMP.

### TX path (`EfiSupplicantEncrypt`)

1. Reassemble all fragments in `FragmentTable` into a single contiguous buffer.
2. Build the CCMP nonce: `Priority || A2 || TxPn`.
3. Build the AAD from the 802.11 header bytes.
4. Call `WpaCcmpEncrypt(PTK_TK, TxPn, A2, Priority, Header, ...)`.
5. Increment `TxPn` (6-byte big-endian counter).
6. Replace `FragmentTable` with a single fragment holding `CCMP_HEADER || ciphertext || MIC`.

### RX path (`EfiSupplicantDecrypt`)

1. Reassemble fragments.
2. Extract the 6-byte PN from the 8-byte CCMP header (bytes 0,1,4,5,6,7 of the header,
   reordered per IEEE 802.11-2020 Figure 12-18).
3. Call `WpaCcmpDecrypt(PTK_TK, PN, A2, Priority, Header, ...)`.
4. On MIC mismatch: return `EFI_SECURITY_VIOLATION`.
5. Replace `FragmentTable` with the decrypted plaintext fragment.

### Return values

| Code | Meaning |
|------|---------|
| `EFI_SUCCESS` | Encryption/decryption succeeded |
| `EFI_INVALID_PARAMETER` | NULL pointer or zero fragment count |
| `EFI_NOT_READY` | PTK not yet installed |
| `EFI_SECURITY_VIOLATION` | CCMP MIC verification failed |
| `EFI_OUT_OF_RESOURCES` | Allocation failure |

---

## SetData

```c
EFI_STATUS EFIAPI SupplicantSetData (
  IN EFI_SUPPLICANT_PROTOCOL   *This,
  IN EFI_SUPPLICANT_DATA_TYPE  DataType,
  IN VOID                      *Data,
  IN UINTN                     DataSize
);
```

### Supported DataType values

| `DataType` | `Data` type | Effect |
|------------|------------|--------|
| `EfiSupplicant80211AKMSuite` | `EFI_80211_AKM_SUITE_SELECTOR` | Sets `AkmSuiteOui`, `AkmSuiteType`; calls `UpdateKeyDescVersion()` |
| `EfiSupplicant80211PairwiseCipherSuite` | `EFI_80211_CIPHER_SUITE_SELECTOR` | Sets `PairwiseCipherOui/Type`; calls `UpdateKeyDescVersion()`; warns if TKIP/WEP |
| `EfiSupplicant80211GroupDataCipherSuite` | `EFI_80211_CIPHER_SUITE_SELECTOR` | Sets `GroupCipherOui/Type` |
| `EfiSupplicant80211PskPassword` | `EFI_SUPPLICANT_PASSWORD_DATA` | Copies passphrase (8–63 chars); invalidates PMK |
| `EfiSupplicant80211TargetSSIDName` | `EFI_80211_SSID` | Copies SSID; invalidates PMK (forces re-derivation) |
| `EfiSupplicant80211StationMac` | `EFI_80211_MAC_ADDRESS` | Sets `StationMac` (SPA) |
| `EfiSupplicant80211TargetSSIDMac` | `EFI_80211_MAC_ADDRESS` | Sets `TargetBssid` (AA) |
| `EfiSupplicant80211PMK` | 32-byte array | Directly installs PMK; sets `PmkValid = TRUE` |
| `EfiSupplicant80211PTK` | up to 64-byte array | Directly installs PTK into `PtkRaw`; sets `PtkValid = TRUE` |
| `EfiSupplicant80211GTK` | `EFI_SUPPLICANT_GTK_DATA` | Installs GTK at specified key ID |
| `EfiSupplicant80211IGTK` | `EFI_SUPPLICANT_IGTK_DATA` | Installs IGTK at specified key ID |
| `EfiSupplicant80211WepKey` | `EFI_SUPPLICANT_WEP_KEY_DATA` | Installs WEP-40 or WEP-104 key; sets `WepKeysValid = TRUE` |

### Notes

- Setting `Password` or `TargetSSIDName` clears `PmkValid`, forcing PBKDF2 re-derivation
  on the next Message 1.
- `UpdateKeyDescVersion()` must be called whenever AKM or pairwise cipher changes because
  `KeyDescVersion` selects the MIC algorithm and key-wrap method for all future EAPOL frames.
- WEP and TKIP installation emit `DEBUG_WARN` messages; these ciphers are insecure.

---

## GetData

```c
EFI_STATUS EFIAPI SupplicantGetData (
  IN     EFI_SUPPLICANT_PROTOCOL   *This,
  IN     EFI_SUPPLICANT_DATA_TYPE  DataType,
  OUT    UINT8                     *Data      OPTIONAL,
  IN OUT UINTN                     *DataSize
);
```

The two-phase size-query pattern applies: call with `Data == NULL` to obtain
the required buffer size, then call again with an allocated buffer.

### Supported DataType values

| `DataType` | Returns |
|------------|---------|
| `EfiSupplicant80211SupportedAKMSuites` | List of 3 AKM suites: PSK(2), PSK-SHA256(6), SAE(8) |
| `EfiSupplicant80211SupportedCipherSuites` | List of 5 cipher suites: CCMP(4), BIP(6), TKIP(2), WEP-40(1), WEP-104(5) |
| `EfiSupplicant80211PMK` | 32-byte PMK (returns `EFI_NOT_READY` if `PmkValid == FALSE`) |
| `EfiSupplicant80211PTK` | PTK bytes; `DataSize` indicates how many bytes are returned |
| `EfiSupplicant80211GTK` | GTK entry identified by key ID embedded in the request |
| `EfiSupplicant80211IGTK` | IGTK entry identified by key ID |
| `EfiSupplicant80211AKMSuite` | Current AKM suite selector |
| `EfiSupplicant80211PairwiseCipherSuite` | Current pairwise cipher selector |
| `EfiSupplicant80211WepKey` | WEP key for the requested key ID (returns `EFI_NOT_READY` if none) |

### Return values

| Code | Meaning |
|------|---------|
| `EFI_SUCCESS` | Data written to `Data`; `*DataSize` is actual length |
| `EFI_BUFFER_TOO_SMALL` | `*DataSize` updated to required size |
| `EFI_INVALID_PARAMETER` | `DataSize == NULL` or other bad parameter |
| `EFI_NOT_READY` | Requested key not yet available |
| `EFI_UNSUPPORTED` | `DataType` not recognised |
