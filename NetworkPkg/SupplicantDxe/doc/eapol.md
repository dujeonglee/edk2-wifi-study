# SupplicantDxe — EAPOL 4-Way and Group Key Handshake

Implemented in `WpaEapol.c` / `WpaEapol.h`.

---

## Protocol Background

The IEEE 802.11-2020 4-Way Handshake derives and installs the Pairwise Transient
Key (PTK) using EAPOL-Key frames exchanged between the Supplicant (STA) and the
Authenticator (AP). A subsequent Group Key Handshake distributes the Group Temporal
Key (GTK) and Integrity Group Temporal Key (IGTK).

```
AP (Authenticator)                       STA (Supplicant)
        │                                        │
        │── EAPOL-Key Msg 1 ──────────────────►  │  ANonce, Pairwise|Ack
        │                                        │  → derive PTK
        │  ◄─── EAPOL-Key Msg 2 ─────────────── │  SNonce, MIC, RSN IE
        │                                        │
        │── EAPOL-Key Msg 3 ──────────────────►  │  Install|Secure|EncKeyData
        │                                        │  → verify MIC, decrypt GTK/IGTK
        │  ◄─── EAPOL-Key Msg 4 ─────────────── │  Secure|MIC (empty key data)
        │                                        │
        │── Group Key Msg 1 ──────────────────►  │  GTK update (periodic rekey)
        │  ◄─── Group Key Msg 2 ──────────────── │
```

---

## State Machine

### 4-Way Handshake States (`WPA_4WAY_STATE`)

```
Wpa4WayIdle
    │  receive Message 1 (Pairwise+Ack, no MIC)
    ▼
Wpa4WayMsg1Received
    │  SNonce generated, PTK derived, Message 2 sent
    ▼
Wpa4WayMsg2Sent
    │  receive Message 3 (Pairwise+Ack+MIC+Secure+Install+EncKeyData)
    ▼
Wpa4WayMsg3Received
    │  MIC verified, GTK/IGTK decrypted and installed, Message 4 sent
    ▼
Wpa4WayComplete
```

### Group Key States (`WPA_GROUP_KEY_STATE`)

```
WpaGroupKeyIdle
    │  receive Group Key Msg 1 (Group key, Ack, MIC, Secure, EncKeyData)
    ▼
WpaGroupKeyMsg1Received
    │  GTK decrypted, Message 2 sent
    ▼
WpaGroupKeyComplete
```

---

## Message Type Detection

`WpaEapol.c` (lines 27–93) classifies incoming frames by the `KeyInformation`
field bit pattern:

| Frame | Pairwise | Ack | MIC | Secure | Install | EncKeyData |
|-------|:--------:|:---:|:---:|:------:|:-------:|:----------:|
| 4-Way Msg 1 | 1 | 1 | 0 | 0 | 0 | 0 |
| 4-Way Msg 2 | 1 | 0 | 1 | 0 | 0 | 0 |
| 4-Way Msg 3 | 1 | 1 | 1 | 1 | 1 | 1 |
| 4-Way Msg 4 | 1 | 0 | 1 | 1 | 0 | 0 |
| Group Key Msg 1 | 0 | 1 | 1 | 1 | 0 | 1 |
| Group Key Msg 2 | 0 | 0 | 1 | 1 | 0 | 0 |

---

## Key Functions

### WpaEapolProcessKeyFrame

```c
EFI_STATUS WpaEapolProcessKeyFrame (
  IN     SUPPLICANT_PRIVATE_DATA  *Private,
  IN     CONST UINT8              *RequestBuffer,
  IN     UINTN                    RequestSize,
  OUT    UINT8                    *Buffer,
  IN OUT UINTN                    *BufferSize
);
```

Main dispatcher called from `SupplicantBuildResponsePacket`.

**Message 1 handling** (`WpaEapol.c` ~line 800):
1. Validate frame size (≥ `EAPOL_KEY_FRAME_MIN_LEN`).
2. Require state `Wpa4WayIdle`.
3. Copy `ANonce` from the key frame.
4. If `PmkValid == FALSE`: call `WpaDerivePmk()` to compute PMK from passphrase and SSID.
5. Generate `SNonce` with `WpaRandomBytes()`.
6. Call `WpaDerivePtk()` to fill `PtkRaw`.
7. Call `BuildMessage2()` to construct and MIC-sign the response.
8. Advance state to `Wpa4WayMsg2Sent`.

**Message 3 handling** (~line 880):
1. Require state `Wpa4WayMsg2Sent`.
2. Verify replay counter > last seen.
3. Verify MIC over the incoming frame using `VerifyMic()`.
4. Confirm `ANonce` in message 3 matches the stored value from message 1.
5. Decrypt key data:
   - `KeyDescVersion == 1` (TKIP): RC4 stream decryption using `EAPOL-Key IV || KEK` as key.
   - `KeyDescVersion == 2` (CCMP): `WpaAesKeyUnwrap(KEK, ...)`.
6. Parse KDEs from decrypted key data → extract GTK and optionally IGTK.
7. Store GTK in `Private->Gtk[]` by key ID; store IGTK in `Private->Igtk[]`.
8. Call `BuildMessage4()`.
9. Advance state to `Wpa4WayComplete`; set `PtkValid = TRUE`.

**Group Key Message 1 handling** (~line 970):
1. Verify MIC.
2. Decrypt key data (same RC4/AES-unwrap path as above).
3. Parse GTK KDE; optionally IGTK KDE.
4. Call `BuildGroupKeyMessage2()`.
5. Set `GtkRefreshed = TRUE`.

### WpaDerivePtk

```c
BOOLEAN WpaDerivePtk (IN SUPPLICANT_PRIVATE_DATA *Private);
```

Produces `PtkRaw` from `PMK`, `ANonce`, `SNonce`, `StationMac` (SPA), `TargetBssid` (AA).

**Data ordering** (IEEE 802.11-2020 Section 12.7.1.3):
```
Data = Min(AA, SPA) || Max(AA, SPA) || Min(ANonce, SNonce) || Max(ANonce, SNonce)
```
Lexicographic comparison on the 6-byte MAC addresses and 32-byte nonces.

**Derivation method by configuration:**

| AKM | Pairwise Cipher | Function | Output size |
|-----|----------------|----------|-------------|
| PSK (2) | CCMP (4) | `WpaPrfSha1(PMK, "Pairwise key expansion", Data, 48)` | 48 bytes |
| PSK (2) | TKIP (2) | `WpaPrfSha1(PMK, "Pairwise key expansion", Data, 64)` | 64 bytes |
| PSK-SHA256 (6) or SAE (8) | any | `WpaKdfSha256(PMK, "Pairwise key expansion", Data, 384)` | 48 bytes |

Result is written into `Private->PtkRaw[0..47]` or `[0..63]`.

### UpdateKeyDescVersion

```c
VOID UpdateKeyDescVersion (IN OUT SUPPLICANT_PRIVATE_DATA *Private);
```

Sets `Private->KeyDescVersion` based on AKM and pairwise cipher:

```c
if (AkmSuiteType == PSK_SHA256 || AkmSuiteType == SAE)
    KeyDescVersion = 0;   // AES-CMAC MIC, AES Key Wrap
else if (PairwiseCipherType == TKIP)
    KeyDescVersion = 1;   // HMAC-MD5 MIC, RC4 key data
else
    KeyDescVersion = 2;   // HMAC-SHA1-128 MIC, AES Key Wrap
```

Must be called whenever `AkmSuiteType` or `PairwiseCipherType` changes.

### MIC Computation

`WpaEapol.c:ComputeMic()` dispatches by `KeyDescVersion`:

| Version | Algorithm | Key |
|---------|-----------|-----|
| 0 | `WpaAesCmac(KCK, frame, 16)` | KCK (16 bytes) |
| 1 | `WpaHmacMd5Mic(KCK, 16, frame, len, mic)` | KCK (16 bytes) |
| 2 | `WpaHmacSha1Mic(KCK, frame, len, mic)` | KCK (16 bytes) |

`VerifyMic()` zeros the `KeyMic` field of a frame copy, recomputes the MIC,
and compares byte-by-byte. Returns `EFI_SECURITY_VIOLATION` on mismatch.

### WpaBuildRsnIe

```c
BOOLEAN WpaBuildRsnIe (
  IN  SUPPLICANT_PRIVATE_DATA  *Private,
  OUT UINT8                    *RsnIe,
  OUT UINTN                    *RsnIeLen
);
```

Builds the RSN Information Element appended as key data to EAPOL-Key Message 2.

RSN IE structure:
```
ElementID (1) = 48
Length    (1)
Version   (2) = 0x0001
GroupCipherSuite  (4) = OUI || CipherType
PairwiseCipherSuiteCount (2) = 1
PairwiseCipherSuite (4)
AkmSuiteCount (2) = 1
AkmSuite      (4)
RsnCapabilities (2)
```

### WpaEapolReset

```c
VOID WpaEapolReset (IN SUPPLICANT_PRIVATE_DATA *Private);
```

Zeros: `ANonce`, `SNonce`, `PtkRaw`, `Gtk[]`, `Igtk[]`, `TxPn`.
Resets: `FourWayState = Wpa4WayIdle`, `PtkValid = FALSE`, `GtkRefreshed = FALSE`,
`LinkState`, `PaeState`.

---

## On-Wire Frame Structures (`WpaCommon.h`)

### EAPOL_HEADER

```c
typedef struct {
  UINT8   ProtocolVersion;    // 1, 2, or 3 (use EAPOL_VERSION_2 = 2)
  UINT8   PacketType;         // EAPOL_PACKET_TYPE_KEY = 3
  UINT16  PacketBodyLength;   // big-endian, body after this header
} EAPOL_HEADER;
```

### EAPOL_KEY_FRAME

```c
typedef struct {
  UINT8   DescriptorType;     // EAPOL_KEY_DESC_TYPE_RSN = 2
  UINT16  KeyInformation;     // big-endian bit field (see below)
  UINT16  KeyLength;          // big-endian; 16 for pairwise, 0 for group
  UINT8   ReplayCounter[8];
  UINT8   KeyNonce[32];       // ANonce (from AP) or SNonce (from STA)
  UINT8   EapolKeyIv[16];     // used only in version-1 RC4 key wrap
  UINT8   KeyRsc[8];          // receive sequence counter (for GTK)
  UINT8   Reserved[8];
  UINT8   KeyMic[16];         // zeroed before MIC computation
  UINT16  KeyDataLength;      // big-endian
  // UINT8 KeyData[];          follows immediately
} EAPOL_KEY_FRAME;
```

Minimum valid frame size: `sizeof(EAPOL_HEADER) + sizeof(EAPOL_KEY_FRAME)` =
4 + 95 = 99 bytes.

### KeyInformation Bit Field

```
Bits 0-2: KeyDescVersion (0=AKM-defined, 1=HMAC-MD5+RC4, 2=HMAC-SHA1+AES)
Bit  3:   KeyType (1=Pairwise, 0=Group)
Bit  6:   Install
Bit  7:   Key ACK
Bit  8:   Key MIC
Bit  9:   Secure
Bit  10:  Error
Bit  11:  Request
Bit  12:  Encrypted Key Data
Bit  13:  SMK Message
```

### KDE (Key Data Encapsulation)

```c
typedef struct {
  UINT8  Type;      // 0xDD (Vendor Specific)
  UINT8  Length;    // length of OUI + DataType + Data
  UINT8  Oui[3];   // 00-0F-AC for IEEE 802.11 RSN KDEs
  UINT8  DataType;  // WPA_KDE_TYPE_GTK=1, WPA_KDE_TYPE_IGTK=9
  // data follows
} WPA_KDE_HEADER;
```

**GTK KDE data** (`DataType == 1`):
```
KeyId  (1 byte): bits 0-1 = key index, bits 2-7 = Tx flag
Reserved (1)
GTK    (16 or 32 bytes)
```

**IGTK KDE data** (`DataType == 9`):
```
KeyId  (1 byte): bits 0-1 = key index
IPN    (6 bytes): IGTK Packet Number
IGTK   (16 bytes)
```

---

## Helper Macros (`WpaCommon.h`)

```c
WPA_GET_BE16(p)       // read big-endian uint16 from byte array
WPA_PUT_BE16(p, v)    // write big-endian uint16
WPA_GET_BE32(p)       // read big-endian uint32
WPA_PUT_BE32(p, v)    // write big-endian uint32
WPA_GET_LE16(p)       // read little-endian uint16
WPA_PUT_LE16(p, v)    // write little-endian uint16
```
