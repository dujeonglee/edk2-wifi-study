# SupplicantDxe — SAE (WPA3-Personal)

Implemented in `WpaSae.c` / `WpaSae.h`.

SAE (Simultaneous Authentication of Equals), also called Dragonfly, is the
key exchange used by WPA3-Personal (AKM Suite 8). It replaces the pre-shared
key's direct use as the PMK with an authenticated Diffie-Hellman exchange that
provides forward secrecy. The implementation uses ECC Group 19 (NIST P-256).

---

## Session State

### SAE_SESSION structure (`WpaSae.h`)

```c
typedef struct {
  SAE_STATE  State;              // Idle, CommitSent, ConfirmSent, Accepted, Failed

  // Own commit values
  UINT8  OwnScalar[32];          // (rand + mask) mod order
  UINT8  OwnElementX[32];        // (-mask × PWE).x
  UINT8  OwnElementY[32];        // (-mask × PWE).y
  UINT8  Rand[32];               // random scalar factor
  UINT8  Mask[32];               // random mask factor

  // Peer commit values
  UINT8  PeerScalar[32];
  UINT8  PeerElementX[32];
  UINT8  PeerElementY[32];

  // Derived session keys
  UINT8  KCK[32];                // SAE Key Confirmation Key (32 bytes)
  UINT8  PMK[32];                // Pairwise Master Key (32 bytes)

  // Confirm exchange
  UINT16  SendConfirm;           // own counter (incremented on each Confirm)
  UINT16  RecvConfirm;           // peer's counter

  // Password Element
  BOOLEAN  PweValid;
  UINT8    PweX[32];             // PWE point x-coordinate
  UINT8    PweY[32];             // PWE point y-coordinate
} SAE_SESSION;
```

### SAE_STATE enum

```
SaeIdle         Initial state; no session
SaeCommitSent   Own Commit frame sent; waiting for peer Commit
SaeConfirmSent  Own Confirm sent; waiting for peer Confirm
SaeAccepted     Both confirms verified; PMK installed
SaeFailed       Authentication failed
```

---

## Protocol Flow

```
STA                                          AP
 │                                            │
 │  SaeInit()                                 │
 │  SaeBuildCommit()                          │
 │──── Auth Frame (Algorithm=SAE, Seq=1) ────►│
 │                                            │
 │◄─── Auth Frame (Algorithm=SAE, Seq=1) ──── │
 │  SaeProcessCommit()                        │
 │  SaeBuildConfirm()                         │
 │──── Auth Frame (Algorithm=SAE, Seq=2) ────►│
 │                                            │
 │◄─── Auth Frame (Algorithm=SAE, Seq=2) ──── │
 │  SaeProcessConfirm()                       │
 │  → PMK installed                           │
 │                                            │
 │  [4-Way Handshake follows using PMK]       │
```

The authentication frame body follows `SAE_AUTH_FRAME`:

```c
typedef struct {
  UINT16  AuthAlgorithm;   // 3 = SAE
  UINT16  TransactionSeq;  // 1=Commit, 2=Confirm
  UINT16  StatusCode;      // 0 = success
  // variable payload
} SAE_AUTH_FRAME;
```

---

## Key Functions

### SaeInit

```c
EFI_STATUS SaeInit (
  IN OUT SAE_SESSION            *Session,
  IN     CONST CHAR8            *Password,
  IN     CONST EFI_80211_MAC_ADDRESS *OwnMac,
  IN     CONST EFI_80211_MAC_ADDRESS *PeerMac
);
```

1. **Password Element derivation** (`SaeDerivePasswordElement`):
   - Hunting-and-Pecking loop, counter = 1..40:
     - `seed = HMAC-SHA256(Max(addr1,addr2) || Min(addr1,addr2), Password || counter)`
     - `x = KDF-256(seed, "SAE Hunting and Pecking", prime_p)` truncated mod p
     - Compute `y² = x³ - 3x + b (mod p)` (P-256 Weierstrass form: a = -3)
     - Check `x < p` and `y²` is a quadratic residue (i.e. `y² ^ ((p+1)/4) mod p` is consistent)
     - Adjust y parity: `y = p - y` if `lsb(y) ≠ (counter & 1)`
     - Store first valid `(x, y)` as PWE; break
   - If no PWE found after 40 iterations: return `EFI_DEVICE_ERROR`

2. **Random scalar/element generation**:
   - Generate `rand` and `mask` in `[2, order-1]` using `WpaRandomBytes()`.
   - `OwnScalar = (rand + mask) mod order`
   - `OwnElement = -(mask × PWE)` (point scalar multiply, negate y coordinate)

### SaeBuildCommit

```c
EFI_STATUS SaeBuildCommit (
  IN     SAE_SESSION  *Session,
  OUT    UINT8        *Buffer,
  IN OUT UINTN        *BufferSize
);
```

Builds the Commit frame payload (after the fixed 6-byte auth header):

```
GroupId     (2 bytes, LE) = 19
OwnScalar   (32 bytes)
OwnElementX (32 bytes)
OwnElementY (32 bytes)
```

Total payload: 98 bytes. Sets `State = SaeCommitSent`.

### SaeProcessCommit

```c
EFI_STATUS SaeProcessCommit (
  IN OUT SAE_SESSION  *Session,
  IN     CONST UINT8  *Buffer,
  IN     UINTN        BufferSize
);
```

1. Extract `GroupId` (must be 19), `PeerScalar[32]`, `PeerElementX[32]`, `PeerElementY[32]`.
2. Validate: `PeerScalar ∈ [2, order-1]`; peer element on P-256 curve.
3. **Shared secret computation** (Dragonfly KEX):
   ```
   K = rand × (PeerScalar × PWE + PeerElement)
   ```
   where addition is point addition on P-256 and `×` is scalar multiplication.
4. Check `K ≠ point-at-infinity`.
5. Extract `K.x` (32 bytes) as the raw shared secret.
6. **Key derivation**:
   ```
   keyseed  = HMAC-SHA256(zeros_32, K.x)
   token    = (OwnScalar + PeerScalar) mod order   (32 bytes)
   KCK||PMK = KDF-512(keyseed, "SAE KCK and PMK", token)
   Session->KCK = KCK[0:32]
   Session->PMK = PMK[32:64]
   ```

### SaeBuildConfirm

```c
EFI_STATUS SaeBuildConfirm (
  IN OUT SAE_SESSION  *Session,
  OUT    UINT8        *Buffer,
  IN OUT UINTN        *BufferSize
);
```

Increments `SendConfirm` counter, then computes:

```
ConfirmInput = LE16(SendConfirm) ||
               OwnScalar(32) || PeerScalar(32) ||
               OwnElementX(32) || OwnElementY(32) ||
               PeerElementX(32) || PeerElementY(32)

Confirm = HMAC-SHA256(KCK, ConfirmInput)
```

Builds frame: `LE16(SendConfirm) || Confirm[32]` (34 bytes after auth header).
Sets `State = SaeConfirmSent`.

### SaeProcessConfirm

```c
EFI_STATUS SaeProcessConfirm (
  IN OUT SAE_SESSION            *Session,
  IN     CONST UINT8            *Buffer,
  IN     UINTN                  BufferSize,
  OUT    SUPPLICANT_PRIVATE_DATA *Private
);
```

1. Extract `PeerSendConfirm` (LE16) and 32-byte confirm value.
2. Build the **expected** confirm using peer scalars/elements in the swapped order:
   ```
   ExpectedInput = LE16(PeerSendConfirm) ||
                   PeerScalar(32) || OwnScalar(32) ||
                   PeerElementX(32) || PeerElementY(32) ||
                   OwnElementX(32) || OwnElementY(32)

   Expected = HMAC-SHA256(KCK, ExpectedInput)
   ```
3. Compare received confirm with `Expected` (constant-time). Mismatch → `EFI_SECURITY_VIOLATION`.
4. Copy `Session->PMK` into `Private->Pmk`; set `Private->PmkValid = TRUE`.
5. Set `State = SaeAccepted`.

### SaeCleanup

```c
VOID SaeCleanup (IN OUT SAE_SESSION *Session);
```

Zeros all sensitive fields: `Rand`, `Mask`, `OwnScalar`, `OwnElement`, `PeerScalar`,
`PeerElement`, `PweX`, `PweY`, `KCK`, `PMK`. Resets `State = SaeIdle`.

---

## ECC Group 19 (P-256) Parameters

The implementation uses the NIST P-256 curve constants hard-coded in `WpaSae.c`:

| Parameter | Value |
|-----------|-------|
| Field prime p | `FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF` |
| Order n | `FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551` |
| Generator x (Gx) | `6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296` |
| Generator y (Gy) | `4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5` |
| Curve coefficient a | -3 (mod p) |
| Curve coefficient b | `5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B` |

For `y² = x³ + ax + b (mod p)` with `a ≡ p-3`, the quadratic residue test uses
`y = y²^((p+1)/4) mod p` (valid because `p ≡ 3 mod 4` for P-256).

All field arithmetic (modular inverse, scalar multiply, point add) is implemented
in `WpaSae.c` using the `BigNum` APIs from `BaseCryptLib` (OpenSSL BN layer).

---

## Security Notes

- The Hunting-and-Pecking loop runs for a **fixed 40 iterations** regardless of
  when a valid PWE is found. This is required to prevent timing side-channels.
- `rand` and `mask` are in `[2, order-1]` (not `[1, order-1]`; zero and one are excluded
  to prevent degenerate scalar values).
- The `KCK || PMK` derivation uses `HMAC-SHA256` with a `zeros_32` key for the keyseed
  step, matching IEEE 802.11-2020 Section 12.4.5.4.
- `SaeCleanup` must be called when the session is discarded to prevent key material
  from persisting in memory.
