# SupplicantDxe — WPA1/2/3 Call Traces

이 문서는 `WifiConnectionManagerDxe`가 `EFI_SUPPLICANT_PROTOCOL`을 통해
SupplicantDxe를 호출하는 흐름을 WPA 버전별로 정리한다.

---

## WPA1 (PSK + TKIP)

```
WifiConnectionManagerDxe
  │
  ├─ SetData(AKMSuite=PSK, PairwiseCipher=TKIP)
  │    └─ UpdateKeyDescVersion() → KeyDescVersion=1 (HMAC-MD5/RC4)
  │
  ├─ SetData(Password, SSID, StationMac, TargetBssid)
  │
  ├─ BuildResponsePacket(NULL)        ← WPA1은 initiation 불필요, BufferSize=0 반환
  │
  │  [AP → STA: EAPOL-Key Msg1 수신]
  │
  ├─ BuildResponsePacket(Msg1)
  │    └─ WpaEapolProcessKeyFrame()
  │         ├─ GetEapolKeyMessageType() → MsgType=1
  │         ├─ CopyMem(ANonce)
  │         ├─ WpaRandomBytes(SNonce)
  │         ├─ WpaDerivePmk()         ← PBKDF2-SHA1(password, SSID, 4096)
  │         ├─ WpaDerivePtk()
  │         │    └─ WpaPrfSha1(PMK, "Pairwise key expansion", ...)
  │         │         → PTK-512bit: KCK(16)+KEK(16)+TK(16)+TX-MIC(8)+RX-MIC(8)
  │         └─ BuildMessage2()
  │              ├─ WpaBuildRsnIe()
  │              └─ ComputeEapolMic()
  │                   └─ WpaHmacMd5Mic()  ← KDescVer=1: HMAC-MD5
  │
  │  [STA → AP: EAPOL-Key Msg2 송신]
  │  [AP → STA: EAPOL-Key Msg3 수신]
  │
  ├─ BuildResponsePacket(Msg3)
  │    └─ WpaEapolProcessKeyFrame()
  │         ├─ VerifyEapolMic() → WpaHmacMd5Mic()
  │         ├─ [KeyData RC4 복호화]
  │         │    ├─ WpaRc4Init(IV||KEK)
  │         │    ├─ WpaRc4Skip(256)
  │         │    └─ WpaRc4Process() → GTK 평문
  │         ├─ ParseKeyData()          ← GTK KDE 파싱
  │         └─ BuildMessage4()
  │              └─ ComputeEapolMic() → WpaHmacMd5Mic()
  │
  │  [STA → AP: EAPOL-Key Msg4 송신] → Handshake Complete
  │
  └─ ProcessPacket(Encrypt/Decrypt)   ← TKIP (WpaCcmpEncrypt/Decrypt 경로 공유)
```

**TKIP 키 복호화** — WPA1/TKIP에서 Msg3의 KeyData는 AES Key Wrap 대신
RC4 스트림 암호로 보호된다. `EapolKeyIv(16) || KEK(16)`을 RC4 키로 사용하고
처음 256 바이트의 키스트림을 버린 뒤 복호화한다 (`WpaEapol.c:947–964`).

---

## WPA2 (PSK + CCMP)

```
WifiConnectionManagerDxe
  │
  ├─ SetData(AKMSuite=PSK, PairwiseCipher=CCMP)
  │    └─ UpdateKeyDescVersion() → KeyDescVersion=2 (HMAC-SHA1/AES)
  │
  ├─ SetData(Password, SSID, StationMac, TargetBssid)
  │
  ├─ BuildResponsePacket(NULL)        ← WPA2도 initiation 불필요, BufferSize=0 반환
  │
  │  [AP → STA: EAPOL-Key Msg1 수신]
  │
  ├─ BuildResponsePacket(Msg1)
  │    └─ WpaEapolProcessKeyFrame()
  │         ├─ GetEapolKeyMessageType() → MsgType=1
  │         ├─ CopyMem(ANonce)
  │         ├─ WpaRandomBytes(SNonce)
  │         ├─ WpaDerivePmk()         ← PBKDF2-SHA1(password, SSID, 4096)
  │         ├─ WpaDerivePtk()
  │         │    └─ WpaPrfSha1(PMK, "Pairwise key expansion", ...)
  │         │         → PTK-384bit: KCK(16)+KEK(16)+TK(16)
  │         └─ BuildMessage2()
  │              ├─ WpaBuildRsnIe()
  │              └─ ComputeEapolMic()
  │                   └─ WpaHmacSha1Mic()  ← KDescVer=2: HMAC-SHA1-128
  │
  │  [STA → AP: EAPOL-Key Msg2 송신]
  │  [AP → STA: EAPOL-Key Msg3 수신]
  │
  ├─ BuildResponsePacket(Msg3)
  │    └─ WpaEapolProcessKeyFrame()
  │         ├─ VerifyEapolMic() → WpaHmacSha1Mic()
  │         ├─ [KeyData AES Key Unwrap 복호화]
  │         │    └─ WpaAesKeyUnwrap(KEK, EncKeyData) → GTK 평문
  │         ├─ ParseKeyData()          ← GTK KDE + IGTK KDE 파싱
  │         └─ BuildMessage4()
  │              └─ ComputeEapolMic() → WpaHmacSha1Mic()
  │
  │  [STA → AP: EAPOL-Key Msg4 송신] → Handshake Complete
  │
  ├─ ProcessPacket(Encrypt)
  │    └─ WpaCcmpEncrypt(PTK_TK, TxPn, ...)
  │
  └─ ProcessPacket(Decrypt)
       └─ WpaCcmpDecrypt(PTK_TK, Pn, ...)
```

---

## WPA3 (SAE + CCMP)

WPA3는 두 단계로 구성된다. 먼저 SAE(Dragonfly) 교환으로 PMK를 도출한 뒤,
WPA2와 동일한 4-Way Handshake를 수행한다. MIC 알고리즘과 PTK 유도 함수만 다르다.

```
WifiConnectionManagerDxe
  │
  ├─ SetData(AKMSuite=SAE, PairwiseCipher=CCMP)
  │    └─ UpdateKeyDescVersion() → KeyDescVersion=0 (AKM-Defined: AES-CMAC)
  │
  ├─ SetData(Password, SSID, StationMac, TargetBssid)
  │
  │  ──── SAE (Dragonfly) Phase ────────────────────────────────────────
  │
  ├─ BuildResponsePacket(NULL)        ← WPA3: SAE Commit 생성
  │    ├─ SaeInit()
  │    │    ├─ SaeDerivePasswordElement()   ← Hunting-and-Pecking (최대 40회)
  │    │    │    ├─ HMAC-SHA256(AddrConcat, password||counter) → pwd-seed
  │    │    │    ├─ WpaKdfSha256(pwd-seed, "SAE Hunting and Pecking", prime)
  │    │    │    │    → pwd-value
  │    │    │    └─ ECC P-256 좌표 계산: y² = x³+ax+b 검증 → PWE(x,y) 결정
  │    │    ├─ WpaRandomBytes(rand, mask)
  │    │    ├─ scalar = (rand + mask) mod order
  │    │    └─ element = -(mask × PWE)    ← EcPointMul + EcPointInvert
  │    └─ SaeBuildCommit()
  │         → [GroupId(2) | Scalar(32) | ElementX(32) | ElementY(32)]
  │
  │  [STA → AP: SAE Commit 송신]
  │  [AP → STA: SAE Commit 수신]
  │
  ├─ BuildResponsePacket(AP_Commit)
  │    ├─ SaeProcessCommit()
  │    │    ├─ 피어 Scalar/Element 유효성 검증 (범위, 곡선 위 여부)
  │    │    ├─ K = rand × (peer_scalar × PWE + peer_element)
  │    │    │    └─ EcPointMul + EcPointAdd + EcPointMul
  │    │    ├─ keyseed = HMAC-SHA256(0x00…, K.x)
  │    │    └─ KCK||PMK = KDF-512(keyseed, "SAE KCK and PMK", scalar_sum)
  │    └─ SaeBuildConfirm()
  │         ├─ confirm = HMAC-SHA256(KCK,
  │         │              send_confirm || own_scalar || peer_scalar ||
  │         │              own_element || peer_element)
  │         └─ [SendConfirm(2) | Confirm(32)]
  │
  │  [STA → AP: SAE Confirm 송신]
  │  [AP → STA: SAE Confirm 수신]
  │
  ├─ BuildResponsePacket(AP_Confirm)
  │    └─ SaeProcessConfirm()
  │         ├─ 예상 Confirm 재계산 (peer/own 순서 교환)
  │         ├─ CompareMem() → 검증
  │         └─ Private->Pmk = Session.Pmk  ← PMK 설치, PmkValid=TRUE
  │
  │  ──── 4-Way Handshake Phase ─────────────────────────────────────────
  │  (WPA2와 동일 흐름, PTK 유도 함수와 MIC 알고리즘만 다름)
  │
  │  [AP → STA: EAPOL-Key Msg1 수신]
  │
  ├─ BuildResponsePacket(Msg1)
  │    └─ WpaEapolProcessKeyFrame()
  │         ├─ WpaDerivePtk()
  │         │    └─ WpaKdfSha256(PMK, "Pairwise key expansion", ...)
  │         │         → PTK-384bit (PRF-SHA1 대신 KDF-SHA256 사용)
  │         └─ BuildMessage2()
  │              └─ ComputeEapolMic()
  │                   └─ WpaAesCmac()  ← KDescVer=0: AES-128-CMAC
  │
  │  [STA → AP: EAPOL-Key Msg2 송신]
  │  [AP → STA: EAPOL-Key Msg3 수신]
  │
  ├─ BuildResponsePacket(Msg3)
  │    └─ WpaEapolProcessKeyFrame()
  │         ├─ VerifyEapolMic() → WpaAesCmac()
  │         ├─ WpaAesKeyUnwrap(KEK, EncKeyData) → GTK + IGTK
  │         ├─ ParseKeyData()
  │         └─ BuildMessage4()
  │              └─ ComputeEapolMic() → WpaAesCmac()
  │
  │  [STA → AP: EAPOL-Key Msg4 송신] → Handshake Complete
  │
  ├─ ProcessPacket(Encrypt)
  │    └─ WpaCcmpEncrypt(PTK_TK, TxPn, ...)
  │
  └─ ProcessPacket(Decrypt)
       └─ WpaCcmpDecrypt(PTK_TK, Pn, ...)
```

---

## 버전별 차이 요약

| 항목 | WPA1 | WPA2 | WPA3 |
|------|------|------|------|
| **PMK 출처** | PBKDF2-SHA1 | PBKDF2-SHA1 | SAE (Dragonfly ECC) |
| **PTK 유도** | PRF-SHA1 (512 bit) | PRF-SHA1 (384 bit) | KDF-SHA256 (384 bit) |
| **EAPOL MIC** | HMAC-MD5 | HMAC-SHA1-128 | AES-128-CMAC |
| **KeyData 복호화** | RC4 (IV\|\|KEK) | AES Key Wrap | AES Key Wrap |
| **데이터 암호화** | TKIP (RC4 기반) | CCMP (AES-CCM) | CCMP (AES-CCM) |
| **SAE Phase** | 없음 | 없음 | Commit → Confirm |
| **전방향 보안** | 없음 | 없음 | 있음 (임시 ECC 키) |
| **KeyDescVersion** | `1` | `2` | `0` |

## 관련 소스 위치

| 함수 | 파일 | 역할 |
|------|------|------|
| `SupplicantBuildResponsePacket` | `SupplicantImpl.c:66` | 최상위 진입점, SAE/EAPOL 분기 |
| `WpaEapolProcessKeyFrame` | `WpaEapol.c:797` | Msg1/Msg3/Group Key 처리 |
| `WpaDerivePtk` | `WpaEapol.c:212` | PRF-SHA1 / KDF-SHA256 분기 |
| `ComputeEapolMic` | `WpaEapol.c:129` | HMAC-MD5 / HMAC-SHA1 / AES-CMAC 분기 |
| `SaeInit` | `WpaSae.c:382` | PWE 유도 + scalar/element 생성 |
| `SaeBuildCommit` | `WpaSae.c:604` | Commit 프레임 직렬화 |
| `SaeProcessCommit` | `WpaSae.c:669` | 공유 비밀 K 계산, KCK+PMK 유도 |
| `SaeBuildConfirm` | `WpaSae.c:977` | Confirm 프레임 직렬화 |
| `SaeProcessConfirm` | `WpaSae.c:1064` | Confirm 검증, PMK 설치 |
