# SupplicantDxe — Documentation Index

`NetworkPkg/SupplicantDxe/` is a UEFI DXE driver that implements WPA2-Personal (PSK)
and WPA3-Personal (SAE) authentication, producing `gEfiSupplicantProtocolGuid`.

## Documents

| File | Contents |
|------|----------|
| [architecture.md](architecture.md) | Module layout, private data structures, data flow |
| [protocol.md](protocol.md) | `EFI_SUPPLICANT_PROTOCOL` — SetData/GetData/BuildResponsePacket/ProcessPacket |
| [crypto.md](crypto.md) | Cryptographic primitives: AES-CMAC, HMAC-SHA1, PRF, KDF, CCMP, TKIP, WEP, RC4 |
| [eapol.md](eapol.md) | IEEE 802.11 4-Way and Group Key Handshake state machine |
| [sae.md](sae.md) | SAE (Dragonfly) Commit/Confirm exchange, ECC Group 19 |
| [testing.md](testing.md) | Unit-test catalogue, build/run instructions, native macOS harness |

## Quick Build Reference

```bash
# Firmware target (requires EDK II toolchain)
build -p NetworkPkg/NetworkPkg.dsc -t GCC -a X64

# EDK II host unit tests (Ubuntu x86-64)
build -p NetworkPkg/Test/NetworkPkgHostTest.dsc -t GCC -a X64 -b NOOPT
Build/NetworkPkg/NOOPT_GCC/X64/SupplicantDxeGoogleTest

# Native macOS test harness (Apple Silicon)
cd NetworkPkg/SupplicantDxe/NativeTest && make run
```

## Key Standards References

- IEEE 802.11-2020 — core Wi-Fi specification (handshakes, key derivation, cipher suites)
- IEEE 802.1X-2010 — EAPOL protocol
- RFC 4493 — AES-128-CMAC
- RFC 3394 — AES Key Wrap
- RFC 2104 — HMAC
- RFC 2202 — HMAC-MD5 test vectors
- RFC 6229 — RC4 test vectors
