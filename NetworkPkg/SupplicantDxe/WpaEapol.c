/** @file
  WPA EAPOL 4-Way Handshake and Group Key Handshake Implementation.

  Implements the supplicant side of the IEEE 802.11 EAPOL-Key protocol.
  Supports WPA2-Personal (AKM Suite 2, Key Descriptor Version 2) and
  WPA3-Personal/PSK-SHA256 (AKM Suite 8/6, AES-CMAC MIC).

  Reference: IEEE 802.11-2020 Section 12.7.6, wpa_supplicant

  Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SupplicantDxe.h"

/**
  Determine the message type from EAPOL-Key information field.

  @param[in]  KeyInfo   Key Information field (host byte order).
  @param[in]  HasMic    Whether the frame has a non-zero MIC.

  @return Message number (1-4 for 4-way, 1-2 for group key), or 0 if unknown.
**/
STATIC
UINT8
GetEapolKeyMessageType (
  IN UINT16  KeyInfo
  )
{
  BOOLEAN  IsPairwise;
  BOOLEAN  HasAck;
  BOOLEAN  HasMic;
  BOOLEAN  IsSecure;
  BOOLEAN  IsInstall;
  BOOLEAN  HasEncKeyData;

  IsPairwise    = (KeyInfo & WPA_KEY_INFO_KEY_TYPE) != 0;
  HasAck        = (KeyInfo & WPA_KEY_INFO_KEY_ACK) != 0;
  HasMic        = (KeyInfo & WPA_KEY_INFO_KEY_MIC) != 0;
  IsSecure      = (KeyInfo & WPA_KEY_INFO_SECURE) != 0;
  IsInstall     = (KeyInfo & WPA_KEY_INFO_INSTALL) != 0;
  HasEncKeyData = (KeyInfo & WPA_KEY_INFO_ENCRYPTED_KEY_DATA) != 0;

  if (IsPairwise) {
    if (HasAck && !HasMic && !IsSecure && !IsInstall) {
      //
      // Message 1: Ack=1, MIC=0, Secure=0, Install=0
      //
      return 1;
    }

    if (!HasAck && HasMic && !IsSecure && !IsInstall) {
      //
      // Message 2: Ack=0, MIC=1, Secure=0, Install=0
      //
      return 2;
    }

    if (HasAck && HasMic && IsSecure && IsInstall && HasEncKeyData) {
      //
      // Message 3: Ack=1, MIC=1, Secure=1, Install=1, EncKeyData=1
      //
      return 3;
    }

    if (!HasAck && HasMic && IsSecure && !IsInstall) {
      //
      // Message 4: Ack=0, MIC=1, Secure=1, Install=0
      //
      return 4;
    }
  } else {
    //
    // Group Key Handshake
    //
    if (HasAck && HasMic && IsSecure && HasEncKeyData) {
      //
      // Group Key Message 1
      //
      return 1;
    }

    if (!HasAck && HasMic && IsSecure) {
      //
      // Group Key Message 2
      //
      return 2;
    }
  }

  return 0;
}

/**
  Compute EAPOL-Key MIC based on the configured key descriptor version.

  @param[in]   Private   Supplicant private data.
  @param[in]   Data      EAPOL frame data (MIC field must be zeroed).
  @param[in]   DataLen   Length of data.
  @param[out]  Mic       16-byte MIC output.

  @retval TRUE   MIC computed.
  @retval FALSE  MIC computation failed.
**/
STATIC
BOOLEAN
ComputeEapolMic (
  IN  SUPPLICANT_PRIVATE_DATA  *Private,
  IN  CONST UINT8              *Data,
  IN  UINTN                    DataLen,
  OUT UINT8                    *Mic
  )
{
  switch (Private->AkmSuiteType) {
    case WPA_AKM_SUITE_PSK:
      //
      // Key Descriptor Version 2: HMAC-SHA1-128
      //
      return WpaHmacSha1Mic (Private->Ptk.Kck, Data, DataLen, Mic);

    case WPA_AKM_SUITE_PSK_SHA256:
    case WPA_AKM_SUITE_SAE:
      //
      // AES-128-CMAC
      //
      return WpaAesCmac (Private->Ptk.Kck, Data, DataLen, Mic);

    default:
      //
      // Default: try HMAC-SHA1-128 for backward compatibility
      //
      return WpaHmacSha1Mic (Private->Ptk.Kck, Data, DataLen, Mic);
  }
}

/**
  Verify the MIC in an incoming EAPOL-Key frame.

  @param[in]  Private        Supplicant private data.
  @param[in]  EapolFrame     Complete EAPOL frame.
  @param[in]  FrameLen       Length of the EAPOL frame.
  @param[in]  MicOffset      Offset of the MIC field within the frame.

  @retval TRUE   MIC is valid.
  @retval FALSE  MIC is invalid.
**/
STATIC
BOOLEAN
VerifyEapolMic (
  IN SUPPLICANT_PRIVATE_DATA  *Private,
  IN CONST UINT8              *EapolFrame,
  IN UINTN                    FrameLen,
  IN UINTN                    MicOffset
  )
{
  UINT8    *FrameCopy;
  UINT8    ComputedMic[WPA_MIC_LEN];
  BOOLEAN  Result;

  FrameCopy = AllocatePool (FrameLen);
  if (FrameCopy == NULL) {
    return FALSE;
  }

  CopyMem (FrameCopy, EapolFrame, FrameLen);

  //
  // Zero the MIC field in the copy
  //
  ZeroMem (FrameCopy + MicOffset, WPA_MIC_LEN);

  Result = ComputeEapolMic (Private, FrameCopy, FrameLen, ComputedMic);
  if (Result) {
    Result = (CompareMem (ComputedMic, EapolFrame + MicOffset, WPA_MIC_LEN) == 0);
  }

  FreePool (FrameCopy);
  return Result;
}

/**
  Derive PTK from PMK, nonces, and MAC addresses.

  @param[in]  Private   Supplicant private data.

  @retval TRUE   PTK derived.
  @retval FALSE  PTK derivation failed.
**/
BOOLEAN
WpaDerivePtk (
  IN SUPPLICANT_PRIVATE_DATA  *Private
  )
{
  UINT8    Data[2 * WPA_MAC_ADDR_LEN + 2 * WPA_NONCE_LEN];
  UINT8    *MinAddr;
  UINT8    *MaxAddr;
  UINT8    *MinNonce;
  UINT8    *MaxNonce;
  INT32    AddrCmp;
  INT32    NonceCmp;

  if (!Private->PmkValid) {
    return FALSE;
  }

  //
  // Sort addresses: Min(AA, SPA) || Max(AA, SPA)
  //
  AddrCmp = CompareMem (Private->StationMac.Addr, Private->TargetBssid.Addr, WPA_MAC_ADDR_LEN);
  if (AddrCmp <= 0) {
    MinAddr = Private->StationMac.Addr;
    MaxAddr = Private->TargetBssid.Addr;
  } else {
    MinAddr = Private->TargetBssid.Addr;
    MaxAddr = Private->StationMac.Addr;
  }

  //
  // Sort nonces: Min(ANonce, SNonce) || Max(ANonce, SNonce)
  //
  NonceCmp = CompareMem (Private->ANonce, Private->SNonce, WPA_NONCE_LEN);
  if (NonceCmp <= 0) {
    MinNonce = Private->ANonce;
    MaxNonce = Private->SNonce;
  } else {
    MinNonce = Private->SNonce;
    MaxNonce = Private->ANonce;
  }

  //
  // Build data: Min(AA,SPA) || Max(AA,SPA) || Min(ANonce,SNonce) || Max(ANonce,SNonce)
  //
  CopyMem (Data, MinAddr, WPA_MAC_ADDR_LEN);
  CopyMem (Data + WPA_MAC_ADDR_LEN, MaxAddr, WPA_MAC_ADDR_LEN);
  CopyMem (Data + 2 * WPA_MAC_ADDR_LEN, MinNonce, WPA_NONCE_LEN);
  CopyMem (Data + 2 * WPA_MAC_ADDR_LEN + WPA_NONCE_LEN, MaxNonce, WPA_NONCE_LEN);

  switch (Private->AkmSuiteType) {
    case WPA_AKM_SUITE_PSK:
      //
      // WPA2-PSK: PRF-384 for CCMP
      //
      Private->KeyDescVersion = WPA_KEY_DESC_VERSION_HMAC_SHA1_AES;
      return WpaPrfSha1 (
               Private->Pmk,
               WPA_PMK_LEN,
               "Pairwise key expansion",
               Data,
               sizeof (Data),
               (UINT8 *)&Private->Ptk,
               WPA_PTK_LEN
               );

    case WPA_AKM_SUITE_PSK_SHA256:
    case WPA_AKM_SUITE_SAE:
      //
      // WPA3/PSK-SHA256: KDF-384 (SHA256-based)
      //
      Private->KeyDescVersion = WPA_KEY_DESC_VERSION_AKM_DEFINED;
      return WpaKdfSha256 (
               Private->Pmk,
               WPA_PMK_LEN,
               "Pairwise key expansion",
               Data,
               sizeof (Data),
               (UINT8 *)&Private->Ptk,
               WPA_PTK_LEN * 8
               );

    default:
      DEBUG ((DEBUG_ERROR, "[Supplicant] Unsupported AKM suite type: %d\n", Private->AkmSuiteType));
      return FALSE;
  }
}

/**
  Build RSN IE for EAPOL-Key Message 2.

  @param[in]   Private   Supplicant private data.
  @param[out]  RsnIe     RSN IE output buffer (at least 22 bytes).
  @param[out]  RsnIeLen  RSN IE length.

  @retval TRUE   Built.
  @retval FALSE  Failed.
**/
BOOLEAN
WpaBuildRsnIe (
  IN  SUPPLICANT_PRIVATE_DATA  *Private,
  OUT UINT8                    *RsnIe,
  OUT UINTN                    *RsnIeLen
  )
{
  UINTN  Offset;

  if ((Private == NULL) || (RsnIe == NULL) || (RsnIeLen == NULL)) {
    return FALSE;
  }

  Offset = 0;

  //
  // Element ID: 48 (RSN)
  //
  RsnIe[Offset++] = 48;

  //
  // Length (filled in later)
  //
  RsnIe[Offset++] = 0;

  //
  // Version: 1
  //
  WPA_PUT_LE16 (RsnIe + Offset, 1);
  Offset += 2;

  //
  // Group Data Cipher Suite
  //
  RsnIe[Offset++] = WPA_RSN_OUI_BYTE0;
  RsnIe[Offset++] = WPA_RSN_OUI_BYTE1;
  RsnIe[Offset++] = WPA_RSN_OUI_BYTE2;
  RsnIe[Offset++] = Private->GroupCipherType;

  //
  // Pairwise Cipher Suite Count: 1
  //
  WPA_PUT_LE16 (RsnIe + Offset, 1);
  Offset += 2;

  //
  // Pairwise Cipher Suite
  //
  RsnIe[Offset++] = WPA_RSN_OUI_BYTE0;
  RsnIe[Offset++] = WPA_RSN_OUI_BYTE1;
  RsnIe[Offset++] = WPA_RSN_OUI_BYTE2;
  RsnIe[Offset++] = Private->PairwiseCipherType;

  //
  // AKM Suite Count: 1
  //
  WPA_PUT_LE16 (RsnIe + Offset, 1);
  Offset += 2;

  //
  // AKM Suite
  //
  RsnIe[Offset++] = WPA_RSN_OUI_BYTE0;
  RsnIe[Offset++] = WPA_RSN_OUI_BYTE1;
  RsnIe[Offset++] = WPA_RSN_OUI_BYTE2;
  RsnIe[Offset++] = Private->AkmSuiteType;

  //
  // RSN Capabilities: 0 (no pre-auth, 1 PTKSA replay counter)
  //
  WPA_PUT_LE16 (RsnIe + Offset, 0x000C);
  Offset += 2;

  //
  // Fill in Length field
  //
  RsnIe[1] = (UINT8)(Offset - 2);
  *RsnIeLen = Offset;

  return TRUE;
}

/**
  Build EAPOL-Key Message 2 response.

  @param[in]      Private     Supplicant private data.
  @param[in]      KeyFrame    Received Message 1 key frame.
  @param[out]     Buffer      Output buffer for Message 2.
  @param[in,out]  BufferSize  Buffer size.

  @retval EFI_SUCCESS           Message 2 built.
  @retval EFI_BUFFER_TOO_SMALL  Need more space.
**/
STATIC
EFI_STATUS
BuildMessage2 (
  IN     SUPPLICANT_PRIVATE_DATA  *Private,
  IN     CONST EAPOL_KEY_FRAME    *KeyFrame,
  OUT    UINT8                    *Buffer,
  IN OUT UINTN                    *BufferSize
  )
{
  EAPOL_HEADER     *EapolHdr;
  EAPOL_KEY_FRAME  *RespKey;
  UINT8            RsnIe[64];
  UINTN            RsnIeLen;
  UINTN            RequiredSize;
  UINT16           KeyInfo;
  UINT8            Mic[WPA_MIC_LEN];

  //
  // Build RSN IE for key data
  //
  if (!WpaBuildRsnIe (Private, RsnIe, &RsnIeLen)) {
    return EFI_DEVICE_ERROR;
  }

  RequiredSize = sizeof (EAPOL_HEADER) + sizeof (EAPOL_KEY_FRAME) + RsnIeLen;

  if (*BufferSize < RequiredSize) {
    *BufferSize = RequiredSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  *BufferSize = RequiredSize;
  ZeroMem (Buffer, RequiredSize);

  //
  // EAPOL header
  //
  EapolHdr = (EAPOL_HEADER *)Buffer;
  EapolHdr->ProtocolVersion = EAPOL_VERSION_2;
  EapolHdr->PacketType      = EAPOL_PACKET_TYPE_KEY;
  WPA_PUT_BE16 (&EapolHdr->PacketBodyLength,
    (UINT16)(sizeof (EAPOL_KEY_FRAME) + RsnIeLen));

  //
  // EAPOL-Key frame
  //
  RespKey = (EAPOL_KEY_FRAME *)(Buffer + sizeof (EAPOL_HEADER));
  RespKey->DescriptorType = EAPOL_KEY_DESC_TYPE_RSN;

  //
  // Key Information: Pairwise + MIC + Key Descriptor Version
  //
  KeyInfo = WPA_KEY_INFO_KEY_TYPE | WPA_KEY_INFO_KEY_MIC;
  KeyInfo |= (Private->KeyDescVersion & WPA_KEY_INFO_KEY_DESC_VERSION_MASK);
  WPA_PUT_BE16 (&RespKey->KeyInformation, KeyInfo);

  //
  // Key Length: 16 for CCMP
  //
  WPA_PUT_BE16 (&RespKey->KeyLength, WPA_TK_LEN);

  //
  // Replay Counter: copy from Message 1
  //
  CopyMem (RespKey->ReplayCounter, KeyFrame->ReplayCounter, WPA_REPLAY_CTR_LEN);

  //
  // Key Nonce: our SNonce
  //
  CopyMem (RespKey->KeyNonce, Private->SNonce, WPA_NONCE_LEN);

  //
  // Key Data: RSN IE
  //
  WPA_PUT_BE16 (&RespKey->KeyDataLength, (UINT16)RsnIeLen);
  CopyMem (Buffer + sizeof (EAPOL_HEADER) + sizeof (EAPOL_KEY_FRAME), RsnIe, RsnIeLen);

  //
  // Compute and set MIC
  //
  if (!ComputeEapolMic (Private, Buffer, RequiredSize, Mic)) {
    return EFI_DEVICE_ERROR;
  }

  CopyMem (RespKey->KeyMic, Mic, WPA_MIC_LEN);

  return EFI_SUCCESS;
}

/**
  Parse GTK from EAPOL-Key Message 3 key data.

  @param[in]   Private     Supplicant private data.
  @param[in]   KeyData     Decrypted key data.
  @param[in]   KeyDataLen  Length of key data.

  @retval TRUE   GTK extracted.
  @retval FALSE  GTK extraction failed.
**/
STATIC
BOOLEAN
ParseKeyData (
  IN SUPPLICANT_PRIVATE_DATA  *Private,
  IN CONST UINT8              *KeyData,
  IN UINTN                    KeyDataLen
  )
{
  UINTN              Offset;
  WPA_KDE_HEADER     *Kde;
  WPA_GTK_KDE_DATA   *GtkData;
  WPA_IGTK_KDE_DATA  *IgtkData;
  UINTN              KdeLen;
  UINTN              GtkLen;

  Offset = 0;
  while (Offset + sizeof (WPA_KDE_HEADER) <= KeyDataLen) {
    if (KeyData[Offset] == 48) {
      //
      // RSN IE - skip it (AP's RSN IE for verification)
      //
      if (Offset + 1 >= KeyDataLen) {
        break;
      }

      Offset += 2 + KeyData[Offset + 1];
      continue;
    }

    if (KeyData[Offset] != 0xDD) {
      //
      // Unknown element, try to skip
      //
      if (Offset + 1 >= KeyDataLen) {
        break;
      }

      Offset += 2 + KeyData[Offset + 1];
      continue;
    }

    Kde = (WPA_KDE_HEADER *)(KeyData + Offset);
    KdeLen = Kde->Length + 2;  // Type + Length + data

    if (Offset + KdeLen > KeyDataLen) {
      break;
    }

    //
    // Check OUI: 00-0F-AC
    //
    if ((Kde->Oui[0] != WPA_RSN_OUI_BYTE0) ||
        (Kde->Oui[1] != WPA_RSN_OUI_BYTE1) ||
        (Kde->Oui[2] != WPA_RSN_OUI_BYTE2))
    {
      Offset += KdeLen;
      continue;
    }

    if (Kde->DataType == WPA_KDE_TYPE_GTK) {
      //
      // GTK KDE: OUI(3) + DataType(1) + KeyId(1) + Tx(1) + GTK
      //
      GtkData = (WPA_GTK_KDE_DATA *)(KeyData + Offset + sizeof (WPA_KDE_HEADER));
      GtkLen  = Kde->Length - 4 - sizeof (WPA_GTK_KDE_DATA);  // Subtract OUI+Type+KdeData

      if (GtkLen > WPA_GTK_MAX_LEN) {
        GtkLen = WPA_GTK_MAX_LEN;
      }

      UINT8  KeyId = GtkData->KeyId & 0x03;
      if (KeyId < 4) {
        CopyMem (
          Private->Gtk[KeyId].Key,
          (UINT8 *)GtkData + sizeof (WPA_GTK_KDE_DATA),
          GtkLen
          );
        Private->Gtk[KeyId].KeyLen = (UINT8)GtkLen;
        Private->Gtk[KeyId].KeyId  = KeyId;
        if (Private->GtkCount <= KeyId) {
          Private->GtkCount = KeyId + 1;
        }

        Private->GtkRefreshed = TRUE;
        DEBUG ((DEBUG_INFO, "[Supplicant] GTK installed, KeyId=%d, Len=%d\n", KeyId, GtkLen));
      }
    } else if (Kde->DataType == WPA_KDE_TYPE_IGTK) {
      //
      // IGTK KDE
      //
      IgtkData = (WPA_IGTK_KDE_DATA *)(KeyData + Offset + sizeof (WPA_KDE_HEADER));
      UINT8  IgtkKeyId = IgtkData->KeyId & 0x01;
      UINTN  IgtkKeyLen = Kde->Length - 4 - sizeof (WPA_IGTK_KDE_DATA);

      if (IgtkKeyLen > WPA_GTK_MAX_LEN) {
        IgtkKeyLen = WPA_GTK_MAX_LEN;
      }

      CopyMem (
        Private->Igtk[IgtkKeyId].Key,
        (UINT8 *)IgtkData + sizeof (WPA_IGTK_KDE_DATA),
        IgtkKeyLen
        );
      Private->Igtk[IgtkKeyId].KeyLen = (UINT8)IgtkKeyLen;
      Private->Igtk[IgtkKeyId].KeyId  = IgtkData->KeyId;
      CopyMem (Private->Igtk[IgtkKeyId].Ipn, IgtkData->Ipn, 6);

      if (Private->IgtkCount <= IgtkKeyId) {
        Private->IgtkCount = IgtkKeyId + 1;
      }

      DEBUG ((DEBUG_INFO, "[Supplicant] IGTK installed, KeyId=%d\n", IgtkData->KeyId));
    }

    Offset += KdeLen;
  }

  return (Private->GtkCount > 0);
}

/**
  Build EAPOL-Key Message 4 response.

  @param[in]      Private     Supplicant private data.
  @param[in]      KeyFrame    Received Message 3 key frame.
  @param[out]     Buffer      Output buffer.
  @param[in,out]  BufferSize  Buffer size.

  @retval EFI_SUCCESS           Message 4 built.
  @retval EFI_BUFFER_TOO_SMALL  Need more space.
**/
STATIC
EFI_STATUS
BuildMessage4 (
  IN     SUPPLICANT_PRIVATE_DATA  *Private,
  IN     CONST EAPOL_KEY_FRAME    *KeyFrame,
  OUT    UINT8                    *Buffer,
  IN OUT UINTN                    *BufferSize
  )
{
  EAPOL_HEADER     *EapolHdr;
  EAPOL_KEY_FRAME  *RespKey;
  UINTN            RequiredSize;
  UINT16           KeyInfo;
  UINT8            Mic[WPA_MIC_LEN];

  RequiredSize = sizeof (EAPOL_HEADER) + sizeof (EAPOL_KEY_FRAME);

  if (*BufferSize < RequiredSize) {
    *BufferSize = RequiredSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  *BufferSize = RequiredSize;
  ZeroMem (Buffer, RequiredSize);

  //
  // EAPOL header
  //
  EapolHdr = (EAPOL_HEADER *)Buffer;
  EapolHdr->ProtocolVersion = EAPOL_VERSION_2;
  EapolHdr->PacketType      = EAPOL_PACKET_TYPE_KEY;
  WPA_PUT_BE16 (&EapolHdr->PacketBodyLength, (UINT16)sizeof (EAPOL_KEY_FRAME));

  //
  // EAPOL-Key frame
  //
  RespKey = (EAPOL_KEY_FRAME *)(Buffer + sizeof (EAPOL_HEADER));
  RespKey->DescriptorType = EAPOL_KEY_DESC_TYPE_RSN;

  //
  // Key Information: Pairwise + MIC + Secure + Key Descriptor Version
  //
  KeyInfo = WPA_KEY_INFO_KEY_TYPE | WPA_KEY_INFO_KEY_MIC | WPA_KEY_INFO_SECURE;
  KeyInfo |= (Private->KeyDescVersion & WPA_KEY_INFO_KEY_DESC_VERSION_MASK);
  WPA_PUT_BE16 (&RespKey->KeyInformation, KeyInfo);

  //
  // Key Length: 16 for CCMP
  //
  WPA_PUT_BE16 (&RespKey->KeyLength, WPA_TK_LEN);

  //
  // Replay Counter: copy from Message 3
  //
  CopyMem (RespKey->ReplayCounter, KeyFrame->ReplayCounter, WPA_REPLAY_CTR_LEN);

  //
  // Key Data Length: 0
  //
  WPA_PUT_BE16 (&RespKey->KeyDataLength, 0);

  //
  // Compute and set MIC
  //
  if (!ComputeEapolMic (Private, Buffer, RequiredSize, Mic)) {
    return EFI_DEVICE_ERROR;
  }

  CopyMem (RespKey->KeyMic, Mic, WPA_MIC_LEN);

  return EFI_SUCCESS;
}

/**
  Build Group Key Handshake Message 2 response.

  @param[in]      Private     Supplicant private data.
  @param[in]      KeyFrame    Received Group Key Message 1 key frame.
  @param[out]     Buffer      Output buffer.
  @param[in,out]  BufferSize  Buffer size.

  @retval EFI_SUCCESS           Group Key Message 2 built.
  @retval EFI_BUFFER_TOO_SMALL  Need more space.
**/
STATIC
EFI_STATUS
BuildGroupKeyMessage2 (
  IN     SUPPLICANT_PRIVATE_DATA  *Private,
  IN     CONST EAPOL_KEY_FRAME    *KeyFrame,
  OUT    UINT8                    *Buffer,
  IN OUT UINTN                    *BufferSize
  )
{
  EAPOL_HEADER     *EapolHdr;
  EAPOL_KEY_FRAME  *RespKey;
  UINTN            RequiredSize;
  UINT16           KeyInfo;
  UINT8            Mic[WPA_MIC_LEN];

  RequiredSize = sizeof (EAPOL_HEADER) + sizeof (EAPOL_KEY_FRAME);

  if (*BufferSize < RequiredSize) {
    *BufferSize = RequiredSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  *BufferSize = RequiredSize;
  ZeroMem (Buffer, RequiredSize);

  EapolHdr = (EAPOL_HEADER *)Buffer;
  EapolHdr->ProtocolVersion = EAPOL_VERSION_2;
  EapolHdr->PacketType      = EAPOL_PACKET_TYPE_KEY;
  WPA_PUT_BE16 (&EapolHdr->PacketBodyLength, (UINT16)sizeof (EAPOL_KEY_FRAME));

  RespKey = (EAPOL_KEY_FRAME *)(Buffer + sizeof (EAPOL_HEADER));
  RespKey->DescriptorType = EAPOL_KEY_DESC_TYPE_RSN;

  KeyInfo = WPA_KEY_INFO_KEY_MIC | WPA_KEY_INFO_SECURE;
  KeyInfo |= (Private->KeyDescVersion & WPA_KEY_INFO_KEY_DESC_VERSION_MASK);
  WPA_PUT_BE16 (&RespKey->KeyInformation, KeyInfo);

  CopyMem (RespKey->ReplayCounter, KeyFrame->ReplayCounter, WPA_REPLAY_CTR_LEN);
  WPA_PUT_BE16 (&RespKey->KeyDataLength, 0);

  if (!ComputeEapolMic (Private, Buffer, RequiredSize, Mic)) {
    return EFI_DEVICE_ERROR;
  }

  CopyMem (RespKey->KeyMic, Mic, WPA_MIC_LEN);

  return EFI_SUCCESS;
}

/**
  Process incoming EAPOL-Key frame and generate response.

  @param[in]       Private       Supplicant private data.
  @param[in]       RequestBuffer Incoming EAPOL packet.
  @param[in]       RequestSize   Packet size.
  @param[out]      Buffer        Response buffer.
  @param[in, out]  BufferSize    Buffer size.

  @retval EFI_SUCCESS            Response built.
  @retval EFI_BUFFER_TOO_SMALL   Buffer too small.
  @retval EFI_INVALID_PARAMETER  Bad input.
  @retval EFI_NOT_READY          State mismatch.
  @retval EFI_SECURITY_VIOLATION MIC verification failed.
**/
EFI_STATUS
WpaEapolProcessKeyFrame (
  IN     SUPPLICANT_PRIVATE_DATA  *Private,
  IN     CONST UINT8              *RequestBuffer,
  IN     UINTN                    RequestSize,
  OUT    UINT8                    *Buffer,
  IN OUT UINTN                    *BufferSize
  )
{
  CONST EAPOL_HEADER     *EapolHdr;
  CONST EAPOL_KEY_FRAME  *KeyFrame;
  UINT16                 KeyInfo;
  UINT8                  MsgType;
  BOOLEAN                IsPairwise;
  UINT16                 KeyDataLen;
  CONST UINT8            *KeyData;
  UINTN                  MicOffset;
  UINT8                  *DecryptedKeyData;
  UINTN                  DecryptedLen;

  if ((Private == NULL) || (RequestBuffer == NULL) || (BufferSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (RequestSize < EAPOL_KEY_FRAME_MIN_LEN) {
    return EFI_INVALID_PARAMETER;
  }

  EapolHdr = (CONST EAPOL_HEADER *)RequestBuffer;
  if (EapolHdr->PacketType != EAPOL_PACKET_TYPE_KEY) {
    return EFI_UNSUPPORTED;
  }

  KeyFrame = (CONST EAPOL_KEY_FRAME *)(RequestBuffer + sizeof (EAPOL_HEADER));
  if (KeyFrame->DescriptorType != EAPOL_KEY_DESC_TYPE_RSN) {
    return EFI_UNSUPPORTED;
  }

  KeyInfo    = WPA_GET_BE16 (&KeyFrame->KeyInformation);
  IsPairwise = (KeyInfo & WPA_KEY_INFO_KEY_TYPE) != 0;
  MsgType    = GetEapolKeyMessageType (KeyInfo);
  KeyDataLen = WPA_GET_BE16 (&KeyFrame->KeyDataLength);
  KeyData    = RequestBuffer + sizeof (EAPOL_HEADER) + sizeof (EAPOL_KEY_FRAME);

  //
  // MIC is at a fixed offset within the EAPOL frame
  //
  MicOffset = sizeof (EAPOL_HEADER) +
              OFFSET_OF (EAPOL_KEY_FRAME, KeyMic);

  DEBUG ((DEBUG_INFO, "[Supplicant] EAPOL-Key: Pairwise=%d, MsgType=%d, KeyDataLen=%d\n",
    IsPairwise, MsgType, KeyDataLen));

  if (IsPairwise) {
    switch (MsgType) {
      case 1:
        //
        // 4-Way Handshake Message 1: Extract ANonce, generate SNonce, derive PTK
        //
        DEBUG ((DEBUG_INFO, "[Supplicant] Processing 4-Way Message 1\n"));

        //
        // Store ANonce from authenticator
        //
        CopyMem (Private->ANonce, KeyFrame->KeyNonce, WPA_NONCE_LEN);

        //
        // Store replay counter
        //
        CopyMem (Private->ReplayCounter, KeyFrame->ReplayCounter, WPA_REPLAY_CTR_LEN);

        //
        // Generate our SNonce
        //
        if (!WpaRandomBytes (Private->SNonce, WPA_NONCE_LEN)) {
          return EFI_DEVICE_ERROR;
        }

        //
        // Derive PMK from password if not already set
        //
        if (!Private->PmkValid && Private->PasswordLen > 0) {
          if (!WpaDerivePmk (
                 Private->Password,
                 Private->TargetSsid.SSId,
                 Private->TargetSsid.SSIdLen,
                 Private->Pmk))
          {
            DEBUG ((DEBUG_ERROR, "[Supplicant] PMK derivation failed\n"));
            return EFI_DEVICE_ERROR;
          }

          Private->PmkValid = TRUE;
          DEBUG ((DEBUG_INFO, "[Supplicant] PMK derived from passphrase\n"));
        }

        //
        // Derive PTK
        //
        if (!WpaDerivePtk (Private)) {
          DEBUG ((DEBUG_ERROR, "[Supplicant] PTK derivation failed\n"));
          return EFI_DEVICE_ERROR;
        }

        Private->PtkValid     = TRUE;
        Private->FourWayState = Wpa4WayMsg1Received;

        //
        // Build Message 2
        //
        return BuildMessage2 (Private, KeyFrame, Buffer, BufferSize);

      case 3:
        //
        // 4-Way Handshake Message 3: Verify MIC, decrypt key data, extract GTK
        //
        DEBUG ((DEBUG_INFO, "[Supplicant] Processing 4-Way Message 3\n"));

        if (!Private->PtkValid) {
          DEBUG ((DEBUG_ERROR, "[Supplicant] PTK not valid for Message 3\n"));
          return EFI_NOT_READY;
        }

        //
        // Verify MIC
        //
        if (!VerifyEapolMic (Private, RequestBuffer, RequestSize, MicOffset)) {
          DEBUG ((DEBUG_ERROR, "[Supplicant] Message 3 MIC verification failed\n"));
          return EFI_SECURITY_VIOLATION;
        }

        //
        // Verify replay counter is not decreasing
        //
        CopyMem (Private->ReplayCounter, KeyFrame->ReplayCounter, WPA_REPLAY_CTR_LEN);

        //
        // Verify ANonce matches
        //
        if (CompareMem (Private->ANonce, KeyFrame->KeyNonce, WPA_NONCE_LEN) != 0) {
          DEBUG ((DEBUG_ERROR, "[Supplicant] Message 3 ANonce mismatch\n"));
          return EFI_SECURITY_VIOLATION;
        }

        //
        // Decrypt key data using AES Key Unwrap with KEK
        //
        if (KeyDataLen > 0) {
          DecryptedLen     = KeyDataLen - 8;
          DecryptedKeyData = AllocatePool (DecryptedLen);
          if (DecryptedKeyData == NULL) {
            return EFI_OUT_OF_RESOURCES;
          }

          if (!WpaAesKeyUnwrap (Private->Ptk.Kek, KeyData, KeyDataLen, DecryptedKeyData)) {
            DEBUG ((DEBUG_ERROR, "[Supplicant] Key data decryption failed\n"));
            FreePool (DecryptedKeyData);
            return EFI_SECURITY_VIOLATION;
          }

          //
          // Parse key data to extract GTK and IGTK
          //
          ParseKeyData (Private, DecryptedKeyData, DecryptedLen);
          ZeroMem (DecryptedKeyData, DecryptedLen);
          FreePool (DecryptedKeyData);
        }

        Private->FourWayState = Wpa4WayMsg3Received;

        //
        // Build Message 4
        //
        {
          EFI_STATUS  Status;

          Status = BuildMessage4 (Private, KeyFrame, Buffer, BufferSize);
          if (!EFI_ERROR (Status)) {
            //
            // Handshake complete! Update state.
            //
            Private->FourWayState = Wpa4WayComplete;
            Private->LinkState    = Ieee80211AuthenticatedAssociated;
            Private->PaeState     = Authenticated;
            DEBUG ((DEBUG_INFO, "[Supplicant] 4-Way Handshake complete!\n"));
          }

          return Status;
        }

      default:
        DEBUG ((DEBUG_WARN, "[Supplicant] Unexpected pairwise message type: %d\n", MsgType));
        return EFI_NOT_READY;
    }
  } else {
    //
    // Group Key Handshake
    //
    if (MsgType == 1) {
      DEBUG ((DEBUG_INFO, "[Supplicant] Processing Group Key Message 1\n"));

      if (!Private->PtkValid) {
        return EFI_NOT_READY;
      }

      //
      // Verify MIC
      //
      if (!VerifyEapolMic (Private, RequestBuffer, RequestSize, MicOffset)) {
        DEBUG ((DEBUG_ERROR, "[Supplicant] Group Key Message 1 MIC failed\n"));
        return EFI_SECURITY_VIOLATION;
      }

      CopyMem (Private->ReplayCounter, KeyFrame->ReplayCounter, WPA_REPLAY_CTR_LEN);

      //
      // Decrypt key data
      //
      if (KeyDataLen > 0) {
        DecryptedLen     = KeyDataLen - 8;
        DecryptedKeyData = AllocatePool (DecryptedLen);
        if (DecryptedKeyData == NULL) {
          return EFI_OUT_OF_RESOURCES;
        }

        if (!WpaAesKeyUnwrap (Private->Ptk.Kek, KeyData, KeyDataLen, DecryptedKeyData)) {
          FreePool (DecryptedKeyData);
          return EFI_SECURITY_VIOLATION;
        }

        ParseKeyData (Private, DecryptedKeyData, DecryptedLen);
        ZeroMem (DecryptedKeyData, DecryptedLen);
        FreePool (DecryptedKeyData);
      }

      return BuildGroupKeyMessage2 (Private, KeyFrame, Buffer, BufferSize);
    }

    return EFI_NOT_READY;
  }
}

/**
  Reset the EAPOL handshake state.

  @param[in]  Private   Supplicant private data.
**/
VOID
WpaEapolReset (
  IN SUPPLICANT_PRIVATE_DATA  *Private
  )
{
  if (Private == NULL) {
    return;
  }

  Private->FourWayState = Wpa4WayIdle;
  Private->PtkValid     = FALSE;
  Private->GtkCount     = 0;
  Private->IgtkCount    = 0;
  Private->GtkRefreshed = FALSE;
  Private->LinkState    = Ieee80211UnauthenticatedUnassociated;
  Private->PaeState     = Disconnected;

  ZeroMem (Private->ANonce, sizeof (Private->ANonce));
  ZeroMem (Private->SNonce, sizeof (Private->SNonce));
  ZeroMem (&Private->Ptk, sizeof (Private->Ptk));
  ZeroMem (Private->Gtk, sizeof (Private->Gtk));
  ZeroMem (Private->Igtk, sizeof (Private->Igtk));
  ZeroMem (Private->TxPn, sizeof (Private->TxPn));
}
