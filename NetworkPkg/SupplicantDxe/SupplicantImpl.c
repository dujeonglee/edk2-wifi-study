/** @file
  EFI Supplicant Protocol Implementation.

  Implements the four protocol functions defined in Supplicant.h:
  - BuildResponsePacket: Process EAPOL/SAE frames and generate responses
  - ProcessPacket: CCMP encrypt/decrypt data frames
  - SetData: Configure PSK, SSID, AKM/cipher suites, keys
  - GetData: Retrieve keys, state, and supported suites

  Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SupplicantDxe.h"

//
// Supported AKM suites (reported via GetData)
//
STATIC EFI_80211_AKM_SUITE_SELECTOR  mSupportedAkmSuites = {
  3,                          // Count: PSK, PSK-SHA256, SAE
  {
    { { WPA_RSN_OUI_BYTE0, WPA_RSN_OUI_BYTE1, WPA_RSN_OUI_BYTE2 }, WPA_AKM_SUITE_PSK },
    { { WPA_RSN_OUI_BYTE0, WPA_RSN_OUI_BYTE1, WPA_RSN_OUI_BYTE2 }, WPA_AKM_SUITE_PSK_SHA256 },
    { { WPA_RSN_OUI_BYTE0, WPA_RSN_OUI_BYTE1, WPA_RSN_OUI_BYTE2 }, WPA_AKM_SUITE_SAE }
  }
};

//
// Supported cipher suites (reported via GetData).
// Includes CCMP, BIP (mandatory), plus TKIP, WEP-40, WEP-104 (legacy).
// WARNING: TKIP and WEP are broken; listed only for legacy interoperability.
//
STATIC EFI_80211_CIPHER_SUITE_SELECTOR  mSupportedCipherSuites = {
  5,                          // Count: CCMP, BIP, TKIP, WEP-40, WEP-104
  {
    { { WPA_RSN_OUI_BYTE0, WPA_RSN_OUI_BYTE1, WPA_RSN_OUI_BYTE2 }, WPA_CIPHER_SUITE_CCMP   },
    { { WPA_RSN_OUI_BYTE0, WPA_RSN_OUI_BYTE1, WPA_RSN_OUI_BYTE2 }, WPA_CIPHER_SUITE_BIP    },
    { { WPA_RSN_OUI_BYTE0, WPA_RSN_OUI_BYTE1, WPA_RSN_OUI_BYTE2 }, WPA_CIPHER_SUITE_TKIP   },
    { { WPA_RSN_OUI_BYTE0, WPA_RSN_OUI_BYTE1, WPA_RSN_OUI_BYTE2 }, WPA_CIPHER_SUITE_WEP40  },
    { { WPA_RSN_OUI_BYTE0, WPA_RSN_OUI_BYTE1, WPA_RSN_OUI_BYTE2 }, WPA_CIPHER_SUITE_WEP104 }
  }
};

/**
  Build a response packet for an incoming EAPOL or SAE authentication frame.

  When RequestBuffer is NULL, the supplicant may initiate a session (e.g.,
  generate an SAE Commit for WPA3). When RequestBuffer contains an EAPOL-Key
  frame, the 4-Way Handshake or Group Key Handshake is processed.

  @param[in]     This               Protocol instance.
  @param[in]     RequestBuffer      Received EAPOL packet, or NULL to initiate.
  @param[in]     RequestBufferSize  Size of RequestBuffer.
  @param[out]    Buffer             Output buffer for response.
  @param[in,out] BufferSize         On input, buffer capacity. On output, used/required size.

  @retval EFI_SUCCESS            Response built.
  @retval EFI_BUFFER_TOO_SMALL   Buffer too small; required size in BufferSize.
  @retval EFI_INVALID_PARAMETER  Bad input.
  @retval EFI_NOT_READY          Not configured or wrong state.
  @retval EFI_SECURITY_VIOLATION Authentication failure.
**/
EFI_STATUS
EFIAPI
SupplicantBuildResponsePacket (
  IN     EFI_SUPPLICANT_PROTOCOL  *This,
  IN     UINT8                    *RequestBuffer      OPTIONAL,
  IN     UINTN                    RequestBufferSize   OPTIONAL,
  OUT    UINT8                    *Buffer,
  IN OUT UINTN                    *BufferSize
  )
{
  SUPPLICANT_PRIVATE_DATA  *Private;

  if ((This == NULL) || (BufferSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Private = SUPPLICANT_PRIVATE_FROM_PROTOCOL (This);

  if (RequestBuffer == NULL) {
    //
    // Initiation request. For WPA3-SAE, build a Commit message.
    // For WPA2-PSK, no initiation is needed (we wait for Message 1).
    //
    if (Private->AkmSuiteType == WPA_AKM_SUITE_SAE) {
      EFI_STATUS  Status;
      UINTN       CommitSize;
      UINTN       AuthFrameSize;
      SAE_AUTH_FRAME  *AuthFrame;

      //
      // Initialize SAE session if not already done
      //
      if (Private->SaeSession.State == SaeStateIdle) {
        if (!SaeInit (Private, &Private->SaeSession)) {
          return EFI_DEVICE_ERROR;
        }
      }

      //
      // Build SAE Commit
      //
      CommitSize = 0;
      Status = SaeBuildCommit (Private, &Private->SaeSession, NULL, &CommitSize);
      if (Status != EFI_BUFFER_TOO_SMALL) {
        return Status;
      }

      //
      // Total frame: SAE Auth header + Commit body
      //
      AuthFrameSize = sizeof (SAE_AUTH_FRAME) + CommitSize;
      if (*BufferSize < AuthFrameSize) {
        *BufferSize = AuthFrameSize;
        return EFI_BUFFER_TOO_SMALL;
      }

      //
      // Build SAE Authentication frame header
      //
      AuthFrame = (SAE_AUTH_FRAME *)Buffer;
      WPA_PUT_LE16 (&AuthFrame->AuthAlgorithm, SAE_AUTH_ALGORITHM);
      WPA_PUT_LE16 (&AuthFrame->TransactionSeq, SAE_COMMIT_SEQ);
      WPA_PUT_LE16 (&AuthFrame->StatusCode, SAE_STATUS_SUCCESS);

      //
      // Build Commit body after the header
      //
      Status = SaeBuildCommit (
                 Private,
                 &Private->SaeSession,
                 Buffer + sizeof (SAE_AUTH_FRAME),
                 &CommitSize
                 );
      if (EFI_ERROR (Status)) {
        return Status;
      }

      *BufferSize = sizeof (SAE_AUTH_FRAME) + CommitSize;
      return EFI_SUCCESS;
    }

    //
    // For WPA2-PSK, no initiation needed
    //
    *BufferSize = 0;
    return EFI_SUCCESS;
  }

  //
  // Process incoming packet
  //
  if (RequestBufferSize < sizeof (EAPOL_HEADER)) {
    //
    // Check if this might be an SAE Authentication frame
    //
    if (RequestBufferSize >= sizeof (SAE_AUTH_FRAME) &&
        Private->AkmSuiteType == WPA_AKM_SUITE_SAE)
    {
      SAE_AUTH_FRAME  *AuthFrame;
      UINT16          TransSeq;
      EFI_STATUS      Status;
      CONST UINT8     *FrameBody;
      UINTN           BodyLen;

      AuthFrame = (SAE_AUTH_FRAME *)RequestBuffer;
      TransSeq  = WPA_GET_LE16 (&AuthFrame->TransactionSeq);
      FrameBody = RequestBuffer + sizeof (SAE_AUTH_FRAME);
      BodyLen   = RequestBufferSize - sizeof (SAE_AUTH_FRAME);

      if (TransSeq == SAE_COMMIT_SEQ) {
        //
        // Process peer's SAE Commit and build Confirm
        //
        Status = SaeProcessCommit (Private, &Private->SaeSession, FrameBody, BodyLen);
        if (EFI_ERROR (Status)) {
          return Status;
        }

        //
        // Build SAE Confirm response
        //
        {
          UINTN  ConfirmSize = 0;
          UINTN  AuthRespSize;

          Status = SaeBuildConfirm (Private, &Private->SaeSession, NULL, &ConfirmSize);
          if (Status != EFI_BUFFER_TOO_SMALL) {
            return Status;
          }

          AuthRespSize = sizeof (SAE_AUTH_FRAME) + ConfirmSize;
          if (*BufferSize < AuthRespSize) {
            *BufferSize = AuthRespSize;
            return EFI_BUFFER_TOO_SMALL;
          }

          SAE_AUTH_FRAME  *RespAuth = (SAE_AUTH_FRAME *)Buffer;
          WPA_PUT_LE16 (&RespAuth->AuthAlgorithm, SAE_AUTH_ALGORITHM);
          WPA_PUT_LE16 (&RespAuth->TransactionSeq, SAE_CONFIRM_SEQ);
          WPA_PUT_LE16 (&RespAuth->StatusCode, SAE_STATUS_SUCCESS);

          Status = SaeBuildConfirm (
                     Private,
                     &Private->SaeSession,
                     Buffer + sizeof (SAE_AUTH_FRAME),
                     &ConfirmSize
                     );
          if (EFI_ERROR (Status)) {
            return Status;
          }

          *BufferSize = sizeof (SAE_AUTH_FRAME) + ConfirmSize;
          return EFI_SUCCESS;
        }
      } else if (TransSeq == SAE_CONFIRM_SEQ) {
        //
        // Process peer's SAE Confirm
        //
        Status = SaeProcessConfirm (Private, &Private->SaeSession, FrameBody, BodyLen);
        if (EFI_ERROR (Status)) {
          return Status;
        }

        //
        // SAE complete, PMK installed. No response needed for confirm.
        //
        *BufferSize = 0;
        return EFI_SUCCESS;
      }
    }

    return EFI_INVALID_PARAMETER;
  }

  //
  // Process EAPOL-Key frame (4-Way or Group Key Handshake)
  //
  {
    CONST EAPOL_HEADER  *EapolHdr;

    EapolHdr = (CONST EAPOL_HEADER *)RequestBuffer;

    //
    // Check if this is a SAE frame disguised with EAPOL header
    //
    if (EapolHdr->PacketType == EAPOL_PACKET_TYPE_KEY) {
      return WpaEapolProcessKeyFrame (
               Private,
               RequestBuffer,
               RequestBufferSize,
               Buffer,
               BufferSize
               );
    }

    //
    // For SAE authentication frames that happen to be larger than EAPOL header size
    //
    if (Private->AkmSuiteType == WPA_AKM_SUITE_SAE &&
        RequestBufferSize >= sizeof (SAE_AUTH_FRAME))
    {
      UINT16  AuthAlg;

      AuthAlg = WPA_GET_LE16 (RequestBuffer);
      if (AuthAlg == SAE_AUTH_ALGORITHM) {
        SAE_AUTH_FRAME  *AuthFrame;
        UINT16          TransSeq;
        CONST UINT8     *FrameBody;
        UINTN           BodyLen;
        EFI_STATUS      Status;

        AuthFrame = (SAE_AUTH_FRAME *)RequestBuffer;
        TransSeq  = WPA_GET_LE16 (&AuthFrame->TransactionSeq);
        FrameBody = RequestBuffer + sizeof (SAE_AUTH_FRAME);
        BodyLen   = RequestBufferSize - sizeof (SAE_AUTH_FRAME);

        if (TransSeq == SAE_COMMIT_SEQ) {
          Status = SaeProcessCommit (Private, &Private->SaeSession, FrameBody, BodyLen);
          if (EFI_ERROR (Status)) {
            return Status;
          }

          //
          // Build Confirm
          //
          UINTN  ConfirmSize = 0;
          Status = SaeBuildConfirm (Private, &Private->SaeSession, NULL, &ConfirmSize);
          if (Status != EFI_BUFFER_TOO_SMALL) {
            return Status;
          }

          UINTN  AuthRespSize = sizeof (SAE_AUTH_FRAME) + ConfirmSize;
          if (*BufferSize < AuthRespSize) {
            *BufferSize = AuthRespSize;
            return EFI_BUFFER_TOO_SMALL;
          }

          SAE_AUTH_FRAME  *Resp = (SAE_AUTH_FRAME *)Buffer;
          WPA_PUT_LE16 (&Resp->AuthAlgorithm, SAE_AUTH_ALGORITHM);
          WPA_PUT_LE16 (&Resp->TransactionSeq, SAE_CONFIRM_SEQ);
          WPA_PUT_LE16 (&Resp->StatusCode, SAE_STATUS_SUCCESS);

          Status = SaeBuildConfirm (
                     Private, &Private->SaeSession,
                     Buffer + sizeof (SAE_AUTH_FRAME), &ConfirmSize
                     );
          if (EFI_ERROR (Status)) {
            return Status;
          }

          *BufferSize = sizeof (SAE_AUTH_FRAME) + ConfirmSize;
          return EFI_SUCCESS;
        } else if (TransSeq == SAE_CONFIRM_SEQ) {
          Status = SaeProcessConfirm (Private, &Private->SaeSession, FrameBody, BodyLen);
          *BufferSize = 0;
          return Status;
        }
      }
    }

    return EFI_UNSUPPORTED;
  }
}

/**
  Process (encrypt/decrypt) a network packet using CCMP.

  @param[in]     This            Protocol instance.
  @param[in,out] FragmentTable   Array of fragment data.
  @param[in]     FragmentCount   Number of fragments.
  @param[in]     CryptMode       EfiSupplicantEncrypt or EfiSupplicantDecrypt.

  @retval EFI_SUCCESS            Packet processed.
  @retval EFI_NOT_READY          Keys not installed.
  @retval EFI_INVALID_PARAMETER  Bad parameters.
**/
EFI_STATUS
EFIAPI
SupplicantProcessPacket (
  IN     EFI_SUPPLICANT_PROTOCOL       *This,
  IN OUT EFI_SUPPLICANT_FRAGMENT_DATA  **FragmentTable,
  IN     UINT32                        *FragmentCount,
  IN     EFI_SUPPLICANT_CRYPT_MODE     CryptMode
  )
{
  SUPPLICANT_PRIVATE_DATA      *Private;
  EFI_SUPPLICANT_FRAGMENT_DATA *Frags;
  UINT32                       Count;
  UINT8                        *Data;
  UINTN                        DataLen;
  UINT8                        *Result;
  UINTN                        ResultLen;
  UINTN                        HeaderLen;
  UINT8                        CcmpHdr[CCMP_HEADER_LEN];
  UINTN                        I;

  if ((This == NULL) || (FragmentTable == NULL) || (*FragmentTable == NULL) ||
      (FragmentCount == NULL) || (*FragmentCount == 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  Private = SUPPLICANT_PRIVATE_FROM_PROTOCOL (This);

  if (!Private->PtkValid) {
    return EFI_NOT_READY;
  }

  Frags = *FragmentTable;
  Count = *FragmentCount;

  //
  // Reassemble fragments into a single buffer
  //
  DataLen = 0;
  for (I = 0; I < Count; I++) {
    DataLen += Frags[I].FragmentLength;
  }

  if (DataLen == 0) {
    return EFI_INVALID_PARAMETER;
  }

  Data = AllocatePool (DataLen);
  if (Data == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  {
    UINTN  Offset = 0;

    for (I = 0; I < Count; I++) {
      CopyMem (Data + Offset, Frags[I].FragmentBuffer, Frags[I].FragmentLength);
      Offset += Frags[I].FragmentLength;
    }
  }

  //
  // Minimum: 802.11 header (24 bytes) + some payload
  //
  HeaderLen = 24;
  if (DataLen < HeaderLen + 1) {
    FreePool (Data);
    return EFI_INVALID_PARAMETER;
  }

  //
  // Check for QoS header (4 additional bytes if subtype indicates QoS data)
  //
  if ((Data[0] & 0x80) != 0) {
    HeaderLen += 2;
  }

  //
  // Check for A4 (ToDS && FromDS)
  //
  if ((Data[1] & 0x03) == 0x03) {
    HeaderLen += 6;
  }

  if (CryptMode == EfiSupplicantEncrypt) {
    //
    // Encrypt: plaintext -> CCMP header + ciphertext + MIC
    //
    UINTN  PlainLen = DataLen - HeaderLen;

    ResultLen = HeaderLen + CCMP_HEADER_LEN + PlainLen + CCMP_MIC_LEN;
    Result    = AllocatePool (ResultLen);
    if (Result == NULL) {
      FreePool (Data);
      return EFI_OUT_OF_RESOURCES;
    }

    //
    // Increment TX packet number
    //
    for (I = CCMP_PN_LEN; I > 0; I--) {
      Private->TxPn[I - 1]++;
      if (Private->TxPn[I - 1] != 0) {
        break;
      }
    }

    //
    // Copy header, add CCMP header, then encrypted payload + MIC
    //
    CopyMem (Result, Data, HeaderLen);

    if (!WpaCcmpEncrypt (
           PTK_TK (Private),
           Private->TxPn,
           Data + 10,  // Source address (A2) at offset 10 in 802.11 header
           0,          // Priority
           Data,
           HeaderLen,
           Data + HeaderLen,
           PlainLen,
           Result + HeaderLen + CCMP_HEADER_LEN,
           CcmpHdr
           ))
    {
      FreePool (Result);
      FreePool (Data);
      return EFI_DEVICE_ERROR;
    }

    //
    // Insert CCMP header
    //
    CopyMem (Result + HeaderLen, CcmpHdr, CCMP_HEADER_LEN);

    //
    // Set Protected Frame bit in Frame Control
    //
    Result[1] |= 0x40;
  } else {
    //
    // Decrypt: header + CCMP header + ciphertext + MIC -> header + plaintext
    //
    UINT8  Pn[CCMP_PN_LEN];
    UINTN  CipherLen;

    if (DataLen < HeaderLen + CCMP_HEADER_LEN + CCMP_MIC_LEN) {
      FreePool (Data);
      return EFI_INVALID_PARAMETER;
    }

    //
    // Extract PN from CCMP header
    //
    Pn[0] = Data[HeaderLen + 7];  // PN5
    Pn[1] = Data[HeaderLen + 6];  // PN4
    Pn[2] = Data[HeaderLen + 5];  // PN3
    Pn[3] = Data[HeaderLen + 4];  // PN2
    Pn[4] = Data[HeaderLen + 1];  // PN1
    Pn[5] = Data[HeaderLen];      // PN0

    CipherLen = DataLen - HeaderLen - CCMP_HEADER_LEN;
    ResultLen = HeaderLen + CipherLen - CCMP_MIC_LEN;
    Result    = AllocatePool (ResultLen);
    if (Result == NULL) {
      FreePool (Data);
      return EFI_OUT_OF_RESOURCES;
    }

    //
    // Copy header
    //
    CopyMem (Result, Data, HeaderLen);

    //
    // Clear Protected Frame bit
    //
    Result[1] &= ~0x40;

    if (!WpaCcmpDecrypt (
           PTK_TK (Private),
           Pn,
           Data + 10,  // Source address (A2)
           0,
           Data,
           HeaderLen,
           Data + HeaderLen + CCMP_HEADER_LEN,
           CipherLen,
           Result + HeaderLen
           ))
    {
      FreePool (Result);
      FreePool (Data);
      return EFI_SECURITY_VIOLATION;
    }
  }

  //
  // Update the first fragment with the result
  //
  FreePool (Data);

  //
  // Free old fragment buffers
  //
  for (I = 0; I < Count; I++) {
    if (Frags[I].FragmentBuffer != NULL) {
      FreePool (Frags[I].FragmentBuffer);
    }
  }

  //
  // Return result as a single fragment
  //
  Frags[0].FragmentBuffer = Result;
  Frags[0].FragmentLength = (UINT32)ResultLen;
  *FragmentCount = 1;

  return EFI_SUCCESS;
}

/**
  Set configuration data for the supplicant.

  @param[in]  This      Protocol instance.
  @param[in]  DataType  Type of data to set.
  @param[in]  Data      Pointer to the data.
  @param[in]  DataSize  Size of the data.

  @retval EFI_SUCCESS            Data set.
  @retval EFI_INVALID_PARAMETER  Invalid parameters.
  @retval EFI_UNSUPPORTED        DataType not supported.
**/
EFI_STATUS
EFIAPI
SupplicantSetData (
  IN EFI_SUPPLICANT_PROTOCOL   *This,
  IN EFI_SUPPLICANT_DATA_TYPE  DataType,
  IN VOID                      *Data,
  IN UINTN                     DataSize
  )
{
  SUPPLICANT_PRIVATE_DATA     *Private;
  EFI_80211_SUITE_SELECTOR    *SuiteSelector;
  EFI_SUPPLICANT_KEY          *SupKey;

  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Private = SUPPLICANT_PRIVATE_FROM_PROTOCOL (This);

  switch (DataType) {
    case EfiSupplicant80211AKMSuite:
      //
      // Set AKM suite (4-byte selector: OUI + Type)
      //
      if ((Data == NULL) || (DataSize < sizeof (EFI_80211_SUITE_SELECTOR))) {
        return EFI_INVALID_PARAMETER;
      }

      SuiteSelector = (EFI_80211_SUITE_SELECTOR *)Data;
      CopyMem (Private->AkmSuiteOui, SuiteSelector->Oui, 3);
      Private->AkmSuiteType = SuiteSelector->SuiteType;

      //
      // Update key descriptor version based on AKM and current pairwise cipher.
      //
      UpdateKeyDescVersion (Private);

      DEBUG ((DEBUG_INFO, "[Supplicant] AKM suite set: type=%d\n", Private->AkmSuiteType));

      //
      // Reset handshake state when AKM changes
      //
      WpaEapolReset (Private);
      if (Private->AkmSuiteType == WPA_AKM_SUITE_SAE) {
        SaeCleanup (&Private->SaeSession);
      }

      return EFI_SUCCESS;

    case EfiSupplicant80211PairwiseCipherSuite:
      if ((Data == NULL) || (DataSize < sizeof (EFI_80211_SUITE_SELECTOR))) {
        return EFI_INVALID_PARAMETER;
      }

      SuiteSelector = (EFI_80211_SUITE_SELECTOR *)Data;
      CopyMem (Private->PairwiseCipherOui, SuiteSelector->Oui, 3);
      Private->PairwiseCipherType = SuiteSelector->SuiteType;

      //
      // TKIP and WEP are broken; emit a warning when selected.
      //
      if ((Private->PairwiseCipherType == WPA_CIPHER_SUITE_TKIP) ||
          (Private->PairwiseCipherType == WPA_CIPHER_SUITE_WEP40) ||
          (Private->PairwiseCipherType == WPA_CIPHER_SUITE_WEP104))
      {
        DEBUG ((DEBUG_WARN,
          "[Supplicant] Insecure pairwise cipher selected (type=%d). "
          "Use CCMP for new deployments.\n",
          Private->PairwiseCipherType));
      }

      UpdateKeyDescVersion (Private);

      DEBUG ((DEBUG_INFO, "[Supplicant] Pairwise cipher set: type=%d\n",
        Private->PairwiseCipherType));
      return EFI_SUCCESS;

    case EfiSupplicant80211GroupDataCipherSuite:
      if ((Data == NULL) || (DataSize < sizeof (EFI_80211_SUITE_SELECTOR))) {
        return EFI_INVALID_PARAMETER;
      }

      SuiteSelector = (EFI_80211_SUITE_SELECTOR *)Data;
      CopyMem (Private->GroupCipherOui, SuiteSelector->Oui, 3);
      Private->GroupCipherType = SuiteSelector->SuiteType;

      DEBUG ((DEBUG_INFO, "[Supplicant] Group cipher set: type=%d\n",
        Private->GroupCipherType));
      return EFI_SUCCESS;

    case EfiSupplicant80211PskPassword:
      //
      // Set PSK passphrase (ASCII, 8-63 chars)
      //
      if (Data == NULL) {
        //
        // Clear password
        //
        ZeroMem (Private->Password, sizeof (Private->Password));
        Private->PasswordLen = 0;
        Private->PmkValid    = FALSE;
        return EFI_SUCCESS;
      }

      if ((DataSize < 8) || (DataSize > WPA_MAX_PASSWORD_LEN)) {
        return EFI_INVALID_PARAMETER;
      }

      ZeroMem (Private->Password, sizeof (Private->Password));
      CopyMem (Private->Password, Data, DataSize);
      Private->Password[DataSize] = '\0';
      Private->PasswordLen        = DataSize;
      Private->PmkValid           = FALSE;  // PMK will be derived when needed

      DEBUG ((DEBUG_INFO, "[Supplicant] PSK password set (len=%d)\n", DataSize));
      return EFI_SUCCESS;

    case EfiSupplicant80211TargetSSIDName:
      //
      // Set target SSID
      //
      if ((Data == NULL) || (DataSize == 0) || (DataSize > 32)) {
        return EFI_INVALID_PARAMETER;
      }

      ZeroMem (&Private->TargetSsid, sizeof (Private->TargetSsid));
      CopyMem (Private->TargetSsid.SSId, Data, DataSize);
      Private->TargetSsid.SSIdLen = (UINT8)DataSize;
      Private->PmkValid = FALSE;  // PMK depends on SSID

      DEBUG ((DEBUG_INFO, "[Supplicant] Target SSID set (len=%d)\n", DataSize));
      return EFI_SUCCESS;

    case EfiSupplicant80211StationMac:
      //
      // Set station MAC address (SPA)
      //
      if ((Data == NULL) || (DataSize < WPA_MAC_ADDR_LEN)) {
        return EFI_INVALID_PARAMETER;
      }

      CopyMem (Private->StationMac.Addr, Data, WPA_MAC_ADDR_LEN);
      DEBUG ((DEBUG_INFO, "[Supplicant] Station MAC set\n"));
      return EFI_SUCCESS;

    case EfiSupplicant80211TargetSSIDMac:
      //
      // Set target AP BSSID (AA)
      //
      if ((Data == NULL) || (DataSize < WPA_MAC_ADDR_LEN)) {
        return EFI_INVALID_PARAMETER;
      }

      CopyMem (Private->TargetBssid.Addr, Data, WPA_MAC_ADDR_LEN);
      DEBUG ((DEBUG_INFO, "[Supplicant] Target BSSID set\n"));
      return EFI_SUCCESS;

    case EfiSupplicant80211PMK:
      //
      // Directly set the PMK (e.g., from external SAE or pre-computed)
      //
      if ((Data == NULL) || (DataSize < WPA_PMK_LEN)) {
        return EFI_INVALID_PARAMETER;
      }

      CopyMem (Private->Pmk, Data, WPA_PMK_LEN);
      Private->PmkValid = TRUE;
      DEBUG ((DEBUG_INFO, "[Supplicant] PMK set directly\n"));
      return EFI_SUCCESS;

    case EfiSupplicant80211PTK:
      //
      // Directly install PTK keys
      //
      if ((Data == NULL) || (DataSize < sizeof (EFI_SUPPLICANT_KEY))) {
        return EFI_INVALID_PARAMETER;
      }

      SupKey = (EFI_SUPPLICANT_KEY *)Data;
      if ((SupKey->KeyLen > 0) && (SupKey->KeyLen <= WPA_PTK_TKIP_LEN)) {
        ZeroMem (Private->PtkRaw, sizeof (Private->PtkRaw));
        CopyMem (Private->PtkRaw, SupKey->Key, SupKey->KeyLen);
        Private->PtkValid = TRUE;
      }

      return EFI_SUCCESS;

    case EfiSupplicant80211GTK:
      //
      // Install GTK
      //
      if ((Data == NULL) || (DataSize < sizeof (EFI_SUPPLICANT_KEY))) {
        return EFI_INVALID_PARAMETER;
      }

      SupKey = (EFI_SUPPLICANT_KEY *)Data;
      {
        UINT8  KeyId = 0;  // Default key ID

        if (KeyId < 4 && SupKey->KeyLen <= WPA_GTK_MAX_LEN) {
          CopyMem (Private->Gtk[KeyId].Key, SupKey->Key, SupKey->KeyLen);
          Private->Gtk[KeyId].KeyLen = (UINT8)SupKey->KeyLen;
          Private->Gtk[KeyId].KeyId  = KeyId;
          if (Private->GtkCount <= KeyId) {
            Private->GtkCount = KeyId + 1;
          }
        }
      }

      return EFI_SUCCESS;

    case EfiSupplicant80211IGTK:
      //
      // Install IGTK
      //
      if ((Data == NULL) || (DataSize < sizeof (EFI_SUPPLICANT_KEY))) {
        return EFI_INVALID_PARAMETER;
      }

      SupKey = (EFI_SUPPLICANT_KEY *)Data;
      {
        UINT8  KeyId = 0;

        if (KeyId < 2 && SupKey->KeyLen <= WPA_GTK_MAX_LEN) {
          CopyMem (Private->Igtk[KeyId].Key, SupKey->Key, SupKey->KeyLen);
          Private->Igtk[KeyId].KeyLen = (UINT8)SupKey->KeyLen;
          Private->Igtk[KeyId].KeyId  = KeyId;
          if (Private->IgtkCount <= KeyId) {
            Private->IgtkCount = KeyId + 1;
          }
        }
      }

      return EFI_SUCCESS;

    case EfiSupplicant80211WepKey:
    {
      //
      // Install a WEP key.
      // Caller provides an EFI_SUPPLICANT_KEY with:
      //   KeyLen  = 5 (WEP-40) or 13 (WEP-104)
      //   KeyIndex = key slot (0-3)
      //   Key[]   = key material
      //
      UINT8  WepKeyId;

      if ((Data == NULL) || (DataSize < sizeof (EFI_SUPPLICANT_KEY))) {
        return EFI_INVALID_PARAMETER;
      }

      SupKey   = (EFI_SUPPLICANT_KEY *)Data;
      WepKeyId = SupKey->KeyId & 0x03;

      if ((SupKey->KeyLen != WEP40_KEY_LEN) && (SupKey->KeyLen != WEP104_KEY_LEN)) {
        return EFI_INVALID_PARAMETER;
      }

      Private->WepKeys[WepKeyId].KeyLen = (UINT8)SupKey->KeyLen;
      CopyMem (Private->WepKeys[WepKeyId].Key, SupKey->Key, SupKey->KeyLen);
      Private->WepDefaultKeyId = WepKeyId;
      Private->WepKeysValid    = TRUE;

      DEBUG ((DEBUG_WARN,
        "[Supplicant] WEP key installed (slot=%d, len=%d). "
        "WEP is insecure; use CCMP.\n",
        WepKeyId, SupKey->KeyLen));
      return EFI_SUCCESS;
    }

    default:
      return EFI_UNSUPPORTED;
  }
}

/**
  Get configuration data from the supplicant.

  @param[in]     This      Protocol instance.
  @param[in]     DataType  Type of data to get.
  @param[out]    Data      Output data buffer (may be NULL for size query).
  @param[in,out] DataSize  On input, buffer size. On output, required size.

  @retval EFI_SUCCESS            Data retrieved.
  @retval EFI_BUFFER_TOO_SMALL   Buffer too small; required size in DataSize.
  @retval EFI_INVALID_PARAMETER  Invalid parameters.
  @retval EFI_UNSUPPORTED        DataType not supported.
**/
EFI_STATUS
EFIAPI
SupplicantGetData (
  IN     EFI_SUPPLICANT_PROTOCOL   *This,
  IN     EFI_SUPPLICANT_DATA_TYPE  DataType,
  OUT    UINT8                     *Data      OPTIONAL,
  IN OUT UINTN                     *DataSize
  )
{
  SUPPLICANT_PRIVATE_DATA  *Private;
  UINTN                    RequiredSize;

  if ((This == NULL) || (DataSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Private = SUPPLICANT_PRIVATE_FROM_PROTOCOL (This);

  switch (DataType) {
    case EfiSupplicant80211SupportedAKMSuites:
      RequiredSize = sizeof (UINT16) +
                     mSupportedAkmSuites.AKMSuiteCount * sizeof (EFI_80211_SUITE_SELECTOR);
      if ((Data == NULL) || (*DataSize < RequiredSize)) {
        *DataSize = RequiredSize;
        return EFI_BUFFER_TOO_SMALL;
      }

      CopyMem (Data, &mSupportedAkmSuites, RequiredSize);
      *DataSize = RequiredSize;
      return EFI_SUCCESS;

    case EfiSupplicant80211SupportedSoftwareCipherSuites:
    case EfiSupplicant80211SupportedHardwareCipherSuites:
      RequiredSize = sizeof (UINT16) +
                     mSupportedCipherSuites.CipherSuiteCount * sizeof (EFI_80211_SUITE_SELECTOR);
      if ((Data == NULL) || (*DataSize < RequiredSize)) {
        *DataSize = RequiredSize;
        return EFI_BUFFER_TOO_SMALL;
      }

      CopyMem (Data, &mSupportedCipherSuites, RequiredSize);
      *DataSize = RequiredSize;
      return EFI_SUCCESS;

    case EfiSupplicant80211PMK:
      if (!Private->PmkValid) {
        return EFI_NOT_READY;
      }

      RequiredSize = WPA_PMK_LEN;
      if ((Data == NULL) || (*DataSize < RequiredSize)) {
        *DataSize = RequiredSize;
        return EFI_BUFFER_TOO_SMALL;
      }

      CopyMem (Data, Private->Pmk, WPA_PMK_LEN);
      *DataSize = RequiredSize;
      return EFI_SUCCESS;

    case EfiSupplicant80211PTK:
      if (!Private->PtkValid) {
        return EFI_NOT_READY;
      }

      //
      // Return the appropriate PTK length based on cipher type:
      // TKIP uses 64 bytes (includes TX-MIC and RX-MIC), others use 48.
      //
      RequiredSize = (Private->PairwiseCipherType == WPA_CIPHER_SUITE_TKIP)
                       ? WPA_PTK_TKIP_LEN
                       : WPA_PTK_LEN;

      if ((Data == NULL) || (*DataSize < RequiredSize)) {
        *DataSize = RequiredSize;
        return EFI_BUFFER_TOO_SMALL;
      }

      CopyMem (Data, Private->PtkRaw, RequiredSize);
      *DataSize = RequiredSize;
      return EFI_SUCCESS;

    case EfiSupplicant80211GTK:
      if (Private->GtkCount == 0) {
        return EFI_NOT_READY;
      }

      //
      // Return the first GTK
      //
      RequiredSize = Private->Gtk[0].KeyLen;
      if ((Data == NULL) || (*DataSize < RequiredSize)) {
        *DataSize = RequiredSize;
        return EFI_BUFFER_TOO_SMALL;
      }

      CopyMem (Data, Private->Gtk[0].Key, RequiredSize);
      *DataSize = RequiredSize;
      return EFI_SUCCESS;

    case EfiSupplicant80211IGTK:
      if (Private->IgtkCount == 0) {
        return EFI_NOT_READY;
      }

      RequiredSize = Private->Igtk[0].KeyLen;
      if ((Data == NULL) || (*DataSize < RequiredSize)) {
        *DataSize = RequiredSize;
        return EFI_BUFFER_TOO_SMALL;
      }

      CopyMem (Data, Private->Igtk[0].Key, RequiredSize);
      *DataSize = RequiredSize;
      return EFI_SUCCESS;

    case EfiSupplicant80211PairwiseCipherSuite:
      RequiredSize = sizeof (EFI_80211_SUITE_SELECTOR);
      if ((Data == NULL) || (*DataSize < RequiredSize)) {
        *DataSize = RequiredSize;
        return EFI_BUFFER_TOO_SMALL;
      }

      {
        EFI_80211_SUITE_SELECTOR  *Suite = (EFI_80211_SUITE_SELECTOR *)Data;

        CopyMem (Suite->Oui, Private->PairwiseCipherOui, 3);
        Suite->SuiteType = Private->PairwiseCipherType;
      }

      *DataSize = RequiredSize;
      return EFI_SUCCESS;

    case EfiSupplicant80211AKMSuite:
      RequiredSize = sizeof (EFI_80211_SUITE_SELECTOR);
      if ((Data == NULL) || (*DataSize < RequiredSize)) {
        *DataSize = RequiredSize;
        return EFI_BUFFER_TOO_SMALL;
      }

      {
        EFI_80211_SUITE_SELECTOR  *Suite = (EFI_80211_SUITE_SELECTOR *)Data;

        CopyMem (Suite->Oui, Private->AkmSuiteOui, 3);
        Suite->SuiteType = Private->AkmSuiteType;
      }

      *DataSize = RequiredSize;
      return EFI_SUCCESS;

    case EfiSupplicant80211WepKey:
    {
      //
      // Return the default WEP key material.
      //
      UINT8  WepKeyId;

      if (!Private->WepKeysValid) {
        return EFI_NOT_READY;
      }

      WepKeyId     = Private->WepDefaultKeyId;
      RequiredSize = Private->WepKeys[WepKeyId].KeyLen;

      if ((Data == NULL) || (*DataSize < RequiredSize)) {
        *DataSize = RequiredSize;
        return EFI_BUFFER_TOO_SMALL;
      }

      CopyMem (Data, Private->WepKeys[WepKeyId].Key, RequiredSize);
      *DataSize = RequiredSize;
      return EFI_SUCCESS;
    }

    default:
      return EFI_UNSUPPORTED;
  }
}
