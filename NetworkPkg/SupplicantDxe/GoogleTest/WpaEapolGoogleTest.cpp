/** @file
  WPA EAPOL Handshake Logic Unit Tests.

  Tests cover:
  - EAPOL-Key message type identification
  - PTK derivation (structure and correctness)
  - RSN IE construction
  - 4-Way Handshake Message 1 processing and Message 2 generation
  - Handshake state machine transitions
  - Replay counter handling

  Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/GoogleTestLib.h>

extern "C" {
  #include <Uefi.h>
  #include <Library/BaseLib.h>
  #include <Library/BaseMemoryLib.h>
  #include <Library/MemoryAllocationLib.h>
  #include <Library/DebugLib.h>
  #include <Library/BaseCryptLib.h>
  #include "../SupplicantDxe.h"
}

// ==========================================================================
// Helper to create a properly initialized SUPPLICANT_PRIVATE_DATA
// ==========================================================================
static
VOID
InitTestPrivateData (
  SUPPLICANT_PRIVATE_DATA  *Private
  )
{
  ZeroMem (Private, sizeof (SUPPLICANT_PRIVATE_DATA));
  Private->Signature = SUPPLICANT_PRIVATE_DATA_SIGNATURE;

  Private->Supplicant.BuildResponsePacket = SupplicantBuildResponsePacket;
  Private->Supplicant.ProcessPacket       = SupplicantProcessPacket;
  Private->Supplicant.SetData             = SupplicantSetData;
  Private->Supplicant.GetData             = SupplicantGetData;

  // Default WPA2-PSK with CCMP
  Private->AkmSuiteOui[0]      = WPA_RSN_OUI_BYTE0;
  Private->AkmSuiteOui[1]      = WPA_RSN_OUI_BYTE1;
  Private->AkmSuiteOui[2]      = WPA_RSN_OUI_BYTE2;
  Private->AkmSuiteType        = WPA_AKM_SUITE_PSK;

  Private->PairwiseCipherOui[0] = WPA_RSN_OUI_BYTE0;
  Private->PairwiseCipherOui[1] = WPA_RSN_OUI_BYTE1;
  Private->PairwiseCipherOui[2] = WPA_RSN_OUI_BYTE2;
  Private->PairwiseCipherType   = WPA_CIPHER_SUITE_CCMP;

  Private->GroupCipherOui[0]   = WPA_RSN_OUI_BYTE0;
  Private->GroupCipherOui[1]   = WPA_RSN_OUI_BYTE1;
  Private->GroupCipherOui[2]   = WPA_RSN_OUI_BYTE2;
  Private->GroupCipherType     = WPA_CIPHER_SUITE_CCMP;

  Private->KeyDescVersion      = WPA_KEY_DESC_VERSION_HMAC_SHA1_AES;
  Private->FourWayState        = Wpa4WayIdle;
  Private->PaeState            = Disconnected;
  Private->LinkState           = Ieee80211UnauthenticatedUnassociated;
}

// ==========================================================================
// RSN IE Construction Tests
// ==========================================================================
class WpaRsnIeTest : public ::testing::Test {
protected:
  SUPPLICANT_PRIVATE_DATA  Private;

  void SetUp () override
  {
    InitTestPrivateData (&Private);
  }
};

TEST_F (WpaRsnIeTest, BasicWpa2PskRsnIe)
{
  UINT8  RsnIe[64];
  UINTN  RsnIeLen = 0;

  EXPECT_TRUE (WpaBuildRsnIe (&Private, RsnIe, &RsnIeLen));

  // RSN IE should have valid structure
  EXPECT_GT (RsnIeLen, (UINTN)0);
  EXPECT_EQ (48, RsnIe[0]);  // Element ID = 48 (RSN)
  EXPECT_EQ (RsnIeLen - 2, (UINTN)RsnIe[1]);  // Length field

  // Version should be 1 (little-endian)
  EXPECT_EQ (1, WPA_GET_LE16 (RsnIe + 2));

  // Group cipher suite: OUI + CCMP
  EXPECT_EQ (WPA_RSN_OUI_BYTE0, RsnIe[4]);
  EXPECT_EQ (WPA_RSN_OUI_BYTE1, RsnIe[5]);
  EXPECT_EQ (WPA_RSN_OUI_BYTE2, RsnIe[6]);
  EXPECT_EQ (WPA_CIPHER_SUITE_CCMP, RsnIe[7]);

  // Pairwise cipher suite count: 1
  EXPECT_EQ (1, WPA_GET_LE16 (RsnIe + 8));

  // Pairwise cipher: OUI + CCMP
  EXPECT_EQ (WPA_RSN_OUI_BYTE0, RsnIe[10]);
  EXPECT_EQ (WPA_RSN_OUI_BYTE1, RsnIe[11]);
  EXPECT_EQ (WPA_RSN_OUI_BYTE2, RsnIe[12]);
  EXPECT_EQ (WPA_CIPHER_SUITE_CCMP, RsnIe[13]);

  // AKM suite count: 1
  EXPECT_EQ (1, WPA_GET_LE16 (RsnIe + 14));

  // AKM: OUI + PSK
  EXPECT_EQ (WPA_RSN_OUI_BYTE0, RsnIe[16]);
  EXPECT_EQ (WPA_RSN_OUI_BYTE1, RsnIe[17]);
  EXPECT_EQ (WPA_RSN_OUI_BYTE2, RsnIe[18]);
  EXPECT_EQ (WPA_AKM_SUITE_PSK, RsnIe[19]);
}

TEST_F (WpaRsnIeTest, SaeAkmRsnIe)
{
  Private.AkmSuiteType = WPA_AKM_SUITE_SAE;

  UINT8  RsnIe[64];
  UINTN  RsnIeLen = 0;

  EXPECT_TRUE (WpaBuildRsnIe (&Private, RsnIe, &RsnIeLen));

  // AKM type should be SAE
  EXPECT_EQ (WPA_AKM_SUITE_SAE, RsnIe[19]);
}

TEST_F (WpaRsnIeTest, NullParametersFail)
{
  UINT8  RsnIe[64];
  UINTN  RsnIeLen;

  EXPECT_FALSE (WpaBuildRsnIe (NULL, RsnIe, &RsnIeLen));
  EXPECT_FALSE (WpaBuildRsnIe (&Private, NULL, &RsnIeLen));
  EXPECT_FALSE (WpaBuildRsnIe (&Private, RsnIe, NULL));
}

// ==========================================================================
// PTK Derivation Tests
// ==========================================================================
class WpaPtkDerivationTest : public ::testing::Test {
protected:
  SUPPLICANT_PRIVATE_DATA  Private;

  void SetUp () override
  {
    InitTestPrivateData (&Private);

    // Set up test PMK, nonces, and addresses
    SetMem (Private.Pmk, WPA_PMK_LEN, 0xAA);
    Private.PmkValid = TRUE;

    SetMem (Private.ANonce, WPA_NONCE_LEN, 0xBB);
    SetMem (Private.SNonce, WPA_NONCE_LEN, 0xCC);

    UINT8  StaMac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    UINT8  ApMac[6]  = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
    CopyMem (Private.StationMac.Addr, StaMac, 6);
    CopyMem (Private.TargetBssid.Addr, ApMac, 6);
  }
};

TEST_F (WpaPtkDerivationTest, Wpa2PskPtkDerivation)
{
  Private.AkmSuiteType = WPA_AKM_SUITE_PSK;

  EXPECT_TRUE (WpaDerivePtk (&Private));
  EXPECT_EQ (WPA_KEY_DESC_VERSION_HMAC_SHA1_AES, Private.KeyDescVersion);

  // PTK should be non-zero
  UINT8  ZeroPtk[sizeof (WPA_PTK)];
  ZeroMem (ZeroPtk, sizeof (ZeroPtk));
  EXPECT_NE (0, CompareMem (&Private.Ptk, ZeroPtk, sizeof (WPA_PTK)));
}

TEST_F (WpaPtkDerivationTest, Wpa3SaePtkDerivation)
{
  Private.AkmSuiteType = WPA_AKM_SUITE_SAE;

  EXPECT_TRUE (WpaDerivePtk (&Private));
  EXPECT_EQ (WPA_KEY_DESC_VERSION_AKM_DEFINED, Private.KeyDescVersion);

  UINT8  ZeroPtk[sizeof (WPA_PTK)];
  ZeroMem (ZeroPtk, sizeof (ZeroPtk));
  EXPECT_NE (0, CompareMem (&Private.Ptk, ZeroPtk, sizeof (WPA_PTK)));
}

TEST_F (WpaPtkDerivationTest, PskSha256PtkDerivation)
{
  Private.AkmSuiteType = WPA_AKM_SUITE_PSK_SHA256;

  EXPECT_TRUE (WpaDerivePtk (&Private));
  EXPECT_EQ (WPA_KEY_DESC_VERSION_AKM_DEFINED, Private.KeyDescVersion);
}

TEST_F (WpaPtkDerivationTest, DeterministicOutput)
{
  // Same inputs should produce same PTK
  WPA_PTK  Ptk1, Ptk2;

  EXPECT_TRUE (WpaDerivePtk (&Private));
  CopyMem (&Ptk1, &Private.Ptk, sizeof (WPA_PTK));

  EXPECT_TRUE (WpaDerivePtk (&Private));
  CopyMem (&Ptk2, &Private.Ptk, sizeof (WPA_PTK));

  EXPECT_EQ (0, CompareMem (&Ptk1, &Ptk2, sizeof (WPA_PTK)));
}

TEST_F (WpaPtkDerivationTest, DifferentNonceDifferentPtk)
{
  WPA_PTK  Ptk1;

  EXPECT_TRUE (WpaDerivePtk (&Private));
  CopyMem (&Ptk1, &Private.Ptk, sizeof (WPA_PTK));

  // Change SNonce
  SetMem (Private.SNonce, WPA_NONCE_LEN, 0xDD);
  EXPECT_TRUE (WpaDerivePtk (&Private));

  EXPECT_NE (0, CompareMem (&Ptk1, &Private.Ptk, sizeof (WPA_PTK)));
}

TEST_F (WpaPtkDerivationTest, NoPmkFails)
{
  Private.PmkValid = FALSE;
  EXPECT_FALSE (WpaDerivePtk (&Private));
}

TEST_F (WpaPtkDerivationTest, AddressSymmetry)
{
  // PTK derivation sorts addresses - swapping STA/AP should produce same PTK
  WPA_PTK  Ptk1;

  EXPECT_TRUE (WpaDerivePtk (&Private));
  CopyMem (&Ptk1, &Private.Ptk, sizeof (WPA_PTK));

  // Swap addresses
  UINT8  Tmp[6];
  CopyMem (Tmp, Private.StationMac.Addr, 6);
  CopyMem (Private.StationMac.Addr, Private.TargetBssid.Addr, 6);
  CopyMem (Private.TargetBssid.Addr, Tmp, 6);

  EXPECT_TRUE (WpaDerivePtk (&Private));
  EXPECT_EQ (0, CompareMem (&Ptk1, &Private.Ptk, sizeof (WPA_PTK)));
}

// ==========================================================================
// EAPOL State Machine Tests
// ==========================================================================
class WpaEapolResetTest : public ::testing::Test {
protected:
  SUPPLICANT_PRIVATE_DATA  Private;

  void SetUp () override
  {
    InitTestPrivateData (&Private);
  }
};

TEST_F (WpaEapolResetTest, ResetClearsState)
{
  // Set up some state
  Private.FourWayState = Wpa4WayComplete;
  Private.PtkValid     = TRUE;
  Private.GtkCount     = 2;
  Private.IgtkCount    = 1;
  Private.GtkRefreshed = TRUE;
  Private.LinkState    = Ieee80211AuthenticatedAssociated;
  Private.PaeState     = Authenticated;
  SetMem (Private.ANonce, WPA_NONCE_LEN, 0xFF);
  SetMem (Private.SNonce, WPA_NONCE_LEN, 0xFF);
  SetMem (&Private.Ptk, sizeof (WPA_PTK), 0xFF);

  WpaEapolReset (&Private);

  EXPECT_EQ (Wpa4WayIdle, Private.FourWayState);
  EXPECT_FALSE (Private.PtkValid);
  EXPECT_EQ (0, Private.GtkCount);
  EXPECT_EQ (0, Private.IgtkCount);
  EXPECT_FALSE (Private.GtkRefreshed);
  EXPECT_EQ (Ieee80211UnauthenticatedUnassociated, Private.LinkState);
  EXPECT_EQ (Disconnected, Private.PaeState);

  // Sensitive data should be zeroed
  UINT8  ZeroNonce[WPA_NONCE_LEN];
  ZeroMem (ZeroNonce, sizeof (ZeroNonce));
  EXPECT_EQ (0, CompareMem (Private.ANonce, ZeroNonce, WPA_NONCE_LEN));
  EXPECT_EQ (0, CompareMem (Private.SNonce, ZeroNonce, WPA_NONCE_LEN));

  UINT8  ZeroPtk[sizeof (WPA_PTK)];
  ZeroMem (ZeroPtk, sizeof (ZeroPtk));
  EXPECT_EQ (0, CompareMem (&Private.Ptk, ZeroPtk, sizeof (WPA_PTK)));
}

TEST_F (WpaEapolResetTest, ResetNullIsSafe)
{
  // Should not crash
  WpaEapolReset (NULL);
}

// ==========================================================================
// 4-Way Handshake Message 1 Processing Tests
// ==========================================================================
class WpaFourWayHandshakeTest : public ::testing::Test {
protected:
  SUPPLICANT_PRIVATE_DATA  Private;

  void SetUp () override
  {
    InitTestPrivateData (&Private);

    // Set password and SSID
    const char  *Password = "testpassword123";
    CopyMem (Private.Password, Password, AsciiStrLen (Password));
    Private.Password[AsciiStrLen (Password)] = '\0';
    Private.PasswordLen                      = AsciiStrLen (Password);

    // Set SSID
    const char  *Ssid = "TestNetwork";
    CopyMem (Private.TargetSsid.SSId, Ssid, AsciiStrLen (Ssid));
    Private.TargetSsid.SSIdLen = (UINT8)AsciiStrLen (Ssid);

    // Set MAC addresses
    UINT8  StaMac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    UINT8  ApMac[6]  = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
    CopyMem (Private.StationMac.Addr, StaMac, 6);
    CopyMem (Private.TargetBssid.Addr, ApMac, 6);
  }

  // Build a minimal EAPOL-Key Message 1
  UINTN
  BuildMessage1 (
    UINT8  *Buffer,
    UINTN  BufferSize,
    UINT8  *ANonce
    )
  {
    EAPOL_HEADER     *EapolHdr;
    EAPOL_KEY_FRAME  *KeyFrame;
    UINTN            FrameSize;

    FrameSize = sizeof (EAPOL_HEADER) + sizeof (EAPOL_KEY_FRAME);
    if (BufferSize < FrameSize) {
      return 0;
    }

    ZeroMem (Buffer, FrameSize);

    EapolHdr                  = (EAPOL_HEADER *)Buffer;
    EapolHdr->ProtocolVersion = EAPOL_VERSION_2;
    EapolHdr->PacketType      = EAPOL_PACKET_TYPE_KEY;
    WPA_PUT_BE16 (&EapolHdr->PacketBodyLength, (UINT16)sizeof (EAPOL_KEY_FRAME));

    KeyFrame                 = (EAPOL_KEY_FRAME *)(Buffer + sizeof (EAPOL_HEADER));
    KeyFrame->DescriptorType = EAPOL_KEY_DESC_TYPE_RSN;

    // Message 1: Pairwise=1, Ack=1, MIC=0
    UINT16  KeyInfo = WPA_KEY_INFO_KEY_TYPE | WPA_KEY_INFO_KEY_ACK;
    KeyInfo |= WPA_KEY_DESC_VERSION_HMAC_SHA1_AES;
    WPA_PUT_BE16 (&KeyFrame->KeyInformation, KeyInfo);
    WPA_PUT_BE16 (&KeyFrame->KeyLength, WPA_TK_LEN);

    // Replay counter
    UINT8  ReplayCounter[8] = { 0, 0, 0, 0, 0, 0, 0, 1 };
    CopyMem (KeyFrame->ReplayCounter, ReplayCounter, WPA_REPLAY_CTR_LEN);

    // ANonce
    CopyMem (KeyFrame->KeyNonce, ANonce, WPA_NONCE_LEN);

    WPA_PUT_BE16 (&KeyFrame->KeyDataLength, 0);

    return FrameSize;
  }
};

TEST_F (WpaFourWayHandshakeTest, ProcessMessage1ProducesMessage2)
{
  UINT8  Msg1[512];
  UINT8  ANonce[WPA_NONCE_LEN];
  UINT8  Response[512];
  UINTN  ResponseSize = sizeof (Response);

  // Generate a random ANonce
  SetMem (ANonce, WPA_NONCE_LEN, 0x42);

  UINTN  Msg1Size = BuildMessage1 (Msg1, sizeof (Msg1), ANonce);
  ASSERT_GT (Msg1Size, (UINTN)0);

  EFI_STATUS  Status = WpaEapolProcessKeyFrame (
                          &Private,
                          Msg1,
                          Msg1Size,
                          Response,
                          &ResponseSize
                          );

  EXPECT_EQ (EFI_SUCCESS, Status);
  EXPECT_GT (ResponseSize, (UINTN)0);

  // Verify state transition
  EXPECT_EQ (Wpa4WayMsg1Received, Private.FourWayState);
  EXPECT_TRUE (Private.PtkValid);
  EXPECT_TRUE (Private.PmkValid);

  // Verify ANonce was stored
  EXPECT_EQ (0, CompareMem (Private.ANonce, ANonce, WPA_NONCE_LEN));

  // Verify response is a valid EAPOL-Key frame
  ASSERT_GE (ResponseSize, sizeof (EAPOL_HEADER) + sizeof (EAPOL_KEY_FRAME));

  EAPOL_HEADER  *RespHdr = (EAPOL_HEADER *)Response;
  EXPECT_EQ (EAPOL_VERSION_2, RespHdr->ProtocolVersion);
  EXPECT_EQ (EAPOL_PACKET_TYPE_KEY, RespHdr->PacketType);

  EAPOL_KEY_FRAME  *RespKey = (EAPOL_KEY_FRAME *)(Response + sizeof (EAPOL_HEADER));
  EXPECT_EQ (EAPOL_KEY_DESC_TYPE_RSN, RespKey->DescriptorType);

  // Message 2: Pairwise=1, MIC=1, Ack=0
  UINT16  RespKeyInfo = WPA_GET_BE16 (&RespKey->KeyInformation);
  EXPECT_TRUE ((RespKeyInfo & WPA_KEY_INFO_KEY_TYPE) != 0);  // Pairwise
  EXPECT_TRUE ((RespKeyInfo & WPA_KEY_INFO_KEY_MIC) != 0);   // MIC set
  EXPECT_FALSE ((RespKeyInfo & WPA_KEY_INFO_KEY_ACK) != 0);  // No ACK

  // SNonce should be set (non-zero)
  UINT8  ZeroNonce[WPA_NONCE_LEN];
  ZeroMem (ZeroNonce, sizeof (ZeroNonce));
  EXPECT_NE (0, CompareMem (RespKey->KeyNonce, ZeroNonce, WPA_NONCE_LEN));

  // Key data should contain RSN IE
  UINT16  KeyDataLen = WPA_GET_BE16 (&RespKey->KeyDataLength);
  EXPECT_GT (KeyDataLen, (UINT16)0);
}

TEST_F (WpaFourWayHandshakeTest, Message1WithoutPasswordStillDerivesKeys)
{
  // Pre-install PMK directly instead of password
  UINT8  TestPmk[WPA_PMK_LEN];
  SetMem (TestPmk, sizeof (TestPmk), 0xDD);
  CopyMem (Private.Pmk, TestPmk, WPA_PMK_LEN);
  Private.PmkValid   = TRUE;
  Private.PasswordLen = 0;  // No password

  UINT8  Msg1[512];
  UINT8  ANonce[WPA_NONCE_LEN];
  UINT8  Response[512];
  UINTN  ResponseSize = sizeof (Response);

  SetMem (ANonce, WPA_NONCE_LEN, 0x55);
  UINTN  Msg1Size = BuildMessage1 (Msg1, sizeof (Msg1), ANonce);

  EFI_STATUS  Status = WpaEapolProcessKeyFrame (
                          &Private,
                          Msg1,
                          Msg1Size,
                          Response,
                          &ResponseSize
                          );

  EXPECT_EQ (EFI_SUCCESS, Status);
  EXPECT_TRUE (Private.PtkValid);
}

TEST_F (WpaFourWayHandshakeTest, BufferTooSmallReturnsRequiredSize)
{
  UINT8  Msg1[512];
  UINT8  ANonce[WPA_NONCE_LEN];
  UINT8  Response[1];
  UINTN  ResponseSize = 1;  // Too small

  SetMem (ANonce, WPA_NONCE_LEN, 0x42);
  UINTN  Msg1Size = BuildMessage1 (Msg1, sizeof (Msg1), ANonce);

  EFI_STATUS  Status = WpaEapolProcessKeyFrame (
                          &Private,
                          Msg1,
                          Msg1Size,
                          Response,
                          &ResponseSize
                          );

  EXPECT_EQ (EFI_BUFFER_TOO_SMALL, Status);
  EXPECT_GT (ResponseSize, (UINTN)1);
}

TEST_F (WpaFourWayHandshakeTest, InvalidPacketTypeFails)
{
  UINT8  BadPacket[sizeof (EAPOL_HEADER) + sizeof (EAPOL_KEY_FRAME)];
  UINT8  Response[512];
  UINTN  ResponseSize = sizeof (Response);

  ZeroMem (BadPacket, sizeof (BadPacket));
  EAPOL_HEADER  *Hdr = (EAPOL_HEADER *)BadPacket;
  Hdr->PacketType = EAPOL_PACKET_TYPE_START;  // Not KEY

  EFI_STATUS  Status = WpaEapolProcessKeyFrame (
                          &Private,
                          BadPacket,
                          sizeof (BadPacket),
                          Response,
                          &ResponseSize
                          );

  EXPECT_EQ (EFI_UNSUPPORTED, Status);
}

TEST_F (WpaFourWayHandshakeTest, TooSmallPacketFails)
{
  UINT8  SmallPacket[4] = { 0 };
  UINT8  Response[512];
  UINTN  ResponseSize = sizeof (Response);

  EFI_STATUS  Status = WpaEapolProcessKeyFrame (
                          &Private,
                          SmallPacket,
                          sizeof (SmallPacket),
                          Response,
                          &ResponseSize
                          );

  EXPECT_EQ (EFI_INVALID_PARAMETER, Status);
}

TEST_F (WpaFourWayHandshakeTest, NullParametersFail)
{
  UINT8  Msg[128];
  UINT8  Resp[128];
  UINTN  RespSize = sizeof (Resp);

  EXPECT_EQ (EFI_INVALID_PARAMETER,
    WpaEapolProcessKeyFrame (NULL, Msg, sizeof (Msg), Resp, &RespSize));
  EXPECT_EQ (EFI_INVALID_PARAMETER,
    WpaEapolProcessKeyFrame (&Private, NULL, sizeof (Msg), Resp, &RespSize));
  EXPECT_EQ (EFI_INVALID_PARAMETER,
    WpaEapolProcessKeyFrame (&Private, Msg, sizeof (Msg), Resp, NULL));
}
