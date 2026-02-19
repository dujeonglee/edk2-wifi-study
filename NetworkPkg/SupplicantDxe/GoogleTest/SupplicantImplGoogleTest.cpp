/** @file
  EFI Supplicant Protocol Implementation Unit Tests (SetData / GetData).

  Tests cover:
  - SetData parameter validation for all supported data types
  - GetData retrieval and buffer size handling
  - Set/Get round-trip correctness
  - Supported suite enumeration
  - State management (handshake reset on configuration change)
  - BuildResponsePacket WPA2-PSK initiation (no-op)
  - ProcessPacket parameter validation

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
// Fixture: allocates a SUPPLICANT_PRIVATE_DATA and wires up the protocol
// ==========================================================================
class SupplicantImplTest : public ::testing::Test {
protected:
  SUPPLICANT_PRIVATE_DATA   *Private;
  EFI_SUPPLICANT_PROTOCOL   *Protocol;

  void SetUp () override
  {
    Private = (SUPPLICANT_PRIVATE_DATA *)AllocateZeroPool (sizeof (SUPPLICANT_PRIVATE_DATA));
    ASSERT_NE (Private, (SUPPLICANT_PRIVATE_DATA *)NULL);

    Private->Signature = SUPPLICANT_PRIVATE_DATA_SIGNATURE;

    Private->Supplicant.BuildResponsePacket = SupplicantBuildResponsePacket;
    Private->Supplicant.ProcessPacket       = SupplicantProcessPacket;
    Private->Supplicant.SetData             = SupplicantSetData;
    Private->Supplicant.GetData             = SupplicantGetData;

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

    Protocol = &Private->Supplicant;
  }

  void TearDown () override
  {
    if (Private != NULL) {
      FreePool (Private);
    }
  }
};

// ==========================================================================
// SetData Null/Invalid Parameter Tests
// ==========================================================================
TEST_F (SupplicantImplTest, SetDataNullThisFails)
{
  UINT8  Data[4] = { 0 };

  EXPECT_EQ (EFI_INVALID_PARAMETER,
    SupplicantSetData (NULL, EfiSupplicant80211PskPassword, Data, sizeof (Data)));
}

TEST_F (SupplicantImplTest, SetDataUnsupportedTypeFails)
{
  UINT8  Data[4] = { 0 };

  EXPECT_EQ (EFI_UNSUPPORTED,
    Protocol->SetData (Protocol, EfiSupplicantDataTypeMaximum, Data, sizeof (Data)));
}

// ==========================================================================
// SetData: AKM Suite
// ==========================================================================
TEST_F (SupplicantImplTest, SetAkmSuitePsk)
{
  EFI_80211_SUITE_SELECTOR  Suite = {
    { WPA_RSN_OUI_BYTE0, WPA_RSN_OUI_BYTE1, WPA_RSN_OUI_BYTE2 },
    WPA_AKM_SUITE_PSK
  };

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->SetData (Protocol, EfiSupplicant80211AKMSuite, &Suite, sizeof (Suite)));
  EXPECT_EQ (WPA_AKM_SUITE_PSK, Private->AkmSuiteType);
  EXPECT_EQ (WPA_KEY_DESC_VERSION_HMAC_SHA1_AES, Private->KeyDescVersion);
}

TEST_F (SupplicantImplTest, SetAkmSuiteSae)
{
  EFI_80211_SUITE_SELECTOR  Suite = {
    { WPA_RSN_OUI_BYTE0, WPA_RSN_OUI_BYTE1, WPA_RSN_OUI_BYTE2 },
    WPA_AKM_SUITE_SAE
  };

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->SetData (Protocol, EfiSupplicant80211AKMSuite, &Suite, sizeof (Suite)));
  EXPECT_EQ (WPA_AKM_SUITE_SAE, Private->AkmSuiteType);
  EXPECT_EQ (WPA_KEY_DESC_VERSION_AKM_DEFINED, Private->KeyDescVersion);
}

TEST_F (SupplicantImplTest, SetAkmSuiteResetsHandshake)
{
  Private->FourWayState = Wpa4WayComplete;
  Private->PtkValid     = TRUE;

  EFI_80211_SUITE_SELECTOR  Suite = {
    { WPA_RSN_OUI_BYTE0, WPA_RSN_OUI_BYTE1, WPA_RSN_OUI_BYTE2 },
    WPA_AKM_SUITE_PSK
  };

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->SetData (Protocol, EfiSupplicant80211AKMSuite, &Suite, sizeof (Suite)));

  // Handshake should be reset
  EXPECT_EQ (Wpa4WayIdle, Private->FourWayState);
  EXPECT_FALSE (Private->PtkValid);
}

TEST_F (SupplicantImplTest, SetAkmSuiteNullDataFails)
{
  EXPECT_EQ (EFI_INVALID_PARAMETER,
    Protocol->SetData (Protocol, EfiSupplicant80211AKMSuite, NULL, sizeof (EFI_80211_SUITE_SELECTOR)));
}

TEST_F (SupplicantImplTest, SetAkmSuiteTooSmallFails)
{
  UINT8  Small[1] = { 0 };

  EXPECT_EQ (EFI_INVALID_PARAMETER,
    Protocol->SetData (Protocol, EfiSupplicant80211AKMSuite, Small, 1));
}

// ==========================================================================
// SetData: PSK Password
// ==========================================================================
TEST_F (SupplicantImplTest, SetPasswordValid)
{
  const char  *Pass = "mysecretpassword";

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->SetData (Protocol, EfiSupplicant80211PskPassword,
      (VOID *)Pass, AsciiStrLen (Pass)));

  EXPECT_EQ (AsciiStrLen (Pass), Private->PasswordLen);
  EXPECT_EQ (0, CompareMem (Private->Password, Pass, AsciiStrLen (Pass)));
  EXPECT_EQ ('\0', Private->Password[AsciiStrLen (Pass)]);
  EXPECT_FALSE (Private->PmkValid);  // PMK invalidated
}

TEST_F (SupplicantImplTest, SetPasswordMinLength)
{
  // Minimum 8 chars
  EXPECT_EQ (EFI_SUCCESS,
    Protocol->SetData (Protocol, EfiSupplicant80211PskPassword,
      (VOID *)"12345678", 8));
  EXPECT_EQ ((UINTN)8, Private->PasswordLen);
}

TEST_F (SupplicantImplTest, SetPasswordMaxLength)
{
  // Maximum 63 chars
  char  MaxPass[64];
  SetMem (MaxPass, 63, 'A');
  MaxPass[63] = '\0';

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->SetData (Protocol, EfiSupplicant80211PskPassword,
      MaxPass, 63));
  EXPECT_EQ ((UINTN)63, Private->PasswordLen);
}

TEST_F (SupplicantImplTest, SetPasswordTooShortFails)
{
  EXPECT_EQ (EFI_INVALID_PARAMETER,
    Protocol->SetData (Protocol, EfiSupplicant80211PskPassword,
      (VOID *)"short", 5));
}

TEST_F (SupplicantImplTest, SetPasswordTooLongFails)
{
  char  TooLong[65];
  SetMem (TooLong, 64, 'A');
  TooLong[64] = '\0';

  EXPECT_EQ (EFI_INVALID_PARAMETER,
    Protocol->SetData (Protocol, EfiSupplicant80211PskPassword,
      TooLong, 64));
}

TEST_F (SupplicantImplTest, SetPasswordNullClearsPassword)
{
  // First set a password
  Protocol->SetData (Protocol, EfiSupplicant80211PskPassword,
    (VOID *)"testpassword", 12);
  EXPECT_EQ ((UINTN)12, Private->PasswordLen);

  // Clear with NULL
  EXPECT_EQ (EFI_SUCCESS,
    Protocol->SetData (Protocol, EfiSupplicant80211PskPassword, NULL, 0));
  EXPECT_EQ ((UINTN)0, Private->PasswordLen);
  EXPECT_FALSE (Private->PmkValid);
}

// ==========================================================================
// SetData: Target SSID
// ==========================================================================
TEST_F (SupplicantImplTest, SetTargetSsid)
{
  const char  *Ssid = "MyWiFiNetwork";

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->SetData (Protocol, EfiSupplicant80211TargetSSIDName,
      (VOID *)Ssid, AsciiStrLen (Ssid)));

  EXPECT_EQ ((UINT8)AsciiStrLen (Ssid), Private->TargetSsid.SSIdLen);
  EXPECT_EQ (0, CompareMem (Private->TargetSsid.SSId, Ssid, AsciiStrLen (Ssid)));
  EXPECT_FALSE (Private->PmkValid);  // PMK invalidated
}

TEST_F (SupplicantImplTest, SetTargetSsidNullFails)
{
  EXPECT_EQ (EFI_INVALID_PARAMETER,
    Protocol->SetData (Protocol, EfiSupplicant80211TargetSSIDName, NULL, 5));
}

TEST_F (SupplicantImplTest, SetTargetSsidZeroLenFails)
{
  UINT8  Data[1] = { 0 };

  EXPECT_EQ (EFI_INVALID_PARAMETER,
    Protocol->SetData (Protocol, EfiSupplicant80211TargetSSIDName, Data, 0));
}

TEST_F (SupplicantImplTest, SetTargetSsidTooLongFails)
{
  UINT8  LongSsid[33];
  SetMem (LongSsid, 33, 'X');

  EXPECT_EQ (EFI_INVALID_PARAMETER,
    Protocol->SetData (Protocol, EfiSupplicant80211TargetSSIDName, LongSsid, 33));
}

// ==========================================================================
// SetData: Station MAC
// ==========================================================================
TEST_F (SupplicantImplTest, SetStationMac)
{
  UINT8  Mac[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->SetData (Protocol, EfiSupplicant80211StationMac, Mac, 6));
  EXPECT_EQ (0, CompareMem (Private->StationMac.Addr, Mac, 6));
}

TEST_F (SupplicantImplTest, SetStationMacNullFails)
{
  EXPECT_EQ (EFI_INVALID_PARAMETER,
    Protocol->SetData (Protocol, EfiSupplicant80211StationMac, NULL, 6));
}

TEST_F (SupplicantImplTest, SetStationMacTooSmallFails)
{
  UINT8  Mac[3] = { 0 };

  EXPECT_EQ (EFI_INVALID_PARAMETER,
    Protocol->SetData (Protocol, EfiSupplicant80211StationMac, Mac, 3));
}

// ==========================================================================
// SetData: Target BSSID (TargetSSIDMac)
// ==========================================================================
TEST_F (SupplicantImplTest, SetTargetBssid)
{
  UINT8  Bssid[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->SetData (Protocol, EfiSupplicant80211TargetSSIDMac, Bssid, 6));
  EXPECT_EQ (0, CompareMem (Private->TargetBssid.Addr, Bssid, 6));
}

// ==========================================================================
// SetData: PMK
// ==========================================================================
TEST_F (SupplicantImplTest, SetPmkDirect)
{
  UINT8  Pmk[WPA_PMK_LEN];
  SetMem (Pmk, sizeof (Pmk), 0x42);

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->SetData (Protocol, EfiSupplicant80211PMK, Pmk, WPA_PMK_LEN));
  EXPECT_TRUE (Private->PmkValid);
  EXPECT_EQ (0, CompareMem (Private->Pmk, Pmk, WPA_PMK_LEN));
}

TEST_F (SupplicantImplTest, SetPmkNullFails)
{
  EXPECT_EQ (EFI_INVALID_PARAMETER,
    Protocol->SetData (Protocol, EfiSupplicant80211PMK, NULL, WPA_PMK_LEN));
}

TEST_F (SupplicantImplTest, SetPmkTooSmallFails)
{
  UINT8  Small[16];

  EXPECT_EQ (EFI_INVALID_PARAMETER,
    Protocol->SetData (Protocol, EfiSupplicant80211PMK, Small, 16));
}

// ==========================================================================
// SetData: Cipher Suites
// ==========================================================================
TEST_F (SupplicantImplTest, SetPairwiseCipher)
{
  EFI_80211_SUITE_SELECTOR  Suite = {
    { WPA_RSN_OUI_BYTE0, WPA_RSN_OUI_BYTE1, WPA_RSN_OUI_BYTE2 },
    WPA_CIPHER_SUITE_CCMP
  };

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->SetData (Protocol, EfiSupplicant80211PairwiseCipherSuite,
      &Suite, sizeof (Suite)));
  EXPECT_EQ (WPA_CIPHER_SUITE_CCMP, Private->PairwiseCipherType);
}

TEST_F (SupplicantImplTest, SetGroupCipher)
{
  EFI_80211_SUITE_SELECTOR  Suite = {
    { WPA_RSN_OUI_BYTE0, WPA_RSN_OUI_BYTE1, WPA_RSN_OUI_BYTE2 },
    WPA_CIPHER_SUITE_CCMP
  };

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->SetData (Protocol, EfiSupplicant80211GroupDataCipherSuite,
      &Suite, sizeof (Suite)));
  EXPECT_EQ (WPA_CIPHER_SUITE_CCMP, Private->GroupCipherType);
}

// ==========================================================================
// GetData Tests
// ==========================================================================
TEST_F (SupplicantImplTest, GetDataNullThisFails)
{
  UINTN  Size = 0;

  EXPECT_EQ (EFI_INVALID_PARAMETER,
    SupplicantGetData (NULL, EfiSupplicant80211AKMSuite, NULL, &Size));
}

TEST_F (SupplicantImplTest, GetDataNullSizeFails)
{
  EXPECT_EQ (EFI_INVALID_PARAMETER,
    Protocol->GetData (Protocol, EfiSupplicant80211AKMSuite, NULL, NULL));
}

TEST_F (SupplicantImplTest, GetDataUnsupportedTypeFails)
{
  UINTN  Size = 0;

  EXPECT_EQ (EFI_UNSUPPORTED,
    Protocol->GetData (Protocol, EfiSupplicantDataTypeMaximum, NULL, &Size));
}

// ==========================================================================
// GetData: Supported AKM Suites
// ==========================================================================
TEST_F (SupplicantImplTest, GetSupportedAkmSuitesSizeQuery)
{
  UINTN  Size = 0;

  EFI_STATUS  Status = Protocol->GetData (
                          Protocol, EfiSupplicant80211SupportedAKMSuites,
                          NULL, &Size
                          );

  EXPECT_EQ (EFI_BUFFER_TOO_SMALL, Status);
  EXPECT_GT (Size, (UINTN)0);
}

TEST_F (SupplicantImplTest, GetSupportedAkmSuitesData)
{
  UINT8  Buffer[256];
  UINTN  Size = sizeof (Buffer);

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->GetData (Protocol, EfiSupplicant80211SupportedAKMSuites,
      Buffer, &Size));

  // First 2 bytes = count
  UINT16  Count = *(UINT16 *)Buffer;
  EXPECT_EQ (3, Count);  // PSK, PSK-SHA256, SAE
}

// ==========================================================================
// GetData: Supported Cipher Suites
// ==========================================================================
TEST_F (SupplicantImplTest, GetSupportedCipherSuites)
{
  UINT8  Buffer[256];
  UINTN  Size = sizeof (Buffer);

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->GetData (Protocol, EfiSupplicant80211SupportedSoftwareCipherSuites,
      Buffer, &Size));

  UINT16  Count = *(UINT16 *)Buffer;
  EXPECT_EQ (2, Count);  // CCMP, BIP
}

TEST_F (SupplicantImplTest, GetHardwareCipherSuitesSameAsSoftware)
{
  UINT8  SwBuf[256];
  UINT8  HwBuf[256];
  UINTN  SwSize = sizeof (SwBuf);
  UINTN  HwSize = sizeof (HwBuf);

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->GetData (Protocol, EfiSupplicant80211SupportedSoftwareCipherSuites,
      SwBuf, &SwSize));
  EXPECT_EQ (EFI_SUCCESS,
    Protocol->GetData (Protocol, EfiSupplicant80211SupportedHardwareCipherSuites,
      HwBuf, &HwSize));

  EXPECT_EQ (SwSize, HwSize);
  EXPECT_EQ (0, CompareMem (SwBuf, HwBuf, SwSize));
}

// ==========================================================================
// GetData: PMK
// ==========================================================================
TEST_F (SupplicantImplTest, GetPmkNotReadyWhenInvalid)
{
  UINTN  Size = WPA_PMK_LEN;

  EXPECT_FALSE (Private->PmkValid);
  EXPECT_EQ (EFI_NOT_READY,
    Protocol->GetData (Protocol, EfiSupplicant80211PMK, NULL, &Size));
}

TEST_F (SupplicantImplTest, GetPmkAfterSet)
{
  UINT8  Pmk[WPA_PMK_LEN];
  UINT8  Retrieved[WPA_PMK_LEN];
  UINTN  Size = sizeof (Retrieved);

  SetMem (Pmk, sizeof (Pmk), 0x77);
  Protocol->SetData (Protocol, EfiSupplicant80211PMK, Pmk, sizeof (Pmk));

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->GetData (Protocol, EfiSupplicant80211PMK, Retrieved, &Size));
  EXPECT_EQ ((UINTN)WPA_PMK_LEN, Size);
  EXPECT_EQ (0, CompareMem (Retrieved, Pmk, WPA_PMK_LEN));
}

TEST_F (SupplicantImplTest, GetPmkBufferTooSmall)
{
  UINT8  Pmk[WPA_PMK_LEN];
  SetMem (Pmk, sizeof (Pmk), 0x77);
  Protocol->SetData (Protocol, EfiSupplicant80211PMK, Pmk, sizeof (Pmk));

  UINT8  Small[8];
  UINTN  Size = sizeof (Small);

  EXPECT_EQ (EFI_BUFFER_TOO_SMALL,
    Protocol->GetData (Protocol, EfiSupplicant80211PMK, Small, &Size));
  EXPECT_EQ ((UINTN)WPA_PMK_LEN, Size);
}

// ==========================================================================
// GetData: PTK
// ==========================================================================
TEST_F (SupplicantImplTest, GetPtkNotReadyWhenInvalid)
{
  UINTN  Size = sizeof (WPA_PTK);

  EXPECT_FALSE (Private->PtkValid);
  EXPECT_EQ (EFI_NOT_READY,
    Protocol->GetData (Protocol, EfiSupplicant80211PTK, NULL, &Size));
}

// ==========================================================================
// GetData: Current AKM Suite (round-trip)
// ==========================================================================
TEST_F (SupplicantImplTest, GetCurrentAkmSuiteRoundTrip)
{
  // Set SAE
  EFI_80211_SUITE_SELECTOR  SetSuite = {
    { WPA_RSN_OUI_BYTE0, WPA_RSN_OUI_BYTE1, WPA_RSN_OUI_BYTE2 },
    WPA_AKM_SUITE_SAE
  };

  Protocol->SetData (Protocol, EfiSupplicant80211AKMSuite, &SetSuite, sizeof (SetSuite));

  // Get it back
  EFI_80211_SUITE_SELECTOR  GetSuite;
  UINTN                     Size = sizeof (GetSuite);

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->GetData (Protocol, EfiSupplicant80211AKMSuite, (UINT8 *)&GetSuite, &Size));
  EXPECT_EQ (sizeof (EFI_80211_SUITE_SELECTOR), Size);
  EXPECT_EQ (WPA_AKM_SUITE_SAE, GetSuite.SuiteType);
  EXPECT_EQ (WPA_RSN_OUI_BYTE0, GetSuite.Oui[0]);
  EXPECT_EQ (WPA_RSN_OUI_BYTE1, GetSuite.Oui[1]);
  EXPECT_EQ (WPA_RSN_OUI_BYTE2, GetSuite.Oui[2]);
}

// ==========================================================================
// GetData: Current Pairwise Cipher Suite (round-trip)
// ==========================================================================
TEST_F (SupplicantImplTest, GetCurrentPairwiseCipherRoundTrip)
{
  EFI_80211_SUITE_SELECTOR  Suite;
  UINTN                     Size = sizeof (Suite);

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->GetData (Protocol, EfiSupplicant80211PairwiseCipherSuite,
      (UINT8 *)&Suite, &Size));

  EXPECT_EQ (WPA_CIPHER_SUITE_CCMP, Suite.SuiteType);
}

// ==========================================================================
// GetData: GTK / IGTK Not Ready
// ==========================================================================
TEST_F (SupplicantImplTest, GetGtkNotReady)
{
  UINTN  Size = 32;

  EXPECT_EQ (EFI_NOT_READY,
    Protocol->GetData (Protocol, EfiSupplicant80211GTK, NULL, &Size));
}

TEST_F (SupplicantImplTest, GetIgtkNotReady)
{
  UINTN  Size = 32;

  EXPECT_EQ (EFI_NOT_READY,
    Protocol->GetData (Protocol, EfiSupplicant80211IGTK, NULL, &Size));
}

// ==========================================================================
// BuildResponsePacket: WPA2-PSK Initiation (should be no-op)
// ==========================================================================
TEST_F (SupplicantImplTest, BuildResponsePacketWpa2PskInitiation)
{
  UINT8  Buffer[256];
  UINTN  BufferSize = sizeof (Buffer);

  // With no request (initiation), WPA2-PSK should return success with size=0
  EFI_STATUS  Status = Protocol->BuildResponsePacket (
                          Protocol, NULL, 0, Buffer, &BufferSize
                          );

  EXPECT_EQ (EFI_SUCCESS, Status);
  EXPECT_EQ ((UINTN)0, BufferSize);
}

TEST_F (SupplicantImplTest, BuildResponsePacketNullThisFails)
{
  UINTN  Size = 64;

  EXPECT_EQ (EFI_INVALID_PARAMETER,
    SupplicantBuildResponsePacket (NULL, NULL, 0, NULL, &Size));
}

TEST_F (SupplicantImplTest, BuildResponsePacketNullSizeFails)
{
  EXPECT_EQ (EFI_INVALID_PARAMETER,
    Protocol->BuildResponsePacket (Protocol, NULL, 0, NULL, NULL));
}

// ==========================================================================
// ProcessPacket: Parameter Validation
// ==========================================================================
TEST_F (SupplicantImplTest, ProcessPacketNullThisFails)
{
  EFI_SUPPLICANT_FRAGMENT_DATA  Frag = { 0, NULL };
  EFI_SUPPLICANT_FRAGMENT_DATA  *FragTable = &Frag;
  UINT32                        FragCount  = 1;

  EXPECT_EQ (EFI_INVALID_PARAMETER,
    SupplicantProcessPacket (NULL, &FragTable, &FragCount, EfiSupplicantEncrypt));
}

TEST_F (SupplicantImplTest, ProcessPacketNullFragTableFails)
{
  UINT32  FragCount = 1;

  EXPECT_EQ (EFI_INVALID_PARAMETER,
    Protocol->ProcessPacket (Protocol, NULL, &FragCount, EfiSupplicantEncrypt));
}

TEST_F (SupplicantImplTest, ProcessPacketNotReadyWithoutPtk)
{
  UINT8                         Data[64];
  EFI_SUPPLICANT_FRAGMENT_DATA  Frag      = { sizeof (Data), Data };
  EFI_SUPPLICANT_FRAGMENT_DATA  *FragTable = &Frag;
  UINT32                        FragCount  = 1;

  SetMem (Data, sizeof (Data), 0);
  EXPECT_FALSE (Private->PtkValid);

  EXPECT_EQ (EFI_NOT_READY,
    Protocol->ProcessPacket (Protocol, &FragTable, &FragCount, EfiSupplicantEncrypt));
}

// ==========================================================================
// SetData: PTK Installation
// ==========================================================================
TEST_F (SupplicantImplTest, SetPtkDirect)
{
  EFI_SUPPLICANT_KEY  SupKey;
  ZeroMem (&SupKey, sizeof (SupKey));
  SupKey.KeyLen = sizeof (WPA_PTK);
  SetMem (SupKey.Key, SupKey.KeyLen, 0xAB);

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->SetData (Protocol, EfiSupplicant80211PTK, &SupKey, sizeof (SupKey)));
  EXPECT_TRUE (Private->PtkValid);
}

TEST_F (SupplicantImplTest, SetPtkNullFails)
{
  EXPECT_EQ (EFI_INVALID_PARAMETER,
    Protocol->SetData (Protocol, EfiSupplicant80211PTK, NULL, sizeof (EFI_SUPPLICANT_KEY)));
}

// ==========================================================================
// SetData: GTK Installation
// ==========================================================================
TEST_F (SupplicantImplTest, SetGtkDirect)
{
  EFI_SUPPLICANT_KEY  SupKey;
  ZeroMem (&SupKey, sizeof (SupKey));
  SupKey.KeyLen = 16;
  SetMem (SupKey.Key, 16, 0xCD);

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->SetData (Protocol, EfiSupplicant80211GTK, &SupKey, sizeof (SupKey)));
  EXPECT_EQ (1, Private->GtkCount);
  EXPECT_EQ (16, Private->Gtk[0].KeyLen);
}

// ==========================================================================
// SetData: IGTK Installation
// ==========================================================================
TEST_F (SupplicantImplTest, SetIgtkDirect)
{
  EFI_SUPPLICANT_KEY  SupKey;
  ZeroMem (&SupKey, sizeof (SupKey));
  SupKey.KeyLen = 16;
  SetMem (SupKey.Key, 16, 0xEF);

  EXPECT_EQ (EFI_SUCCESS,
    Protocol->SetData (Protocol, EfiSupplicant80211IGTK, &SupKey, sizeof (SupKey)));
  EXPECT_EQ (1, Private->IgtkCount);
  EXPECT_EQ (16, Private->Igtk[0].KeyLen);
}
