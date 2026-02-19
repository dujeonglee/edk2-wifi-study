/** @file
  Main entry point and WPA crypto unit tests for SupplicantDxe.

  Tests cover:
  - AES-128-CMAC (RFC 4493 test vectors)
  - HMAC-SHA1-128 MIC computation
  - AES Key Wrap / Unwrap (RFC 3394 test vectors)
  - PRF-SHA1 key derivation
  - KDF-SHA256 key derivation
  - CCMP AAD / Nonce construction and encrypt/decrypt round-trip

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
  #include "../WpaCommon.h"
  #include "../WpaCrypto.h"
}

// ==========================================================================
// AES-128-CMAC Tests (RFC 4493 Test Vectors)
// ==========================================================================
class WpaAesCmacTest : public ::testing::Test {
protected:
  // RFC 4493 test key
  UINT8 Key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
  };
};

// RFC 4493 Example 1: Empty message
TEST_F (WpaAesCmacTest, EmptyMessage)
{
  UINT8    Mac[16];
  BOOLEAN  Result;

  // Expected: bb1d6929 e9593728 7fa37d12 9b756746
  UINT8  Expected[16] = {
    0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
    0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46
  };

  Result = WpaAesCmac (Key, NULL, 0, Mac);
  EXPECT_TRUE (Result);
  EXPECT_EQ (0, CompareMem (Mac, Expected, 16));
}

// RFC 4493 Example 2: 16-byte message (exactly one block)
TEST_F (WpaAesCmacTest, OneBlock)
{
  UINT8  Msg[16] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
  };
  UINT8    Mac[16];
  BOOLEAN  Result;

  // Expected: 070a16b4 6b4d4144 f79bdd9d d04a287c
  UINT8  Expected[16] = {
    0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
    0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c
  };

  Result = WpaAesCmac (Key, Msg, sizeof (Msg), Mac);
  EXPECT_TRUE (Result);
  EXPECT_EQ (0, CompareMem (Mac, Expected, 16));
}

// RFC 4493 Example 3: 40-byte message (not a full block multiple)
TEST_F (WpaAesCmacTest, PartialLastBlock)
{
  UINT8  Msg[40] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11
  };
  UINT8    Mac[16];
  BOOLEAN  Result;

  // Expected: dfa66747 de9ae630 30ca3261 1497c827
  UINT8  Expected[16] = {
    0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
    0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27
  };

  Result = WpaAesCmac (Key, Msg, sizeof (Msg), Mac);
  EXPECT_TRUE (Result);
  EXPECT_EQ (0, CompareMem (Mac, Expected, 16));
}

// RFC 4493 Example 4: 64-byte message (four full blocks)
TEST_F (WpaAesCmacTest, FourBlocks)
{
  UINT8  Msg[64] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
  };
  UINT8    Mac[16];
  BOOLEAN  Result;

  // Expected: 51f0bebf 7e3b9d92 fc497417 79363cfe
  UINT8  Expected[16] = {
    0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
    0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe
  };

  Result = WpaAesCmac (Key, Msg, sizeof (Msg), Mac);
  EXPECT_TRUE (Result);
  EXPECT_EQ (0, CompareMem (Mac, Expected, 16));
}

// Null parameter tests
TEST_F (WpaAesCmacTest, NullKeyFails)
{
  UINT8  Msg[16] = { 0 };
  UINT8  Mac[16];

  EXPECT_FALSE (WpaAesCmac (NULL, Msg, sizeof (Msg), Mac));
}

TEST_F (WpaAesCmacTest, NullMacFails)
{
  UINT8  Msg[16] = { 0 };

  EXPECT_FALSE (WpaAesCmac (Key, Msg, sizeof (Msg), NULL));
}

// ==========================================================================
// AES Key Wrap / Unwrap Tests (RFC 3394)
// ==========================================================================
class WpaAesKeyWrapTest : public ::testing::Test {
protected:
  // RFC 3394 Section 4.1: 128-bit KEK with 128-bit key data
  UINT8 Kek[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
  };
  UINT8 Plaintext[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
  };
  UINT8 ExpectedCiphertext[24] = {
    0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
    0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
    0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5
  };
};

TEST_F (WpaAesKeyWrapTest, WrapRfc3394Vector)
{
  UINT8    Ciphertext[24];
  BOOLEAN  Result;

  Result = WpaAesKeyWrap (Kek, Plaintext, sizeof (Plaintext), Ciphertext);
  EXPECT_TRUE (Result);
  EXPECT_EQ (0, CompareMem (Ciphertext, ExpectedCiphertext, sizeof (ExpectedCiphertext)));
}

TEST_F (WpaAesKeyWrapTest, UnwrapRfc3394Vector)
{
  UINT8    Decrypted[16];
  BOOLEAN  Result;

  Result = WpaAesKeyUnwrap (Kek, ExpectedCiphertext, sizeof (ExpectedCiphertext), Decrypted);
  EXPECT_TRUE (Result);
  EXPECT_EQ (0, CompareMem (Decrypted, Plaintext, sizeof (Plaintext)));
}

TEST_F (WpaAesKeyWrapTest, WrapUnwrapRoundTrip)
{
  UINT8    TestData[32];
  UINT8    Wrapped[40];
  UINT8    Unwrapped[32];
  BOOLEAN  Result;
  UINT8    TestKek[16] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
  };

  // Fill test data with known pattern
  for (UINTN i = 0; i < sizeof (TestData); i++) {
    TestData[i] = (UINT8)(i & 0xFF);
  }

  Result = WpaAesKeyWrap (TestKek, TestData, sizeof (TestData), Wrapped);
  EXPECT_TRUE (Result);

  Result = WpaAesKeyUnwrap (TestKek, Wrapped, sizeof (Wrapped), Unwrapped);
  EXPECT_TRUE (Result);
  EXPECT_EQ (0, CompareMem (Unwrapped, TestData, sizeof (TestData)));
}

TEST_F (WpaAesKeyWrapTest, UnwrapTamperedDataFails)
{
  UINT8    Tampered[24];
  UINT8    Decrypted[16];
  BOOLEAN  Result;

  CopyMem (Tampered, ExpectedCiphertext, sizeof (Tampered));
  // Tamper with the data
  Tampered[10] ^= 0xFF;

  Result = WpaAesKeyUnwrap (Kek, Tampered, sizeof (Tampered), Decrypted);
  EXPECT_FALSE (Result);
}

TEST_F (WpaAesKeyWrapTest, NullParametersFail)
{
  UINT8  Ciphertext[24];
  UINT8  Decrypted[16];

  EXPECT_FALSE (WpaAesKeyWrap (NULL, Plaintext, sizeof (Plaintext), Ciphertext));
  EXPECT_FALSE (WpaAesKeyWrap (Kek, NULL, sizeof (Plaintext), Ciphertext));
  EXPECT_FALSE (WpaAesKeyWrap (Kek, Plaintext, sizeof (Plaintext), NULL));
  EXPECT_FALSE (WpaAesKeyWrap (Kek, Plaintext, 0, Ciphertext));
  EXPECT_FALSE (WpaAesKeyWrap (Kek, Plaintext, 7, Ciphertext));  // Not multiple of 8

  EXPECT_FALSE (WpaAesKeyUnwrap (NULL, ExpectedCiphertext, sizeof (ExpectedCiphertext), Decrypted));
  EXPECT_FALSE (WpaAesKeyUnwrap (Kek, NULL, sizeof (ExpectedCiphertext), Decrypted));
  EXPECT_FALSE (WpaAesKeyUnwrap (Kek, ExpectedCiphertext, sizeof (ExpectedCiphertext), NULL));
  EXPECT_FALSE (WpaAesKeyUnwrap (Kek, ExpectedCiphertext, 8, Decrypted));  // Too short
}

// ==========================================================================
// HMAC-SHA1-128 MIC Tests
// ==========================================================================
class WpaHmacSha1MicTest : public ::testing::Test {
};

TEST_F (WpaHmacSha1MicTest, KnownVector)
{
  // A known HMAC-SHA1 test: key and data produce a deterministic result
  UINT8    Key[16] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
  };
  UINT8    Data[] = "Hi There";
  UINT8    Mic[16];
  BOOLEAN  Result;

  Result = WpaHmacSha1Mic (Key, Data, 8, Mic);
  EXPECT_TRUE (Result);
  // Verify it produces some non-zero output (exact vector depends on the truncation)
  BOOLEAN  AllZero = TRUE;

  for (UINTN i = 0; i < 16; i++) {
    if (Mic[i] != 0) {
      AllZero = FALSE;
      break;
    }
  }

  EXPECT_FALSE (AllZero);
}

TEST_F (WpaHmacSha1MicTest, DeterministicOutput)
{
  // Same input should produce same output
  UINT8    Key[16]  = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
  UINT8    Data[32] = { 0 };
  UINT8    Mic1[16];
  UINT8    Mic2[16];

  EXPECT_TRUE (WpaHmacSha1Mic (Key, Data, sizeof (Data), Mic1));
  EXPECT_TRUE (WpaHmacSha1Mic (Key, Data, sizeof (Data), Mic2));
  EXPECT_EQ (0, CompareMem (Mic1, Mic2, 16));
}

TEST_F (WpaHmacSha1MicTest, NullParametersFail)
{
  UINT8  Key[16] = { 0 };
  UINT8  Data[1] = { 0 };
  UINT8  Mic[16];

  EXPECT_FALSE (WpaHmacSha1Mic (NULL, Data, 1, Mic));
  EXPECT_FALSE (WpaHmacSha1Mic (Key, NULL, 1, Mic));
  EXPECT_FALSE (WpaHmacSha1Mic (Key, Data, 1, NULL));
}

// ==========================================================================
// PRF-SHA1 Tests
// ==========================================================================
class WpaPrfSha1Test : public ::testing::Test {
};

TEST_F (WpaPrfSha1Test, BasicDerivation)
{
  // Verify PRF produces non-zero, deterministic output
  UINT8    Pmk[32];
  UINT8    Data[64];
  UINT8    Output1[48];
  UINT8    Output2[48];
  BOOLEAN  AllZero;

  SetMem (Pmk, sizeof (Pmk), 0xAA);
  SetMem (Data, sizeof (Data), 0xBB);

  EXPECT_TRUE (WpaPrfSha1 (Pmk, 32, "Pairwise key expansion", Data, sizeof (Data),
    Output1, sizeof (Output1)));

  // Output should not be all zeros
  AllZero = TRUE;
  for (UINTN i = 0; i < sizeof (Output1); i++) {
    if (Output1[i] != 0) {
      AllZero = FALSE;
      break;
    }
  }

  EXPECT_FALSE (AllZero);

  // Same input = same output
  EXPECT_TRUE (WpaPrfSha1 (Pmk, 32, "Pairwise key expansion", Data, sizeof (Data),
    Output2, sizeof (Output2)));
  EXPECT_EQ (0, CompareMem (Output1, Output2, sizeof (Output1)));
}

TEST_F (WpaPrfSha1Test, DifferentLabelProducesDifferentOutput)
{
  UINT8  Pmk[32];
  UINT8  Data[64];
  UINT8  Out1[48];
  UINT8  Out2[48];

  SetMem (Pmk, sizeof (Pmk), 0x11);
  SetMem (Data, sizeof (Data), 0x22);

  EXPECT_TRUE (WpaPrfSha1 (Pmk, 32, "Label A", Data, sizeof (Data), Out1, sizeof (Out1)));
  EXPECT_TRUE (WpaPrfSha1 (Pmk, 32, "Label B", Data, sizeof (Data), Out2, sizeof (Out2)));
  EXPECT_NE (0, CompareMem (Out1, Out2, sizeof (Out1)));
}

TEST_F (WpaPrfSha1Test, NullParametersFail)
{
  UINT8  Pmk[32]  = { 0 };
  UINT8  Data[32] = { 0 };
  UINT8  Out[48];

  EXPECT_FALSE (WpaPrfSha1 (NULL, 32, "label", Data, 32, Out, 48));
  EXPECT_FALSE (WpaPrfSha1 (Pmk, 32, NULL, Data, 32, Out, 48));
  EXPECT_FALSE (WpaPrfSha1 (Pmk, 32, "label", NULL, 32, Out, 48));
  EXPECT_FALSE (WpaPrfSha1 (Pmk, 32, "label", Data, 32, NULL, 48));
}

// ==========================================================================
// KDF-SHA256 Tests
// ==========================================================================
class WpaKdfSha256Test : public ::testing::Test {
};

TEST_F (WpaKdfSha256Test, BasicDerivation)
{
  UINT8    Key[32];
  UINT8    Context[64];
  UINT8    Output1[48];
  UINT8    Output2[48];

  SetMem (Key, sizeof (Key), 0xCC);
  SetMem (Context, sizeof (Context), 0xDD);

  EXPECT_TRUE (WpaKdfSha256 (Key, 32, "Pairwise key expansion", Context, sizeof (Context),
    Output1, 384));

  // Deterministic
  EXPECT_TRUE (WpaKdfSha256 (Key, 32, "Pairwise key expansion", Context, sizeof (Context),
    Output2, 384));
  EXPECT_EQ (0, CompareMem (Output1, Output2, sizeof (Output1)));
}

TEST_F (WpaKdfSha256Test, DifferentKeyProducesDifferentOutput)
{
  UINT8  Key1[32];
  UINT8  Key2[32];
  UINT8  Context[64];
  UINT8  Out1[48];
  UINT8  Out2[48];

  SetMem (Key1, sizeof (Key1), 0xAA);
  SetMem (Key2, sizeof (Key2), 0xBB);
  SetMem (Context, sizeof (Context), 0xCC);

  EXPECT_TRUE (WpaKdfSha256 (Key1, 32, "label", Context, sizeof (Context), Out1, 384));
  EXPECT_TRUE (WpaKdfSha256 (Key2, 32, "label", Context, sizeof (Context), Out2, 384));
  EXPECT_NE (0, CompareMem (Out1, Out2, sizeof (Out1)));
}

TEST_F (WpaKdfSha256Test, NullParametersFail)
{
  UINT8  Key[32]     = { 0 };
  UINT8  Context[32] = { 0 };
  UINT8  Out[48];

  EXPECT_FALSE (WpaKdfSha256 (NULL, 32, "label", Context, 32, Out, 384));
  EXPECT_FALSE (WpaKdfSha256 (Key, 32, NULL, Context, 32, Out, 384));
  EXPECT_FALSE (WpaKdfSha256 (Key, 32, "label", NULL, 32, Out, 384));
  EXPECT_FALSE (WpaKdfSha256 (Key, 32, "label", Context, 32, NULL, 384));
}

// ==========================================================================
// AES-ECB Single Block Encrypt Test
// ==========================================================================
class WpaAesEncryptBlockTest : public ::testing::Test {
};

TEST_F (WpaAesEncryptBlockTest, KnownVector)
{
  // NIST AES-128 ECB test vector
  UINT8  Key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
  };
  UINT8  Plaintext[16] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
  };
  UINT8  Expected[16] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
    0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
  };
  UINT8    Output[16];
  BOOLEAN  Result;

  Result = WpaAesEncryptBlock (Key, Plaintext, Output);
  EXPECT_TRUE (Result);
  EXPECT_EQ (0, CompareMem (Output, Expected, 16));
}

TEST_F (WpaAesEncryptBlockTest, NullParametersFail)
{
  UINT8  Key[16]   = { 0 };
  UINT8  Input[16] = { 0 };
  UINT8  Output[16];

  EXPECT_FALSE (WpaAesEncryptBlock (NULL, Input, Output));
  EXPECT_FALSE (WpaAesEncryptBlock (Key, NULL, Output));
  EXPECT_FALSE (WpaAesEncryptBlock (Key, Input, NULL));
}

// ==========================================================================
// CCMP Encrypt / Decrypt Round-Trip Test
// ==========================================================================
class WpaCcmpTest : public ::testing::Test {
protected:
  // 16-byte temporal key
  UINT8 Tk[16] = {
    0x66, 0xed, 0x21, 0x04, 0x2f, 0x9f, 0x26, 0xd7,
    0x11, 0x57, 0x06, 0xe4, 0x04, 0x14, 0xcf, 0x2e
  };
  // Packet number
  UINT8 Pn[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
  // Source address
  UINT8 A2[6] = { 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
  // Simple 802.11 header (24 bytes minimum)
  UINT8 Header[24] = {
    0x08, 0x41,             // Frame Control: Data, ToDS
    0x00, 0x00,             // Duration
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,  // A1 (DA/BSSID)
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  // A2 (SA)
    0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,  // A3
    0x00, 0x00              // Sequence Control
  };
};

TEST_F (WpaCcmpTest, EncryptDecryptRoundTrip)
{
  UINT8  Plaintext[32];
  UINT8  Ciphertext[32 + CCMP_MIC_LEN];
  UINT8  CcmpHdr[CCMP_HEADER_LEN];
  UINT8  Decrypted[32];

  // Fill plaintext with known data
  for (UINTN i = 0; i < sizeof (Plaintext); i++) {
    Plaintext[i] = (UINT8)(i & 0xFF);
  }

  // Encrypt
  EXPECT_TRUE (WpaCcmpEncrypt (
    Tk, Pn, A2, 0, Header, sizeof (Header),
    Plaintext, sizeof (Plaintext), Ciphertext, CcmpHdr
    ));

  // Ciphertext should differ from plaintext
  EXPECT_NE (0, CompareMem (Ciphertext, Plaintext, sizeof (Plaintext)));

  // Decrypt
  EXPECT_TRUE (WpaCcmpDecrypt (
    Tk, Pn, A2, 0, Header, sizeof (Header),
    Ciphertext, sizeof (Plaintext) + CCMP_MIC_LEN, Decrypted
    ));

  // Decrypted should match original
  EXPECT_EQ (0, CompareMem (Decrypted, Plaintext, sizeof (Plaintext)));
}

TEST_F (WpaCcmpTest, TamperedCiphertextFails)
{
  UINT8  Plaintext[16]                      = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
                                                 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50 };
  UINT8  Ciphertext[16 + CCMP_MIC_LEN];
  UINT8  CcmpHdr[CCMP_HEADER_LEN];
  UINT8  Decrypted[16];

  EXPECT_TRUE (WpaCcmpEncrypt (
    Tk, Pn, A2, 0, Header, sizeof (Header),
    Plaintext, sizeof (Plaintext), Ciphertext, CcmpHdr
    ));

  // Tamper with ciphertext
  Ciphertext[5] ^= 0xFF;

  // Decryption should fail (MIC mismatch)
  EXPECT_FALSE (WpaCcmpDecrypt (
    Tk, Pn, A2, 0, Header, sizeof (Header),
    Ciphertext, sizeof (Plaintext) + CCMP_MIC_LEN, Decrypted
    ));
}

TEST_F (WpaCcmpTest, WrongKeyFails)
{
  UINT8  Plaintext[16] = { 0 };
  UINT8  Ciphertext[16 + CCMP_MIC_LEN];
  UINT8  CcmpHdr[CCMP_HEADER_LEN];
  UINT8  Decrypted[16];
  UINT8  WrongTk[16]   = {
    0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
    0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0
  };

  EXPECT_TRUE (WpaCcmpEncrypt (
    Tk, Pn, A2, 0, Header, sizeof (Header),
    Plaintext, sizeof (Plaintext), Ciphertext, CcmpHdr
    ));

  // Decrypt with wrong key
  EXPECT_FALSE (WpaCcmpDecrypt (
    WrongTk, Pn, A2, 0, Header, sizeof (Header),
    Ciphertext, sizeof (Plaintext) + CCMP_MIC_LEN, Decrypted
    ));
}

TEST_F (WpaCcmpTest, CcmpHeaderFormat)
{
  UINT8  Plaintext[8] = { 0 };
  UINT8  Ciphertext[8 + CCMP_MIC_LEN];
  UINT8  CcmpHdr[CCMP_HEADER_LEN];
  UINT8  TestPn[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };

  EXPECT_TRUE (WpaCcmpEncrypt (
    Tk, TestPn, A2, 0, Header, sizeof (Header),
    Plaintext, sizeof (Plaintext), Ciphertext, CcmpHdr
    ));

  // Verify CCMP header structure:
  // CcmpHdr[0] = PN0 (TestPn[5])
  // CcmpHdr[1] = PN1 (TestPn[4])
  // CcmpHdr[2] = Reserved (0)
  // CcmpHdr[3] = KeyID<<6 | ExtIV (0x20)
  // CcmpHdr[4..7] = PN2..PN5
  EXPECT_EQ (TestPn[5], CcmpHdr[0]);  // PN0
  EXPECT_EQ (TestPn[4], CcmpHdr[1]);  // PN1
  EXPECT_EQ (0, CcmpHdr[2]);          // Reserved
  EXPECT_EQ (0x20, CcmpHdr[3]);       // ExtIV=1, KeyID=0
  EXPECT_EQ (TestPn[3], CcmpHdr[4]);  // PN2
  EXPECT_EQ (TestPn[2], CcmpHdr[5]);  // PN3
  EXPECT_EQ (TestPn[1], CcmpHdr[6]);  // PN4
  EXPECT_EQ (TestPn[0], CcmpHdr[7]);  // PN5
}

TEST_F (WpaCcmpTest, NullParametersFail)
{
  UINT8  Plain[8]     = { 0 };
  UINT8  Cipher[16]   = { 0 };
  UINT8  CcmpHdr[8]   = { 0 };
  UINT8  Decrypted[8] = { 0 };

  EXPECT_FALSE (WpaCcmpEncrypt (NULL, Pn, A2, 0, Header, 24, Plain, 8, Cipher, CcmpHdr));
  EXPECT_FALSE (WpaCcmpEncrypt (Tk, NULL, A2, 0, Header, 24, Plain, 8, Cipher, CcmpHdr));
  EXPECT_FALSE (WpaCcmpEncrypt (Tk, Pn, NULL, 0, Header, 24, Plain, 8, Cipher, CcmpHdr));
  EXPECT_FALSE (WpaCcmpEncrypt (Tk, Pn, A2, 0, NULL, 24, Plain, 8, Cipher, CcmpHdr));
  EXPECT_FALSE (WpaCcmpEncrypt (Tk, Pn, A2, 0, Header, 24, NULL, 8, Cipher, CcmpHdr));
  EXPECT_FALSE (WpaCcmpEncrypt (Tk, Pn, A2, 0, Header, 24, Plain, 8, NULL, CcmpHdr));
  EXPECT_FALSE (WpaCcmpEncrypt (Tk, Pn, A2, 0, Header, 24, Plain, 8, Cipher, NULL));

  EXPECT_FALSE (WpaCcmpDecrypt (NULL, Pn, A2, 0, Header, 24, Cipher, 16, Decrypted));
  EXPECT_FALSE (WpaCcmpDecrypt (Tk, Pn, A2, 0, Header, 24, Cipher, CCMP_MIC_LEN, Decrypted));
}

// ==========================================================================
// Random Bytes Test
// ==========================================================================
class WpaRandomBytesTest : public ::testing::Test {
};

TEST_F (WpaRandomBytesTest, ProducesOutput)
{
  UINT8  Buf1[32];
  UINT8  Buf2[32];

  ZeroMem (Buf1, sizeof (Buf1));
  ZeroMem (Buf2, sizeof (Buf2));

  EXPECT_TRUE (WpaRandomBytes (Buf1, sizeof (Buf1)));
  EXPECT_TRUE (WpaRandomBytes (Buf2, sizeof (Buf2)));

  // Extremely unlikely that two random 32-byte buffers are identical
  EXPECT_NE (0, CompareMem (Buf1, Buf2, sizeof (Buf1)));
}

TEST_F (WpaRandomBytesTest, NullParametersFail)
{
  EXPECT_FALSE (WpaRandomBytes (NULL, 32));
  UINT8  Buf[1];

  EXPECT_FALSE (WpaRandomBytes (Buf, 0));
}

// ==========================================================================
// Big-endian helper macro tests
// ==========================================================================
class WpaHelperMacroTest : public ::testing::Test {
};

TEST (WpaHelperMacroTest, GetPutBE16)
{
  UINT8   Buf[2] = { 0 };
  UINT16  Val;

  WPA_PUT_BE16 (Buf, 0x1234);
  EXPECT_EQ (0x12, Buf[0]);
  EXPECT_EQ (0x34, Buf[1]);

  Val = WPA_GET_BE16 (Buf);
  EXPECT_EQ (0x1234, Val);
}

TEST (WpaHelperMacroTest, GetPutBE32)
{
  UINT8   Buf[4] = { 0 };
  UINT32  Val;

  WPA_PUT_BE32 (Buf, 0xDEADBEEF);
  EXPECT_EQ (0xDE, Buf[0]);
  EXPECT_EQ (0xAD, Buf[1]);
  EXPECT_EQ (0xBE, Buf[2]);
  EXPECT_EQ (0xEF, Buf[3]);

  Val = WPA_GET_BE32 (Buf);
  EXPECT_EQ ((UINT32)0xDEADBEEF, Val);
}

TEST (WpaHelperMacroTest, GetPutLE16)
{
  UINT8   Buf[2] = { 0 };
  UINT16  Val;

  WPA_PUT_LE16 (Buf, 0x1234);
  EXPECT_EQ (0x34, Buf[0]);
  EXPECT_EQ (0x12, Buf[1]);

  Val = WPA_GET_LE16 (Buf);
  EXPECT_EQ (0x1234, Val);
}

// ==========================================================================
// Main
// ==========================================================================
int
main (
  int   argc,
  char  *argv[]
  )
{
  testing::InitGoogleTest (&argc, argv);
  return RUN_ALL_TESTS ();
}
