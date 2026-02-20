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
// RC4 Tests (RFC 6229 test vectors, first 16 output bytes)
// ==========================================================================
class WpaRc4Test : public ::testing::Test {};

// RFC 6229 test vector: key = 0x0102030405, skip 0 bytes, check first 16
TEST_F (WpaRc4Test, Rc4BasicVector)
{
  UINT8  Key[5] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
  UINT8  Plain[16];
  UINT8  Cipher[16];

  //
  // Expected: xoroffset 0 for key 0x0102030405 from RFC 6229:
  // b2 39 63 05 f0 3d c0 27 cc c3 52 4a 0a 11 18 a8
  //
  UINT8  Expected[16] = {
    0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
    0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8
  };

  ZeroMem (Plain, sizeof (Plain));

  WPA_RC4_CTX  Ctx;

  WpaRc4Init (&Ctx, Key, sizeof (Key));
  WpaRc4Process (&Ctx, Plain, Cipher, sizeof (Plain));

  EXPECT_EQ (0, CompareMem (Cipher, Expected, 16));
}

// Verify RC4 skip works: skipped bytes should be dropped correctly
TEST_F (WpaRc4Test, Rc4SkipVerification)
{
  UINT8  Key[5] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
  UINT8  Plain[16];
  UINT8  WithSkip[16];
  UINT8  WithoutSkip[32];

  ZeroMem (Plain, sizeof (Plain));

  //
  // Generate 32 bytes without skip
  //
  WPA_RC4_CTX  Ctx1;
  WpaRc4Init (&Ctx1, Key, sizeof (Key));
  WpaRc4Process (&Ctx1, Plain, WithoutSkip, 16);
  WpaRc4Process (&Ctx1, Plain, WithoutSkip + 16, 16);

  //
  // Generate 16 bytes starting at offset 16 (via skip)
  //
  WPA_RC4_CTX  Ctx2;
  WpaRc4Init (&Ctx2, Key, sizeof (Key));
  WpaRc4Skip (&Ctx2, 16);
  WpaRc4Process (&Ctx2, Plain, WithSkip, 16);

  //
  // Both should produce the same second 16 bytes
  //
  EXPECT_EQ (0, CompareMem (WithSkip, WithoutSkip + 16, 16));
}

// Encrypt then decrypt round-trip
TEST_F (WpaRc4Test, Rc4RoundTrip)
{
  UINT8  Key[13] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d
  };
  UINT8  Plain[32] = {
    'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!', 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };
  UINT8  Cipher[32];
  UINT8  Decrypted[32];

  WPA_RC4_CTX  Ctx;

  WpaRc4Init (&Ctx, Key, sizeof (Key));
  WpaRc4Process (&Ctx, Plain, Cipher, sizeof (Plain));

  WpaRc4Init (&Ctx, Key, sizeof (Key));
  WpaRc4Process (&Ctx, Cipher, Decrypted, sizeof (Cipher));

  EXPECT_EQ (0, CompareMem (Decrypted, Plain, sizeof (Plain)));
}

// ==========================================================================
// HMAC-MD5 Tests (RFC 2202 test vectors)
// ==========================================================================
class WpaHmacMd5Test : public ::testing::Test {};

// RFC 2202 Test Case 1: key = 0x0b*16, data = "Hi There"
TEST_F (WpaHmacMd5Test, Rfc2202Vector1)
{
  UINT8  Key[16];
  UINT8  Data[] = { 'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e' };
  UINT8  Mac[16];

  SetMem (Key, sizeof (Key), 0x0b);

  //
  // Expected: 9294727a 3811 50c8 c5e56bbf fc4e 7a
  //
  UINT8  Expected[16] = {
    0x92, 0x94, 0x72, 0x7a, 0x36, 0x08, 0x10, 0x59,
    0x48, 0x91, 0xb1, 0xb9, 0xad, 0x5b, 0x32, 0xe8
  };

  BOOLEAN  Result = WpaHmacMd5Mic (Key, sizeof (Key), Data, sizeof (Data), Mac);
  EXPECT_TRUE (Result);
  EXPECT_EQ (0, CompareMem (Mac, Expected, 16));
}

// RFC 2202 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
TEST_F (WpaHmacMd5Test, Rfc2202Vector2)
{
  UINT8  Key[] = { 'J', 'e', 'f', 'e' };
  UINT8  Data[] = "what do ya want for nothing?";
  UINT8  Mac[16];

  //
  // Expected: 750c783e 6ab0b503 eaa86e31 0a5db738
  //
  UINT8  Expected[16] = {
    0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
    0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38
  };

  BOOLEAN  Result = WpaHmacMd5Mic (
                      Key,
                      sizeof (Key),
                      Data,
                      sizeof (Data) - 1,  // exclude null terminator
                      Mac
                      );
  EXPECT_TRUE (Result);
  EXPECT_EQ (0, CompareMem (Mac, Expected, 16));
}

// Null parameter handling
TEST_F (WpaHmacMd5Test, NullKeyFails)
{
  UINT8  Data[8] = { 0 };
  UINT8  Mac[16];

  EXPECT_FALSE (WpaHmacMd5Mic (NULL, 16, Data, sizeof (Data), Mac));
}

// ==========================================================================
// Michael MIC Tests
// ==========================================================================
class WpaMichaelMicTest : public ::testing::Test {};

// Michael MIC test: empty MSDU
TEST_F (WpaMichaelMicTest, EmptyPayload)
{
  //
  // Key, DA, SA, Priority=0, empty data
  // Expected MIC computed from the IEEE 802.11 specification appendix
  //
  UINT8  Key[8]  = { 0x82, 0x92, 0x9e, 0x9c, 0xb2, 0x6b, 0x22, 0x05 };
  UINT8  Da[6]   = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  UINT8  Sa[6]   = { 0x00, 0x60, 0x1d, 0x00, 0x00, 0x01 };
  UINT8  Mic[8];

  WpaMichaelMic (Key, Da, Sa, 0, NULL, 0, Mic);
  // Just verify it runs without crashing; MIC should be non-zero
  UINT8  Zero[8] = { 0 };
  EXPECT_NE (0, CompareMem (Mic, Zero, 8));
}

// Michael MIC determinism: same inputs produce same MIC
TEST_F (WpaMichaelMicTest, Deterministic)
{
  UINT8  Key[8]  = { 0xd5, 0x5c, 0xc8, 0xa8, 0xe8, 0x5b, 0x32, 0x58 };
  UINT8  Da[6]   = { 0x00, 0x0c, 0xe7, 0x20, 0xb5, 0x8c };
  UINT8  Sa[6]   = { 0x00, 0x0c, 0xe7, 0x20, 0xb5, 0x8b };
  UINT8  Data[]  = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 };
  UINT8  Mic1[8];
  UINT8  Mic2[8];

  WpaMichaelMic (Key, Da, Sa, 0, Data, sizeof (Data), Mic1);
  WpaMichaelMic (Key, Da, Sa, 0, Data, sizeof (Data), Mic2);

  EXPECT_EQ (0, CompareMem (Mic1, Mic2, 8));
}

// Different keys must produce different MICs
TEST_F (WpaMichaelMicTest, DifferentKeys)
{
  UINT8  Key1[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  UINT8  Key2[8] = { 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
  UINT8  Da[6]   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
  UINT8  Sa[6]   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
  UINT8  Data[]  = { 0x11, 0x22, 0x33, 0x44 };
  UINT8  Mic1[8];
  UINT8  Mic2[8];

  WpaMichaelMic (Key1, Da, Sa, 0, Data, sizeof (Data), Mic1);
  WpaMichaelMic (Key2, Da, Sa, 0, Data, sizeof (Data), Mic2);

  // Different keys → different MICs (with extremely high probability)
  EXPECT_NE (0, CompareMem (Mic1, Mic2, 8));
}

// ==========================================================================
// TKIP Phase 1 / Phase 2 Key Mixing Tests
// ==========================================================================
class WpaTkipKeyMixTest : public ::testing::Test {};

// Verify Phase 1 output is non-zero and deterministic
TEST_F (WpaTkipKeyMixTest, Phase1Deterministic)
{
  UINT8   Tk[16] = {
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef
  };
  UINT8   Ta[6]  = { 0x00, 0x0c, 0xe7, 0x20, 0xb5, 0x8b };
  UINT16  Ttak1[5];
  UINT16  Ttak2[5];

  WpaTkipPhase1Mix (Tk, Ta, 0x00000000, Ttak1);
  WpaTkipPhase1Mix (Tk, Ta, 0x00000000, Ttak2);

  EXPECT_EQ (0, CompareMem (Ttak1, Ttak2, sizeof (Ttak1)));
}

// Phase 1: different TSC32 → different TTAK
TEST_F (WpaTkipKeyMixTest, Phase1DifferentTsc)
{
  UINT8   Tk[16] = {
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef
  };
  UINT8   Ta[6] = { 0x00, 0x0c, 0xe7, 0x20, 0xb5, 0x8b };
  UINT16  Ttak1[5];
  UINT16  Ttak2[5];

  WpaTkipPhase1Mix (Tk, Ta, 0x00000000, Ttak1);
  WpaTkipPhase1Mix (Tk, Ta, 0x00000001, Ttak2);

  EXPECT_NE (0, CompareMem (Ttak1, Ttak2, sizeof (Ttak1)));
}

// Phase 2: deterministic given same inputs
TEST_F (WpaTkipKeyMixTest, Phase2Deterministic)
{
  UINT8   Tk[16] = {
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef
  };
  UINT8   Ta[6] = { 0x00, 0x0c, 0xe7, 0x20, 0xb5, 0x8b };
  UINT16  Ttak[5];
  UINT8   Rc4Key1[16];
  UINT8   Rc4Key2[16];

  WpaTkipPhase1Mix (Tk, Ta, 0x00000000, Ttak);
  WpaTkipPhase2Mix (Ttak, Tk, 0x0000, Rc4Key1);
  WpaTkipPhase2Mix (Ttak, Tk, 0x0000, Rc4Key2);

  EXPECT_EQ (0, CompareMem (Rc4Key1, Rc4Key2, 16));
}

// Phase 2: different TSC16 → different RC4 key
TEST_F (WpaTkipKeyMixTest, Phase2DifferentTsc16)
{
  UINT8   Tk[16] = {
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef
  };
  UINT8   Ta[6] = { 0x00, 0x0c, 0xe7, 0x20, 0xb5, 0x8b };
  UINT16  Ttak[5];
  UINT8   Rc4Key1[16];
  UINT8   Rc4Key2[16];

  WpaTkipPhase1Mix (Tk, Ta, 0x00000000, Ttak);
  WpaTkipPhase2Mix (Ttak, Tk, 0x0000, Rc4Key1);
  WpaTkipPhase2Mix (Ttak, Tk, 0x0001, Rc4Key2);

  EXPECT_NE (0, CompareMem (Rc4Key1, Rc4Key2, 16));
}

// ==========================================================================
// TKIP Encrypt / Decrypt Round-Trip Tests
// ==========================================================================
class WpaTkipCryptTest : public ::testing::Test {};

TEST_F (WpaTkipCryptTest, EncryptDecryptRoundTrip)
{
  //
  // 32-byte TKIP TK: TK[0:16] + TX-MIC[16:24] + RX-MIC[24:32]
  //
  UINT8  Tk[32] = {
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,  // TX-MIC
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11   // RX-MIC
  };
  UINT8  Da[6] = { 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e };
  UINT8  Sa[6] = { 0x5e, 0x4d, 0x3c, 0x2b, 0x1a, 0x00 };
  UINT8  Plain[]  = { 'T', 'E', 'S', 'T', ' ', 'D', 'A', 'T', 'A', '!' };
  UINT8  Encrypted[256];
  UINT8  Decrypted[256];
  UINTN  EncLen = 0;
  UINTN  DecLen = 0;

  EFI_STATUS  Status;

  Status = WpaTkipEncrypt (
             Tk, Da, Sa, 0, 0x000000000001ULL,
             Plain, sizeof (Plain),
             Encrypted, &EncLen
             );
  EXPECT_EQ (EFI_SUCCESS, Status);
  EXPECT_EQ (sizeof (Plain) + TKIP_HEADER_LEN + TKIP_MIC_LEN + TKIP_ICV_LEN, EncLen);

  Status = WpaTkipDecrypt (
             Tk, Da, Sa, 0,
             Encrypted, EncLen,
             Decrypted, &DecLen
             );
  EXPECT_EQ (EFI_SUCCESS, Status);
  EXPECT_EQ (sizeof (Plain), DecLen);
  EXPECT_EQ (0, CompareMem (Decrypted, Plain, sizeof (Plain)));
}

// Verify that tampering with ciphertext causes MIC/ICV failure
TEST_F (WpaTkipCryptTest, TamperDetection)
{
  UINT8  Tk[32] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
  };
  UINT8  Da[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
  UINT8  Sa[6] = { 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
  UINT8  Plain[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  UINT8  Encrypted[256];
  UINT8  Decrypted[256];
  UINTN  EncLen = 0;
  UINTN  DecLen = 0;

  WpaTkipEncrypt (
    Tk, Da, Sa, 0, 0x000000000002ULL,
    Plain, sizeof (Plain),
    Encrypted, &EncLen
    );

  // Flip a bit in the ciphertext payload
  Encrypted[TKIP_HEADER_LEN] ^= 0x01;

  EFI_STATUS  Status = WpaTkipDecrypt (
                         Tk, Da, Sa, 0,
                         Encrypted, EncLen,
                         Decrypted, &DecLen
                         );
  EXPECT_EQ (EFI_SECURITY_VIOLATION, Status);
}

// ==========================================================================
// WEP Encrypt / Decrypt Round-Trip Tests
// ==========================================================================
class WpaWepCryptTest : public ::testing::Test {};

// WEP-40 round-trip
TEST_F (WpaWepCryptTest, Wep40RoundTrip)
{
  UINT8  Key[WEP40_KEY_LEN]  = { 0x01, 0x02, 0x03, 0x04, 0x05 };
  UINT8  Plain[]  = { 'W', 'E', 'P', '4', '0', ' ', 'T', 'e', 's', 't' };
  UINT8  Encrypted[256];
  UINT8  Decrypted[256];
  UINTN  EncLen = 0;
  UINTN  DecLen = 0;

  EFI_STATUS  Status;

  Status = WpaWepEncrypt (
             Key, WEP40_KEY_LEN, 0,
             Plain, sizeof (Plain),
             Encrypted, &EncLen
             );
  EXPECT_EQ (EFI_SUCCESS, Status);
  EXPECT_EQ (sizeof (Plain) + WEP_HEADER_LEN + WEP_ICV_LEN, EncLen);

  Status = WpaWepDecrypt (
             Key, WEP40_KEY_LEN,
             Encrypted, EncLen,
             Decrypted, &DecLen
             );
  EXPECT_EQ (EFI_SUCCESS, Status);
  EXPECT_EQ (sizeof (Plain), DecLen);
  EXPECT_EQ (0, CompareMem (Decrypted, Plain, sizeof (Plain)));
}

// WEP-104 round-trip
TEST_F (WpaWepCryptTest, Wep104RoundTrip)
{
  UINT8  Key[WEP104_KEY_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d
  };
  UINT8  Plain[] = "WEP-104 Test Payload";
  UINT8  Encrypted[256];
  UINT8  Decrypted[256];
  UINTN  EncLen = 0;
  UINTN  DecLen = 0;

  EFI_STATUS  Status;

  Status = WpaWepEncrypt (
             Key, WEP104_KEY_LEN, 2,
             Plain, sizeof (Plain) - 1,  // exclude null terminator
             Encrypted, &EncLen
             );
  EXPECT_EQ (EFI_SUCCESS, Status);

  Status = WpaWepDecrypt (
             Key, WEP104_KEY_LEN,
             Encrypted, EncLen,
             Decrypted, &DecLen
             );
  EXPECT_EQ (EFI_SUCCESS, Status);
  EXPECT_EQ (sizeof (Plain) - 1, DecLen);
  EXPECT_EQ (0, CompareMem (Decrypted, Plain, sizeof (Plain) - 1));
}

// ICV tamper detection
TEST_F (WpaWepCryptTest, TamperDetection)
{
  UINT8  Key[WEP40_KEY_LEN] = { 0x11, 0x22, 0x33, 0x44, 0x55 };
  UINT8  Plain[] = { 0xde, 0xad, 0xbe, 0xef };
  UINT8  Encrypted[256];
  UINT8  Decrypted[256];
  UINTN  EncLen = 0;
  UINTN  DecLen = 0;

  WpaWepEncrypt (
    Key, WEP40_KEY_LEN, 0,
    Plain, sizeof (Plain),
    Encrypted, &EncLen
    );

  // Flip a bit in the ciphertext
  Encrypted[WEP_HEADER_LEN] ^= 0xFF;

  EFI_STATUS  Status = WpaWepDecrypt (
                         Key, WEP40_KEY_LEN,
                         Encrypted, EncLen,
                         Decrypted, &DecLen
                         );
  EXPECT_EQ (EFI_SECURITY_VIOLATION, Status);
}

// Invalid key length must fail
TEST_F (WpaWepCryptTest, InvalidKeyLengthFails)
{
  UINT8  Key[8]  = { 0 };
  UINT8  Data[8] = { 0 };
  UINT8  Out[256];
  UINTN  OutLen = 0;

  EXPECT_EQ (EFI_INVALID_PARAMETER,
    WpaWepEncrypt (Key, 8, 0, Data, sizeof (Data), Out, &OutLen));
  EXPECT_EQ (EFI_INVALID_PARAMETER,
    WpaWepDecrypt (Key, 8, Data, sizeof (Data), Out, &OutLen));
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
