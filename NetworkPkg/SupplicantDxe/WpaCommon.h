/** @file
  Common WPA definitions for EAPOL packets, key structures, and IEEE 802.11 constants.

  This header defines the on-wire EAPOL frame formats used in the WPA2/WPA3
  4-Way Handshake and Group Key Handshake per IEEE 802.11-2020.

  Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef WPA_COMMON_H_
#define WPA_COMMON_H_

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>

//
// EAPOL Protocol Versions
//
#define EAPOL_VERSION_1  1  // IEEE 802.1X-2001
#define EAPOL_VERSION_2  2  // IEEE 802.1X-2004
#define EAPOL_VERSION_3  3  // IEEE 802.1X-2010

//
// EAPOL Packet Types
//
#define EAPOL_PACKET_TYPE_EAP       0
#define EAPOL_PACKET_TYPE_START     1
#define EAPOL_PACKET_TYPE_LOGOFF    2
#define EAPOL_PACKET_TYPE_KEY       3
#define EAPOL_PACKET_TYPE_ASF       4

//
// EAPOL-Key Descriptor Types
//
#define EAPOL_KEY_DESC_TYPE_RC4     1   // WPA (legacy)
#define EAPOL_KEY_DESC_TYPE_RSN     2   // WPA2/WPA3 (802.11i/RSN)

//
// Key Information field bit definitions (big-endian wire format)
// Bits are numbered from 0 (LSB) as per IEEE 802.11-2020 Figure 12-33
//
#define WPA_KEY_INFO_KEY_DESC_VERSION_MASK  0x0007  // Bits 0-2
#define WPA_KEY_INFO_KEY_TYPE               0x0008  // Bit 3: 0=Group, 1=Pairwise
#define WPA_KEY_INFO_INSTALL                0x0040  // Bit 6: Install flag
#define WPA_KEY_INFO_KEY_ACK                0x0080  // Bit 7: Key ACK
#define WPA_KEY_INFO_KEY_MIC                0x0100  // Bit 8: Key MIC
#define WPA_KEY_INFO_SECURE                 0x0200  // Bit 9: Secure
#define WPA_KEY_INFO_ERROR                  0x0400  // Bit 10: Error
#define WPA_KEY_INFO_REQUEST                0x0800  // Bit 11: Request
#define WPA_KEY_INFO_ENCRYPTED_KEY_DATA     0x1000  // Bit 12: Encrypted Key Data
#define WPA_KEY_INFO_SMK_MESSAGE            0x2000  // Bit 13: SMK Message

//
// Key Descriptor Versions
//
#define WPA_KEY_DESC_VERSION_HMAC_MD5_RC4     1  // HMAC-MD5 MIC, RC4 Key Wrap
#define WPA_KEY_DESC_VERSION_HMAC_SHA1_AES    2  // HMAC-SHA1-128 MIC, AES Key Wrap
#define WPA_KEY_DESC_VERSION_AES_CMAC         3  // AES-128-CMAC MIC, AES Key Wrap
#define WPA_KEY_DESC_VERSION_AKM_DEFINED      0  // AKM-defined (WPA3)

//
// AKM Suite Types (from IEEE 802.11-2020 Table 9-151)
//
#define WPA_AKM_SUITE_8021X            1
#define WPA_AKM_SUITE_PSK              2
#define WPA_AKM_SUITE_FT_8021X         3
#define WPA_AKM_SUITE_FT_PSK           4
#define WPA_AKM_SUITE_8021X_SHA256     5
#define WPA_AKM_SUITE_PSK_SHA256       6
#define WPA_AKM_SUITE_SAE              8
#define WPA_AKM_SUITE_FT_SAE           9
#define WPA_AKM_SUITE_8021X_SUITE_B    11
#define WPA_AKM_SUITE_8021X_SUITE_B192 12
#define WPA_AKM_SUITE_OWE              18

//
// Cipher Suite Types (from IEEE 802.11-2020 Table 9-149)
//
#define WPA_CIPHER_SUITE_USE_GROUP  0
#define WPA_CIPHER_SUITE_WEP40     1
#define WPA_CIPHER_SUITE_TKIP      2
#define WPA_CIPHER_SUITE_CCMP      4
#define WPA_CIPHER_SUITE_WEP104    5
#define WPA_CIPHER_SUITE_BIP       6
#define WPA_CIPHER_SUITE_GCMP      8
#define WPA_CIPHER_SUITE_GCMP256   9

//
// OUI for IEEE 802.11 RSN
//
#define WPA_RSN_OUI_BYTE0  0x00
#define WPA_RSN_OUI_BYTE1  0x0F
#define WPA_RSN_OUI_BYTE2  0xAC

//
// Key sizes
//
#define WPA_NONCE_LEN       32
#define WPA_MIC_LEN         16  // HMAC-SHA1-128, AES-128-CMAC
#define WPA_KCK_LEN         16  // Key Confirmation Key
#define WPA_KEK_LEN         16  // Key Encryption Key
#define WPA_TK_LEN          16  // Temporal Key (CCMP-128)
#define WPA_PTK_LEN         48  // KCK + KEK + TK (for CCMP)
#define WPA_PMK_LEN         32  // Pairwise Master Key
#define WPA_GMK_LEN         32  // Group Master Key
#define WPA_GTK_MAX_LEN     32  // Group Temporal Key
#define WPA_REPLAY_CTR_LEN  8
#define WPA_KEY_IV_LEN      16
#define WPA_KEY_RSC_LEN     8
#define WPA_MAC_ADDR_LEN    6

//
// CCMP Constants
//
#define CCMP_HEADER_LEN  8
#define CCMP_MIC_LEN     8
#define CCMP_PN_LEN      6
#define AES_BLOCK_SIZE   16

//
// PBKDF2 parameters for WPA2 PSK
//
#define WPA2_PBKDF2_ITERATIONS  4096

//
// Maximum password length
//
#define WPA_MAX_PASSWORD_LEN  63

//
// SAE constants
//
#define SAE_COMMIT_MAX_LEN   512
#define SAE_CONFIRM_MAX_LEN  256
#define SAE_KEYSEED_LEN      32
#define SAE_KCK_LEN          32
#define SAE_PMK_LEN          32

//
// SAE Authentication Frame Types
//
#define SAE_AUTH_ALGORITHM        3     // Authentication Algorithm Number for SAE
#define SAE_COMMIT_SEQ            1     // Transaction Sequence Number for Commit
#define SAE_CONFIRM_SEQ           2     // Transaction Sequence Number for Confirm
#define SAE_STATUS_SUCCESS        0

#pragma pack(1)

///
/// EAPOL Header (IEEE 802.1X-2010 Section 11.3)
///
typedef struct {
  UINT8     ProtocolVersion;
  UINT8     PacketType;
  UINT16    PacketBodyLength;   // Big-endian
} EAPOL_HEADER;

///
/// EAPOL-Key Frame Body (IEEE 802.11-2020 Figure 12-33)
/// Follows the EAPOL_HEADER when PacketType == EAPOL_PACKET_TYPE_KEY
///
typedef struct {
  UINT8     DescriptorType;
  UINT16    KeyInformation;     // Big-endian
  UINT16    KeyLength;          // Big-endian
  UINT8     ReplayCounter[WPA_REPLAY_CTR_LEN];
  UINT8     KeyNonce[WPA_NONCE_LEN];
  UINT8     EapolKeyIv[WPA_KEY_IV_LEN];
  UINT8     KeyRsc[WPA_KEY_RSC_LEN];
  UINT8     Reserved[8];
  UINT8     KeyMic[WPA_MIC_LEN];
  UINT16    KeyDataLength;      // Big-endian
  // UINT8  KeyData[];          // Variable-length key data follows
} EAPOL_KEY_FRAME;

///
/// SAE Authentication Frame (IEEE 802.11-2020 Section 12.4)
/// This is the body portion of an 802.11 Authentication frame for SAE.
///
typedef struct {
  UINT16    AuthAlgorithm;      // Must be SAE_AUTH_ALGORITHM (3)
  UINT16    TransactionSeq;     // 1=Commit, 2=Confirm
  UINT16    StatusCode;
  // Variable-length fields follow
} SAE_AUTH_FRAME;

///
/// RSN Information Element (simplified for key data)
///
typedef struct {
  UINT8     ElementId;          // 48 for RSN
  UINT8     Length;
  UINT16    Version;            // Must be 1
  UINT8     GroupCipherSuite[4];
  UINT16    PairwiseCipherSuiteCount;
  // Pairwise cipher suites follow
  // AKM suites follow
  // RSN capabilities follow
} RSN_IE_HEADER;

///
/// KDE (Key Data Encapsulation) format for EAPOL-Key key data
/// IEEE 802.11-2020 Figure 12-34
///
typedef struct {
  UINT8     Type;               // 0xDD for Vendor Specific
  UINT8     Length;
  UINT8     Oui[3];            // 00-0F-AC
  UINT8     DataType;
  // Data follows
} WPA_KDE_HEADER;

#pragma pack()

//
// KDE Data Types
//
#define WPA_KDE_TYPE_GTK     1
#define WPA_KDE_TYPE_MAC     3
#define WPA_KDE_TYPE_PMKID   4
#define WPA_KDE_TYPE_NONCE   6
#define WPA_KDE_TYPE_IGTK    9

//
// GTK KDE data format
//
#pragma pack(1)
typedef struct {
  UINT8    KeyId;     // Bits 0-1: Key ID, Bits 2-7: Tx
  UINT8    Reserved;
  // GTK follows
} WPA_GTK_KDE_DATA;

typedef struct {
  UINT8    KeyId;     // Bits 0-1: Key ID
  UINT8    Ipn[6];    // IGTK Packet Number
  // IGTK follows
} WPA_IGTK_KDE_DATA;
#pragma pack()

//
// Helper macros for big-endian conversions
//
#define WPA_GET_BE16(p)  ((UINT16)(((UINT8 *)(p))[0] << 8 | ((UINT8 *)(p))[1]))
#define WPA_PUT_BE16(p, v) do { \
    ((UINT8 *)(p))[0] = (UINT8)((UINT16)(v) >> 8); \
    ((UINT8 *)(p))[1] = (UINT8)((UINT16)(v) & 0xFF); \
  } while (0)

#define WPA_GET_BE32(p)  ((UINT32)(((UINT8 *)(p))[0] << 24 | ((UINT8 *)(p))[1] << 16 | \
                                   ((UINT8 *)(p))[2] << 8  | ((UINT8 *)(p))[3]))
#define WPA_PUT_BE32(p, v) do { \
    ((UINT8 *)(p))[0] = (UINT8)((UINT32)(v) >> 24); \
    ((UINT8 *)(p))[1] = (UINT8)((UINT32)(v) >> 16); \
    ((UINT8 *)(p))[2] = (UINT8)((UINT32)(v) >> 8); \
    ((UINT8 *)(p))[3] = (UINT8)((UINT32)(v) & 0xFF); \
  } while (0)

#define WPA_PUT_LE16(p, v) do { \
    ((UINT8 *)(p))[0] = (UINT8)((UINT16)(v) & 0xFF); \
    ((UINT8 *)(p))[1] = (UINT8)((UINT16)(v) >> 8); \
  } while (0)

#define WPA_GET_LE16(p)  ((UINT16)(((UINT8 *)(p))[0] | ((UINT8 *)(p))[1] << 8))

///
/// Size of the EAPOL-Key frame (header + key body, excluding variable key data)
///
#define EAPOL_KEY_FRAME_MIN_LEN  (sizeof (EAPOL_HEADER) + sizeof (EAPOL_KEY_FRAME))

#endif // WPA_COMMON_H_
