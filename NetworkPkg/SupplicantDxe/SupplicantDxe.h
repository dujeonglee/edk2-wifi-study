/** @file
  WPA2/WPA3 Personal Supplicant DXE Driver Header.

  Defines the private data structure and internal interfaces for the
  EFI Supplicant Protocol implementation.

  Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef SUPPLICANT_DXE_H_
#define SUPPLICANT_DXE_H_

#include <Uefi.h>

#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseCryptLib.h>

#include <Protocol/Supplicant.h>
#include <Protocol/WiFi2.h>
#include <Protocol/EapManagement.h>

#include "WpaCommon.h"
#include "WpaCrypto.h"
#include "WpaEapol.h"
#include "WpaSae.h"

#define SUPPLICANT_PRIVATE_DATA_SIGNATURE  SIGNATURE_32 ('W', 'P', 'A', 'S')

//
// Maximum supported AKM suites
//
#define MAX_SUPPORTED_AKM_SUITES     4
#define MAX_SUPPORTED_CIPHER_SUITES  4

///
/// PTK (Pairwise Transient Key) decomposition
///
typedef struct {
  UINT8    Kck[WPA_KCK_LEN];   ///< Key Confirmation Key
  UINT8    Kek[WPA_KEK_LEN];   ///< Key Encryption Key
  UINT8    Tk[WPA_TK_LEN];     ///< Temporal Key
} WPA_PTK;

///
/// GTK entry
///
typedef struct {
  UINT8    Key[WPA_GTK_MAX_LEN];
  UINT8    KeyLen;
  UINT8    KeyId;
  UINT8    Rsc[WPA_KEY_RSC_LEN];
  UINT8    RscLen;
} WPA_GTK_ENTRY;

///
/// IGTK entry
///
typedef struct {
  UINT8    Key[WPA_GTK_MAX_LEN];
  UINT8    KeyLen;
  UINT8    KeyId;
  UINT8    Ipn[6];
} WPA_IGTK_ENTRY;

///
/// Supplicant private data
///
struct _SUPPLICANT_PRIVATE_DATA {
  UINT32                      Signature;
  EFI_HANDLE                  Handle;
  EFI_SUPPLICANT_PROTOCOL     Supplicant;

  //
  // Configuration (set via SetData)
  //
  UINT8                       AkmSuiteOui[3];
  UINT8                       AkmSuiteType;       ///< Current AKM suite type
  UINT8                       PairwiseCipherOui[3];
  UINT8                       PairwiseCipherType;  ///< Current pairwise cipher
  UINT8                       GroupCipherOui[3];
  UINT8                       GroupCipherType;     ///< Current group cipher

  CHAR8                       Password[WPA_MAX_PASSWORD_LEN + 1];
  UINTN                       PasswordLen;

  EFI_80211_SSID              TargetSsid;
  EFI_80211_MAC_ADDRESS       StationMac;
  EFI_80211_MAC_ADDRESS       TargetBssid;

  //
  // PMK (either derived from PSK or provided externally for SAE)
  //
  UINT8                       Pmk[WPA_PMK_LEN];
  BOOLEAN                     PmkValid;

  //
  // 4-Way Handshake state
  //
  WPA_4WAY_STATE              FourWayState;
  UINT8                       ANonce[WPA_NONCE_LEN];
  UINT8                       SNonce[WPA_NONCE_LEN];
  UINT8                       ReplayCounter[WPA_REPLAY_CTR_LEN];
  WPA_PTK                     Ptk;
  BOOLEAN                     PtkValid;

  //
  // GTK / IGTK
  //
  WPA_GTK_ENTRY               Gtk[4];     ///< Up to 4 GTK entries
  UINT8                       GtkCount;
  WPA_IGTK_ENTRY              Igtk[2];    ///< Up to 2 IGTK entries
  UINT8                       IgtkCount;
  BOOLEAN                     GtkRefreshed;

  //
  // Link state
  //
  EFI_80211_LINK_STATE        LinkState;
  EFI_EAPOL_SUPPLICANT_PAE_STATE  PaeState;

  //
  // SAE session (for WPA3-Personal)
  //
  SAE_SESSION                 SaeSession;

  //
  // CCMP packet number (for encryption)
  //
  UINT8                       TxPn[CCMP_PN_LEN];

  //
  // Key descriptor version determined by AKM
  //
  UINT8                       KeyDescVersion;
};

#define SUPPLICANT_PRIVATE_FROM_PROTOCOL(p) \
  CR (p, SUPPLICANT_PRIVATE_DATA, Supplicant, SUPPLICANT_PRIVATE_DATA_SIGNATURE)

//
// Protocol function declarations (SupplicantImpl.c)
//

EFI_STATUS
EFIAPI
SupplicantBuildResponsePacket (
  IN     EFI_SUPPLICANT_PROTOCOL  *This,
  IN     UINT8                    *RequestBuffer      OPTIONAL,
  IN     UINTN                    RequestBufferSize   OPTIONAL,
  OUT    UINT8                    *Buffer,
  IN OUT UINTN                    *BufferSize
  );

EFI_STATUS
EFIAPI
SupplicantProcessPacket (
  IN     EFI_SUPPLICANT_PROTOCOL       *This,
  IN OUT EFI_SUPPLICANT_FRAGMENT_DATA  **FragmentTable,
  IN     UINT32                        *FragmentCount,
  IN     EFI_SUPPLICANT_CRYPT_MODE     CryptMode
  );

EFI_STATUS
EFIAPI
SupplicantSetData (
  IN EFI_SUPPLICANT_PROTOCOL   *This,
  IN EFI_SUPPLICANT_DATA_TYPE  DataType,
  IN VOID                      *Data,
  IN UINTN                     DataSize
  );

EFI_STATUS
EFIAPI
SupplicantGetData (
  IN     EFI_SUPPLICANT_PROTOCOL   *This,
  IN     EFI_SUPPLICANT_DATA_TYPE  DataType,
  OUT    UINT8                     *Data      OPTIONAL,
  IN OUT UINTN                     *DataSize
  );

#endif // SUPPLICANT_DXE_H_
