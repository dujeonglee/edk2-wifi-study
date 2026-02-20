/** @file
  WPA EAPOL 4-Way Handshake and Group Key Handshake Declarations.

  Implements the IEEE 802.11 EAPOL-Key handshake protocol for WPA2-Personal
  and WPA3-Personal (post-SAE authentication).

  Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef WPA_EAPOL_H_
#define WPA_EAPOL_H_

#include "WpaCommon.h"

//
// Forward declaration
//
typedef struct _SUPPLICANT_PRIVATE_DATA SUPPLICANT_PRIVATE_DATA;

///
/// 4-Way Handshake state
///
typedef enum {
  Wpa4WayIdle = 0,       ///< No handshake in progress
  Wpa4WayMsg1Received,   ///< Message 1 received, waiting to send Message 2
  Wpa4WayMsg2Sent,       ///< Message 2 sent, waiting for Message 3
  Wpa4WayMsg3Received,   ///< Message 3 received, waiting to send Message 4
  Wpa4WayComplete        ///< Handshake complete, keys installed
} WPA_4WAY_STATE;

///
/// Group Key Handshake state
///
typedef enum {
  WpaGroupKeyIdle = 0,
  WpaGroupKeyMsg1Received,
  WpaGroupKeyComplete
} WPA_GROUP_KEY_STATE;

/**
  Process an incoming EAPOL-Key frame and generate a response.

  Handles the 4-Way Handshake (Messages 1 and 3) and Group Key Handshake
  (Message 1). Generates the appropriate response (Messages 2, 4, or
  Group Key Message 2).

  @param[in]       Private       Supplicant private data with session state.
  @param[in]       RequestBuffer The incoming EAPOL packet.
  @param[in]       RequestSize   Size of the incoming packet.
  @param[out]      Buffer        Output buffer for the response packet.
  @param[in, out]  BufferSize    On input, size of Buffer. On output, required size.

  @retval EFI_SUCCESS            Response packet built successfully.
  @retval EFI_BUFFER_TOO_SMALL   Buffer is too small; required size returned.
  @retval EFI_INVALID_PARAMETER  Invalid input parameters.
  @retval EFI_NOT_READY          Handshake state does not expect this message.
  @retval EFI_SECURITY_VIOLATION MIC verification failed.
**/
EFI_STATUS
WpaEapolProcessKeyFrame (
  IN     SUPPLICANT_PRIVATE_DATA  *Private,
  IN     CONST UINT8              *RequestBuffer,
  IN     UINTN                    RequestSize,
  OUT    UINT8                    *Buffer,
  IN OUT UINTN                    *BufferSize
  );

/**
  Derive PTK (Pairwise Transient Key) from PMK, nonces, and MAC addresses.

  For WPA2-PSK (AKM 2): Uses PRF-SHA1 with "Pairwise key expansion" label.
  For WPA3-SAE (AKM 8) / PSK-SHA256 (AKM 6): Uses KDF-SHA256.

  @param[in]  Private   Supplicant private data containing PMK, nonces, and addresses.

  @retval TRUE   PTK derivation succeeded.
  @retval FALSE  PTK derivation failed.
**/
BOOLEAN
WpaDerivePtk (
  IN SUPPLICANT_PRIVATE_DATA  *Private
  );

/**
  Build RSN Information Element for EAPOL-Key Message 2.

  Constructs the RSN IE based on the configured AKM and cipher suites.

  @param[in]   Private   Supplicant private data.
  @param[out]  RsnIe     Output buffer for RSN IE.
  @param[out]  RsnIeLen  Length of the RSN IE.

  @retval TRUE   RSN IE built successfully.
  @retval FALSE  Failed to build RSN IE.
**/
BOOLEAN
WpaBuildRsnIe (
  IN  SUPPLICANT_PRIVATE_DATA  *Private,
  OUT UINT8                    *RsnIe,
  OUT UINTN                    *RsnIeLen
  );

/**
  Reset the EAPOL handshake state machine.

  @param[in]  Private   Supplicant private data.
**/
VOID
WpaEapolReset (
  IN SUPPLICANT_PRIVATE_DATA  *Private
  );

/**
  Update the KeyDescVersion field based on the current AKM and pairwise cipher.

  Call this whenever AkmSuiteType or PairwiseCipherType changes.
    Version 0 — AKM-defined (WPA3-SAE, PSK-SHA256)
    Version 1 — HMAC-MD5 MIC, RC4 key wrap (WPA1/TKIP)
    Version 2 — HMAC-SHA1-128 MIC, AES Key Wrap (WPA2/CCMP)

  @param[in,out]  Private  Supplicant private data.
**/
VOID
UpdateKeyDescVersion (
  IN OUT SUPPLICANT_PRIVATE_DATA  *Private
  );

#endif // WPA_EAPOL_H_
