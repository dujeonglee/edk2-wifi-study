/** @file
  WPA2/WPA3 Personal Supplicant DXE Driver Entry Point.

  This module installs the EFI_SUPPLICANT_PROTOCOL on a new handle.
  The WiFi Connection Manager (or other consumers) locates this protocol
  to perform WPA2-Personal and WPA3-Personal (SAE) authentication.

  Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SupplicantDxe.h"

//
// Module-level private data (single instance)
//
STATIC SUPPLICANT_PRIVATE_DATA  *mPrivateData = NULL;

//
// EFI Supplicant Protocol GUID
//
extern EFI_GUID  gEfiSupplicantProtocolGuid;

/**
  Initialize the supplicant private data with default values.

  @param[in,out]  Private   Private data structure to initialize.
**/
STATIC
VOID
InitializePrivateData (
  IN OUT SUPPLICANT_PRIVATE_DATA  *Private
  )
{
  ZeroMem (Private, sizeof (SUPPLICANT_PRIVATE_DATA));

  Private->Signature = SUPPLICANT_PRIVATE_DATA_SIGNATURE;

  //
  // Set up protocol function pointers
  //
  Private->Supplicant.BuildResponsePacket = SupplicantBuildResponsePacket;
  Private->Supplicant.ProcessPacket       = SupplicantProcessPacket;
  Private->Supplicant.SetData             = SupplicantSetData;
  Private->Supplicant.GetData             = SupplicantGetData;

  //
  // Default to WPA2-PSK with CCMP
  //
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

/**
  The entry point for the Supplicant DXE driver.

  Installs the EFI Supplicant Protocol on a new handle so that the
  WiFi Connection Manager can locate and use it.

  @param[in]  ImageHandle  The firmware allocated handle for the driver image.
  @param[in]  SystemTable  A pointer to the EFI System Table.

  @retval EFI_SUCCESS      The protocol was installed successfully.
  @retval Others           Failed to install the protocol.
**/
EFI_STATUS
EFIAPI
SupplicantDxeDriverEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "[Supplicant] WPA2/WPA3 Personal Supplicant Driver loading\n"));

  //
  // Allocate and initialize private data
  //
  mPrivateData = AllocateZeroPool (sizeof (SUPPLICANT_PRIVATE_DATA));
  if (mPrivateData == NULL) {
    DEBUG ((DEBUG_ERROR, "[Supplicant] Failed to allocate private data\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  InitializePrivateData (mPrivateData);

  //
  // Install the Supplicant Protocol on a new handle
  //
  mPrivateData->Handle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &mPrivateData->Handle,
                  &gEfiSupplicantProtocolGuid,
                  &mPrivateData->Supplicant,
                  NULL
                  );

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[Supplicant] Failed to install protocol: %r\n", Status));
    FreePool (mPrivateData);
    mPrivateData = NULL;
    return Status;
  }

  DEBUG ((DEBUG_INFO, "[Supplicant] Protocol installed successfully\n"));
  DEBUG ((DEBUG_INFO, "[Supplicant] Supported: WPA2-Personal (PSK), WPA3-Personal (SAE)\n"));

  return EFI_SUCCESS;
}

/**
  Unload handler for the Supplicant driver.

  @param[in]  ImageHandle  Handle of the driver to unload.

  @retval EFI_SUCCESS      Driver unloaded successfully.
  @retval Others           Failed to unload.
**/
EFI_STATUS
EFIAPI
SupplicantDxeDriverUnload (
  IN EFI_HANDLE  ImageHandle
  )
{
  EFI_STATUS  Status;

  if (mPrivateData == NULL) {
    return EFI_SUCCESS;
  }

  //
  // Uninstall the protocol
  //
  Status = gBS->UninstallMultipleProtocolInterfaces (
                  mPrivateData->Handle,
                  &gEfiSupplicantProtocolGuid,
                  &mPrivateData->Supplicant,
                  NULL
                  );

  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Clean up SAE session
  //
  SaeCleanup (&mPrivateData->SaeSession);

  //
  // Zero sensitive data before freeing
  //
  ZeroMem (mPrivateData->Password, sizeof (mPrivateData->Password));
  ZeroMem (mPrivateData->Pmk, sizeof (mPrivateData->Pmk));
  ZeroMem (&mPrivateData->Ptk, sizeof (mPrivateData->Ptk));
  ZeroMem (mPrivateData->Gtk, sizeof (mPrivateData->Gtk));
  ZeroMem (mPrivateData->Igtk, sizeof (mPrivateData->Igtk));

  FreePool (mPrivateData);
  mPrivateData = NULL;

  DEBUG ((DEBUG_INFO, "[Supplicant] Driver unloaded\n"));
  return EFI_SUCCESS;
}
