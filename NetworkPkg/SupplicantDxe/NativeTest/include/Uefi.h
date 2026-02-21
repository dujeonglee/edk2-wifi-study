/** @file
  EDK2 type shims for native macOS/clang unit test builds.
  Maps UEFI/EDK2 types and macros to standard C equivalents.
**/

#ifndef UEFI_SHIM_H_
#define UEFI_SHIM_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* ---- Fundamental types ---- */
typedef uint8_t   UINT8;
typedef uint16_t  UINT16;
typedef uint32_t  UINT32;
typedef uint64_t  UINT64;
typedef int8_t    INT8;
typedef int16_t   INT16;
typedef int32_t   INT32;
typedef int64_t   INT64;
typedef size_t    UINTN;
typedef ptrdiff_t INTN;
typedef bool      BOOLEAN;
typedef void      VOID;
typedef char      CHAR8;
typedef uint16_t  CHAR16;

/* ---- Boolean constants ---- */
#define TRUE  true
#define FALSE false

/* ---- EDK2 annotation macros (no-ops on native) ---- */
#define IN
#define OUT
#define OPTIONAL
#define CONST     const
#define STATIC    static
#define EFIAPI
#define GLOBAL_REMOVE_IF_UNREFERENCED  __attribute__((unused))

/* ---- EFI_STATUS and common return codes ---- */
typedef UINTN EFI_STATUS;

#define EFI_SUCCESS             ((EFI_STATUS)0UL)
#define EFI_LOAD_ERROR          ((EFI_STATUS)(0x8000000000000001UL))
#define EFI_INVALID_PARAMETER   ((EFI_STATUS)(0x8000000000000002UL))
#define EFI_UNSUPPORTED         ((EFI_STATUS)(0x8000000000000003UL))
#define EFI_OUT_OF_RESOURCES    ((EFI_STATUS)(0x8000000000000009UL))
#define EFI_NOT_FOUND           ((EFI_STATUS)(0x800000000000000EUL))
#define EFI_SECURITY_VIOLATION  ((EFI_STATUS)(0x800000000000001AUL))

#define EFI_DEVICE_ERROR        ((EFI_STATUS)(0x8000000000000007UL))
#define EFI_ACCESS_DENIED       ((EFI_STATUS)(0x800000000000000FUL))
#define EFI_TIMEOUT             ((EFI_STATUS)(0x8000000000000012UL))
#define EFI_ABORTED             ((EFI_STATUS)(0x8000000000000015UL))

/* ---- EFI_GUID ---- */
typedef struct {
  UINT32  Data1;
  UINT16  Data2;
  UINT16  Data3;
  UINT8   Data4[8];
} EFI_GUID;

/* Pull in AsciiStrLen and friends so WpaCrypto.c doesn't need an explicit
   BaseLib include (EDK2 compilers get it transitively through the build system). */
#include <Library/BaseLib.h>

#endif /* UEFI_SHIM_H_ */
