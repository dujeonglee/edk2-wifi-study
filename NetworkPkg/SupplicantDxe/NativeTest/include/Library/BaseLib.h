/** @file
  BaseLib shim: maps EDK2 string/math utilities to C stdlib equivalents.
**/

#ifndef BASE_LIB_SHIM_H_
#define BASE_LIB_SHIM_H_

#include <Uefi.h>
#include <string.h>

static inline UINTN
AsciiStrLen (
  const CHAR8  *String
  )
{
  return strlen (String);
}

static inline UINTN
AsciiStrnLenS (
  const CHAR8  *String,
  UINTN        MaxSize
  )
{
  return strnlen (String, MaxSize);
}

#endif /* BASE_LIB_SHIM_H_ */
