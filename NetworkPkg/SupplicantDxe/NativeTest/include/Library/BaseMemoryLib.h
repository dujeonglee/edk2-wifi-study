/** @file
  BaseMemoryLib shim: maps EDK2 memory primitives to C standard library.
**/

#ifndef BASE_MEMORY_LIB_SHIM_H_
#define BASE_MEMORY_LIB_SHIM_H_

#include <Uefi.h>
#include <string.h>

static inline VOID *
CopyMem (
  VOID        *Dest,
  const VOID  *Src,
  UINTN       Len
  )
{
  memcpy (Dest, Src, Len);
  return Dest;
}

static inline VOID *
ZeroMem (
  VOID   *Dest,
  UINTN  Len
  )
{
  memset (Dest, 0, Len);
  return Dest;
}

static inline VOID *
SetMem (
  VOID   *Dest,
  UINTN  Len,
  UINT8  Val
  )
{
  memset (Dest, (int)Val, Len);
  return Dest;
}

static inline INTN
CompareMem (
  const VOID  *A,
  const VOID  *B,
  UINTN       Len
  )
{
  return (INTN)memcmp (A, B, Len);
}

#endif /* BASE_MEMORY_LIB_SHIM_H_ */
