/** @file
  MemoryAllocationLib shim: maps EDK2 heap functions to malloc/free.
**/

#ifndef MEMORY_ALLOCATION_LIB_SHIM_H_
#define MEMORY_ALLOCATION_LIB_SHIM_H_

#include <Uefi.h>
#include <stdlib.h>
#include <string.h>

static inline VOID *
AllocatePool (
  UINTN  Size
  )
{
  return malloc (Size);
}

static inline VOID *
AllocateZeroPool (
  UINTN  Size
  )
{
  return calloc (1, Size);
}

static inline VOID
FreePool (
  VOID  *Ptr
  )
{
  free (Ptr);
}

#endif /* MEMORY_ALLOCATION_LIB_SHIM_H_ */
