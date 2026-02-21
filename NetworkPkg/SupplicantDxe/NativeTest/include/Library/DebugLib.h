/** @file
  DebugLib shim: no-op DEBUG(), assert-based ASSERT().
**/

#ifndef DEBUG_LIB_SHIM_H_
#define DEBUG_LIB_SHIM_H_

#include <assert.h>

/* Debug levels (unused in shim but referenced by WpaCrypto.c) */
#define DEBUG_INIT      0x00000001UL
#define DEBUG_WARN      0x00000002UL
#define DEBUG_LOAD      0x00000004UL
#define DEBUG_FS        0x00000008UL
#define DEBUG_POOL      0x00000010UL
#define DEBUG_PAGE      0x00000020UL
#define DEBUG_INFO      0x00000040UL
#define DEBUG_DISPATCH  0x00000080UL
#define DEBUG_VARIABLE  0x00000100UL
#define DEBUG_BM        0x00000400UL
#define DEBUG_BLKIO     0x00001000UL
#define DEBUG_NET       0x00004000UL
#define DEBUG_UNDI      0x00010000UL
#define DEBUG_LOADFILE  0x00020000UL
#define DEBUG_EVENT     0x00080000UL
#define DEBUG_GCD       0x00100000UL
#define DEBUG_CACHE     0x00200000UL
#define DEBUG_VERBOSE   0x00400000UL
#define DEBUG_ERROR     0x80000000UL

/* Silently discard all DEBUG() calls */
#define DEBUG(args)  do {} while (0)

/* Map ASSERT to C standard assert */
#define ASSERT(expression)  assert (expression)

#endif /* DEBUG_LIB_SHIM_H_ */
