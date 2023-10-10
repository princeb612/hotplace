/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_LINUX_TYPES__
#define __HOTPLACE_SDK_BASE_SYSTEM_LINUX_TYPES__

#include <limits.h>
#include <stdint.h>

namespace hotplace {

typedef int8_t int8;
typedef int8_t sint8;
typedef uint8_t uint8;
typedef int16_t int16;
typedef int16_t sint16;
typedef uint16_t uint16;
typedef int32_t int32;
typedef int32_t sint32;
typedef uint32_t uint32;
typedef int64_t int64;
typedef int64_t sint64;
typedef uint64_t uint64;
#if defined __SIZEOF_INT128__
typedef __int128_t int128;
typedef __int128_t sint128;
typedef __uint128_t uint128;
#endif

#if __WORDSIZE == 32
typedef uint32_t arch_t;
typedef uint64_t time64_t;
#elif __WORDSIZE == 64
typedef uint64_t arch_t;
typedef uint64_t time64_t;
#endif

typedef int handle_t;

typedef union _LARGE_INTEGER {
    struct {
        uint32 LowPart;
        uint32 HighPart;
    };
    struct {
        uint32 LowPart;
        uint32 HighPart;
    } u;
    uint64 QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

#define INVALID_SOCKET -1

}  // namespace hotplace

#endif
