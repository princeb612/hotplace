/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_TYPES__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_TYPES__

// #warning Please include winsock2.h before windows.h
#include <winsock2.h>
#include <windows.h>

namespace hotplace {

typedef __int8 int8;
typedef __int8 sint8;
typedef unsigned __int8 uint8;
typedef __int16 int16;
typedef __int16 sint16;
typedef unsigned __int16 uint16;
typedef __int32 int32;
typedef __int32 sint32;
#if defined __MINGW32__
typedef long unsigned int uint32;
#else
typedef unsigned __int32 uint32;
#endif
typedef __int64 int64;
typedef __int64 sint64;
typedef unsigned __int64 uint64;
#if defined __SIZEOF_INT128__
typedef __int128 int128;
typedef __int128 sint128;
typedef unsigned __int128 uint128;
#endif

#ifdef _WIN64
typedef uint64 arch_t;
#elif defined _WIN32
typedef uint32 arch_t;
#else
#error _WIN32 or _WIN64 not defined
#endif
typedef __int128_t time64_t;

//typedef __int16 wchar;

typedef HANDLE handle_t;

} // namespace

#endif
