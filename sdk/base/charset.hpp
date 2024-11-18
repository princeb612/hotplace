/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_CHARSET__
#define __HOTPLACE_SDK_BASE_CHARSET__

#if defined __linux__  // linux

#if defined _UNICODE || defined UNICODE
#error "not supported"
#endif

#define _T(x) x
typedef char TCHAR;
typedef char* LPTSTR;
typedef const char* LPCTSTR;

#define _itot itoa
#define _sntprintf snprintf
#define _tcslen strlen
#define _tcsncmp strncmp
#define _ttoi atoi
#define _ttol atol
#define _vsntprintf vsnprintf

#define stricmp strcasecmp
#define strnicmp strncasecmp

#elif defined _WIN32 || defined _WIN64  // windows

#include <tchar.h>

#endif  // __linux__

#if defined _MBCS || defined MBCS
#elif defined _UNICODE || defined UNICODE
#else
#define _MBCS
#endif

#endif
