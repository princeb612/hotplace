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

#if defined _WIN32 || defined _WIN64
    #include <tchar.h>
#elif defined __linux__
    #if defined _UNICODE || defined UNICODE
        #error "not supported"
    #endif

    #define _T(x) x
typedef char TCHAR;
typedef char* LPTSTR;
typedef const char* LPCTSTR;

    #define _tcslen strlen
    #define _tcsncmp strncmp
    #define stricmp strcasecmp
    #define strnicmp strncasecmp
#endif

#if defined _MBCS || defined MBCS
#elif defined _UNICODE || defined UNICODE
#else
    #define _MBCS
#endif

#endif
