/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_WS2_32__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_WS2_32__

// #include <winsock2.h>

#if defined _WINSOCK2API_

// Windows 2000

/* "WSALookupServiceBeginA" */
#define DECLARE_NAMEOF_API_WSALOOKUPSERVICEBEGINA                                                                        \
    CHAR NAMEOF_API_WSALOOKUPSERVICEBEGINA[] = {                                                                         \
        'W', 'S', 'A', 'L', 'o', 'o', 'k', 'u', 'p', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'B', 'e', 'g', 'i', 'n', 'A', 0, \
    };
/* "WSALookupServiceBeginW" */
#define DECLARE_NAMEOF_API_WSALOOKUPSERVICEBEGINW                                                                        \
    CHAR NAMEOF_API_WSALOOKUPSERVICEBEGINW[] = {                                                                         \
        'W', 'S', 'A', 'L', 'o', 'o', 'k', 'u', 'p', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'B', 'e', 'g', 'i', 'n', 'W', 0, \
    };
/* "WSALookupServiceNextA" */
#define DECLARE_NAMEOF_API_WSALOOKUPSERVICENEXTA                                                                    \
    CHAR NAMEOF_API_WSALOOKUPSERVICENEXTA[] = {                                                                     \
        'W', 'S', 'A', 'L', 'o', 'o', 'k', 'u', 'p', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'N', 'e', 'x', 't', 'A', 0, \
    };
/* "WSALookupServiceNextW" */
#define DECLARE_NAMEOF_API_WSALOOKUPSERVICENEXTW                                                                    \
    CHAR NAMEOF_API_WSALOOKUPSERVICENEXTW[] = {                                                                     \
        'W', 'S', 'A', 'L', 'o', 'o', 'k', 'u', 'p', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'N', 'e', 'x', 't', 'W', 0, \
    };
/* "WSALookupServiceEnd" */
#define DECLARE_NAMEOF_API_WSALOOKUPSERVICEEND                                                            \
    CHAR NAMEOF_API_WSALOOKUPSERVICEEND[] = {                                                             \
        'W', 'S', 'A', 'L', 'o', 'o', 'k', 'u', 'p', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 'E', 'n', 'd', 0, \
    };

/* @brief
    The WSALookupServiceBegin function initiates a client query that is constrained by the information contained within a WSAQUERYSET structure.
    WSALookupServiceBegin only returns a handle, which should be used by subsequent calls to WSALookupServiceNext to get the actual results.
 */
typedef INT(WINAPI *WSALOOKUPSERVICEBEGINA)(LPWSAQUERYSETA lpqsRestrictions, DWORD dwControlFlags, LPHANDLE lphLookup);

typedef INT(WINAPI *WSALOOKUPSERVICEBEGINW)(LPWSAQUERYSETW lpqsRestrictions, DWORD dwControlFlags, LPHANDLE lphLookup);

/* @brief
    The WSALookupServiceNext function is called after obtaining a handle from a previous call to WSALookupServiceBegin in order to retrieve the requested
   service information. The provider will pass back a WSAQUERYSET structure in the lpqsResults buffer. The client should continue to call this function until it
   returns WSA_E_NO_MORE, indicating that all of WSAQUERYSET has been returned.
 */
typedef INT(WINAPI *WSALOOKUPSERVICENEXTA)(HANDLE hLookup, DWORD dwControlFlags, LPDWORD lpdwBufferLength, LPWSAQUERYSETA lpqsResults);

typedef INT(WINAPI *WSALOOKUPSERVICENEXTW)(HANDLE hLookup, DWORD dwControlFlags, LPDWORD lpdwBufferLength, LPWSAQUERYSETW lpqsResults);

/* @brief
    The WSALookupServiceEnd function is called to free the handle after previous calls to WSALookupServiceBegin and WSALookupServiceNext.
    If you call WSALookupServiceEnd from another thread while an existing WSALookupServiceNext is blocked, the end call will have the same effect as a cancel
   and will cause the WSALookupServiceNext call to return immediately.
 */
typedef INT(WINAPI *WSALOOKUPSERVICEEND)(HANDLE hLookup);

#if defined _MBCS || defined MBCS

#define DECLARE_NAMEOF_API_WSALOOKUPSERVICEBEGIN DECLARE_NAMEOF_API_WSALOOKUPSERVICEBEGINA
#define DECLARE_NAMEOF_API_WSALOOKUPSERVICENEXT DECLARE_NAMEOF_API_WSALOOKUPSERVICENEXTA

#define NAMEOF_API_WSALOOKUPSERVICEBEGIN NAMEOF_API_WSALOOKUPSERVICEBEGINA
#define NAMEOF_API_WSALOOKUPSERVICENEXT NAMEOF_API_WSALOOKUPSERVICENEXTA

#define WSALOOKUPSERVICEBEGIN WSALOOKUPSERVICEBEGINA
#define WSALOOKUPSERVICENEXT WSALOOKUPSERVICENEXTA

#elif defined _UNICODE || defined UNICODE

#define DECLARE_NAMEOF_API_WSALOOKUPSERVICEBEGIN DECLARE_NAMEOF_API_WSALOOKUPSERVICEBEGINW
#define DECLARE_NAMEOF_API_WSALOOKUPSERVICENEXT DECLARE_NAMEOF_API_WSALOOKUPSERVICENEXTW

#define NAMEOF_API_WSALOOKUPSERVICEBEGIN NAMEOF_API_WSALOOKUPSERVICEBEGINW
#define NAMEOF_API_WSALOOKUPSERVICENEXT NAMEOF_API_WSALOOKUPSERVICENEXTW

#define WSALOOKUPSERVICEBEGIN WSALOOKUPSERVICEBEGINW
#define WSALOOKUPSERVICENEXT WSALOOKUPSERVICENEXTW

#endif

// Windows 2003 / Windows XP

/* "WSANSPIoctl" */
#define DECLARE_NAMEOF_API_WSANSPIOCTL                            \
    CHAR NAMEOF_API_WSANSPIOCTL[] = {                             \
        'W', 'S', 'A', 'N', 'S', 'P', 'I', 'o', 'c', 't', 'l', 0, \
    };

/* @brief
    The Windows Sockets WSANSPIoctl function enables developers to make I/O control calls to a registered namespace.
 */
typedef int(WINAPI *WSANSPIOCTL)(HANDLE hLookup, DWORD dwControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer,
                                 LPDWORD lpcbBytesReturned, LPWSACOMPLETION lpCompletion);

#endif

#endif
