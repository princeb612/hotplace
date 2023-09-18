/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_PSAPI__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_PSAPI__

#include <psapi.h>

/* "EnumProcesses" */
#define DECLARE_NAMEOF_API_ENUMPROCESSES CHAR NAMEOF_API_ENUMPROCESSES[] = { 'E', 'n', 'u', 'm', 'P', 'r', 'o', 'c', 'e', 's', 's', 'e', 's', 0, };

/* @brief
    Retrieves the process identifier for each process object in the system.
 */
typedef BOOL (WINAPI* ENUMPROCESSES)(
    DWORD*                  pProcessIds,
    DWORD cb,
    DWORD*                  pBytesReturned
    );

/* "EnumProcessModules" */
#define DECLARE_NAMEOF_API_ENUMPROCESSMODULES CHAR NAMEOF_API_ENUMPROCESSMODULES[] = { 'E', 'n', 'u', 'm', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'o', 'd', 'u', 'l', 'e', 's', 0, };

/* @brief
    Retrieves a handle for each module in the specified process.
    To control whether a 64-bit application enumerates 32-bit modules, 64-bit modules, or both types of modules, use the EnumProcessModulesEx function.
 */
typedef BOOL (__stdcall *ENUMPROCESSMODULES)(
    HANDLE hProcess,                        // handle to process
    HMODULE*                lphModule,      // array of module handles
    DWORD cb,                               // size of array
    LPDWORD lpcbNeeded                      // number of bytes required
    );


#undef  NAMEOF_API_GETMODULEBASENAME
#undef  NAMEOF_API_GETMODULEFILENAMEEX

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_GETMODULEBASENAME    DECLARE_NAMEOF_API_GETMODULEBASENAMEA
#define DECLARE_NAMEOF_API_GETMODULEFILENAMEEX  DECLARE_NAMEOF_API_GETMODULEFILENAMEEXA

#define NAMEOF_API_GETMODULEBASENAME            NAMEOF_API_GETMODULEBASENAMEA
#define NAMEOF_API_GETMODULEFILENAMEEX          NAMEOF_API_GETMODULEFILENAMEEXA
#define GETMODULEBASENAME                       GETMODULEBASENAMEA
#define GETMODULEFILENAMEEX                     GETMODULEFILENAMEEXA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_GETMODULEBASENAME    DECLARE_NAMEOF_API_GETMODULEBASENAMEW
#define DECLARE_NAMEOF_API_GETMODULEFILENAMEEX  DECLARE_NAMEOF_API_GETMODULEFILENAMEEXW

#define NAMEOF_API_GETMODULEBASENAME            NAMEOF_API_GETMODULEBASENAMEW
#define NAMEOF_API_GETMODULEFILENAMEEX          NAMEOF_API_GETMODULEFILENAMEEXW
#define GETMODULEBASENAME                       GETMODULEBASENAMEW
#define GETMODULEFILENAMEEX                     GETMODULEFILENAMEEXW
#endif

/* "GetModuleBaseNameA" */
#define DECLARE_NAMEOF_API_GETMODULEBASENAMEA CHAR NAMEOF_API_GETMODULEBASENAMEA[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'B', 'a', 's', 'e', 'N', 'a', 'm', 'e', 'A', 0, };
/* "GetModuleBaseNameW" */
#define DECLARE_NAMEOF_API_GETMODULEBASENAMEW CHAR NAMEOF_API_GETMODULEBASENAMEW[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'B', 'a', 's', 'e', 'N', 'a', 'm', 'e', 'W', 0, }
/* "GetModuleFileNameExA" */
#define DECLARE_NAMEOF_API_GETMODULEFILENAMEEXA CHAR NAMEOF_API_GETMODULEFILENAMEEXA[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'F', 'i', 'l', 'e', 'N', 'a', 'm', 'e', 'E', 'x', 'A', 0, };
/* "GetModuleFileNameExW"*/
#define DECLARE_NAMEOF_API_GETMODULEFILENAMEEXW CHAR NAMEOF_API_GETMODULEFILENAMEEXW[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'F', 'i', 'l', 'e', 'N', 'a', 'm', 'e', 'E', 'x', 'W', 0, }

/* @brief
    Retrieves the base name of the specified module.
 */
typedef DWORD (__stdcall *GETMODULEBASENAMEA)(
    HANDLE hProcess,                        // handle to process
    HMODULE hModule,                        // handle to module
    LPSTR lpBaseName,                       // base name buffer
    DWORD nSize                             // maximum characters to retrieve
    );
typedef DWORD (__stdcall *GETMODULEBASENAMEW)(
    HANDLE hProcess,                        // handle to process
    HMODULE hModule,                        // handle to module
    LPWSTR lpBaseName,                      // base name buffer
    DWORD nSize                             // maximum characters to retrieve
    );
/* @brief
    Retrieves the fully qualified path for the file containing the specified module.
 */
typedef DWORD (__stdcall *GETMODULEFILENAMEEXA)(
    HANDLE hProcess,                        // handle to process
    HMODULE hModule,                        // handle to module
    LPSTR lpFileName,                       // base name buffer
    DWORD nSize                             // maximum characters to retrieve
    );

typedef DWORD (__stdcall *GETMODULEFILENAMEEXW)(
    HANDLE hProcess,                        // handle to process
    HMODULE hModule,                        // handle to module
    LPWSTR lpFileName,                      // base name buffer
    DWORD nSize                             // maximum characters to retrieve
    );

/* "GetProcessImageFileNameA" */
#define DECLARE_NAMEOF_API_GETPROCESSIMAGEFILENAMEA CHAR NAMEOF_API_GETPROCESSIMAGEFILENAMEA[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'I', 'm', 'a', 'g', 'e', 'F', 'i', 'l', 'e', 'N', 'a', 'm', 'e', 'A', 0, };
/* "GetProcessImageFileNameW" */
#define DECLARE_NAMEOF_API_GETPROCESSIMAGEFILENAMEW CHAR NAMEOF_API_GETPROCESSIMAGEFILENAMEW[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'I', 'm', 'a', 'g', 'e', 'F', 'i', 'l', 'e', 'N', 'a', 'm', 'e', 'W', 0, };

/* @brief
    Retrieves the name of the executable file for the specified process.
 */
typedef DWORD (WINAPI *GETPROCESSIMAGEFILENAMEA)
(
    ___in HANDLE hProcess,
    __out_ecount (nSize) LPSTR lpImageFileName,
    ___in DWORD nSize
);

typedef DWORD (WINAPI *GETPROCESSIMAGEFILENAMEW)
(
    ___in HANDLE hProcess,
    __out_ecount (nSize) LPWSTR lpImageFileName,
    ___in DWORD nSize
);

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_GETPROCESSIMAGEFILENAME  DECLARE_NAMEOF_API_GETPROCESSIMAGEFILENAMEA

#define NAMEOF_API_GETPROCESSIMAGEFILENAME          NAMEOF_API_GETPROCESSIMAGEFILENAMEA
#define GETPROCESSIMAGEFILENAME                     GETPROCESSIMAGEFILENAMEA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_GETPROCESSIMAGEFILENAME  DECLARE_NAMEOF_API_GETPROCESSIMAGEFILENAMEW

#define NAMEOF_API_GETPROCESSIMAGEFILENAME          NAMEOF_API_GETPROCESSIMAGEFILENAMEW
#define GETPROCESSIMAGEFILENAME                     GETPROCESSIMAGEFILENAMEW
#endif

/* "GetModuleInformation" */
#define DECLARE_NAMEOF_API_GETMODULEINFORMATION CHAR NAMEOF_API_GETMODULEINFORMATION[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 0, };

/* @brief
    Retrieves information about the specified module in the MODULEINFO structure.
 */
typedef BOOL (__stdcall *GETMODULEINFORMATION)
(
    HANDLE hProcess,
    HMODULE hModule,
    LPMODULEINFO lpmodinfo,
    DWORD cb
);

#endif
