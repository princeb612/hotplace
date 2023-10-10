/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_SHELL32__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_SHELL32__

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_SHGETFOLDERPATH DECLARE_NAMEOF_API_SHGETFOLDERPATHA

#define NAMEOF_API_SHGETFOLDERPATH NAMEOF_API_SHGETFOLDERPATHA
#define SHGETFOLDERPATH SHGETFOLDERPATHA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_SHGETFOLDERPATH DECLARE_NAMEOF_API_SHGETFOLDERPATHW

#define NAMEOF_API_SHGETFOLDERPATH NAMEOF_API_SHGETFOLDERPATHW
#define SHGETFOLDERPATH SHGETFOLDERPATHW
#endif

/* "SHGetFolderPathA" */
#define DECLARE_NAMEOF_API_SHGETFOLDERPATHA                                                \
    CHAR NAMEOF_API_SHGETFOLDERPATHA[] = {                                                 \
        'S', 'H', 'G', 'e', 't', 'F', 'o', 'l', 'd', 'e', 'r', 'P', 'a', 't', 'h', 'A', 0, \
    };
/* "SHGetFolderPathW" */
#define DECLARE_NAMEOF_API_SHGETFOLDERPATHW                                                \
    CHAR NAMEOF_API_SHGETFOLDERPATHW[] = {                                                 \
        'S', 'H', 'G', 'e', 't', 'F', 'o', 'l', 'd', 'e', 'r', 'P', 'a', 't', 'h', 'W', 0, \
    };

/* @brief
    Deprecated. Gets the path of a folder identified by a CSIDL value.

    Note
    As of Windows Vista, this function is merely a wrapper for SHGetKnownFolderPath.
    The CSIDL value is translated to its associated KNOWNFOLDERID and then SHGetKnownFolderPath is called.
    New applications should use the known folder system rather than the older CSIDL system, which is supported only for backward compatibility.
 */
typedef HRESULT(__stdcall* SHGETFOLDERPATHA)(HWND hwndOwner, int nFolder, HANDLE hToken, DWORD dwFlags, LPSTR pszPath);

typedef HRESULT(__stdcall* SHGETFOLDERPATHW)(HWND hwndOwner, int nFolder, HANDLE hToken, DWORD dwFlags, LPWSTR pszPath);

#include <shellapi.h>

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_SHELLEXECUTEEX DECLARE_NAMEOF_API_SHELLEXECUTEEXA
#define NAMEOF_API_SHELLEXECUTEEX NAMEOF_API_SHELLEXECUTEEXA
#define SHELLEXECUTEEX SHELLEXECUTEEXA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_SHELLEXECUTEEX DECLARE_NAMEOF_API_SHELLEXECUTEEXW
#define NAMEOF_API_SHELLEXECUTEEX NAMEOF_API_SHELLEXECUTEEXW
#define SHELLEXECUTEEX SHELLEXECUTEEXW
#endif

/* ShellExecuteExA */
#define DECLARE_NAMEOF_API_SHELLEXECUTEEXA                                            \
    CHAR NAMEOF_API_SHELLEXECUTEEXA[] = {                                             \
        'S', 'h', 'e', 'l', 'l', 'E', 'x', 'e', 'c', 'u', 't', 'e', 'E', 'x', 'A', 0, \
    };
/* ShellExecuteExW */
#define DECLARE_NAMEOF_API_SHELLEXECUTEEXW                                            \
    CHAR NAMEOF_API_SHELLEXECUTEEXW[] = {                                             \
        'S', 'h', 'e', 'l', 'l', 'E', 'x', 'e', 'c', 'u', 't', 'e', 'E', 'x', 'W', 0, \
    };

typedef BOOL(__stdcall* SHELLEXECUTEEXA)(LPSHELLEXECUTEINFOA lpExecInfo);
typedef BOOL(__stdcall* SHELLEXECUTEEXW)(LPSHELLEXECUTEINFOW lpExecInfo);

#endif
