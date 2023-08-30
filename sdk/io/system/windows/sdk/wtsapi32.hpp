/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab textwidth=130 colorcolumn=+1: */
/**
 * @file wtsapi32.h
 * @author Soo Han, Kim (hush@ahnlab.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_SDK_SDK_WTSAPI32__
#define __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_SDK_SDK_WTSAPI32__

#include <wtsapi32.h>

#undef  NAMEOF_API_WTSENUMERATESESSIONS
#undef  NAMEOF_API_WTSQUERYSESSIONINFORMATION

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_WTSENUMERATESESSIONS         DECLARE_NAMEOF_API_WTSENUMERATESESSIONSA
#define DECLARE_NAMEOF_API_WTSQUERYSESSIONINFORMATION   DECLARE_NAMEOF_API_WTSQUERYSESSIONINFORMATIONA

#define NAMEOF_API_WTSENUMERATESESSIONS                 NAMEOF_API_WTSENUMERATESESSIONSA
#define NAMEOF_API_WTSQUERYSESSIONINFORMATION           NAMEOF_API_WTSQUERYSESSIONINFORMATIONA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_WTSENUMERATESESSIONS         DECLARE_NAMEOF_API_WTSENUMERATESESSIONSW
#define DECLARE_NAMEOF_API_WTSQUERYSESSIONINFORMATION   DECLARE_NAMEOF_API_WTSQUERYSESSIONINFORMATIONW

#define NAMEOF_API_WTSENUMERATESESSIONS                 NAMEOF_API_WTSENUMERATESESSIONSW
#define NAMEOF_API_WTSQUERYSESSIONINFORMATION           NAMEOF_API_WTSQUERYSESSIONINFORMATIONW
#endif

/* "WTSEnumerateSessionsA" */
#define DECLARE_NAMEOF_API_WTSENUMERATESESSIONSA char NAMEOF_API_WTSENUMERATESESSIONSA[] = { 'W', 'T', 'S', 'E', 'n', 'u', 'm', 'e', 'r', 'a', 't', 'e', 'S', 'e', 's', 's', 'i', 'o', 'n', 's', 'A', 0, };
/* "WTSEnumerateSessionsW" */
#define DECLARE_NAMEOF_API_WTSENUMERATESESSIONSW char NAMEOF_API_WTSENUMERATESESSIONSW[] = { 'W', 'T', 'S', 'E', 'n', 'u', 'm', 'e', 'r', 'a', 't', 'e', 'S', 'e', 's', 's', 'i', 'o', 'n', 's', 'W', 0, };

/* @brief
    Retrieves a list of sessions on a specified Remote Desktop Session Host (RD Session Host) server.
 */
typedef DWORD (__stdcall *WTSENUMERATESESSIONS)(HANDLE hServer, DWORD Reserved, DWORD Version, PWTS_SESSION_INFO* ppSessionInfo, DWORD* pCount);

/* "WTSQuerySessionInformationA" */
#define DECLARE_NAMEOF_API_WTSQUERYSESSIONINFORMATIONA char NAMEOF_API_WTSQUERYSESSIONINFORMATIONA[] = { 'W', 'T', 'S', 'Q', 'u', 'e', 'r', 'y', 'S', 'e', 's', 's', 'i', 'o', 'n', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'A', 0, };
/* "WTSQuerySessionInformationW" */
#define DECLARE_NAMEOF_API_WTSQUERYSESSIONINFORMATIONW char NAMEOF_API_WTSQUERYSESSIONINFORMATIONW[] = { 'W', 'T', 'S', 'Q', 'u', 'e', 'r', 'y', 'S', 'e', 's', 's', 'i', 'o', 'n', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'W', 0, };

/* @brief
    Retrieves session information for the specified session on the specified Remote Desktop Session Host (RD Session Host) server.
    It can be used to query session information on local and remote RD Session Host servers.
 */
typedef BOOL (__stdcall *WTSQUERYSESSIONINFORMATION)(HANDLE hServer, DWORD SessionId, WTS_INFO_CLASS WTSInfoClass, LPTSTR* ppBuffer, DWORD* pBytesReturned);

/* "WTSQueryUserToken" */
#define DECLARE_NAMEOF_API_WTSQUERYUSERTOKEN char NAMEOF_API_WTSQUERYUSERTOKEN[] = { 'W', 'T', 'S', 'Q', 'u', 'e', 'r', 'y', 'U', 's', 'e', 'r', 'T', 'o', 'k', 'e', 'n', 0, };

/* @brief
    Obtains the primary access token of the logged-on user specified by the session ID. To call this function successfully, the calling application must be running within the context of the LocalSystem account and have the SE_TCB_NAME privilege.
    Caution  WTSQueryUserToken is intended for highly trusted services. Service providers must use caution that they do not leak user tokens when calling this function. Service providers must close token handles after they have finished using them.
 */
typedef BOOL (__stdcall *WTSQUERYUSERTOKEN)(IN ULONG SessionId, OUT PHANDLE phToken);

/* "WTSFreeMemory" */
#define DECLARE_NAMEOF_API_WTSFREEMEMORY char NAMEOF_API_WTSFREEMEMORY[] = { 'W', 'T', 'S', 'F', 'r', 'e', 'e', 'M', 'e', 'm', 'o', 'r', 'y', 0, };

/* @brief
    Frees memory allocated by a Remote Desktop Services function.
 */
typedef VOID (__stdcall *WTSFREEMEMORY)(PVOID pMemory);

/* "WTSWaitSystemEvent" */
#define DECLARE_NAMEOF_API_WTSWAITSYSTEMEVENT char NAMEOF_API_WTSWAITSYSTEMEVENT[] = { 'W', 'T', 'S', 'W', 'a', 'i', 't', 'S', 'y', 's', 't', 'e', 'm', 'E', 'v', 'e', 'n', 't', 0, };

/* @brief
    Waits for a Remote Desktop Services event before returning to the caller.
 */
typedef BOOL (__stdcall *WTSWAITSYSTEMEVENT)(HANDLE hServer, DWORD EventMask, DWORD *pEventFlags);

#endif

