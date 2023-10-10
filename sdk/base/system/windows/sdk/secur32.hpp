/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_SECUR32__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_SECUR32__

#include <Ntsecapi.h>

/* "LsaEnumerateLogonSessions" */
#define DECLARE_NAMEOF_API_LSAENUMERATELOGONSESSIONS                                                                                    \
    char NAMEOF_API_LSAENUMERATELOGONSESSIONS[] = {                                                                                     \
        'L', 's', 'a', 'E', 'n', 'u', 'm', 'e', 'r', 'a', 't', 'e', 'L', 'o', 'g', 'o', 'n', 'S', 'e', 's', 's', 'i', 'o', 'n', 's', 0, \
    };
/* "LsaGetLogonSessionData" */
#define DECLARE_NAMEOF_API_LSAGETLOGONSESSIONDATA                                                                        \
    char NAMEOF_API_LSAGETLOGONSESSIONDATA[] = {                                                                         \
        'L', 's', 'a', 'G', 'e', 't', 'L', 'o', 'g', 'o', 'n', 'S', 'e', 's', 's', 'i', 'o', 'n', 'D', 'a', 't', 'a', 0, \
    };
/* "LsaFreeReturnBuffer" */
#define DECLARE_NAMEOF_API_LSAFREERETURNBUFFER                                                            \
    char NAMEOF_API_LSAFREERETURNBUFFER[] = {                                                             \
        'L', 's', 'a', 'F', 'r', 'e', 'e', 'R', 'e', 't', 'u', 'r', 'n', 'B', 'u', 'f', 'f', 'e', 'r', 0, \
    };

/* @brief
    The LsaEnumerateLogonSessions function retrieves the set of existing logon session identifiers (LUIDs) and the number of sessions.
 */
typedef NTSTATUS(NTAPI *LSAENUMERATELOGONSESSIONS)(OUT PULONG LogonSessionCount, OUT PLUID *LogonSessionList);

/* @brief
    The LsaGetLogonSessionData function retrieves information about a specified logon session.
    To retrieve information about a logon session, the caller must be the owner of the session or a local system administrator.
 */
typedef NTSTATUS(NTAPI *LSAGETLOGONSESSIONDATA)(IN PLUID LogonId, OUT PSECURITY_LOGON_SESSION_DATA *ppLogonSessionData);

/* @brief
    The LsaFreeReturnBuffer function frees the memory used by a buffer previously allocated by the LSA.
 */
typedef NTSTATUS(NTAPI *LSAFREERETURNBUFFER)(IN PVOID Buffer);

#endif
