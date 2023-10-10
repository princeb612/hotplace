/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_NETAPI32__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_NETAPI32__

/* "NetUserEnum" */
#define DECLARE_NAMEOF_API_NETUSERENUM                            \
    CHAR NAMEOF_API_NETUSERENUM[] = {                             \
        'N', 'e', 't', 'U', 's', 'e', 'r', 'E', 'n', 'u', 'm', 0, \
    };

/* @brief
    The NetUserEnum function retrieves information about all user accounts on a server.
 */
typedef NET_API_STATUS(__stdcall* NETUSERENUM)(___in LPCWSTR servername OPTIONAL, ___in DWORD level, ___in DWORD filter, ___out LPBYTE* bufptr,
                                               ___in DWORD prefmaxlen, ___out LPDWORD entriesread, ___out LPDWORD totalentries,
                                               __inout LPDWORD resume_handle OPTIONAL);

/* "NetApiBufferFree" */
#define DECLARE_NAMEOF_API_NETAPIBUFFERFREE                                                \
    CHAR NAMEOF_API_NETAPIBUFFERFREE[] = {                                                 \
        'N', 'e', 't', 'A', 'p', 'i', 'B', 'u', 'f', 'f', 'e', 'r', 'F', 'r', 'e', 'e', 0, \
    };

/* @brief
    The NetApiBufferFree function frees the memory that the NetApiBufferAllocate function allocates.
    Applications should also call NetApiBufferFree to free the memory that other network management functions use internally to return information.
 */
typedef NET_API_STATUS(__stdcall* NETAPIBUFFERFREE)(___in LPVOID Buffer);

/* "NetLocalGroupEnum" */
#define DECLARE_NAMEOF_API_NETLOCALGROUPENUM                                                    \
    CHAR NAMEOF_API_NETLOCALGROUPENUM[] = {                                                     \
        'N', 'e', 't', 'L', 'o', 'c', 'a', 'l', 'G', 'r', 'o', 'u', 'p', 'E', 'n', 'u', 'm', 0, \
    };

/* @brief
    The NetLocalGroupEnum function returns information about each local group account on the specified server.
 */
typedef NET_API_STATUS(__stdcall* NETLOCALGROUPENUM)(___in LPCWSTR servername OPTIONAL, ___in DWORD level, ___out LPBYTE* bufptr, ___in DWORD prefmaxlen,
                                                     ___out LPDWORD entriesread, ___out LPDWORD totalentries, __inout PDWORD_PTR resumehandle OPTIONAL);

/* "NetLocalGroupGetMembers" */
#define DECLARE_NAMEOF_API_NETLOCALGROUPGETMEMBERS                                                                            \
    CHAR NAMEOF_API_NETLOCALGROUPGETMEMBERS[] = {                                                                             \
        'N', 'e', 't', 'L', 'o', 'c', 'a', 'l', 'G', 'r', 'o', 'u', 'p', 'G', 'e', 't', 'M', 'e', 'm', 'b', 'e', 'r', 's', 0, \
    };

/* @brief
    The NetLocalGroupGetMembers function retrieves a list of the members of a particular local group in the security database, which is the security accounts
   manager (SAM) database or, in the case of domain controllers, the Active Directory. Local group members can be users or global groups.
 */
typedef NET_API_STATUS(__stdcall* NETLOCALGROUPGETMEMBERS)(___in LPCWSTR servername OPTIONAL, ___in LPCWSTR localgroupname, ___in DWORD level,
                                                           ___out LPBYTE* bufptr, ___in DWORD prefmaxlen, ___out LPDWORD entriesread,
                                                           ___out LPDWORD totalentries, __inout PDWORD_PTR resumehandle);

/* windows nt share */
/* "NetShareEnum" */
#define DECLARE_NAMEOF_API_NETAPI32_NETSHAREENUM                       \
    CHAR NAMEOF_API_NETAPI32_NETSHAREENUM[] = {                        \
        'N', 'e', 't', 'S', 'h', 'a', 'r', 'e', 'E', 'n', 'u', 'm', 0, \
    };

/* @brief
    Retrieves information about each shared resource on a server.
    You can also use the WNetEnumResource function to retrieve resource information.
    However, WNetEnumResource does not enumerate hidden shares or users connected to a share.
 */
typedef NET_API_STATUS(__stdcall* NETAPI32_NETSHAREENUM)(___in LPWSTR servername, ___in DWORD level, ___out LPBYTE* bufptr, ___in DWORD prefmaxlen,
                                                         ___out LPDWORD entriesread, ___out LPDWORD totalentries, __inout LPDWORD resume_handle);

/* "NetFileEnum" */
#define DECLARE_NAMEOF_API_NETAPI32_NETFILEENUM                   \
    CHAR NAMEOF_API_NETAPI32_NETFILEENUM[] = {                    \
        'N', 'e', 't', 'F', 'i', 'l', 'e', 'E', 'n', 'u', 'm', 0, \
    };

/* @brief
    Returns information about some or all open files on a server, depending on the parameters specified.
 */
typedef NET_API_STATUS(__stdcall* NETAPI32_NETFILEENUM)(___in LPWSTR servername, ___in LPWSTR basepath, ___in LPWSTR username, ___in DWORD level,
                                                        ___out LPBYTE* bufptr, ___in DWORD prefmaxlen, ___out LPDWORD entriesread, ___out LPDWORD totalentries,
                                                        __inout PDWORD_PTR resume_handle);

/* "NetConnectionEnum" */
#define DECLARE_NAMEOF_API_NETAPI32_NETCONNECTIONENUM                                           \
    CHAR NAMEOF_API_NETAPI32_NETCONNECTIONENUM[] = {                                            \
        'N', 'e', 't', 'C', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n', 'E', 'n', 'u', 'm', 0, \
    };

/* @brief
    Lists all connections made to a shared resource on the server or all connections established from a particular computer.
    If there is more than one user using this connection, then it is possible to get more than one structure for the same connection, but with a different user
   name.
 */
typedef NET_API_STATUS(__stdcall* NETAPI32_NETCONNECTIONENUM)(___in LPWSTR servername, ___in LPWSTR qualifier, ___in DWORD level, ___out LPBYTE* bufptr,
                                                              ___in DWORD prefmaxlen, ___out LPDWORD entriesread, ___out LPDWORD totalentries,
                                                              __inout LPDWORD resume_handle);

/* "NetSessionEnum" */
#define DECLARE_NAMEOF_API_NETAPI32_NETSESSIONENUM                               \
    CHAR NAMEOF_API_NETAPI32_NETSESSIONENUM[] = {                                \
        'N', 'e', 't', 'S', 'e', 's', 's', 'i', 'o', 'n', 'E', 'n', 'u', 'm', 0, \
    };

/* @brief
    Provides information about sessions established on a server.
 */
typedef NET_API_STATUS(__stdcall* NETAPI32_NETSESSIONENUM)(___in LPWSTR servername, ___in LPWSTR UncClientName, ___in LPWSTR username, ___in DWORD level,
                                                           ___out LPBYTE* bufptr, ___in DWORD prefmaxlen, ___out LPDWORD entriesread,
                                                           ___out LPDWORD totalentries, __inout LPDWORD resume_handle);

/* "NetApiBufferFree" */
#define DECLARE_NAMEOF_API_NETAPI32_NETAPIBUFFERFREE                                       \
    CHAR NAMEOF_API_NETAPI32_NETAPIBUFFERFREE[] = {                                        \
        'N', 'e', 't', 'A', 'p', 'i', 'B', 'u', 'f', 'f', 'e', 'r', 'F', 'r', 'e', 'e', 0, \
    };

/* @brief
    The NetApiBufferFree function frees the memory that the NetApiBufferAllocate function allocates.
    Applications should also call NetApiBufferFree to free the memory that other network management functions use internally to return information.
 */
typedef NET_API_STATUS(__stdcall* NETAPI32_NETAPIBUFFERFREE)(___in LPVOID Buffer);

/* "NetShareAdd" */
#define DECLARE_NAMEOF_API_NETAPI32_NETSHAREADD                   \
    CHAR NAMEOF_API_NETAPI32_NETSHAREADD[] = {                    \
        'N', 'e', 't', 'S', 'h', 'a', 'r', 'e', 'A', 'd', 'd', 0, \
    };

/* @brief
    Shares a server resource.
 */
typedef NET_API_STATUS(__stdcall* NETAPI32_NETSHAREADD)(___in LPWSTR servername, ___in DWORD level, ___in LPBYTE buf, ___out LPDWORD parm_err);

/* "NetShareDel" */
#define DECLARE_NAMEOF_API_NETAPI32_NETSHAREDEL                   \
    CHAR NAMEOF_API_NETAPI32_NETSHAREDEL[] = {                    \
        'N', 'e', 't', 'S', 'h', 'a', 'r', 'e', 'D', 'e', 'l', 0, \
    };

/* @brief
    Deletes a share name from a server's list of shared resources, disconnecting all connections to the shared resource.
    The extended function NetShareDelEx allows the caller to specify a SHARE_INFO_0, SHARE_INFO_1, SHARE_INFO_2, SHARE_INFO_502, or SHARE_INFO_503 structure.
 */
typedef NET_API_STATUS(__stdcall* NETAPI32_NETSHAREDEL)(___in LPWSTR servername, ___in LPWSTR netname, ___in DWORD reserved);

/* "NetWkstaGetInfo" */
#define DECLARE_NAMEOF_API_NETWKSTAGETINFO                                            \
    CHAR NAMEOF_API_NETWKSTAGETINFO[] = {                                             \
        'N', 'e', 't', 'W', 'k', 's', 't', 'a', 'G', 'e', 't', 'I', 'n', 'f', 'o', 0, \
    };

/* @brief
    The NetWkstaGetInfo function returns information about the configuration of a workstation.
 */
typedef NET_API_STATUS(__stdcall* NETWKSTAGETINFO)(___in LPWSTR servername, ___in DWORD level, ___out LPBYTE* bufptr);

/* "NetWkstaUserGetInfo" */
#define DECLARE_NAMEOF_API_NETWKSTAUSERGETINFO                                                            \
    CHAR NAMEOF_API_NETWKSTAUSERGETINFO[] = {                                                             \
        'N', 'e', 't', 'W', 'k', 's', 't', 'a', 'U', 's', 'e', 'r', 'G', 'e', 't', 'I', 'n', 'f', 'o', 0, \
    };

/* @brief
    The NetWkstaUserGetInfo function returns information about the currently logged-on user. This function must be called in the context of the logged-on user.
 */
typedef NET_API_STATUS(__stdcall* NETWKSTAUSERGETINFO)(LPWSTR reserved, DWORD level, LPBYTE* bufptr);

/* "NetWkstaUserEnum" */
#define DECLARE_NAMEOF_API_NETWKSTAUSERENUM                                                \
    CHAR NAMEOF_API_NETWKSTAUSERENUM[] = {                                                 \
        'N', 'e', 't', 'W', 'k', 's', 't', 'a', 'U', 's', 'e', 'r', 'E', 'n', 'u', 'm', 0, \
    };

/* @brief
    The NetWkstaUserEnum function lists information about all users currently logged on to the workstation. This list includes interactive, service and batch
   logons.
 */
typedef NET_API_STATUS(__stdcall* NETWKSTAUSERENUM)(___in LPWSTR servername, ___in DWORD level, ___out LPBYTE* bufptr, ___in DWORD prefmaxlen,
                                                    ___out LPDWORD entriesread, ___out LPDWORD totalentries, __inout LPDWORD resumehandle);

/* "Netbios" */
#define DECLARE_NAMEOF_API_NETBIOS            \
    CHAR NAMEOF_API_NETBIOS[] = {             \
        'N', 'e', 't', 'b', 'i', 'o', 's', 0, \
    };

typedef struct _NCB* PNCB;
/* @brief
    [Netbios is not supported on Windows Vista, Windows Server 2008, and subsequent versions of the operating system]

    The Netbios function interprets and executes the specified network control block (NCB).
    The Netbios function is provided primarily for applications that were written for the NetBIOS interface and need to be ported to Windows.
    Applications not requiring compatibility with NetBIOS should use other interfaces, such as Windows Sockets, mailslots, named pipes, RPC, or distributed COM
   to accomplish tasks similar to those supported by NetBIOS. These other interfaces are more flexible and portable.
   @comment
    see GetMACAddress
 */
typedef UCHAR(__stdcall* NETBIOS)(PNCB pncb);

#endif
