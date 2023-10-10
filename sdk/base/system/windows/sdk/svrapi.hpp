/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_SVRAPI__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_SVRAPI__

/* windows 9x share */

/* "NetShareEnum" */
#define DECLARE_NAMEOF_API_SVRAPI_NETSHAREENUM                         \
    char NAMEOF_API_SVRAPI_NETSHAREENUM[] = {                          \
        'N', 'e', 't', 'S', 'h', 'a', 'r', 'e', 'E', 'n', 'u', 'm', 0, \
    };

/* @brief
    Retrieves information about each shared resource on a server.
    You can also use the WNetEnumResource function to retrieve resource information.
    However, WNetEnumResource does not enumerate hidden shares or users connected to a share.
 */
typedef NET_API_STATUS(__stdcall *SVRAPI_NETSHAREENUM)(const char FAR *pszServer, short sLevel, char FAR *pbBuffer, unsigned short cbBuffer,
                                                       unsigned short FAR *pcEntriesRead, unsigned short FAR *pcTotalAvail);

/* "NetFileEnum" */
#define DECLARE_NAMEOF_API_SVRAPI_NETFILEENUM                     \
    char NAMEOF_API_SVRAPI_NETFILEENUM[] = {                      \
        'N', 'e', 't', 'F', 'i', 'l', 'e', 'E', 'n', 'u', 'm', 0, \
    };

/* @brief
    Returns information about some or all open files on a server, depending on the parameters specified.
 */
typedef NET_API_STATUS(__stdcall *SVRAPI_NETFILEENUM)(const char FAR *pszServer, const char FAR *pszBasePath, short sLevel, char FAR *pbBuffer,
                                                      unsigned short cbBuffer, unsigned short FAR *pcEntriesRead, unsigned short FAR *pcTotalAvail);

/* "NetConnectionEnum" */
#define DECLARE_NAMEOF_API_SVRAPI_NETCONNECTIONENUM                                             \
    char NAMEOF_API_SVRAPI_NETCONNECTIONENUM[] = {                                              \
        'N', 'e', 't', 'C', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n', 'E', 'n', 'u', 'm', 0, \
    };

/* @brief
    Lists all connections made to a shared resource on the server or all connections established from a particular computer.
    If there is more than one user using this connection, then it is possible to get more than one structure for the same connection, but with a different user
   name.
 */
typedef NET_API_STATUS(__stdcall *SVRAPI_NETCONNECTIONENUM)(const char FAR *pszServer, const char FAR *pszQualifier, short sLevel, char FAR *pbBuffer,
                                                            unsigned short cbBuffer, unsigned short FAR *pcEntriesRead, unsigned short FAR *pcTotalAvail);

/* "NetShareAdd" */
#define DECLARE_NAMEOF_API_SVRAPI_NETSHAREADD                     \
    char NAMEOF_API_SVRAPI_NETSHAREADD[] = {                      \
        'N', 'e', 't', 'S', 'h', 'a', 'r', 'e', 'A', 'd', 'd', 0, \
    };

/* @brief
    Shares a server resource.
 */
typedef NET_API_STATUS(__stdcall *SVRAPI_NETSHAREADD)(const char FAR *pszServer, short sLevel, const char FAR *pbBuffer, unsigned short cbBuffer);

/* "NetShareDel" */
#define DECLARE_NAMEOF_API_SVRAPI_NETSHAREDEL                     \
    char NAMEOF_API_SVRAPI_NETSHAREDEL[] = {                      \
        'N', 'e', 't', 'S', 'h', 'a', 'r', 'e', 'D', 'e', 'l', 0, \
    };

/* @brief
    Deletes a share name from a server's list of shared resources, disconnecting all connections to the shared resource.
    The extended function NetShareDelEx allows the caller to specify a SHARE_INFO_0, SHARE_INFO_1, SHARE_INFO_2, SHARE_INFO_502, or SHARE_INFO_503 structure.
 */
typedef NET_API_STATUS(__stdcall *SVRAPI_NETSHAREDEL)(const char FAR *pszServer, const char FAR *pszNetName, unsigned short usReserved);

#endif
