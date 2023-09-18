/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_IPHLPAPI__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_IPHLPAPI__

/* iphlp */

#include <Iptypes.h>
#include <Iphlpapi.h>

/* "GetAdaptersInfo" */
#define DECLARE_NAMEOF_API_GETADAPTERSINFO CHAR NAMEOF_API_GETADAPTERSINFO[] = { 'G', 'e', 't', 'A', 'd', 'a', 'p', 't', 'e', 'r', 's', 'I', 'n', 'f', 'o', 0, };
/* "GetIpAddrTable" */
#define DECLARE_NAMEOF_API_GETIPADDRTABLE CHAR NAMEOF_API_GETIPADDRTABLE[] = { 'G', 'e', 't', 'I', 'p', 'A', 'd', 'd', 'r', 'T', 'a', 'b', 'l', 'e', 0, };
/* "GetIpNetTable" */
#define DECLARE_NAMEOF_API_GETIPNETTABLE CHAR NAMEOF_API_GETIPNETTABLE[] = { 'G', 'e', 't', 'I', 'p', 'N', 'e', 't', 'T', 'a', 'b', 'l', 'e', 0, };
/* "GetIfTable" */
#define DECLARE_NAMEOF_API_GETIFTABLE CHAR NAMEOF_API_GETIFTABLE[] = { 'G', 'e', 't', 'I', 'f', 'T', 'a', 'b', 'l', 'e', 0, };
/* "GetNetworkParams" */
#define DECLARE_NAMEOF_API_GETNETWORKPARAMS CHAR NAMEOF_API_GETNETWORKPARAMS[] = { 'G', 'e', 't', 'N', 'e', 't', 'w', 'o', 'r', 'k', 'P', 'a', 'r', 'a', 'm', 's', 0, };
/* "GetTcpTable" */
#define DECLARE_NAMEOF_API_GETTCPTABLE CHAR NAMEOF_API_GETTCPTABLE[] = { 'G', 'e', 't', 'T', 'c', 'p', 'T', 'a', 'b', 'l', 'e', 0, };
/* "GetUdpTable" */
#define DECLARE_NAMEOF_API_GETUDPTABLE CHAR NAMEOF_API_GETUDPTABLE[] = { 'G', 'e', 't', 'U', 'd', 'p', 'T', 'a', 'b', 'l', 'e', 0, };
/* "AllocateAndGetTcpExTableFromStack" */
#define DECLARE_NAMEOF_API_ALLOCATEANDGETTCPEXTABLEFROMSTACK CHAR NAMEOF_API_ALLOCATEANDGETTCPEXTABLEFROMSTACK[] = { 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'A', 'n', 'd', 'G', 'e', 't', 'T', 'c', 'p', 'E', 'x', 'T', 'a', 'b', 'l', 'e', 'F', 'r', 'o', 'm', 'S', 't', 'a', 'c', 'k', 0, };
/* "AllocateAndGetUdpExTableFromStack" */
#define DECLARE_NAMEOF_API_ALLOCATEANDGETUDPEXTABLEFROMSTACK CHAR NAMEOF_API_ALLOCATEANDGETUDPEXTABLEFROMSTACK[] = { 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'A', 'n', 'd', 'G', 'e', 't', 'U', 'd', 'p', 'E', 'x', 'T', 'a', 'b', 'l', 'e', 'F', 'r', 'o', 'm', 'S', 't', 'a', 'c', 'k', 0, };
/* "GetExtendedTcpTable" */
#define DECLARE_NAMEOF_API_GETEXTENDEDTCPTABLE CHAR NAMEOF_API_GETEXTENDEDTCPTABLE[] = { 'G', 'e', 't', 'E', 'x', 't', 'e', 'n', 'd', 'e', 'd', 'T', 'c', 'p', 'T', 'a', 'b', 'l', 'e', 0, };
/* "GetExtendedUdpTable" */
#define DECLARE_NAMEOF_API_GETEXTENDEDUDPTABLE CHAR NAMEOF_API_GETEXTENDEDUDPTABLE[] = { 'G', 'e', 't', 'E', 'x', 't', 'e', 'n', 'd', 'e', 'd', 'U', 'd', 'p', 'T', 'a', 'b', 'l', 'e', 0, };
/* "NotifyAddrChange" */
#define DECLARE_NAMEOF_API_NOTIFYADDRCHANGE CHAR NAMEOF_API_NOTIFYADDRCHANGE[] = { 'N', 'o', 't', 'i', 'f', 'y', 'A', 'd', 'd', 'r', 'C', 'h', 'a', 'n', 'g', 'e', 0, };
/* "NotifyRouteChange" */
#define DECLARE_NAMEOF_API_NOTIFYROUTECHANGE CHAR NAMEOF_API_NOTIFYROUTECHANGE[] = { 'N', 'o', 't', 'i', 'f', 'y', 'R', 'o', 'u', 't', 'e', 'C', 'h', 'a', 'n', 'g', 'e', 0, };
/* "CancelIPChangeNotify" */
#define DECLARE_NAMEOF_API_CANCELIPCHANGENOTIFY CHAR NAMEOF_API_CANCELIPCHANGENOTIFY[] = { 'C', 'a', 'n', 'c', 'e', 'l', 'I', 'P', 'C', 'h', 'a', 'n', 'g', 'e', 'N', 'o', 't', 'i', 'f', 'y', 0, };

/* @brief
    The GetAdaptersInfo function retrieves adapter information for the local computer.
    On Windows XP and later:  Use the GetAdaptersAddresses function instead of GetAdaptersInfo.
 */
typedef DWORD (WINAPI *GETADAPTERSINFO)(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen);
typedef DWORD (WINAPI *GETIPADDRTABLE)(
    OUT PMIB_IPADDRTABLE pIpAddrTable,
    IN OUT PULONG pdwSize,
    IN BOOL bOrder
    );

/* @brief
    The GetIpNetTable function retrieves the IPv4 to physical address mapping table.
 */
typedef DWORD (WINAPI *GETIPNETTABLE)(
    OUT PMIB_IPNETTABLE pIpNetTable,
    IN OUT PULONG pdwSize,
    IN BOOL bOrder
    );
/* @brief
    The GetIfTable function retrieves the MIB-II interface table.
 */
typedef DWORD (WINAPI *GETIFTABLE)(
    OUT PMIB_IFTABLE pIfTable,
    IN OUT PULONG pdwSize,
    IN BOOL bOrder
    );

/* @brief
    The GetNetworkParams function retrieves network parameters for the local computer.
 */
typedef DWORD (WINAPI *GETNETWORKPARAMS)(PFIXED_INFO pFixedInfo, PULONG pOutBufLen);

/* @brief
    The GetTcpTable function retrieves the IPv4 TCP connection table.
 */
typedef DWORD (WINAPI *GETTCPTABLE)(
    OUT PMIB_TCPTABLE pUdpTable,
    IN OUT PDWORD pdwSize,
    IN BOOL bOrder
    );

/* @brief
    The GetUdpTable function retrieves the IPv4 User Datagram Protocol (UDP) listener table.
 */
typedef DWORD (WINAPI *GETUDPTABLE)(
    OUT PMIB_UDPTABLE pUdpTable,
    IN OUT PDWORD pdwSize,
    IN BOOL bOrder
    );

typedef struct _MIB_TCPROW_EX {
    DWORD dwState;
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwRemoteAddr;
    DWORD dwRemotePort;
    DWORD dwProcessId;
} MIB_TCPROW_EX, *PMIB_TCPROW_EX;

typedef struct _MIB_TCPTABLE_EX {
    DWORD dwNumEntries;
    MIB_TCPROW_EX table[ANY_SIZE];
} MIB_TCPTABLE_EX, *PMIB_TCPTABLE_EX;

typedef struct _MIB_TCP6ROW_EX {
    UCHAR ucLocalAddr[16];
    DWORD dwLocalScopeId;
    DWORD dwLocalPort;
    UCHAR ucRemoteAddr[16];
    DWORD dwRemoteScopeId;
    DWORD dwRemotePort;
    DWORD dwState;
    DWORD dwProcessId;
} MIB_TCP6ROW_EX, *PMIB_TCP6ROW_EX;

typedef struct _MIB_TCP6TABLE_EX {
    DWORD dwNumEntries;
    MIB_TCP6ROW_EX table[ANY_SIZE];
} MIB_TCP6TABLE_EX, *PMIB_TCP6TABLE_EX;

typedef struct _MIB_UDPROW_EX {
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwProcessId;
} MIB_UDPROW_EX, *PMIB_UDPROW_EX;

typedef struct _MIB_UDPTABLE_EX {
    DWORD dwNumEntries;
    MIB_UDPROW_EX table[ANY_SIZE];
} MIB_UDPTABLE_EX, *PMIB_UDPTABLE_EX;

typedef struct _MIB_UDP6ROW_EX {
    UCHAR ucLocalAddr[16];
    DWORD dwLocalScopeId;
    DWORD dwLocalPort;
    DWORD dwProcessId;
} MIB_UDP6ROW_EX, *PMIB_UDP6ROW_EX;

typedef struct _MIB_UDP6TABLE_EX {
    DWORD dwNumEntries;
    MIB_UDP6ROW_EX table[ANY_SIZE];
} MIB_UDP6TABLE_EX,  *PMIB_UDP6TABLE_EX;

/* @brief
    [This function is no longer available for use as of Windows Vista. Instead, use the GetTcpTable or GetExtendedTcpTable function to retrieve the TCP connection table.]
    The AllocateAndGetTcpExTableFromStack function retrieves the TCP connection table and allocates memory from the local heap to store the table.
   @comment
    see IPHelper::GetExtendedTcpTable1
 */
typedef DWORD (WINAPI *ALLOCATEANDGETTCPEXTABLEFROMSTACK)(
    OUT PVOID* ppTcpTable,
    IN BOOL bOrder,
    IN HANDLE hHeap,
    IN DWORD dwFlags,
    IN DWORD dwFamily
    );

/* @brief
    [This function is no longer available for use as of Windows Vista. Instead, use the GetUdpTable or GetExtendedUdpTable function to retrieve the UDP connection table.]
    The AllocateAndGetUdpExTableFromStack function retrieves the UDP connection table and allocates memory from the local heap to store the table.
   @comment
    see IPHelper::GetExtendedUdpTable1
 */
typedef DWORD (WINAPI *ALLOCATEANDGETUDPEXTABLEFROMSTACK)(
    OUT PVOID *ppUDPTable,
    IN BOOL bOrder,
    IN HANDLE hHeap,
    IN DWORD dwFlags,
    IN DWORD dwFamily
    );

#if _MSC_FULL_VER >= 140050727

#else

#ifndef __MINGW32__
typedef enum _TCP_TABLE_CLASS {
    TCP_TABLE_BASIC_LISTENER,
    TCP_TABLE_BASIC_CONNECTIONS,
    TCP_TABLE_BASIC_ALL,
    TCP_TABLE_OWNER_PID_LISTENER,
    TCP_TABLE_OWNER_PID_CONNECTIONS,
    TCP_TABLE_OWNER_PID_ALL,
    TCP_TABLE_OWNER_MODULE_LISTENER,
    TCP_TABLE_OWNER_MODULE_CONNECTIONS,
    TCP_TABLE_OWNER_MODULE_ALL
} TCP_TABLE_CLASS, *PTCP_TABLE_CLASS;

typedef enum _UDP_TABLE_CLASS {
    UDP_TABLE_BASIC,
    UDP_TABLE_OWNER_PID,
    UDP_TABLE_OWNER_MODULE
} UDP_TABLE_CLASS, *PUDP_TABLE_CLASS;
#endif

#endif

/* @brief
    The GetExtendedTcpTable function retrieves a table that contains a list of TCP endpoints available to the application.
 */
typedef DWORD (WINAPI *GETEXTENDEDTCPTABLE)(
    OUT PVOID pTcpTable,
    IN OUT PDWORD pdwSize,
    IN BOOL bOrder,
    IN ULONG ulAf,
    IN TCP_TABLE_CLASS TableClass,
    IN ULONG Reserved
    );

/* @brief
    The GetExtendedUdpTable function retrieves a table that contains a list of UDP endpoints available to the application.
 */
typedef DWORD (WINAPI *GETEXTENDEDUDPTABLE)(
    OUT PVOID pUdpTable,
    IN OUT PDWORD pdwSize,
    IN BOOL bOrder,
    IN ULONG ulAf,
    IN UDP_TABLE_CLASS TableClass,
    IN ULONG Reserved
    );

/* @brief
    The NotifyAddrChange function causes a notification to be sent to the caller whenever a change occurs in the table that maps IPv4 addresses to interfaces.
 */
typedef DWORD (WINAPI *NOTIFYADDRCHANGE)(
    ___out PHANDLE Handle,
    ___in LPOVERLAPPED overlapped
    );

/* @brief
    The NotifyRouteChange function causes a notification to be sent to the caller whenever a change occurs in the IPv4 routing table.
 */
typedef DWORD (WINAPI *NOTIFYROUTECHANGE)(
    ___out PHANDLE Handle,
    ___in LPOVERLAPPED overlapped
    );

/* @brief
    The CancelIPChangeNotify function cancels notification of IPv4 address and route changes previously requested with successful calls to the NotifyAddrChange or NotifyRouteChange functions.
   @comment
    XP, 2003+
 */
typedef BOOL (WINAPI* CANCELIPCHANGENOTIFY)(
    ___in LPOVERLAPPED notifyOverlapped
    );

#endif
