/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab textwidth=130 colorcolumn=+1: */
/**
 * @file wininet.h
 * @author Soo Han, Kim (hush@ahnlab.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_WININET__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_WININET__

/* wininet */

//#include <wininet.h>
typedef LPVOID HINTERNET;
typedef WORD INTERNET_PORT;

#undef  NAMEOF_API_INTERNETOPEN
#undef  NAMEOF_API_INTERNETCONNECT
#undef  NAMEOF_API_HTTPOPENREQUEST
#undef  NAMEOF_API_HTTPADDREQUESTHEADERS
#undef  NAMEOF_API_HTTPSENDREQUEST

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_INTERNETOPEN             DECLARE_NAMEOF_API_INTERNETOPENA
#define DECLARE_NAMEOF_API_INTERNETCONNECT          DECLARE_NAMEOF_API_INTERNETCONNECTA
#define DECLARE_NAMEOF_API_HTTPOPENREQUEST          DECLARE_NAMEOF_API_HTTPOPENREQUESTA
#define DECLARE_NAMEOF_API_HTTPADDREQUESTHEADERS    DECLARE_NAMEOF_API_HTTPADDREQUESTHEADERSA
#define DECLARE_NAMEOF_API_HTTPSENDREQUEST          DECLARE_NAMEOF_API_HTTPSENDREQUESTA

#define NAMEOF_API_INTERNETOPEN                     NAMEOF_API_INTERNETOPENA
#define NAMEOF_API_INTERNETCONNECT                  NAMEOF_API_INTERNETCONNECTA
#define NAMEOF_API_HTTPOPENREQUEST                  NAMEOF_API_HTTPOPENREQUESTA
#define NAMEOF_API_HTTPADDREQUESTHEADERS            NAMEOF_API_HTTPADDREQUESTHEADERSA
#define NAMEOF_API_HTTPSENDREQUEST                  NAMEOF_API_HTTPSENDREQUESTA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_INTERNETOPEN             DECLARE_NAMEOF_API_INTERNETOPENW
#define DECLARE_NAMEOF_API_INTERNETCONNECT          DECLARE_NAMEOF_API_INTERNETCONNECTW
#define DECLARE_NAMEOF_API_HTTPOPENREQUEST          DECLARE_NAMEOF_API_HTTPOPENREQUESTW
#define DECLARE_NAMEOF_API_HTTPADDREQUESTHEADERS    DECLARE_NAMEOF_API_HTTPADDREQUESTHEADERSW
#define DECLARE_NAMEOF_API_HTTPSENDREQUEST          DECLARE_NAMEOF_API_HTTPSENDREQUESTW

#define NAMEOF_API_INTERNETOPEN                     NAMEOF_API_INTERNETOPENW
#define NAMEOF_API_INTERNETCONNECT                  NAMEOF_API_INTERNETCONNECTW
#define NAMEOF_API_HTTPOPENREQUEST                  NAMEOF_API_HTTPOPENREQUESTW
#define NAMEOF_API_HTTPADDREQUESTHEADERS            NAMEOF_API_HTTPADDREQUESTHEADERSW
#define NAMEOF_API_HTTPSENDREQUEST                  NAMEOF_API_HTTPSENDREQUESTW
#endif

/* "InternetOpenA" */
#define DECLARE_NAMEOF_API_INTERNETOPENA CHAR NAMEOF_API_INTERNETOPENA[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'O', 'p', 'e', 'n', 'A', 0, };
/* "InternetConnectA" */
#define DECLARE_NAMEOF_API_INTERNETCONNECTA CHAR NAMEOF_API_INTERNETCONNECTA[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'C', 'o', 'n', 'n', 'e', 'c', 't', 'A', 0, };
/* "HttpOpenRequestA" */
#define DECLARE_NAMEOF_API_HTTPOPENREQUESTA CHAR NAMEOF_API_HTTPOPENREQUESTA[] = { 'H', 't', 't', 'p', 'O', 'p', 'e', 'n', 'R', 'e', 'q', 'u', 'e', 's', 't', 'A', 0, };
/* "HttpAddRequestHeadersA" */
#define DECLARE_NAMEOF_API_HTTPADDREQUESTHEADERSA CHAR NAMEOF_API_HTTPADDREQUESTHEADERSA[] = { 'H', 't', 't', 'p', 'A', 'd', 'd', 'R', 'e', 'q', 'u', 'e', 's', 't', 'H', 'e', 'a', 'd', 'e', 'r', 's', 'A', 0, };
/* "HttpSendRequestA" */
#define DECLARE_NAMEOF_API_HTTPSENDREQUESTA CHAR NAMEOF_API_HTTPSENDREQUESTA[] = { 'H', 't', 't', 'p', 'S', 'e', 'n', 'd', 'R', 'e', 'q', 'u', 'e', 's', 't', 'A', 0, };

/* "InternetOpenW" */
#define DECLARE_NAMEOF_API_INTERNETOPENW CHAR NAMEOF_API_INTERNETOPENW[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'O', 'p', 'e', 'n', 'W', 0, };
/* "InternetConnectW" */
#define DECLARE_NAMEOF_API_INTERNETCONNECTW CHAR NAMEOF_API_INTERNETCONNECTW[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'C', 'o', 'n', 'n', 'e', 'c', 't', 'W', 0, };
/* "HttpOpenRequestW" */
#define DECLARE_NAMEOF_API_HTTPOPENREQUESTW CHAR NAMEOF_API_HTTPOPENREQUESTW[] = { 'H', 't', 't', 'p', 'O', 'p', 'e', 'n', 'R', 'e', 'q', 'u', 'e', 's', 't', 'W', 0, };
/* "HttpAddRequestHeadersW" */
#define DECLARE_NAMEOF_API_HTTPADDREQUESTHEADERSW CHAR NAMEOF_API_HTTPADDREQUESTHEADERSW[] = { 'H', 't', 't', 'p', 'A', 'd', 'd', 'R', 'e', 'q', 'u', 'e', 's', 't', 'H', 'e', 'a', 'd', 'e', 'r', 's', 'W', 0, };
/* "HttpSendRequestW" */
#define DECLARE_NAMEOF_API_HTTPSENDREQUESTW CHAR NAMEOF_API_HTTPSENDREQUESTW[] = { 'H', 't', 't', 'p', 'S', 'e', 'n', 'd', 'R', 'e', 'q', 'u', 'e', 's', 't', 'W', 0, };

/* "InternetAttemptConnect" */
#define DECLARE_NAMEOF_API_INTERNETATTEMPTCONNECT CHAR NAMEOF_API_INTERNETATTEMPTCONNECT[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'A', 't', 't', 'e', 'm', 'p', 't', 'C', 'o', 'n', 'n', 'e', 'c', 't', 0, };
/* "InternetCloseHandle" */
#define DECLARE_NAMEOF_API_INTERNETCLOSEHANDLE CHAR NAMEOF_API_INTERNETCLOSEHANDLE[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0, };
/* "HttpQueryInfo" */
#define DECLARE_NAMEOF_API_HTTPQUERYINFO CHAR NAMEOF_API_HTTPQUERYINFO[] = { 'H', 't', 't', 'p', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 0, };
/* "InternetSetOption" */
#define DECLARE_NAMEOF_API_INTERNETSETOPTION CHAR NAMEOF_API_INTERNETSETOPTION[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'S', 'e', 't', 'O', 'p', 't', 'i', 'o', 'n', 0, };
/* "InternetQueryOption" */
#define DECLARE_NAMEOF_API_INTERNETQUERYOPTION CHAR NAMEOF_API_INTERNETQUERYOPTION[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'Q', 'u', 'e', 'r', 'y', 'O', 'p', 't', 'i', 'o', 'n', 0, };
/* "InternetReadFile" */
#define DECLARE_NAMEOF_API_INTERNETREADFILE CHAR NAMEOF_API_INTERNETREADFILE[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', 'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e', 0, };

/* @brief
    Initializes an application's use of the WinINet functions.
 */
typedef HINTERNET (__stdcall* INTERNETOPEN)(
    ___in LPCTSTR lpszAgent,
    ___in DWORD dwAccessType,
    ___in LPCTSTR lpszProxyName,
    ___in LPCTSTR lpszProxyBypass,
    ___in DWORD dwFlags
    );

/* @brief
    Opens an File Transfer Protocol (FTP) or HTTP session for a given site.
 */
typedef HINTERNET (__stdcall* INTERNETCONNECT)(
    ___in HINTERNET hInternet,
    ___in LPCTSTR lpszServerName,
    ___in INTERNET_PORT nServerPort,
    ___in LPCTSTR lpszUsername,
    ___in LPCTSTR lpszPassword,
    ___in DWORD dwService,
    ___in DWORD dwFlags,
    ___in DWORD_PTR dwContext
    );

/* @brief
    Attempts to make a connection to the Internet.
 */
typedef DWORD (__stdcall* INTERNETATTEMPTCONNECT)(
    ___in DWORD dwReserved
    );

/* @brief
    Closes a single Internet handle.
 */
typedef BOOL (__stdcall* INTERNETCLOSEHANDLE)(
    ___in HINTERNET hInternet
    );

/* @brief
    Creates an HTTP request handle.
 */
typedef HINTERNET (__stdcall* HTTPOPENREQUEST)(
    ___in HINTERNET hConnect,
    ___in LPCTSTR lpszVerb,
    ___in LPCTSTR lpszObjectName,
    ___in LPCTSTR lpszVersion,
    ___in LPCTSTR lpszReferer,
    ___in LPCTSTR* lplpszAcceptTypes,
    ___in DWORD dwFlags,
    ___in DWORD_PTR dwContext
    );

/* @brief
    Adds one or more HTTP request headers to the HTTP request handle.
 */
typedef BOOL (__stdcall* HTTPADDREQUESTHEADERS)(
    ___in HINTERNET hConnect,
    ___in LPCTSTR lpszHeaders,
    ___in DWORD dwHeadersLength,
    ___in DWORD dwModifiers
    );

/* @brief
    Sends the specified request to the HTTP server, allowing callers to send extra data beyond what is normally passed to HttpSendRequestEx.
 */
typedef BOOL (__stdcall* HTTPSENDREQUEST)(
    ___in HINTERNET hRequest,
    ___in LPCTSTR lpszHeaders,
    ___in DWORD dwHeadersLength,
    ___in LPVOID lpOptional,
    ___in DWORD dwOptionalLength
    );

/* @brief
    Retrieves header information associated with an HTTP request.
 */
typedef BOOL (__stdcall* HTTPQUERYINFO)(
    ___in HINTERNET hRequest,
    ___in DWORD dwInfoLevel,
    __inout LPVOID lpvBuffer,
    __inout LPDWORD lpdwBufferLength,
    __inout LPDWORD lpdwIndex
    );

/* @brief
    Sets an Internet option.
 */
typedef BOOL (__stdcall* INTERNETSETOPTION)(
    ___in HINTERNET hInternet,
    ___in DWORD dwOption,
    ___in LPVOID lpBuffer,
    ___in DWORD dwBufferLength
    );

/* @brief
    Queries an Internet option on the specified handle.
 */
typedef BOOL (__stdcall* INTERNETQUERYOPTION)(
    ___in HINTERNET hInternet,
    ___in DWORD dwOption,
    ___out LPVOID lpBuffer,
    __inout LPDWORD lpdwBufferLength
    );

/* @brief
    Reads data from a handle opened by the InternetOpenUrl, FtpOpenFile, or HttpOpenRequest function.
 */
typedef BOOL (__stdcall* INTERNETREADFILE)(
    ___in HINTERNET hFile,
    ___out LPVOID lpBuffer,
    ___in DWORD dwNumberOfBytesToRead,
    ___out LPDWORD lpdwNumberOfBytesRead
    );

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_FINDFIRSTURLCACHEENTRY   DECLARE_NAMEOF_API_FINDFIRSTURLCACHEENTRYA
#define DECLARE_NAMEOF_API_FINDNEXTURLCACHEENTRY    DECLARE_NAMEOF_API_FINDNEXTURLCACHEENTRYA
#define DECLARE_NAMEOF_API_DELETEURLCACHEENTRY      DECLARE_NAMEOF_API_DELETEURLCACHEENTRYA

#define NAMEOF_API_FINDFIRSTURLCACHEENTRY           NAMEOF_API_FINDFIRSTURLCACHEENTRYA
#define NAMEOF_API_FINDNEXTURLCACHEENTRY            NAMEOF_API_FINDNEXTURLCACHEENTRYA
#define NAMEOF_API_DELETEURLCACHEENTRY              NAMEOF_API_DELETEURLCACHEENTRYA
#define FINDFIRSTURLCACHEENTRY                      FINDFIRSTURLCACHEENTRYA
#define FINDNEXTURLCACHEENTRY                       FINDNEXTURLCACHEENTRYA
#define DELETEURLCACHEENTRY                         DELETEURLCACHEENTRYA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_FINDFIRSTURLCACHEENTRY   DECLARE_NAMEOF_API_FINDFIRSTURLCACHEENTRYW
#define DECLARE_NAMEOF_API_FINDNEXTURLCACHEENTRY    DECLARE_NAMEOF_API_FINDNEXTURLCACHEENTRYW
#define DECLARE_NAMEOF_API_DELETEURLCACHEENTRY      DECLARE_NAMEOF_API_DELETEURLCACHEENTRYW

#define NAMEOF_API_FINDFIRSTURLCACHEENTRY           NAMEOF_API_FINDFIRSTURLCACHEENTRYW
#define NAMEOF_API_FINDNEXTURLCACHEENTRY            NAMEOF_API_FINDNEXTURLCACHEENTRYW
#define NAMEOF_API_DELETEURLCACHEENTRY              NAMEOF_API_DELETEURLCACHEENTRYW
#define FINDFIRSTURLCACHEENTRY                      FINDFIRSTURLCACHEENTRYW
#define FINDNEXTURLCACHEENTRY                       FINDNEXTURLCACHEENTRYW
#define DELETEURLCACHEENTRY                         DELETEURLCACHEENTRYW
#endif

/* "FindFirstUrlCacheEntryA" */
#define DECLARE_NAMEOF_API_FINDFIRSTURLCACHEENTRYA CHAR NAMEOF_API_FINDFIRSTURLCACHEENTRYA[] = { 'F', 'i', 'n', 'd', 'F', 'i', 'r', 's', 't', 'U', 'r', 'l', 'C', 'a', 'c', 'h', 'e', 'E', 'n', 't', 'r', 'y', 'A', 0, };
/* "FindFirstUrlCacheEntryW" */
#define DECLARE_NAMEOF_API_FINDFIRSTURLCACHEENTRYW CHAR NAMEOF_API_FINDFIRSTURLCACHEENTRYW[] = { 'F', 'i', 'n', 'd', 'F', 'i', 'r', 's', 't', 'U', 'r', 'l', 'C', 'a', 'c', 'h', 'e', 'E', 'n', 't', 'r', 'y', 'W', 0, };
/* "FindNextUrlCacheEntryA" */
#define DECLARE_NAMEOF_API_FINDNEXTURLCACHEENTRYA CHAR NAMEOF_API_FINDNEXTURLCACHEENTRYA[] = { 'F', 'i', 'n', 'd', 'N', 'e', 'x', 't', 'U', 'r', 'l', 'C', 'a', 'c', 'h', 'e', 'E', 'n', 't', 'r', 'y', 'A', 0, };
/* "FindNextUrlCacheEntryW" */
#define DECLARE_NAMEOF_API_FINDNEXTURLCACHEENTRYW CHAR NAMEOF_API_FINDNEXTURLCACHEENTRYW[] = { 'F', 'i', 'n', 'd', 'N', 'e', 'x', 't', 'U', 'r', 'l', 'C', 'a', 'c', 'h', 'e', 'E', 'n', 't', 'r', 'y', 'W', 0, };
/* "FindCloseUrlCache" */
#define DECLARE_NAMEOF_API_FINDCLOSEURLCACHE CHAR NAMEOF_API_FINDCLOSEURLCACHE[] = { 'F', 'i', 'n', 'd', 'C', 'l', 'o', 's', 'e', 'U', 'r', 'l', 'C', 'a', 'c', 'h', 'e', 0, };
/* "DeleteUrlCacheEntryA" */
#define DECLARE_NAMEOF_API_DELETEURLCACHEENTRYA CHAR NAMEOF_API_DELETEURLCACHEENTRYA[] = { 'D', 'e', 'l', 'e', 't', 'e', 'U', 'r', 'l', 'C', 'a', 'c', 'h', 'e', 'E', 'n', 't', 'r', 'y', 'A', 0, };
/* "DeleteUrlCacheEntryW" */
#define DECLARE_NAMEOF_API_DELETEURLCACHEENTRYW CHAR NAMEOF_API_DELETEURLCACHEENTRYW[] = { 'D', 'e', 'l', 'e', 't', 'e', 'U', 'r', 'l', 'C', 'a', 'c', 'h', 'e', 'E', 'n', 't', 'r', 'y', 'W', 0, };

/* wininet.h 충돌하므로 실제 구조체 이름을 사용하지 않는다. */
typedef void* LPINTERNET_CACHE_ENTRY_INFOA_;
typedef void* LPINTERNET_CACHE_ENTRY_INFOW_;

/* @brief
    Begins the enumeration of the Internet cache.
 */
typedef HANDLE (__stdcall* FINDFIRSTURLCACHEENTRYA)(
    ___in LPCSTR lpszUrlSearchPattern,
    ___out LPINTERNET_CACHE_ENTRY_INFOA_ lpFirstCacheEntryInfo,
    __inout LPDWORD lpcbCacheEntryInfo
    );

typedef HANDLE (__stdcall* FINDFIRSTURLCACHEENTRYW)(
    ___in LPCWSTR lpszUrlSearchPattern,
    ___out LPINTERNET_CACHE_ENTRY_INFOW_ lpFirstCacheEntryInfo,
    __inout LPDWORD lpcbCacheEntryInfo
    );

/* @brief
    Retrieves the next entry in the Internet cache.
 */
typedef BOOL (__stdcall* FINDNEXTURLCACHEENTRYA)(
    ___in HANDLE hEnumHandle,
    ___out LPINTERNET_CACHE_ENTRY_INFOA_ lpNextCacheEntryInfo,
    __inout LPDWORD lpcbCacheEntryInfo
    );

typedef BOOL (__stdcall* FINDNEXTURLCACHEENTRYW)(
    ___in HANDLE hEnumHandle,
    ___out LPINTERNET_CACHE_ENTRY_INFOW_ lpNextCacheEntryInfo,
    __inout LPDWORD lpcbCacheEntryInfo
    );

/* @brief
    Closes the specified cache enumeration handle.
 */
typedef BOOL (__stdcall* FINDCLOSEURLCACHE)(
    ___in HANDLE hEnumHandle
    );

/* @brief
    Removes the file associated with the source name from the cache, if the file exists.
 */
typedef BOOL (__stdcall* DELETEURLCACHEENTRYA)(
    ___in LPCSTR lpszUrlName
    );

typedef BOOL (__stdcall* DELETEURLCACHEENTRYW)(
    ___in LPCWSTR lpszUrlName
    );

#endif
