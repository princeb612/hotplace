/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_SDK__
#define __HOTPLACE_SDK_NET_BASIC_SDK__

#include <hotplace/sdk/net/types.hpp>

namespace hotplace {
namespace net {

/*
 * @brief   create a socket, see alse close_socket to free
 * @param   socket_t*           socket_created [out] socket
 * @param   sockaddr_storage_t* sockaddr_created [out] socket address
 * @param   int                 address_type [in]
 * @param   const char*         address [in] 127.0.0.1 socket ipv4, ::1 socket ipv6
 * @param   uint16              port [in]
 * @return  error code (see error.hpp)
 * @sample
 *          address = "127.0.0.1";
 *          port = 1234;
 *          socket_t sock = INVALID_SOCKET;
 *          sockaddr_storage_t sockaddr_address;
 *          create_socket (&sock, &sockaddr_address, SOCK_STREAM, address, port);
 *          // ...
 *          close_socket (sock, true, 0);
 */
return_t create_socket (socket_t* socket_created, sockaddr_storage_t* sockaddr_created, int address_type, const char* address, uint16 port);
/*
 * @brief   create a socket and listen, see alse CloseListener to free
 * @param   unsigned int size_vector    [in]
 * @param   unsigned int* vector_family [in] AF_INET, AF_INET6
 * @param   socket_t* vector_socket     [out]
 * @param   int protocol_type           [in] PROTOCOL_TCP
 * @param   uint32 port                 [in]
 * @param   bool support_win32_acceptex [inopt]
 * @error   error code (see error.hpp)
 * @sample
 *          unsigned int nFamily[2] = { AF_INET, AF_INET6 };  // IPv4 and IPv6
 *          socket_t Sockets[2] = { INVALID_SOCKET, INVALID_SOCKET };
 *          create_listener (2, nFamily, Sockets, PROTOCOL_TCP, 9000);
 *          // ...
 *          close_listener (2, Sockets);
 */
return_t create_listener (unsigned int size_vector, unsigned int* vector_family, socket_t* vector_socket, int protocol_type,
                          uint32 port, bool support_win32_acceptex = false);
/*
 * @brief   create_socket and connect_socket_addr
 * @param   socket_t*   socket  [out]
 * @param   int         nType   [in]
 * @param   const char* address [in]
 * @param   uint16      port    [in]
 * @param   uint32      timeout [in]
 * @error   error code (see error.hpp)
 */
return_t connect_socket (socket_t* socket, int nType, const char* address, uint16 port, uint32 timeout);
/*
 * @brief   connect to address
 * @param   socket_t            sock            [in]
 * @param   sockaddr_storage_t* pSockAddr       [in]
 * @param   size_t              sizeSockAddr    [in]
 * @param   uint32              dwTimeout       [in]
 */
return_t connect_socket_addr (socket_t sock, sockaddr_storage_t* pSockAddr, size_t sizeSockAddr, uint32 dwTimeout);
/*
 * @brief   disconnect
 * @param   socket_t    sock    [in]
 * @param   bool        onoff   [in]
 * @param   uint16      linger  [in]
 */
return_t close_socket (socket_t sock, bool onoff, uint16 linger);
/*
 * @brief   stop listen
 * @param   unsigned int    nSockets    [in]
 * @param   socket_t*       Sockets     [in]
 * @return  error code (see error.hpp)
 * @sample  see create_listener
 */
return_t close_listener (unsigned int nSockets, socket_t* Sockets);

enum SOCK_WAIT_FLAGS {
    SOCK_WAIT_READABLE  = 1 << 0,
    SOCK_WAIT_WRITABLE  = 1 << 1,
};
/*
 * @brief   wait
 * @param   socket_t    sock            [in]
 * @param   uint32      dwMilliSeconds  [in]
 * @param   uint32      dwFlag          [in] see SOCK_WAIT_FLAGS
 */
return_t wait_socket (socket_t sock, uint32 dwMilliSeconds, uint32 dwFlag);

return_t set_sock_nbio (socket_t sock, uint32 nbio_mode);

#if defined _WIN32 || defined _WIN64
return_t winsock_startup ();
void winsock_cleanup ();
#endif

/*
 * split url
 * @sample
 *        URL_INFO info;
 *        const char *url = "http://test.com/download/meta/file.txt";
 *        split_url(url, &info);
 *        // info.protocol => http
 *        // info.domainip => test.com
 *        // info.port => 80
 *        // info.uri => /download/meta/file.txt
 *        // info.uripath => download/meta
 *        // info.urifile => file.txt
 * @remarks
 *        input                             -> prot / domainip / uripath  / urifile
 *        http://test.com/download/file.txt -> http / test.com / download / file.txt
 *        http://test.com/download/         -> http / test.com / download / NA
 *        http://test.com/download          -> http / test.com / NA       / download
 *        http://test.com/a/b/              -> http / test.com / a/b      / NA
 *        http://test.com/a/b               -> http / test.com / a        / b
 *        http://test.com                   -> http / test.com / NA       / NA
 *        /download/file.txt                -> NA   / NA       / download / file.txt
 *        /download/                        -> NA   / NA       / download / N/A
 */
return_t split_url (const char* url, URL_INFO* info);

}
}  // namespace

#endif
