/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TYPES__
#define __HOTPLACE_SDK_NET_TYPES__

#if defined __linux__ || defined __APPLE__
    #include <fcntl.h>
    #include <sys/types.h>
    #include <sys/file.h>
    #include <unistd.h>

    #if __GLIBC_MINOR__ >= 3
        #include <sys/epoll.h>
    #endif
    #include <sys/socket.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
#elif defined _WIN32 || defined _WIN64
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <mswsock.h>
#endif

#include <hotplace/sdk/base.hpp>

namespace hotplace {
namespace net {

#if defined __linux__ || defined __APPLE__
typedef int socket_t;
#elif defined _WIN32 || defined _WIN64
typedef SOCKET socket_t;

#endif
typedef struct sockaddr sockaddr_t;
typedef struct sockaddr_storage sockaddr_storage_t;
typedef struct linger linger_t;

typedef struct _URL_INFO {
    std::string protocol;
    std::string domainip;
    int port;
    std::string uri;
    std::string uripath;
    std::string urifile;

    _URL_INFO () : port (0)
    {
    }
} URL_INFO;

enum TLS_READ_FLAG {
    TLS_READ_SSL_READ       = (1 << 0),
    TLS_READ_BIO_WRITE      = (1 << 1),
    TLS_READ_SOCKET_RECV    = (1 << 2),
    TLS_SEND_SSL_WRITE      = (1 << 3),
    TLS_SEND_BIO_READ       = (1 << 4),
    TLS_SEND_SOCKET_SEND    = (1 << 5),
    TLS_READ_IOCP           = (TLS_READ_BIO_WRITE),
    TLS_READ_EPOLL          = (TLS_READ_BIO_WRITE | TLS_READ_SOCKET_RECV),
    TLS_SEND_ALL            = (TLS_SEND_SSL_WRITE | TLS_SEND_BIO_READ | TLS_SEND_SOCKET_SEND),
};

struct _TLS_CONTEXT;
typedef struct _TLS_CONTEXT tls_context_t;

}
}  // namespace

#endif
