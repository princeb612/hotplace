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

#if defined __linux__
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

#if defined __linux__
typedef int socket_t;
#elif defined _WIN32 || defined _WIN64
typedef SOCKET socket_t;

#endif
typedef struct sockaddr sockaddr_t;
typedef struct sockaddr_storage sockaddr_storage_t;
typedef struct linger linger_t;

enum tls_io_flag_t {
    read_ssl_read       = (1 << 0),                                             // 0000 0001
    read_bio_write      = (1 << 1),                                             // 0000 0010
    read_socket_recv    = (1 << 2),                                             // 0000 0100
    send_ssl_write      = (1 << 3),                                             // 0000 1000
    send_bio_read       = (1 << 4),                                             // 0001 0000
    send_socket_send    = (1 << 5),                                             // 0010 0000
    read_iocp           = (read_bio_write),                                     // 0000 0010
    read_epoll          = (read_bio_write | read_socket_recv),                  // 0000 0110
    send_all            = (send_ssl_write | send_bio_read | send_socket_send),  // 0011 1000
};

#define NET_DEFAULT_TIMEOUT 10
typedef struct linger linger_t;

struct _tls_context_t;
typedef struct _tls_context_t tls_context_t;

}
}  // namespace

#endif
