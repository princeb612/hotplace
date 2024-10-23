/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TYPES__
#define __HOTPLACE_SDK_NET_TYPES__

#if defined __linux__

#include <fcntl.h>
#include <sys/file.h>
#include <sys/types.h>
#include <unistd.h>

#if __GLIBC_MINOR__ >= 3
#include <sys/epoll.h>
#endif
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#elif defined _WIN32 || defined _WIN64

#include <sdk/base/system/windows/types.hpp>

#endif

#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/io/types.hpp>

namespace hotplace {
namespace net {

enum tls_io_flag_t {
    read_ssl_read = (1 << 0),                                        // 0000 0001
    read_bio_write = (1 << 1),                                       // 0000 0010
    read_socket_recv = (1 << 2),                                     // 0000 0100
    send_ssl_write = (1 << 3),                                       // 0000 1000
    send_bio_read = (1 << 4),                                        // 0001 0000
    send_socket_send = (1 << 5),                                     // 0010 0000
    read_iocp = (read_bio_write),                                    // 0000 0010
    read_epoll = (read_bio_write | read_socket_recv),                // 0000 0110
    send_all = (send_ssl_write | send_bio_read | send_socket_send),  // 0011 1000
    peek_msg = (1 << 6),                                             // 0100 0000
};

struct _tls_context_t;
typedef struct _tls_context_t tls_context_t;

// net/basic
class client_socket;
class ipaddr_acl;
class server_socket;
class tcp_client_socket;
class tcp_server_socket;
class udp_client_socket;
class udp_server_socket;

// net/server
class network_server;
class network_session;
class network_session_data;
class network_session_manager;
class network_stream;
class network_stream_data;
class network_protocol;
class network_protocol_group;
class server_conf;

// net/tls
class dtls_client_socket;
class dtls_server_socket;
class tls_client_socket;
class tls_server_socket;
class transport_layer_security;
class x509cert;

}  // namespace net
}  // namespace hotplace

#endif
