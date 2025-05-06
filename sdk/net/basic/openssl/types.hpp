/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_OPENSSL_TYPES__
#define __HOTPLACE_SDK_NET_BASIC_OPENSSL_TYPES__

#include <sdk/net/basic/types.hpp>

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

}  // namespace net
}  // namespace hotplace

#endif
