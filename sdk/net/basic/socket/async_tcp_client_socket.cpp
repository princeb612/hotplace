/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/socket/async_client_socket.hpp>

namespace hotplace {
namespace net {

async_tcp_client_socket::async_tcp_client_socket() : async_client_socket() {}

int async_tcp_client_socket::socket_type() { return SOCK_STREAM; }

}  // namespace net
}  // namespace hotplace
