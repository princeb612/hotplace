/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/socket/tcp_client_socket2.hpp>

namespace hotplace {
namespace net {

tcp_client_socket2::tcp_client_socket2() : async_client_socket() {}

int tcp_client_socket2::socket_type() { return SOCK_STREAM; }

}  // namespace net
}  // namespace hotplace
