/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/sdk/udp_client_socket2.hpp>

namespace hotplace {
namespace net {

udp_client_socket2::udp_client_socket2() : async_client_socket() {}

int udp_client_socket2::socket_type() { return SOCK_DGRAM; }

}  // namespace net
}  // namespace hotplace
