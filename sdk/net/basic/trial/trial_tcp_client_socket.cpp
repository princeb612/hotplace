/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/trial/trial_tcp_client_socket.hpp>

namespace hotplace {
namespace net {

trial_tcp_client_socket::trial_tcp_client_socket() : client_socket_prosumer() {}

int trial_tcp_client_socket::socket_type() { return SOCK_STREAM; }

}  // namespace net
}  // namespace hotplace
