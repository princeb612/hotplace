/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/basic/trial/trial_udp_client_socket.hpp>

namespace hotplace {
namespace net {

trial_udp_client_socket::trial_udp_client_socket() : client_socket_prosumer() {}

trial_udp_client_socket::~trial_udp_client_socket() {}

int trial_udp_client_socket::socket_type() { return SOCK_DGRAM; }

uint32 trial_udp_client_socket::get_scheme() { return socket_scheme_udp | socket_scheme_trial | socket_scheme_client; }

}  // namespace net
}  // namespace hotplace
