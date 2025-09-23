/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/basic/trial/trial_tcp_client_socket.hpp>

namespace hotplace {
namespace net {

trial_tcp_client_socket::trial_tcp_client_socket() : client_socket_prosumer() {}

trial_tcp_client_socket::~trial_tcp_client_socket() {}

int trial_tcp_client_socket::socket_type() { return SOCK_STREAM; }

uint32 trial_tcp_client_socket::get_scheme() { return socket_scheme_tcp | socket_scheme_trial | socket_scheme_client; }

}  // namespace net
}  // namespace hotplace
