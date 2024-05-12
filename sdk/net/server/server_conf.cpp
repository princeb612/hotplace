/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <queue>
#include <sdk/base.hpp>
#include <sdk/io.hpp>
#include <sdk/net/server/network_server.hpp>

namespace hotplace {
using namespace io;
namespace net {

server_conf::server_conf() : t_key_value<netserver_config_t, uint16>() {
    set(netserver_config_t::serverconf_concurrent_event, 1024)  // concurrent (linux epoll concerns, windows ignore)
        .set(netserver_config_t::serverconf_concurrent_tls_accept, 1)
        .set(netserver_config_t::serverconf_concurrent_network, 2)
        .set(netserver_config_t::serverconf_concurrent_consume, 2);
}

server_conf::server_conf(const server_conf& rhs) : t_key_value<netserver_config_t, uint16>(rhs) {}

}  // namespace net
}  // namespace hotplace
