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

server_conf::server_conf() {
    set(netserver_config_t::serverconf_concurrent_event, 1024)  // concurrent (linux epoll concerns, windows ignore)
        .set(netserver_config_t::serverconf_concurrent_tls_accept, 1)
        .set(netserver_config_t::serverconf_concurrent_network, 2)
        .set(netserver_config_t::serverconf_concurrent_consume, 2);
}

server_conf::server_conf(const server_conf& conf) { _config_map = conf._config_map; }

server_conf& server_conf::set(netserver_config_t type, uint16 value) {
    return_t ret = errorcode_t::success;

    config_map_pib_t pib = _config_map.insert(std::make_pair(type, value));
    if (false == pib.second) {
        pib.first->second = value;
    }

    return *this;
}

uint16 server_conf::get(netserver_config_t type) {
    uint16 value = 0;

    config_map_t::iterator iter = _config_map.find(type);
    if (_config_map.end() != iter) {
        value = iter->second;
    }

    return value;
}

}  // namespace net
}  // namespace hotplace
