/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base.hpp>
#include <sdk/io.hpp>
#include <sdk/net/http/http_server_builder.hpp>

namespace hotplace {
using namespace io;
namespace net {

http_server_builder::http_server_builder() : _handler(nullptr) {
    get_server_conf()
        .set(netserver_config_t::serverconf_enable_ipv4, 0)
        .set(netserver_config_t::serverconf_enable_ipv6, 0)
        .set(netserver_config_t::serverconf_enable_tls, 0)
        .set(netserver_config_t::serverconf_verify_peer, 0)
        .set(netserver_config_t::serverconf_enable_http, 0)
        .set(netserver_config_t::serverconf_enable_https, 0)
        .set(netserver_config_t::serverconf_port_http, 80)
        .set(netserver_config_t::serverconf_port_https, 443)
        .set(netserver_config_t::serverconf_concurrent_tls_accept, 2)
        .set(netserver_config_t::serverconf_concurrent_network, 2)
        .set(netserver_config_t::serverconf_concurrent_consume, 2);
}

http_server_builder::~http_server_builder() {}

http_server_builder& http_server_builder::enable_http(bool enable) {
    get_server_conf().set(netserver_config_t::serverconf_enable_http, enable ? 1 : 0);
    return *this;
}

http_server_builder& http_server_builder::set_port_http(uint16 port) {
    get_server_conf().set(netserver_config_t::serverconf_port_http, port);
    return *this;
}

http_server_builder& http_server_builder::enable_https(bool enable) {
    get_server_conf().set(netserver_config_t::serverconf_enable_https, enable ? 1 : 0);
    return *this;
}

http_server_builder& http_server_builder::set_port_https(uint16 port) {
    get_server_conf().set(netserver_config_t::serverconf_port_https, port);
    return *this;
}

http_server_builder& http_server_builder::set_tls_certificate(std::string const& server_cert, std::string const& server_key) {
    _server_cert = server_cert;
    _server_key = server_key;
    return *this;
}

http_server_builder& http_server_builder::set_tls_cipher_list(std::string const& cipher_list) {
    _tls_cipher_list = cipher_list;
    return *this;
}

http_server_builder& http_server_builder::set_tls_verify_peer(uint16 value) {
    get_server_conf().set(netserver_config_t::serverconf_verify_peer, value);
    return *this;
}

http_server_builder& http_server_builder::enable_ipv4(bool enable) {
    get_server_conf().set(netserver_config_t::serverconf_enable_ipv4, enable ? 1 : 0);
    return *this;
}

http_server_builder& http_server_builder::enable_ipv6(bool enable) {
    get_server_conf().set(netserver_config_t::serverconf_enable_ipv6, enable ? 1 : 0);
    return *this;
}

http_server_builder& http_server_builder::enable_h2(bool enable) {
    get_server_conf().set(netserver_config_t::serverconf_enable_h2, enable ? 1 : 0);
    return *this;
}

http_server_builder& http_server_builder::set_handler(http_server_handler_t handler) {
    _handler = handler;
    return *this;
}

http_server* http_server_builder::build() {
    http_server* server = nullptr;
    return_t ret = errorcode_t::success;
    __try2 {
        __try_new_catch(server, new http_server, ret, __leave2);

        server_conf& config = server->get_server_conf();
        config = get_server_conf();

        uint16 ipv4 = get_server_conf().get(netserver_config_t::serverconf_enable_ipv4);
        uint16 ipv6 = get_server_conf().get(netserver_config_t::serverconf_enable_ipv6);
        if (ipv4 || ipv6) {
            uint16 enable_https = get_server_conf().get(netserver_config_t::serverconf_enable_https);
            if (enable_https) {
                uint16 port_https = get_server_conf().get(netserver_config_t::serverconf_port_https);
                uint16 verify_peer = get_server_conf().get(netserver_config_t::serverconf_verify_peer);

                ret = server->startup_tls(_server_cert, _server_key, _tls_cipher_list, verify_peer);
                if (errorcode_t::success != ret) {
                    __leave2;
                }
                if (ipv4) {
                    server->startup_server(1, AF_INET, port_https, _handler);
                }
                if (ipv6) {
                    server->startup_server(1, AF_INET6, port_https, _handler);
                }
            }

            uint16 enable_http = get_server_conf().get(netserver_config_t::serverconf_enable_http);
            if (enable_http) {
                uint16 port_http = get_server_conf().get(netserver_config_t::serverconf_port_http);

                if (ipv4) {
                    server->startup_server(0, AF_INET, port_http, _handler);
                }
                if (ipv6) {
                    server->startup_server(0, AF_INET6, port_http, _handler);
                }
            }
        }
        uint16 enable_h2 = get_server_conf().get(netserver_config_t::serverconf_enable_h2);
        if (enable_h2) {
            if (server->_cert) {
                server->_cert->enable_alpn_h2(true);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return server;
}

server_conf& http_server_builder::get_server_conf() { return _config; }

}  // namespace net
}  // namespace hotplace
