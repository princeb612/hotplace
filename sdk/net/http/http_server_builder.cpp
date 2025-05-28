/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/http_server_builder.hpp>

namespace hotplace {
namespace net {

http_server_builder::http_server_builder() : _handler(nullptr), _user_context(nullptr), _adapter(nullptr) {
    get_server_conf()
        .set(netserver_config_t::serverconf_enable_ipv4, 0)
        .set(netserver_config_t::serverconf_enable_ipv6, 0)
        .set(netserver_config_t::serverconf_verify_peer, 0)
        .set(netserver_config_t::serverconf_enable_http, 0)
        .set(netserver_config_t::serverconf_enable_https, 0)
        .set(netserver_config_t::serverconf_port_http, 80)
        .set(netserver_config_t::serverconf_port_https, 443)
        .set(netserver_config_t::serverconf_enable_h1, 1)
        .set(netserver_config_t::serverconf_concurrent_event, 1024)
        .set(netserver_config_t::serverconf_concurrent_tls_accept, 2)
        .set(netserver_config_t::serverconf_concurrent_network, 2)
        .set(netserver_config_t::serverconf_concurrent_consume, 2);
}

http_server_builder::~http_server_builder() { clear(); }

void http_server_builder::clear() {
    auto adapter = get_adapter();
    if (adapter) {
        adapter->release();
    }
}

http_server_builder &http_server_builder::enable_http(bool enable) {
    get_server_conf().set(netserver_config_t::serverconf_enable_http, enable ? 1 : 0);
    return *this;
}

http_server_builder &http_server_builder::set_port_http(uint16 port) {
    get_server_conf().set(netserver_config_t::serverconf_port_http, port);
    return *this;
}

http_server_builder &http_server_builder::enable_https(bool enable) {
    get_server_conf().set(netserver_config_t::serverconf_enable_https, enable ? 1 : 0);
    return *this;
}

http_server_builder &http_server_builder::set_port_https(uint16 port) {
    get_server_conf().set(netserver_config_t::serverconf_port_https, port);
    return *this;
}

http_server_builder &http_server_builder::set_tls_certificate(const std::string &server_cert, const std::string &server_key) {
    _server_cert = server_cert;
    _server_key = server_key;
    return *this;
}

http_server_builder &http_server_builder::set_tls_cipher_list(const std::string &cipher_list) {
    _tls_cipher_list = cipher_list;
    return *this;
}

http_server_builder &http_server_builder::set_tls_verify_peer(uint16 value) {
    get_server_conf().set(netserver_config_t::serverconf_verify_peer, value);
    return *this;
}

http_server_builder &http_server_builder::enable_ipv4(bool enable) {
    get_server_conf().set(netserver_config_t::serverconf_enable_ipv4, enable ? 1 : 0);
    return *this;
}

http_server_builder &http_server_builder::enable_ipv6(bool enable) {
    get_server_conf().set(netserver_config_t::serverconf_enable_ipv6, enable ? 1 : 0);
    return *this;
}

http_server_builder &http_server_builder::enable_h2(bool enable) {
    get_server_conf().set(netserver_config_t::serverconf_enable_h2, enable ? 1 : 0);
    return *this;
}

http_server_builder &http_server_builder::enable_h3(bool enable) {
    get_server_conf().set(netserver_config_t::serverconf_enable_h3, enable ? 1 : 0);
    return *this;
}

http_server_builder &http_server_builder::allow_content_encoding(const std::string &encoding) {
    _content_encoding = encoding;
    return *this;
}

http_server_builder &http_server_builder::set_handler(http_server_handler_t handler, void *user_context) {
    _handler = handler;
    _user_context = user_context;
    return *this;
}

http_server *http_server_builder::build() {
    http_server *server = nullptr;
    return_t ret = errorcode_t::success;
    __try2 {
        auto adapter = get_adapter();
        if (nullptr == adapter) {
            ret = errorcode_t::not_specified;
            __leave2;
        }

        __try_new_catch(server, new http_server(adapter), ret, __leave2);

        server->get_server_conf().copyfrom(&get_server_conf());

        uint16 ipv4 = get_server_conf().get(netserver_config_t::serverconf_enable_ipv4);
        uint16 ipv6 = get_server_conf().get(netserver_config_t::serverconf_enable_ipv6);
        if (ipv4 || ipv6) {
            uint16 enable_h1 = get_server_conf().get(netserver_config_t::serverconf_enable_h1);
            uint16 enable_h2 = get_server_conf().get(netserver_config_t::serverconf_enable_h2);
            uint16 enable_h3 = get_server_conf().get(netserver_config_t::serverconf_enable_h3);
            uint16 enable_http = get_server_conf().get(netserver_config_t::serverconf_enable_http);
            uint16 enable_https = get_server_conf().get(netserver_config_t::serverconf_enable_https);

            if (enable_https) {
                uint16 port_https = get_server_conf().get(netserver_config_t::serverconf_port_https);
                uint16 verify_peer = get_server_conf().get(netserver_config_t::serverconf_verify_peer);

                if (enable_h1 || enable_h2) {
                    // TLS
                    ret = server->startup_tls(_server_cert, _server_key, _tls_cipher_list, verify_peer);
                    if (errorcode_t::success != ret) {
                        __leave2;
                    }
                    if (ipv4) {
                        server->startup_server(http_service_t::service_https, AF_INET, port_https, _handler, _user_context);
                    }
                    if (ipv6) {
                        server->startup_server(http_service_t::service_https, AF_INET6, port_https, _handler, _user_context);
                    }
                }
                if (enable_h3) {
                    // DTLS
                    ret = server->startup_dtls(_server_cert, _server_key, _tls_cipher_list, verify_peer);
                    if (errorcode_t::success != ret) {
                        __leave2;
                    }
                    if (ipv4) {
                        server->startup_server(http_service_t::service_http3, AF_INET, port_https, _handler, _user_context);
                    }
                    if (ipv6) {
                        server->startup_server(http_service_t::service_http3, AF_INET6, port_https, _handler, _user_context);
                    }
                }
            }

            if (enable_http) {
                uint16 port_http = get_server_conf().get(netserver_config_t::serverconf_port_http);

                if (ipv4) {
                    server->startup_server(http_service_t::service_http, AF_INET, port_http, _handler, _user_context);
                }
                if (ipv6) {
                    server->startup_server(http_service_t::service_http, AF_INET6, port_http, _handler, _user_context);
                }
            }

            if (enable_h2) {
                adapter->enable_alpn("h2");
            }

            if (false == _content_encoding.empty()) {
                server->get_http_conf().set("Content-Encoding", _content_encoding);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return server;
}

server_conf &http_server_builder::get_server_conf() { return _config; }

http_server_builder &http_server_builder::set(server_socket_adapter *adapter) {
    _adapter = adapter;
    return *this;
}

server_socket_adapter *http_server_builder::get_adapter() { return _adapter; }

}  // namespace net
}  // namespace hotplace
