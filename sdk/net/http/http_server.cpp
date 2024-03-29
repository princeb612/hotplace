/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/system/critical_section.hpp>
#include <sdk/io/basic/zlib.hpp>
#include <sdk/io/string/string.hpp>
#include <sdk/net/basic/sdk.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace io;
namespace net {

http_server_builder::http_server_builder() : _flags(0), _port_http(80), _port_https(443), _tls_verify_peer(0), _handler(nullptr), _concurrent(1) {}

http_server_builder::~http_server_builder() {}

http_server_builder& http_server_builder::enable_http(bool enable) {
    uint32 mask = http_server_builder_flag_t::http_server_enable_http;
    if (enable) {
        _flags |= mask;
    } else {
        _flags &= ~mask;
    }
    return *this;
}

http_server_builder& http_server_builder::set_port_http(uint16 port) {
    _port_http = port;
    return *this;
}

http_server_builder& http_server_builder::enable_https(bool enable) {
    uint32 mask = http_server_builder_flag_t::http_server_enable_https;
    if (enable) {
        _flags |= mask;
    } else {
        _flags &= ~mask;
    }
    return *this;
}

http_server_builder& http_server_builder::set_port_https(uint16 port) {
    _port_https = port;
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

http_server_builder& http_server_builder::set_tls_verify_peer(int value) {
    _tls_verify_peer = value;
    return *this;
}

http_server_builder& http_server_builder::enable_ip4(bool enable) {
    uint32 mask = http_server_builder_flag_t::http_server_enable_ip4;
    if (enable) {
        _flags |= mask;
    } else {
        _flags &= ~mask;
    }
    return *this;
}

http_server_builder& http_server_builder::enable_ip6(bool enable) {
    uint32 mask = http_server_builder_flag_t::http_server_enable_ip6;
    if (enable) {
        _flags |= mask;
    } else {
        _flags &= ~mask;
    }
    return *this;
}

http_server_builder& http_server_builder::set_handler(http_server_handler_t handler) {
    _handler = handler;
    return *this;
}

http_server_builder& http_server_builder::set_concurrent(uint16 concurrent) {
    _concurrent = concurrent;
    return *this;
}

http_server* http_server_builder::build() {
    http_server* server = nullptr;
    return_t ret = errorcode_t::success;
    uint32 mask1 = 0;
    uint32 mask2 = 0;
    uint16 port = 0;
    __try2 {
        __try_new_catch(server, new http_server, ret, __leave2);

        mask1 = http_server_builder_flag_t::http_server_enable_https;
        if (_flags & mask1) {
            port = _port_https;

            ret = server->startup_tls(_server_cert, _server_key, _tls_cipher_list, _tls_verify_peer);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            mask2 = http_server_builder_flag_t::http_server_enable_ip4;
            if (_flags & mask2) {
                server->startup_server(mask1 | mask2, port, _handler);
            }
            mask2 = http_server_builder_flag_t::http_server_enable_ip6;
            if (_flags & mask2) {
                server->startup_server(mask1 | mask2, port, _handler);
            }
        }

        mask1 = http_server_builder_flag_t::http_server_enable_http;
        if (_flags & mask1) {
            port = _port_http;

            mask2 = http_server_builder_flag_t::http_server_enable_ip4;
            if (_flags & mask2) {
                server->startup_server(mask1 | mask2, port, _handler);
            }
            mask2 = http_server_builder_flag_t::http_server_enable_ip6;
            if (_flags & mask2) {
                server->startup_server(mask1 | mask2, port, _handler);
            }
        }
    }
    __finally2 {
        //
    }
    return server;
}

http_server::http_server() : _concurrent(1), _cert(nullptr), _tls(nullptr), _tls_server_socket(nullptr) {
    get_http_protocol()->set_constraints(protocol_constraints_t::protocol_packet_size, 1 << 12);  // constraints maximum packet size to 4KB
}

http_server::~http_server() { shutdown(); }

return_t http_server::start() {
    return_t ret = errorcode_t::success;
    http_handles_t::iterator iter;
    for (iter = _http_handles.begin(); iter != _http_handles.end(); iter++) {
        network_multiplexer_context_t* handle = iter->second;

        get_network_server().consumer_loop_run(handle, _concurrent);
        get_network_server().event_loop_run(handle, _concurrent);
    }
    return ret;
}

return_t http_server::stop() {
    return_t ret = errorcode_t::success;
    http_handles_t::iterator iter;
    for (iter = _http_handles.begin(); iter != _http_handles.end(); iter++) {
        network_multiplexer_context_t* handle = iter->second;

        get_network_server().event_loop_break(handle, _concurrent);
        get_network_server().consumer_loop_break(handle, _concurrent);
    }
    return ret;
}

return_t http_server::set_concurrent(uint16 concurrent) {
    return_t ret = errorcode_t::success;
    _concurrent = concurrent;
    return ret;
}

return_t http_server::startup_tls(std::string const& server_cert, std::string const& server_key, std::string const& cipher_list, int verify_peer) {
    return_t ret = errorcode_t::success;
    __try2 {
        __try_new_catch(_cert, new x509cert(server_cert.c_str(), server_key.c_str()), ret, __leave2);
        __try_new_catch(_tls, new transport_layer_security(_cert->get()), ret, __leave2);
        __try_new_catch(_tls_server_socket, new transport_layer_security_server(_tls), ret, __leave2);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_server::shutdown_tls() {
    return_t ret = errorcode_t::success;
    __try2 {
        if (_tls_server_socket) {
            _tls_server_socket->release();
            _tls_server_socket = nullptr;
        }
        if (_tls) {
            _tls->release();
            _tls = nullptr;
        }
        if (_cert) {
            delete _cert;
            _cert = nullptr;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_server::startup_server(uint32 flags, uint16 port, http_server_handler_t handler) {
    return_t ret = errorcode_t::success;
    network_multiplexer_context_t* handle = nullptr;
    __try2 {
        if (nullptr == handler) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        unsigned int family = 0;
        server_socket* socket = nullptr;

        if (flags & http_server_builder_flag_t::http_server_enable_ip4) {
            family = AF_INET;
        } else if (flags & flags & http_server_builder_flag_t::http_server_enable_ip6) {
            family = AF_INET6;
        } else {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (flags & http_server_builder_flag_t::http_server_enable_https) {
            socket = _tls_server_socket;
        } else if (flags & http_server_builder_flag_t::http_server_enable_http) {
            socket = &_server_socket;
        } else {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        http_handles_t::iterator iter = _http_handles.find(flags);
        if (_http_handles.end() != iter) {
            ret = errorcode_t::already_exist;
            __leave2;
        }

        ret = get_network_server().open(&handle, family, IPPROTO_TCP, port, 32000, handler, nullptr, socket);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        get_network_server().add_protocol(handle, get_http_protocol());

        _http_handles.insert(std::make_pair(flags, handle));
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_server::shutdown_server() {
    return_t ret = errorcode_t::success;
    http_handles_t::iterator iter;
    for (iter = _http_handles.begin(); iter != _http_handles.end(); iter++) {
        network_multiplexer_context_t* handle = iter->second;
        get_network_server().close(handle);
    }
    _http_handles.clear();
    return ret;
}

void http_server::shutdown() { shutdown_server(); }

network_server& http_server::get_network_server() { return _server; }

http_protocol* http_server::get_http_protocol() { return &_protocol; }

http_router& http_server::get_http_router() { return _router; }

}  // namespace net
}  // namespace hotplace
