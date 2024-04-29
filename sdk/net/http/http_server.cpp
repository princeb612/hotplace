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
#include <sdk/net/http/http_server.hpp>

namespace hotplace {
using namespace io;
namespace net {

http_server::http_server() : _cert(nullptr), _tls(nullptr), _tls_server_socket(nullptr) {
    get_http_protocol()->set_constraints(protocol_constraints_t::protocol_packet_size, 1 << 12);  // constraints maximum packet size to 4KB
}

http_server::~http_server() { shutdown(); }

return_t http_server::start() {
    return_t ret = errorcode_t::success;
    uint16 producers = get_server_conf().get(netserver_config_t::serverconf_concurrent_network);
    uint16 consumers = get_server_conf().get(netserver_config_t::serverconf_concurrent_consume);
    http_handles_t::iterator iter;
    for (iter = _http_handles.begin(); iter != _http_handles.end(); iter++) {
        network_multiplexer_context_t* handle = *iter;

        get_network_server().consumer_loop_run(handle, consumers);
        get_network_server().event_loop_run(handle, producers);
    }
    return ret;
}

return_t http_server::stop() {
    return_t ret = errorcode_t::success;
    uint16 producers = get_server_conf().get(netserver_config_t::serverconf_concurrent_network);
    uint16 consumers = get_server_conf().get(netserver_config_t::serverconf_concurrent_consume);
    http_handles_t::iterator iter;
    for (iter = _http_handles.begin(); iter != _http_handles.end(); iter++) {
        network_multiplexer_context_t* handle = *iter;

        get_network_server().event_loop_break(handle, producers);
        get_network_server().consumer_loop_break(handle, consumers);
    }
    return ret;
}

return_t http_server::accept_handler(socket_t socket, sockaddr_storage_t* client_addr, CALLBACK_CONTROL* control, void* parameter) {
    return_t ret = errorcode_t::success;
    if (control) {
        http_server* server = (http_server*)parameter;
        bool result = false;
        server->get_ipaddr_acl().determine(client_addr, result);
        *control = result ? CONTINUE_CONTROL : STOP_CONTROL;
    }
    return ret;
}

return_t http_server::startup_tls(std::string const& server_cert, std::string const& server_key, std::string const& cipher_list, int verify_peer) {
    return_t ret = errorcode_t::success;
    __try2 {
        __try_new_catch(_cert, new x509cert(server_cert.c_str(), server_key.c_str()), ret, __leave2);
        __try_new_catch(_tls, new transport_layer_security(_cert->get()), ret, __leave2);
        __try_new_catch(_tls_server_socket, new tls_server_socket(_tls), ret, __leave2);
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

return_t http_server::startup_server(uint16 tls, uint16 family, uint16 port, http_server_handler_t handler) {
    return_t ret = errorcode_t::success;
    network_multiplexer_context_t* handle = nullptr;
    tcp_server_socket* socket = nullptr;

    __try2 {
        if (nullptr == handler) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (tls) {
            socket = _tls_server_socket;
        } else {
            socket = &_server_socket;
        }

        ret = get_network_server().open(&handle, family, IPPROTO_TCP, port, 1024, handler, this, socket);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        get_network_server().set_accept_control_handler(handle, accept_handler);
        get_network_server().add_protocol(handle, get_http_protocol());
        if (get_server_conf().get(netserver_config_t::serverconf_enable_h2)) {
            get_network_server().add_protocol(handle, get_http2_protocol());
        }

        _http_handles.push_back(handle);
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
        network_multiplexer_context_t* handle = *iter;
        get_network_server().close(handle);
    }
    _http_handles.clear();
    return ret;
}

void http_server::shutdown() {
    shutdown_server();
    shutdown_tls();
}

network_server& http_server::get_network_server() { return _server; }

http_protocol* http_server::get_http_protocol() { return &_protocol; }

http2_protocol* http_server::get_http2_protocol() { return &_protocol2; }

hpack_encoder& http_server::get_hpack_encoder() { return _hpack_encoder; }

http_router& http_server::get_http_router() { return _router; }

ipaddr_acl& http_server::get_ipaddr_acl() { return _acl; }

server_conf& http_server::get_server_conf() { return _server.get_server_conf(); }

}  // namespace net
}  // namespace hotplace
