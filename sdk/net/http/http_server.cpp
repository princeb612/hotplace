/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io.hpp>
#include <sdk/net/http/http_server.hpp>

namespace hotplace {
using namespace io;
namespace net {

http_server::http_server() : _cert(nullptr), _tls(nullptr), _tls_server_socket(nullptr) {
    get_http_protocol().set_constraints(protocol_constraints_t::protocol_packet_size, 1 << 12);  // constraints maximum packet size to 4KB
}

http_server::~http_server() { shutdown(); }

return_t http_server::start() {
    return_t ret = errorcode_t::success;
    uint16 producers = get_server_conf().get(netserver_config_t::serverconf_concurrent_network);
    uint16 consumers = get_server_conf().get(netserver_config_t::serverconf_concurrent_consume);
    for (network_multiplexer_context_t* handle : _http_handles) {
        get_network_server().consumer_loop_run(handle, consumers);
        get_network_server().event_loop_run(handle, producers);
    }
    return ret;
}

return_t http_server::stop() {
    return_t ret = errorcode_t::success;
    uint16 producers = get_server_conf().get(netserver_config_t::serverconf_concurrent_network);
    uint16 consumers = get_server_conf().get(netserver_config_t::serverconf_concurrent_consume);
    for (network_multiplexer_context_t* handle : _http_handles) {
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

return_t http_server::startup_tls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_list, int verify_peer) {
    return_t ret = errorcode_t::success;
    __try2 {
        __try_new_catch(_cert, new x509cert(x509cert_flag_tls, server_cert.c_str(), server_key.c_str()), ret, __leave2);
        __try_new_catch(_tls, new transport_layer_security(_cert->get_ctx()), ret, __leave2);
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

return_t http_server::startup_server(uint16 tls, uint16 family, uint16 port, http_server_handler_t handler, void* user_context) {
    return_t ret = errorcode_t::success;
    network_multiplexer_context_t* handle = nullptr;
    tcp_server_socket* socket = nullptr;

    __try2 {
        if (nullptr == handler) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        _consumer = handler;
        _user_context = user_context;

        if (tls) {
            socket = _tls_server_socket;
        } else {
            socket = &_server_socket;
        }

        ret = get_network_server().open(&handle, family, port, socket, &get_server_conf(), &consume_routine, this);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        get_network_server().set_accept_control_handler(handle, accept_handler);
        get_network_server().add_protocol(handle, &get_http_protocol());
        if (get_server_conf().get(netserver_config_t::serverconf_enable_h2)) {
            get_network_server().add_protocol(handle, &get_http2_protocol());
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
    for (network_multiplexer_context_t* handle : _http_handles) {
        get_network_server().close(handle);
    }
    _http_handles.clear();
    return ret;
}

void http_server::shutdown() {
    shutdown_server();
    shutdown_tls();
}

return_t http_server::consume_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* server_context) {
    http_server* server = (http_server*)server_context;
    return server->consume(type, data_count, data_array, callback_control, server->_user_context);
}

return_t http_server::consume(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    return_t ret = errorcode_t::success;
    http_request request;
    http_request* h2request = nullptr;

    void* dispatch_data[5] = {data_array[0], data_array[1], data_array[2], data_array[3], nullptr};
    char* buf = (char*)data_array[1];
    size_t bufsize = (size_t)data_array[2];

#if 0
    if (_df) {
        network_session_socket_t* session_socket = (network_session_socket_t*)data_array[0];
        basic_stream bs;

        switch (type) {
            case mux_connect:
                bs.printf("connect %i\n", session_socket->cli_socket);
                break;
            case mux_read: {
                bs.printf("read %i\n", session_socket->cli_socket);
                byte_t* buf = (byte_t*)data_array[1];
                size_t bufsize = (size_t)data_array[2];
                dump_memory((byte_t*)buf, bufsize, &bs, 16, 2, 0, dump_memory_flag_t::dump_notrunc);
                bs.printf("\n");
            } break;
            case mux_disconnect:
                bs.printf("disconnect %i\n", session_socket->cli_socket);
                break;
            default:
                break;
        }
        _df(&bs);
    }
#endif

    if (errorcode_t::success == get_http_protocol().is_kind_of(buf, bufsize)) {  // HTTP/1.1
        request.open(buf, bufsize);
        dispatch_data[4] = &request;
    } else if (get_server_conf().get(netserver_config_t::serverconf_enable_h2)) {
        network_session* session = (network_session*)data_array[3];
        if (session) {
            if (get_server_conf().get(netserver_config_t::serverconf_trace_h2)) {
                session->get_http2_session().trace(_df);
            }
            session->get_http2_session().consume(type, data_count, data_array, this, &h2request);
        }
        dispatch_data[4] = h2request;
    }

    ret = _consumer(type, RTL_NUMBER_OF(dispatch_data), dispatch_data, callback_control, user_context);

    if (h2request) {
        h2request->release();
    }

    return ret;
}

http_server& http_server::trace(std::function<void(stream_t*)> f) {
    _df = f;
    if (get_server_conf().get(netserver_config_t::serverconf_trace_ns)) {
        for (auto item : _http_handles) {
            network_server::trace(item, f);
        }
    }
    return *this;
}

network_server& http_server::get_network_server() { return _server; }

server_conf& http_server::get_server_conf() { return _conf; }

http_protocol& http_server::get_http_protocol() { return _protocol; }

http2_protocol& http_server::get_http2_protocol() { return _protocol2; }

hpack_encoder& http_server::get_hpack_encoder() { return _hpack_encoder; }

http_router& http_server::get_http_router() { return _router; }

ipaddr_acl& http_server::get_ipaddr_acl() { return _acl; }

}  // namespace net
}  // namespace hotplace
