/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/net/http/http_request.hpp>
#include <sdk/net/http/http_server.hpp>
#include <sdk/net/server/network_session.hpp>

namespace hotplace {
namespace net {

http_server::http_server(server_socket_adapter* adapter) : _server_socket_adapter(adapter), _user_context(nullptr) {
    if (nullptr == adapter) {
        throw exception(not_specified);
    }
    get_server_socket_adapter()->addref();
    get_http_router().set_owner(this);
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
        auto adapter = get_server_socket_adapter();
        if (nullptr == adapter) {
            ret = errorcode_t::not_specified;
            __leave2;
        }
        ret = adapter->startup_tls(server_cert, server_key, cipher_list, verify_peer);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_server::shutdown_tls() {
    return_t ret = errorcode_t::success;
    __try2 {
        auto adapter = get_server_socket_adapter();
        if (nullptr == adapter) {
            ret = errorcode_t::not_specified;
            __leave2;
        }
        ret = adapter->shutdown_tls();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_server::startup_dtls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_list, int verify_peer) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto adapter = get_server_socket_adapter();
        if (nullptr == adapter) {
            ret = errorcode_t::not_specified;
            __leave2;
        }
        ret = adapter->startup_dtls(server_cert, server_key, cipher_list, verify_peer);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_server::shutdown_dtls() {
    return_t ret = errorcode_t::success;
    __try2 {
        auto adapter = get_server_socket_adapter();
        if (nullptr == adapter) {
            ret = errorcode_t::not_specified;
            __leave2;
        }
        ret = adapter->shutdown_dtls();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_server::startup_server(http_service_t service, uint16 family, uint16 port, http_server_handler_t handler, void* user_context) {
    return_t ret = errorcode_t::success;
    network_multiplexer_context_t* handle = nullptr;
    server_socket* socket = nullptr;

    __try2 {
        if (nullptr == handler) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        _consumer = handler;
        _user_context = user_context;

        switch (service) {
            case service_http:
                socket = get_server_socket_adapter()->get_tcp_server_socket();
                break;
            case service_http3:
                socket = get_server_socket_adapter()->get_dtls_server_socket();
                break;
            case service_https:
            default:
                socket = get_server_socket_adapter()->get_tls_server_socket();
                break;
        }

        if (nullptr == socket) {
            ret = errorcode_t::not_specified;
            __leave2;
        }

        ret = get_network_server().open(&handle, family, port, socket, &get_server_conf(), &consume_routine, this);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        get_network_server().set_accept_control_handler(handle, accept_handler);
        get_network_server().add_protocol(handle, &get_http_protocol());

        uint16 enable_h2 = get_server_conf().get(netserver_config_t::serverconf_enable_h2);
        if (enable_h2) {
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
    get_server_socket_adapter()->release();
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

#if defined DEBUG
    if (istraceable(trace_category_net, loglevel_debug)) {
        netsocket_t* session_socket = (netsocket_t*)data_array[0];  // mux_tryconnect can be nullptr
        basic_stream bs;

        switch (type) {
            case mux_connect: {
                socket_t clisock = session_socket->get_event_socket();
                bs.printf("connect %i\n", clisock);
            } break;
            case mux_read: {
                socket_t clisock = session_socket->get_event_socket();
                bs.printf("read %i\n", clisock);
                byte_t* buf = (byte_t*)data_array[1];
                size_t bufsize = (size_t)data_array[2];
                dump_memory((byte_t*)buf, bufsize, &bs, 16, 2, 0, dump_memory_flag_t::dump_notrunc);
            } break;
            case mux_disconnect: {
                socket_t clisock = session_socket->get_event_socket();
                bs.printf("disconnect %i\n", clisock);
            } break;
            default:
                break;
        }
        trace_debug_event(trace_category_net, trace_event_net_consume, &bs);
    }
#endif

    if (mux_read == type || mux_dgram == type) {
        if (errorcode_t::success == get_http_protocol().is_kind_of(buf, bufsize)) {  // HTTP/1.1
            request.open(buf, bufsize);
            dispatch_data[4] = &request;
        } else if (get_server_conf().get(netserver_config_t::serverconf_enable_h2)) {
            network_session* session = (network_session*)data_array[3];
            if (session) {
                session->get_http2_session().consume(type, data_count, data_array, this, &h2request);
            }
            dispatch_data[4] = h2request;
        }
    }

    /**
     * HTTP/1.1 dispatch_data[4] not nullptr
     * HTTP/2   dispatch_data[4] can be nullptr - if END_HEADERS, END_STREAM is not set
     */
    if (dispatch_data[4]) {
        ret = _consumer(type, RTL_NUMBER_OF(dispatch_data), dispatch_data, callback_control, user_context);
    }

    if (h2request) {
        h2request->release();
    }

    return ret;
}

network_server& http_server::get_network_server() { return _server; }

server_conf& http_server::get_server_conf() { return _conf; }

skey_value& http_server::get_http_conf() { return _httpconf; }

http_protocol& http_server::get_http_protocol() { return _protocol; }

http2_protocol& http_server::get_http2_protocol() { return _protocol2; }

http_router& http_server::get_http_router() { return _router; }

ipaddr_acl& http_server::get_ipaddr_acl() { return _acl; }

server_socket_adapter* http_server::get_server_socket_adapter() { return _server_socket_adapter; }

}  // namespace net
}  // namespace hotplace
