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
#include <sdk/net/basic/trial/tls_composer.hpp>
#include <sdk/net/basic/trial/trial_tls_server_socket.hpp>
#include <sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

trial_tls_server_socket::trial_tls_server_socket() : naive_tcp_server_socket() {}

trial_tls_server_socket::~trial_tls_server_socket() {}

return_t trial_tls_server_socket::tls_accept(socket_context_t **handle, socket_t cli_socket) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = new tls_session(session_type_tls);
        auto context = new socket_context_t(cli_socket);

        context->handle.session = session;
        *handle = context;

        {
            auto lambda_send = [&](tls_session *sess, binary_t &bin) -> void {
                socket_context_t *ctx = (socket_context_t *)(sess->get_hook_param());
#if defined DEBUG
                if (istraceable(trace_category_net)) {
                    basic_stream dbs;
                    dbs.println("send %p %i", ctx, ctx->fd);
                    dump_memory(bin, &dbs, 16, 3, 0, dump_notrunc);
                    trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
                }
#endif
                size_t sent = 0;
                naive_tcp_server_socket::send(ctx, (char *)&bin[0], bin.size(), &sent);
            };
            auto lambda = [&](tls_session *sess, uint32 status) -> void {
                tls_composer composer(sess);
                composer.session_status_changed(status, from_server, 1000, lambda_send);
            };

            session->set_hook_change_session_status(lambda);
            session->set_hook_param(context);
        }
    }
    __finally2 {}
    return ret;
}

return_t trial_tls_server_socket::tls_stop_accept() {
    return_t ret = errorcode_t::success;
    return ret;
}

return_t trial_tls_server_socket::read(socket_context_t *handle, int mode, char *ptr_data, size_t size_data, size_t *cbread) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle || nullptr == ptr_data) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
#if defined __linux
        if (nullptr == cbread) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
#endif

        if (read_socket_recv & mode) {
            // epoll
            ret = naive_tcp_server_socket::read(handle, 0, ptr_data, size_data, cbread);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        size_t ptr_size = 0;
#if defined __linux__
        ptr_size = *cbread;
#elif defined _WIN32 || defined _WIN64
        ptr_size = size_data;
#endif
        if (read_bio_write & mode) {
            // iocp & epoll, handshake, alert
            ret = get_secure_prosumer()->produce(handle->handle.session, from_client, (byte_t *)ptr_data, ptr_size);
        }
        if (read_ssl_read & mode) {
            // iocp & epoll, application_data
            ret = get_secure_prosumer()->consume(socket_type(), 0, ptr_data, size_data, cbread, nullptr, 0);
        }
    }
    __finally2 {}
    return ret;
}

return_t trial_tls_server_socket::send(socket_context_t *handle, const char *ptr_data, size_t size_data, size_t *cbsent) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = handle->handle.session;

        binary_t bin;
        tls_direction_t dir = from_server;
        tls_record_application_data record(session);
        record.get_records().add(new tls_record_application_data(session, (byte_t *)ptr_data, size_data));
        record.write(dir, bin);

        size_t sent = 0;
        naive_tcp_server_socket::send(handle, (char *)&bin[0], bin.size(), &sent);
    }
    __finally2 {}
    return ret;
}

bool trial_tls_server_socket::support_tls() { return true; }

secure_prosumer *trial_tls_server_socket::get_secure_prosumer() { return &_secure; }

}  // namespace net
}  // namespace hotplace
