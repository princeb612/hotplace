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
#include <sdk/base/nostd/exception.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/net/basic/trial/tls_composer.hpp>
#include <sdk/net/basic/trial/trial_dtls_server_socket.hpp>
#include <sdk/net/tls/tls/record/dtls13_ciphertext.hpp>
#include <sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

trial_dtls_server_socket::trial_dtls_server_socket() : naive_udp_server_socket() {}

trial_dtls_server_socket::~trial_dtls_server_socket() {}

return_t trial_dtls_server_socket::dtls_open(socket_context_t** handle, socket_t fd) {
    return_t ret = errorcode_t::success;
    socket_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle || INVALID_SOCKET == fd) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(context, new socket_context_t, ret, __leave2);

        auto session = new tls_session(session_type_dtls);
        context->fd = fd;
        context->handle.session = session;
        context->flags = 0;

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            close(context);
        }
    }
    return ret;
}

return_t trial_dtls_server_socket::dtls_handshake(socket_context_t* handle, sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;

    __try2 {
        auto lambda_send = [&](tls_session* sess, binary_t& bin) -> void {
            socket_context_t* ctx = (socket_context_t*)(sess->get_hook_param());
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                basic_stream dbs;
                dbs.println("send %p %i", ctx, ctx->fd);
                dump_memory(bin, &dbs, 16, 3, 0, dump_notrunc);
                trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
            }
#endif
            size_t sent = 0;
            naive_udp_server_socket::sendto(ctx, (char*)&bin[0], bin.size(), &sent, addr, addrlen);
        };
        auto lambda = [&](tls_session* sess, uint32 status) -> void {
            tls_composer composer(sess);
            composer.session_status_changed(status, from_server, 1000, lambda_send);
        };

        auto session = handle->handle.session;
        session->set_hook_change_session_status(lambda);
        session->set_hook_param(handle);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t trial_dtls_server_socket::recvfrom(socket_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr,
                                            socklen_t* addrlen) {
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
            ret = naive_udp_server_socket::recvfrom(handle, 0, ptr_data, size_data, cbread, addr, addrlen);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        auto session = handle->handle.session;

        size_t ptr_size = 0;
#if defined __linux__
        ptr_size = *cbread;
#elif defined _WIN32 || defined _WIN64
        ptr_size = size_data;
#endif
        if (read_bio_write & mode) {
            // iocp & epoll, handshake, alert
            ret = session->get_secure_prosumer()->produce(session, from_client, (byte_t*)ptr_data, ptr_size);
        }
        if (read_ssl_read & mode) {
            // iocp & epoll, application_data
            ret = session->get_secure_prosumer()->consume(socket_type(), 0, ptr_data, size_data, cbread, nullptr, 0);
        }
    }
    __finally2 {}
    return ret;
}

return_t trial_dtls_server_socket::sendto(socket_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr,
                                          socklen_t addrlen) {
    return_t ret = errorcode_t::success;

    __try2 {
        auto session = handle->handle.session;
        auto& protection = session->get_tls_protection();
        auto tlsver = session->get_tls_protection().get_tls_version();

        binary_t bin;
        tls_direction_t dir = from_server;

        if (dtls_13 == tlsver) {
            dtls13_ciphertext record(tls_content_type_application_data, session);
            record.get_records().add(new tls_record_application_data(session, (byte_t*)ptr_data, size_data));
            record.write(dir, bin);
        } else {
            tls_record_application_data record(session);
            record.get_records().add(new tls_record_application_data(session, (byte_t*)ptr_data, size_data));
            record.write(dir, bin);
        }

        size_t sent = 0;
        naive_udp_server_socket::sendto(handle, (char*)&bin[0], bin.size(), &sent, addr, addrlen);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

bool trial_dtls_server_socket::support_tls() { return true; }

}  // namespace net
}  // namespace hotplace
