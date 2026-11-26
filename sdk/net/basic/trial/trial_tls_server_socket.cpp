/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   trial_tls_server_socket.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/net/basic/trial/tls_composer.hpp>
#include <hotplace/sdk/net/basic/trial/trial_tls_server_socket.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

trial_tls_server_socket::trial_tls_server_socket(tls_version_t minspec, tls_version_t maxspec)
    : naive_tcp_server_socket(), _minspec(minspec), _maxspec(maxspec), _tls12_ticket_store(std::make_shared<tls1_2_resumption_ticket_store>()) {}

trial_tls_server_socket::~trial_tls_server_socket() {}

return_t trial_tls_server_socket::tls_accept(socket_context_t** handle, socket_t cli_socket) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = new tls_session(session_type_t::tls);
        session->set_tls1_2_resumption_ticket_store(_tls12_ticket_store);
        auto context = new socket_context_t(cli_socket);

        context->handle.session = session;
        *handle = context;

        auto composer = session->get_tls_composer();
        composer->set_minver(_minspec);
        composer->set_maxver(_maxspec);

        {
            auto lambda_send = [this](tls_session* sess, binary_t& bin) -> return_t {
                socket_context_t* ctx = (socket_context_t*)(sess->get_hook_param());
#if defined DEBUG
                if (istraceable(trace_category_t::trace_category_net, loglevel_t::loglevel_debug)) {
                    trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_handshake, [&](basic_stream& dbs) -> void {
                        dbs.println("send %p %i", ctx, ctx->fd);
                        dump_memory(bin, &dbs, 16, 3, 0, dump_notrunc);
                    });
                }
#endif
                size_t sent = 0;
                return_t ret = naive_tcp_server_socket::send(ctx, (char*)bin.data(), bin.size(), &sent);
                if (errorcode_t::success != ret) {
                    return ret;
                }
                if (sent != bin.size()) {
                    return errorcode_t::send_failure;
                }
                return errorcode_t::success;
            };
            auto lambda = [&lambda_send](tls_session* sess, uint32 status) -> return_t {
                return sess->get_tls_composer()->session_status_changed(status, from_server, 1000, lambda_send);
            };

            session->set_hook_change_session_status(lambda);
            session->set_hook_param(context);
        }
    }
    __finally2 {}
    return ret;
}

return_t trial_tls_server_socket::tls_accept_fails(socket_t socket) { return close_socket(socket, true, 0); }

return_t trial_tls_server_socket::tls_stop_accept() { return errorcode_t::success; }

return_t trial_tls_server_socket::read(socket_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread) {
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

        auto session = handle->handle.session;
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        const bool tls12_stream = (session_type_t::tls == session->get_type()) && session->get_tls_protection().is_kindof_tls1_2();
        auto read_and_produce = [&]() -> return_t {
            return_t read_ret = errorcode_t::success;
            if (read_socket_recv & mode) {
                // epoll
                read_ret = naive_tcp_server_socket::read(handle, 0, ptr_data, size_data, cbread);
                if (errorcode_t::success != read_ret) {
                    if (tls12_stream) {
                        session->mark_terminal();
                    }
                    return read_ret;
                }
            }

            size_t ptr_size = 0;
#if defined __linux__
            ptr_size = *cbread;
#elif defined _WIN32 || defined _WIN64
            ptr_size = size_data;
#endif
            if (read_bio_write & mode) {
                // iocp & epoll, handshake, alert. The status hook may compose
                // and send the server's next handshake flight synchronously.
                read_ret = session->get_secure_prosumer()->produce(session, from_client, (byte_t*)ptr_data, ptr_size);
                if ((errorcode_t::success != read_ret) && tls12_stream) {
                    session->mark_terminal();
                }
            }
            return read_ret;
        };

        if (tls12_stream) {
            // Serialize socket receive and TLS parsing as one operation for
            // TLS 1.2 only; TLS 1.3 and DTLS retain their existing path.
            critical_section_guard io_guard(session->get_tls_io_lock());
            ret = read_and_produce();
        } else {
            ret = read_and_produce();
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
        if (read_ssl_read & mode) {
            // iocp & epoll, application_data
            ret = session->get_secure_prosumer()->consume(socket_type(), 0, ptr_data, size_data, cbread, nullptr, 0);
        }
    }
    __finally2 {}
    return ret;
}

return_t trial_tls_server_socket::send(socket_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent) {
    return_t ret = errorcode_t::success;
    if (nullptr != cbsent) {
        *cbsent = 0;
    }
    __try2 {
        if (nullptr == handle || (nullptr == ptr_data && 0 != size_data)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = handle->handle.session;
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto protection = &session->get_tls_protection();
        const bool tls12_stream = (session_type_t::tls == session->get_type()) && protection->is_kindof_tls1_2();

        auto send_impl = [&]() -> return_t {
            return_t send_ret = errorcode_t::success;
            __try2 {
                if (tls12_stream && session->is_terminal()) {
                    send_ret = errorcode_t::disconnect;
                    __leave2;
                }

                auto send_wire = [this, handle](tls_session*, binary_t& wire) -> return_t {
                    size_t sent = 0;
                    return_t wire_ret = naive_tcp_server_socket::send(handle, (char*)wire.data(), wire.size(), &sent);
                    if (errorcode_t::success != wire_ret) {
                        return wire_ret;
                    }
                    if (sent != wire.size()) {
                        return errorcode_t::send_failure;
                    }
                    return errorcode_t::success;
                };

                bool peer_renegotiation_pending = false;
                bool application_transport_attempted = false;
                auto send_record = [&]() -> return_t {
                    binary_t bin;
                    tls_record_application_data record(session, (byte_t*)ptr_data, size_data);
                    return_t write_ret = record.write(from_server, bin);
                    if (errorcode_t::success != write_ret) {
                        return write_ret;
                    }

                    size_t sent = 0;
                    application_transport_attempted = true;
                    return_t wire_ret = naive_tcp_server_socket::send(handle, (char*)bin.data(), bin.size(), &sent);
                    if (errorcode_t::success != wire_ret) {
                        return wire_ret;
                    }
                    if (sent != bin.size()) {
                        return errorcode_t::send_failure;
                    }
                    return errorcode_t::success;
                };

                auto send_application_data = [&]() -> return_t {
                    peer_renegotiation_pending = false;
                    application_transport_attempted = false;
                    if (false == tls12_stream) {
                        return send_record();
                    }

                    critical_section_guard io_guard(session->get_tls_io_lock());
                    if (session->is_terminal()) {
                        return errorcode_t::disconnect;
                    }
                    // Inspect flow under the same lock that protects record
                    // serialization. The receive thread may have processed
                    // ClientHello while this application sender waited.
                    if (tls_flow_t::renegotiation == protection->get_flow()) {
                        peer_renegotiation_pending = true;
                        return errorcode_t::success;
                    }
                    return send_record();
                };

                bool renegotiation_attempted = false;
                send_ret = send_application_data();

                if (peer_renegotiation_pending) {
                    // Join a peer-initiated exchange; do not send application
                    // data under the old connection state.
                    renegotiation_attempted = true;
                    tls_composer composer(session);
                    composer.set_minver(tls1_2);
                    composer.set_maxver(tls1_2);
                    send_ret = composer.handshake(from_server, get_wto(), send_wire);
                    if (errorcode_t::success != send_ret) {
                        retire_transport(handle);
                        __leave2;
                    }
                    send_ret = send_application_data();
                    if (peer_renegotiation_pending) {
                        send_ret = errorcode_t::handshake_failure;
                    }
                } else if ((errorcode_t::exceed == send_ret) && tls12_stream) {
                    if (session->is_terminal()) {
                        send_ret = errorcode_t::disconnect;
                        retire_transport(handle);
                        __leave2;
                    }

                    constexpr uint64 sequence_max = ~static_cast<uint64>(0);
                    constexpr uint64 sequence_reserve = 65535;
                    constexpr uint64 sequence_reserve_start = sequence_max - (sequence_reserve - 1);
                    const bool reserve_reached = session->get_recordno(from_server) >= sequence_reserve_start;
                    if (true == reserve_reached) {
                        const bool renegotiation_enabled = (0 != session->get_keyvalue().get(session_conf_enable_tls12_renegotiation));
                        const bool secure_renegotiation = (0 != session->get_keyvalue().get(session_tls12_secure_renegotiation));
                        if ((false == renegotiation_enabled) || (false == secure_renegotiation)) {
                            // The application record cannot be sent and the server
                            // is not permitted to start a secure renegotiation.
                            retire_transport(handle);
                            __leave2;
                        }

                        renegotiation_attempted = true;
                        tls_composer composer(session);
                        composer.set_minver(tls1_2);
                        composer.set_maxver(tls1_2);
                        send_ret = composer.handshake(from_server, get_wto(), send_wire);
                        if (errorcode_t::success != send_ret) {
                            retire_transport(handle);
                            __leave2;
                        }

                        // Retry only after both Finished messages and the
                        // receive-side status-hook send callback have completed.
                        send_ret = send_application_data();
                        if (peer_renegotiation_pending) {
                            send_ret = errorcode_t::handshake_failure;
                        }
                    }
                }

                if (errorcode_t::success != send_ret) {
                    if (tls12_stream && (session->is_terminal() || renegotiation_attempted || application_transport_attempted)) {
                        retire_transport(handle);
                    }
                    __leave2;
                }
                if (nullptr != cbsent) {
                    *cbsent = size_data;
                }
            }
            __finally2 {}
            return send_ret;
        };

        if (tls12_stream) {
            // The coordinator is held across the wait, but the shared I/O lock
            // is not; this prevents duplicate HelloRequest attempts without
            // blocking the receive thread.
            critical_section_guard application_send_guard(session->get_application_send_lock());
            ret = send_impl();
        } else {
            // Preserve the pre-existing TLS 1.3/DTLS send path.
            ret = send_impl();
        }
    }
    __finally2 {}
    return ret;
}

return_t trial_tls_server_socket::retire_transport(socket_context_t* handle) {
    if (nullptr == handle) {
        return errorcode_t::invalid_parameter;
    }

    auto session = handle->handle.session;
    if (nullptr != session) {
        session->mark_terminal();
        session->get_secure_prosumer()->notify_transport_closed();
    }

    // The socket context is owned by network_session/the event loop. Request
    // shutdown only; mux_disconnect/read failure is responsible for retirement.
    if (INVALID_SOCKET != handle->fd) {
#if defined __linux__
        ::shutdown(handle->fd, SHUT_RDWR);
#elif defined _WIN32 || defined _WIN64
        ::shutdown(handle->fd, SD_BOTH);
#endif
    }
    return errorcode_t::success;
}

uint32 trial_tls_server_socket::get_wto() const { return 1000; }

bool trial_tls_server_socket::support_tls() const { return true; }

uint32 trial_tls_server_socket::get_scheme() const { return socket_scheme_tls | socket_scheme_trial | socket_scheme_server; }

}  // namespace net
}  // namespace hotplace
