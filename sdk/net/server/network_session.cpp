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
#include <sdk/base/unittest/trace.hpp>
#include <sdk/net/basic/openssl/types.hpp>
#include <sdk/net/basic/server_socket.hpp>
#include <sdk/net/http/http2/hpack.hpp>
#include <sdk/net/server/network_server.hpp>
#include <sdk/net/server/network_session.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

network_session::network_session(server_socket* serversocket, const sockaddr_storage_t* addr) : _http2_session(nullptr) {
    _shared.make_share(this);
    if (addr) {
        memcpy(&_session.netsock.cli_addr, addr, sizeof(sockaddr_storage_t));
    }
    serversocket->addref();
    _session.svr_socket = serversocket;
}

network_session::~network_session() {
    if (_http2_session) {
        delete _http2_session;
    }
    get_server_socket()->close(_session.netsock.event_handle);
    get_server_socket()->release();
}

return_t network_session::connected(handle_t event_socket, sockaddr_storage_t* sockaddr, socket_context_t* socket_handle) {
    return_t ret = errorcode_t::success;

    _session.netsock.event_handle = socket_handle;
    memcpy(&(_session.netsock.cli_addr), sockaddr, sizeof(sockaddr_storage_t));
    return ret;
}

return_t network_session::udp_session_open(handle_t listen_sock) {
    return_t ret = errorcode_t::success;
    if (false == get_server_socket()->support_tls()) {
        _session.netsock.event_handle = new socket_context_t((socket_t)listen_sock, 0);
    }
    return ret;
}

return_t network_session::dtls_session_open(handle_t listen_sock) {
    return_t ret = errorcode_t::success;

    // memset(&(_session.netsock.cli_addr), 0, sizeof(sockaddr_storage_t));

    auto& event_handle = _session.netsock.event_handle;
    if (event_handle) {
        get_server_socket()->close(event_handle);
        event_handle = nullptr;
    }

    get_server_socket()->dtls_open(&_session.netsock.event_handle, (socket_t)listen_sock);

    return ret;
}

return_t network_session::dtls_session_open(handle_t listen_sock, const binary_t& cookie) {
    return_t ret = errorcode_t::success;

    ret = dtls_session_open(listen_sock);

    auto& event_handle = _session.netsock.event_handle;
    if (0 == (tls_using_openssl & event_handle->flags)) {
        // DTLS cookie (see tls_handshake_hello_verify_request)
        auto session = event_handle->handle.session;
        session->get_tls_protection().get_secrets().assign(tls_context_dtls_cookie, cookie);
    }

    return ret;
}

return_t network_session::dtls_session_handshake() {
    return_t ret = errorcode_t::success;
    get_server_socket()->dtls_handshake(&_session);
    return ret;
}

return_t network_session::ready_to_read() {
    return_t ret = errorcode_t::success;

#if defined _WIN32 || defined _WIN64
    /* asynchronous read */
    int type = get_server_socket()->socket_type();
    socket_t sock = _session.netsock.get_event_socket();
    WSABUF& wsabuf = _session.buf.wsabuf;
    OVERLAPPED& ov = _session.buf.overlapped;
    if (SOCK_STREAM == type) {
        DWORD dwFlags = 0;
        DWORD dwRecvBytes = 0;

        WSARecv(sock, &wsabuf, 1, &dwRecvBytes, &dwFlags, &ov, nullptr);
    } else if (SOCK_DGRAM == type) {
        uint32 flags = 0;
        if (get_server_socket()->support_tls()) {
            /**
             * MSG_PEEK to get the peer address
             * - design OVERLAPPED structure ex. { OVERLAPPED, socket address, ...}
             * - call WSARecvFrom using MSG_PEEK, OVERLAPPED structure
             * - GetQueuedCompletionStatus
             *
             * cookie = HMAC(key, address, port)
             * - manage DTLS session by cookie
             * - copy the peer address into DTLS session
             * - set cookie of hello_verify_request
             */

            /**
             *  DTLS IOCP (blocking io, no SO_RCVTIMEO)
             *  1. recvfrom, flag = 0
             *      Client: SSL_connect
             *      Server: int flag = 0;
             *      Server: WSARecvFrom(..., &flags, &ov, ...)
             *      Server: GetQueuedCompletionStatus
             *      Server:     00000000 : 16 FE FF 00 00 00 00 00 00 00 00 00 C0 01 00 00 | ................
             *      Server:     ; handshake 0x16, DTLS1_VERSION 0xFEFF (DTLS1_2_VERSION 0xFEFD)
             *      Server: DTLSv1_listen
             *      Server:     recvfrom - hang
             *      Client: SSL_connect
             *      Server: DTLSv1_listen
             *      Server:     recvfrom - resume
             *                  SSL_get_state -> TLS_ST_SR_CLNT_HELLO
             *      Server: SSL_accept
             *                  SSL_get_state -> TLS_ST_OK
             *      Client: SSL_write
             *      Server: SSL_read
             *      Server: WSARecvFrom(..., &flags, &ov, ...)
             *  2. recvfrom, flag = MSG_PEEK
             *      Client: SSL_connect
             *      Server: int flag = MSG_PEEK;
             *      Server: WSARecvFrom(..., &flags, &ov, ...)
             *      Server: GetQueuedCompletionStatus
             *      Server: DTLSv1_listen
             *                  SSL_get_state -> TLS_ST_SR_CLNT_HELLO
             *      Server: SSL_accept
             *                  SSL_get_state -> TLS_ST_OK
             *      Client: SSL_write
             *      Server: SSL_read
             *      Server: WSARecvFrom(..., &flags, &ov, ...)
             *      Client: SSL_write
             *      Server: GetQueuedCompletionStatus
             *      Server: SSL_read
             *      Server: WSARecvFrom(..., &flags, &ov, ...)
             */
            flags = MSG_PEEK;
        }
        int addrlen = sizeof(sockaddr_storage_t);
        WSARecvFrom(sock, &wsabuf, 1, nullptr, &flags, (sockaddr*)&socket_info()->cli_addr, &addrlen, &ov, nullptr);
    }
#endif
    return ret;
}

return_t network_session::send(const char* data_ptr, size_t size_data) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == data_ptr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        size_t cbsent = 0;
        ret = get_server_socket()->send(_session.netsock.event_handle, data_ptr, size_data, &cbsent);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t network_session::send(const byte_t* data_ptr, size_t size_data) { return send((char*)data_ptr, size_data); }

return_t network_session::sendto(const char* data_ptr, size_t size_data, sockaddr_storage_t* addr) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == data_ptr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        size_t cbsent = 0;
        ret = get_server_socket()->sendto(_session.netsock.event_handle, data_ptr, size_data, &cbsent, (sockaddr*)addr, sizeof(sockaddr_storage_t));
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t network_session::sendto(const byte_t* data_ptr, size_t size_data, sockaddr_storage_t* addr) { return sendto((char*)data_ptr, size_data, addr); }

netsocket_t* network_session::socket_info() { return _session.socket_info(); }

netbuffer_t* network_session::get_buffer() { return &_session.buf; }

#if defined _WIN32 || defined _WIN64
WSABUF* network_session::wsabuf_read() { return &_session.buf.wsabuf; }
#endif

network_stream* network_session::getstream() { return &_stream; }

network_stream* network_session::getrequest() { return &_request; }

int network_session::get_priority() { return _session.priority; }

void network_session::set_priority(int priority) { _session.priority = priority; }

int network_session::addref() { return _shared.addref(); }

int network_session::release() { return _shared.delref(); }

return_t network_session::produce(t_mlfq<network_session>* q, byte_t* buf_read, size_t size_buf_read, const sockaddr_storage_t* addr) {
    // const sockaddr_storage_t* addr
    // (epoll) nullptr
    // (iocp)  valid
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);

    __try2 {
        if (nullptr == q) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

#if defined __linux__
        // read
        size_buf_read = _session.buf.buflen;
        buf_read = (byte_t*)_session.buf.buffer;
#elif defined _WIN32 || defined _WIN64
        // buf_read, size_buf_read transmitted
#endif

        int socktype = get_server_socket()->socket_type();
        bool is_stream = (SOCK_STREAM == socktype);
        if (is_stream) {
            ret = produce_stream(q, buf_read, size_buf_read, addr);
        } else {
            ret = produce_dgram(q, buf_read, size_buf_read, addr);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t network_session::produce_stream(t_mlfq<network_session>* q, byte_t* buf_read, size_t size_buf_read, const sockaddr_storage_t* addr) {
    // const sockaddr_storage_t* addr
    // (epoll) nullptr
    // (iocp)  valid
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);

    __try2 {
        if (nullptr == q) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

#if defined __linux__
        // read
        size_buf_read = _session.buf.buflen;
        buf_read = (byte_t*)_session.buf.buffer;
#elif defined _WIN32 || defined _WIN64
        // buf_read, size_buf_read transmitted
#endif

        return_t result = errorcode_t::success;

        if (get_server_socket()->support_tls()) { /* TLS */
            size_t cbread = 0;
            bool data_ready = false;
            int mode = 0;
#if defined __linux__
            mode = tls_io_flag_t::read_epoll;
            ret = get_server_socket()->read(_session.netsock.event_handle, mode, (char*)buf_read, size_buf_read, &cbread);
#elif defined _WIN32 || defined _WIN64
            mode = tls_io_flag_t::read_iocp;
            ret = get_server_socket()->read(_session.netsock.event_handle, mode, (char*)buf_read, size_buf_read, nullptr);
#endif
            if (errorcode_t::success != ret) {
                __leave2;
            }

            while (true) {
                result = get_server_socket()->read(_session.netsock.event_handle, tls_io_flag_t::read_ssl_read, (char*)buf_read, size_buf_read,
                                                   &cbread); /*SSL_read */
                if (errorcode_t::success == result || errorcode_t::more_data == result) {
                    getstream()->produce(buf_read, cbread);

                    data_ready = true;

#if defined DEBUG
                    if (istraceable(trace_category_net)) {
                        basic_stream dbs;
                        dbs << "[ns] read " << (socket_t)_session.netsock.get_event_socket() << "\n";
                        dump_memory(buf_read, cbread, &dbs, 16, 2, 0, dump_notrunc);
                        trace_debug_event(trace_category_net, trace_event_net_produce, &dbs);
                    }
#endif
                } else {
                    break;
                }
            }

            if (data_ready) {
                q->push(get_priority(), this);
            }
        } else { /* wo TLS */
            size_t cbread = 0;
#if defined __linux__
            ret = get_server_socket()->read(_session.netsock.event_handle, 0, (char*)buf_read, size_buf_read, &cbread);
            if (errorcode_t::success == ret) {
                getstream()->produce(buf_read, cbread);
                q->push(get_priority(), this);
            }
#elif defined _WIN32 || defined _WIN64
            // udp client address
            cbread = size_buf_read;
            getstream()->produce(buf_read, size_buf_read);
            q->push(get_priority(), this);
#endif

#if defined DEBUG
            if (istraceable(trace_category_net) && (errorcode_t::success == ret)) {
                basic_stream dbs;
                dbs << "[ns] read " << _session.netsock.get_event_socket() << "\n";
                dump_memory(buf_read, cbread, &dbs, 16, 2, 0, dump_notrunc);
                trace_debug_event(trace_category_net, trace_event_net_produce, &dbs);
            }
#endif
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t network_session::produce_dgram(t_mlfq<network_session>* q, byte_t* buf_read, size_t size_buf_read, const sockaddr_storage_t* addr) {
    // const sockaddr_storage_t* addr
    // (epoll) nullptr
    // (iocp)  valid
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);

    __try2 {
        if (nullptr == q) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

#if defined __linux__
        // read
        size_buf_read = _session.buf.buflen;
        buf_read = (byte_t*)_session.buf.buffer;
#elif defined _WIN32 || defined _WIN64
        // buf_read, size_buf_read transmitted
#endif
        auto event_handle = _session.netsock.event_handle;

        return_t result = errorcode_t::success;

        if (get_server_socket()->support_tls()) { /* TLS */
            __try2 {
                size_t cbread = 0;
                bool data_ready = false;

                sockaddr* sa = nullptr;
                socklen_t salen = sizeof(sockaddr_storage_t);
#if defined __linux__
                sockaddr_storage_t sockstorage;
                sa = (sockaddr*)&sockstorage;
#elif defined _WIN32 || defined _WIN64
                sa = (sockaddr*)addr;
#endif

                int mode = 0;
                if (tls_using_openssl & event_handle->flags) {
                    // openssl_dtls_server_socket
                    mode = tls_io_flag_t::read_ssl_read;
                } else {
                    // trial_dtls_server_socket
                    mode = tls_io_flag_t::read_bio_write | tls_io_flag_t::read_socket_recv;  // tls_io_flag_t::read_epoll
                }
                result = get_server_socket()->recvfrom(event_handle, mode, (char*)buf_read, size_buf_read, &cbread, sa, &salen);
                if (errorcode_t::success == result || errorcode_t::more_data == result) {
                    getstream()->produce(buf_read, cbread, addr);

                    data_ready = true;

#if defined DEBUG
                    if (istraceable(trace_category_net)) {
                        basic_stream dbs;
                        dbs << "[ns] read " << (socket_t)_session.netsock.get_event_socket() << "\n";
                        dump_memory(buf_read, cbread, &dbs, 16, 2, 0, dump_notrunc);
                        trace_debug_event(trace_category_net, trace_event_net_produce, &dbs);
                    }
#endif
                }

                if (data_ready) {
                    q->push(get_priority(), this);
                }
            }
            __finally2 {
                //
            }
        } else { /* wo TLS */
            size_t cbread = 0;
#if defined __linux__
            sockaddr_storage_t sa;
            socklen_t sa_size = sizeof(sa);
            ret = get_server_socket()->recvfrom(event_handle, 0, (char*)buf_read, size_buf_read, &cbread, (sockaddr*)&sa, &sa_size);
            if (errorcode_t::success == ret) {
                getstream()->produce(buf_read, cbread, &sa);
                q->push(get_priority(), this);
            }
#elif defined _WIN32 || defined _WIN64
            // udp client address
            cbread = size_buf_read;
            getstream()->produce(buf_read, size_buf_read, addr);
            q->push(get_priority(), this);
#endif

#if defined DEBUG
            if (istraceable(trace_category_net) && (errorcode_t::success == ret)) {
                basic_stream dbs;
                dbs << "[ns] read " << (socket_t)_session.netsock.get_event_socket() << "\n";
                dump_memory(buf_read, cbread, &dbs, 16, 2, 0, dump_notrunc);
                trace_debug_event(trace_category_net, trace_event_net_produce, &dbs);
            }
#endif
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t network_session::consume(network_protocol_group* protocol_group, network_stream_data** ptr_network_stream_buffer) {
    return_t ret = errorcode_t::success;

    _request.read(protocol_group, &_stream);
    ret = _request.consume(ptr_network_stream_buffer);
    return ret;
}

server_socket* network_session::get_server_socket() { return _session.svr_socket; }

network_session_data* network_session::get_session_data() { return &_session_data; }

http2_session* network_session::get_http2_session() {
    if (nullptr == _http2_session) {
        critical_section_guard guard(_lock);
        if (nullptr == _http2_session) {
            _http2_session = new http2_session;
        }
    }
    return _http2_session;
}

return_t network_session::dgram_get_sockaddr(sockaddr_storage_t* addr) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == addr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        socklen_t sa_size = sizeof(sockaddr_storage_t);
        size_t cbread = _session.buf.bin.size();
        int mode = read_socket_recv | peek_msg;
        ret = get_server_socket()->recvfrom(_session.netsock.event_handle, mode, &_session.buf.bin[0], _session.buf.bin.size(), &cbread, (sockaddr*)addr,
                                            &sa_size);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
