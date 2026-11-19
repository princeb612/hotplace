/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   client_socket_prosumer.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <errno.h>

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/thread.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/net/basic/trial/client_socket_prosumer.hpp>

namespace hotplace {
namespace net {

client_socket_prosumer::client_socket_prosumer() : client_socket(), _remote_transport_closed(false), _fd(INVALID_SOCKET), _mphandle(nullptr), _thread(nullptr) {}

client_socket_prosumer::~client_socket_prosumer() { close(); }

return_t client_socket_prosumer::open(sockaddr_storage_t* sa, const char* address, uint16 port) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == sa || nullptr == address) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (INVALID_SOCKET != _fd) {
            ret = errorcode_t::already_assigned;
            __leave2;
        }

        auto type = socket_type();
        ret = create_socket(&_fd, sa, type, address, port);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (SOCK_DGRAM == type) {
            memcpy(&_sa, sa, sizeof(sockaddr_storage_t));
            ret = start_consumer();
            if (errorcode_t::success != ret) {
                __leave2;
            }
            ret = do_handshake();
        }
    }
    __finally2 {
        // A failed datagram handshake or consumer startup must not leave the
        // socket (or a partially initialized consumer) attached to this object.
        if ((errorcode_t::success != ret) && (INVALID_SOCKET != _fd)) {
            close();
        }
    }
    return ret;
}

return_t client_socket_prosumer::connect(const char* address, uint16 port, uint32 timeout) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto type = socket_type();
        if (SOCK_STREAM != type) {
            ret = errorcode_t::bad_request;
            __leave2;
        }

        if (INVALID_SOCKET == _fd) {
            auto type = socket_type();
            ret = create_socket(&_fd, &_sa, type, address, port);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        addr_to_sockaddr(&_sa, address, port);
        ret = connect_socket_addr(_fd, (sockaddr*)&_sa, sizeof(_sa), timeout);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = start_consumer();
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = do_handshake();
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        // Do not retain a connected socket or consumer after a failed
        // handshake. Preserve the original connect/handshake error.
        if ((errorcode_t::success != ret) && (INVALID_SOCKET != _fd)) {
            close();
        }
    }
    return ret;
}

return_t client_socket_prosumer::close() {
    return_t ret = errorcode_t::success;
    return_t test = errorcode_t::success;
    __try2 {
        // Wake blocked readers before waiting for graceful TLS shutdown.
        test = do_transport_disconnect();
        if ((errorcode_t::success == ret) && (errorcode_t::success != test)) {
            ret = test;
        }

        test = do_shutdown();
        if ((errorcode_t::success == ret) && (errorcode_t::success != test)) {
            ret = test;
        }

        test = stop_consumer();
        if ((errorcode_t::success == ret) && (errorcode_t::success != test)) {
            ret = test;
        }

        test = do_close();
        if ((errorcode_t::success == ret) && (errorcode_t::success != test)) {
            ret = test;
        }
    }
    __finally2 {}
    return ret;
}

return_t client_socket_prosumer::read(char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ptr_data || nullptr == cbread) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = do_read(ptr_data, size_data, cbread, nullptr, nullptr);
    }
    __finally2 {}
    return ret;
}

return_t client_socket_prosumer::more(char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ptr_data || nullptr == cbread) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = read(ptr_data, size_data, cbread);
    }
    __finally2 {}
    return ret;
}

return_t client_socket_prosumer::send(const char* ptr_data, size_t size_data, size_t* cbsent) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (INVALID_SOCKET == _fd) {
            ret = errorcode_t::not_open;
            __leave2;
        }
        if (SOCK_STREAM != socket_type()) {
            ret = errorcode_t::bad_request;
            __leave2;
        }

        int flags = 0;
        int ret_send = 0;
#if defined __linux__
        flags = MSG_NOSIGNAL;  // Don't generate a SIGPIPE signal
        ret_send = ::send(_fd, ptr_data, size_data, flags);
#elif defined _WIN32 || defined _WIN64
        ret_send = ::send(_fd, ptr_data, (int)size_data, flags);
#endif
        if (-1 == ret_send) {
            ret = get_lasterror(ret_send);
        }
        if (nullptr != cbsent) {
            *cbsent = ret_send;
        }
    }
    __finally2 {}
    return ret;
}

return_t client_socket_prosumer::recvfrom(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    ret = do_read(ptr_data, size_data, cbread, addr, addrlen);
    return ret;
}

return_t client_socket_prosumer::sendto(const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (INVALID_SOCKET == _fd) {
            ret = errorcode_t::not_open;
            __leave2;
        }

        if (SOCK_DGRAM != socket_type()) {
            ret = errorcode_t::bad_request;
            __leave2;
        }

#if defined __linux__
        int ret_send = ::sendto(_fd, ptr_data, size_data, 0, addr, addrlen);
#elif defined _WIN32 || defined _WIN64
        int ret_send = ::sendto(_fd, ptr_data, (int)size_data, 0, addr, addrlen);
#endif
        if (-1 == ret_send) {
            ret = get_lasterror(ret_send);
        } else if (0 == ret_send) {
            //
        }
    }
    __finally2 {
        // do something
    }
    return ret;
}

socket_t client_socket_prosumer::get_socket() const { return _fd; }

return_t client_socket_prosumer::start_consumer() {
    return_t ret = errorcode_t::success;
    bool bound = false;
    bool started = false;
#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif
    __try2 {
        if (nullptr != _mphandle) {
            __leave2;
        }
        if (INVALID_SOCKET == _fd) {
            ret = errorcode_t::not_open;
            __leave2;
        }

        _remote_transport_closed.store(false);

        ret = mplexer.open(&_mphandle, 5);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = mplexer.bind(_mphandle, (handle_t)_fd, &_mplexer_key);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        bound = true;

        _thread = new thread(producer_thread, this);
        if (nullptr == _thread) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        ret = _thread->start();
        if (errorcode_t::success != ret) {
            __leave2;
        }
        started = true;

        ret = async_read();
    }
    __finally2 {}

    if (errorcode_t::success != ret) {
        // Roll back only resources acquired by this invocation.
        if (true == started) {
            mplexer.event_loop_break_concurrent(_mphandle, 1);
            _thread->join();
        }
        if (nullptr != _thread) {
            delete _thread;
            _thread = nullptr;
        }
        if (nullptr != _mphandle) {
            if (true == bound) {
                mplexer.unbind(_mphandle, (handle_t)_fd, &_mplexer_key);
            }
            mplexer.close(_mphandle);
            _mphandle = nullptr;
        }
    }

    return ret;
}

return_t client_socket_prosumer::stop_consumer() {
    return_t ret = errorcode_t::success;
    return_t test = errorcode_t::success;
#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif
    __try2 {
        if (nullptr == _mphandle) {
            if (nullptr != _thread) {
                delete _thread;
                _thread = nullptr;
            }
            __leave2;
        }

        test = mplexer.unbind(_mphandle, (handle_t)_fd, &_mplexer_key);
        if ((errorcode_t::success == ret) && (errorcode_t::success != test)) {
            ret = test;
        }

        test = mplexer.event_loop_break_concurrent(_mphandle, 1);
        if ((errorcode_t::success == ret) && (errorcode_t::success != test)) {
            ret = test;
        }

        if (nullptr != _thread) {
            test = _thread->join();
            if ((errorcode_t::success == ret) && (errorcode_t::success != test)) {
                ret = test;
            }
            delete _thread;
            _thread = nullptr;
        }

        test = mplexer.close(_mphandle);
        if ((errorcode_t::success == ret) && (errorcode_t::success != test)) {
            ret = test;
        }
        _mphandle = nullptr;
    }
    __finally2 {}
    return ret;
}

return_t client_socket_prosumer::producer_thread(void* param) {
    client_socket_prosumer* instance = (client_socket_prosumer*)param;
    return instance->producer_routine(param);
}

return_t client_socket_prosumer::producer_routine(void* param) {
    return_t ret = errorcode_t::success;
#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif
    mplexer.event_loop_run(_mphandle, (handle_t)_fd, consumer_routine, param);
    return ret;
}

return_t client_socket_prosumer::consumer_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    return_t ret = errorcode_t::success;
    client_socket_prosumer* instance = (client_socket_prosumer*)user_context;
    ret = instance->do_consumer_routine(type, data_count, data_array, callback_control, user_context);
    return ret;
}

return_t client_socket_prosumer::do_consumer_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    return_t ret = errorcode_t::success;
    return_t rearm_status = errorcode_t::success;
    __try2 {
        if (mux_read == type) {
            socket_buffer_t item;
#if defined __linux__
            int sock = (int)(long)data_array[1];
            auto& netbuf = _mplexer_key.buffer;
            int rc = recv(sock, netbuf.buffer, netbuf.buflen, 0);
            if (rc < 0) {
                int error = errno;
                if ((EINTR == error) || (EAGAIN == error) || (EWOULDBLOCK == error)) {
                    // epoll is level-triggered; a transient read condition can be retried.
                    __leave2;
                }
                ret = get_lasterror(rc);
                do_remote_transport_disconnect();
                __leave2;
            }
            if (0 == rc) {
                do_remote_transport_disconnect();
                __leave2;
            }
            enqueue(item, netbuf.buffer, rc);
#elif defined _WIN32 || defined _WIN64
            uint32 bytes_transfered = (uint32)(arch_t)data_array[1];
            mplexer_key_t* netbuf = (mplexer_key_t*)data_array[2];
            if (0 == bytes_transfered) {
                do_remote_transport_disconnect();
                __leave2;
            }
            enqueue(item, netbuf->buffer.wsabuf.buf, bytes_transfered);
            rearm_status = async_read();
            if (errorcode_t::success != rearm_status) {
                do_remote_transport_disconnect();
            }
#endif
            if (false == support_tls()) {
                _rsem.signal();
            }

            // Process bytes from this completion even if posting the next read failed.
            ret = do_secure();
            if ((errorcode_t::success == ret) && (errorcode_t::success != rearm_status)) {
                ret = rearm_status;
            }
        } else if (mux_dgram == type) {
            socket_buffer_t item;
#if defined __linux__
            socklen_t socklen = sizeof(sockaddr_storage_t);
            int sock = (int)(long)data_array[1];
            auto& netbuf = _mplexer_key.buffer;
            int rc = ::recvfrom(sock, netbuf.buffer, netbuf.buflen, 0, (sockaddr*)&item.addr, &socklen);
            if (rc <= 0) {
                __leave2;
            } else {
                enqueue(item, netbuf.buffer, rc);
            }
#elif defined _WIN32 || defined _WIN64
            uint32 bytes_transfered = (uint32)(arch_t)data_array[1];
            mplexer_key_t* mpkey = (mplexer_key_t*)data_array[2];
            auto& netbuf = mpkey->buffer;
            memcpy(&item.addr, &mpkey->addr, sizeof(sockaddr_storage_t));
            enqueue(item, netbuf.wsabuf.buf, bytes_transfered);
            rearm_status = async_read();
            if (errorcode_t::success != rearm_status) {
                do_remote_transport_disconnect();
            }
#endif
            if (false == support_tls()) {
                _rsem.signal();
            }

            // Process bytes from this completion even if posting the next read failed.
            ret = do_secure();
            if ((errorcode_t::success == ret) && (errorcode_t::success != rearm_status)) {
                ret = rearm_status;
            }
        } else if (mux_disconnect == type) {
            do_remote_transport_disconnect();
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

void client_socket_prosumer::enqueue(socket_buffer_t& item, const char* buf, size_t size) {
    if (buf) {
        item.buffer.write((byte_t*)buf, size);

        critical_section_guard guard(_rlock);
        _rq.push(item);
    }
#if defined DEBUG
    if (istraceable(trace_category_t::trace_category_net, loglevel_t::loglevel_debug)) {
        trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_net_produce, [&](basic_stream& dbs) -> void {
            dbs.println("[ns] read size 0x%x", size);
            dump_memory((byte_t*)buf, size, &dbs, 16, 3, 0, dump_notrunc);
        });
    }
#endif
}

return_t client_socket_prosumer::async_read() {
    return_t ret = errorcode_t::success;
#if defined _WIN32 || defined _WIN64
    auto& netbuf = _mplexer_key.buffer;
    netbuf.init();

    auto type = socket_type();

    DWORD flags = 0;
    int rc = 0;
    if (SOCK_STREAM == type) {
        rc = WSARecv(_fd, &netbuf.wsabuf, 1, nullptr, &flags, &netbuf.overlapped, nullptr);
    } else if (SOCK_DGRAM == type) {
        auto& netaddr = _mplexer_key.addr;
        int addrlen = sizeof(sockaddr_storage_t);
        rc = WSARecvFrom(_fd, &netbuf.wsabuf, 1, nullptr, &flags, (sockaddr*)&netaddr, &addrlen, &netbuf.overlapped, nullptr);
    } else {
        ret = errorcode_t::bad_request;
    }

    if ((errorcode_t::success == ret) && (SOCKET_ERROR == rc)) {
        int error = WSAGetLastError();
        if (WSA_IO_PENDING != error) {
            ret = get_lasterror(rc);
        }
    }
#endif
    return ret;
}

return_t client_socket_prosumer::do_consume(basic_stream& stream, sockaddr_storage_t& addr) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (support_tls()) {
            critical_section_guard guard(_rlock);

            while (false == _rq.empty()) {
                const auto& item = _rq.front();
                stream << item.buffer;
                memcpy(&addr, &item.addr, sizeof(sockaddr_storage_t));
                _rq.pop();
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t client_socket_prosumer::do_handshake() { return errorcode_t::success; }

return_t client_socket_prosumer::do_read(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ptr_data || nullptr == cbread) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        auto type = socket_type();
        if (SOCK_DGRAM == type) {
            if ((nullptr == addr) || (nullptr == addrlen) || (size_t(*addrlen) < sizeof(sockaddr_storage_t))) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
        }

        *cbread = 0;

        if (INVALID_SOCKET == _fd) {
            ret = errorcode_t::not_open;
        } else {
            return_t test = errorcode_t::success;
            if (false == support_tls()) {
                test = _rsem.wait(get_wto());
            }
            if (errorcode_t::success == test) {
                critical_section_guard guard(_rlock);
                if (false == _rq.empty()) {
                    auto& item = _rq.front();

                    if (SOCK_DGRAM == type && nullptr != addr) {
                        memcpy(addr, &item.addr, sizeof(sockaddr_storage_t));
                    }

                    auto datasize = item.buffer.size();
                    if (datasize >= size_data) {
                        memcpy(ptr_data, item.buffer.data(), size_data);
                        item.buffer.cut(0, size_data);

                        *cbread = size_data;

                        if (false == support_tls()) {
                            _rsem.signal();
                        }
                    } else {
                        memcpy(ptr_data, item.buffer.data(), datasize);

                        *cbread = datasize;

                        _rq.pop();
                    }
                    if (false == _rq.empty()) {
                        ret = errorcode_t::more_data;
                    }
                }
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t client_socket_prosumer::do_secure() {
    return_t ret = errorcode_t::success;
    __try2 {}
    __finally2 {}
    return ret;
}

return_t client_socket_prosumer::do_shutdown() {
    return_t ret = errorcode_t::success;
    __try2 {}
    __finally2 {}
    return ret;
}

return_t client_socket_prosumer::do_transport_disconnect() { return errorcode_t::success; }

return_t client_socket_prosumer::do_remote_transport_disconnect() {
    _remote_transport_closed.store(true);
    return do_transport_disconnect();
}

bool client_socket_prosumer::is_remote_transport_closed() const { return _remote_transport_closed.load(); }

return_t client_socket_prosumer::do_close() {
    return_t ret = errorcode_t::success;
    __try2 {
        close_socket(_fd, true, 0);
        _fd = INVALID_SOCKET;
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
