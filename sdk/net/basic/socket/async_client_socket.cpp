/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/unittest/trace.hpp>
#include <sdk/net/basic/socket/async_client_socket.hpp>

namespace hotplace {
namespace net {

async_client_socket::async_client_socket() : client_socket(), _fd(INVALID_SOCKET), _mphandle(nullptr), _thread(nullptr), _wto(3000) {}

async_client_socket::~async_client_socket() { close(); }

return_t async_client_socket::open(sockaddr_storage_t* sa, const char* address, uint16 port) {
    return_t ret = errorcode_t::success;
    __try2 {
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
            start_consumer();
        }
    }
    __finally2 {}
    return ret;
}

return_t async_client_socket::connect(const char* address, uint16 port, uint32 timeout) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto type = socket_type();
        if (SOCK_STREAM != type) {
            ret = bad_request;
            __leave2;
        }

        sockaddr_storage_t sa;
        if (INVALID_SOCKET == _fd) {
            auto type = socket_type();
            ret = create_socket(&_fd, &sa, type, address, port);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        addr_to_sockaddr(&sa, address, port);
        ret = connect_socket_addr(_fd, (sockaddr*)&sa, sizeof(sa), timeout);

        start_consumer();

        ret = do_handshake();
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            close();
        }
    }
    return ret;
}

return_t async_client_socket::close() {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = do_shutdown();

        stop_consumer();

        ret = do_close();
    }
    __finally2 {}
    return ret;
}

return_t async_client_socket::read(char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;
    ret = do_read(ptr_data, size_data, cbread, nullptr, nullptr);
    return ret;
}

return_t async_client_socket::more(char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;
    ret = read(ptr_data, size_data, cbread);
    return ret;
}

return_t async_client_socket::send(const char* ptr_data, size_t size_data, size_t* cbsent) {
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

        int ret_send = 0;
#if defined __linux__
        ret_send = ::send(_fd, ptr_data, size_data, 0);
#elif defined _WIN32 || defined _WIN64
        ret_send = ::send(_fd, ptr_data, (int)size_data, 0);
#endif
        if (-1 == ret_send) {
            ret = get_lasterror(ret_send);
        }
        if (nullptr != cbsent) {
            *cbsent = ret_send;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t async_client_socket::recvfrom(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    ret = do_read(ptr_data, size_data, cbread, addr, addrlen);
    return ret;
}

return_t async_client_socket::sendto(const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr, socklen_t addrlen) {
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

void async_client_socket::set_wto(uint32 milliseconds) { _wto = milliseconds; }

uint32 async_client_socket::get_wto() { return _wto; }

return_t async_client_socket::start_consumer() {
    return_t ret = errorcode_t::success;
#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif

    mplexer.open(&_mphandle, 5);
    mplexer.bind(_mphandle, (handle_t)_fd, &_mplexer_key);

    _thread = new thread(producer_thread, this);
    _thread->start();

    async_read();

    return ret;
}

return_t async_client_socket::stop_consumer() {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == _mphandle) {
            __leave2;
        }

#if defined __linux__
        multiplexer_epoll mplexer;
#elif defined _WIN32 || defined _WIN64
        multiplexer_iocp mplexer;
#endif

        mplexer.unbind(_mphandle, (handle_t)_fd, nullptr);
        mplexer.event_loop_break_concurrent(_mphandle, 1);

        _thread->join();
        delete _thread;
        _thread = nullptr;

        mplexer.close(_mphandle);
        _mphandle = nullptr;
    }
    __finally2 {}
    return ret;
}

return_t async_client_socket::producer_thread(void* param) {
    async_client_socket* instance = (async_client_socket*)param;
    return instance->producer_routine(param);
}

return_t async_client_socket::producer_routine(void* param) {
    return_t ret = errorcode_t::success;
#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif
    mplexer.event_loop_run(_mphandle, (handle_t)_fd, consumer_routine, param);
    return ret;
}

return_t async_client_socket::consumer_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    return_t ret = errorcode_t::success;
    async_client_socket* instance = (async_client_socket*)user_context;
    ret = instance->do_consumer_routine(type, data_count, data_array, callback_control, user_context);
    return ret;
}

return_t async_client_socket::do_consumer_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (mux_read == type) {
            bufferqueue_item_t item;
#if defined __linux__
            // multiplexer_epoll mplexer;
            // multiplexer_context_t* handle = (multiplexer_context_t*)data_array[0];
            int sock = (int)(long)data_array[1];
            auto& netbuf = _mplexer_key.buffer;
            int rc = recv(sock, netbuf.buffer, netbuf.buflen, 0);
            if (rc <= 0) {
                __leave2;
            } else {
                item.buffer.write(netbuf.buffer, rc);

                critical_section_guard guard(_rlock);
                _rq.push(item);
            }
#elif defined _WIN32 || defined _WIN64
            uint32 bytes_transfered = (uint32)(arch_t)data_array[1];
            mplexer_key_t* netbuf = (mplexer_key_t*)data_array[2];
            {
                item.buffer.write(netbuf->buffer.wsabuf.buf, bytes_transfered);

                critical_section_guard guard(_rlock);
                _rq.push(item);
            }
            async_read();
#endif
            if (false == support_tls()) {
                _rsem.signal();
            }

            do_secure();
        } else if (mux_dgram == type) {
            bufferqueue_item_t item;
#if defined __linux__
            // multiplexer_epoll mplexer;
            // multiplexer_context_t* handle = (multiplexer_context_t*)data_array[0];
            socklen_t socklen = sizeof(sockaddr_storage_t);
            int sock = (int)(long)data_array[1];
            auto& netbuf = _mplexer_key.buffer;
            int rc = recvfrom(sock, netbuf.buffer, netbuf.buflen, 0, (sockaddr*)&item.addr, &socklen);
            if (rc <= 0) {
                __leave2;
            } else {
                item.buffer.write(netbuf.buffer, rc);

                critical_section_guard guard(_rlock);
                _rq.push(item);
            }
#elif defined _WIN32 || defined _WIN64
            uint32 bytes_transfered = (uint32)(arch_t)data_array[1];
            mplexer_key_t* mpkey = (mplexer_key_t*)data_array[2];
            auto& netbuf = mpkey->buffer;
            {
                item.buffer.write(netbuf.wsabuf.buf, bytes_transfered);
                if (SOCK_DGRAM == socket_type()) {
                    memcpy(&item.addr, &mpkey->addr, sizeof(sockaddr_storage_t));
                }

                critical_section_guard guard(_rlock);
                _rq.push(item);
            }
            async_read();
#endif
            if (false == support_tls()) {
                _rsem.signal();
            }

            do_secure();
        } else if (mux_disconnect == type) {
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

void async_client_socket::async_read() {
#if defined _WIN32 || defined _WIN64
    auto& netbuf = _mplexer_key.buffer;
    netbuf.init();

    auto type = socket_type();

    DWORD flags = 0;
    DWORD bytes_received = 0;
    if (SOCK_STREAM == type) {
        WSARecv(_fd, &netbuf.wsabuf, 1, &bytes_received, &flags, &netbuf.overlapped, nullptr);
    } else {
        auto& netaddr = _mplexer_key.addr;
        int addrlen = sizeof(sockaddr_storage_t);
        WSARecvFrom(_fd, &netbuf.wsabuf, 1, &bytes_received, &flags, (sockaddr*)&netaddr, &addrlen, &netbuf.overlapped, nullptr);
    }
#endif
}

return_t async_client_socket::do_handshake() {
    return_t ret = errorcode_t::success;
    return ret;
}

return_t async_client_socket::do_read(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ptr_data || nullptr == cbread) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        auto type = socket_type();
        if (SOCK_DGRAM == type) {
            if ((nullptr == addr) || (nullptr == addrlen) || (*addrlen != sizeof(sockaddr_storage_t))) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
        }

        *cbread = 0;

        if (INVALID_SOCKET == _fd) {
            ret = not_open;
        } else {
            return_t test = success;
            if (false == support_tls()) {
                test = _rsem.wait(get_wto());
            }
            if (errorcode_t::success == test) {
                critical_section_guard guard(_rlock);
                if (false == _rq.empty()) {
                    auto& item = _rq.front();

                    if (SOCK_DGRAM == type) {
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
                        ret = more_data;
                    }
                }
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t async_client_socket::do_secure() {
    return_t ret = errorcode_t::success;
    __try2 {}
    __finally2 {}
    return ret;
}

return_t async_client_socket::do_shutdown() {
    return_t ret = errorcode_t::success;
    __try2 {}
    __finally2 {}
    return ret;
}

return_t async_client_socket::do_close() {
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
