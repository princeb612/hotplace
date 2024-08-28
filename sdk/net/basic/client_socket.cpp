/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/basic/sdk.hpp>
#include <sdk/net/basic/client_socket.hpp>

namespace hotplace {
using namespace io;
namespace net {

tcp_client_socket::tcp_client_socket() : _wto(1000) {
    // do nothing
}

tcp_client_socket::~tcp_client_socket() {
    // do nothing
}

return_t tcp_client_socket::connect(socket_t* sock, tls_context_t** tls_handle, const char* address, uint16 port, uint32 timeout) {
    return_t ret = errorcode_t::success;

    __try2 { ret = connect_socket(sock, SOCK_STREAM, address, port, timeout); }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tcp_client_socket::close(socket_t sock, tls_context_t* tls_handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (INVALID_SOCKET == sock) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
#if defined __linux__
        ::close(sock);
#elif defined _WIN32 || defined _WIN64
        closesocket(sock);
#endif
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tcp_client_socket::read(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* size_read) {
    return_t ret = errorcode_t::success;

    ret = wait_socket(sock, _wto, SOCK_WAIT_READABLE);
    if (errorcode_t::success == ret) {
#if defined __linux__
        int ret_recv = recv(sock, ptr_data, size_data, 0);
#elif defined _WIN32 || defined _WIN64
        int ret_recv = recv(sock, ptr_data, (int)size_data, 0);
#endif
        if (-1 == ret_recv) {
            ret = get_lasterror(ret_recv);
        } else if (0 == ret_recv) {
            ret = errorcode_t::closed;
        }

        if (nullptr != size_read) {
            *size_read = ret_recv;
        }
        if (size_data == ret_recv) {
            ret = errorcode_t::more_data;
        }
    }
    return ret;
}

return_t tcp_client_socket::more(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;
    ret = read(sock, tls_handle, ptr_data, size_data, cbread);
    return ret;
}

return_t tcp_client_socket::send(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* size_sent) {
    return_t ret = errorcode_t::success;

    __try2 {
#if defined __linux__
        int ret_send = ::send(sock, ptr_data, size_data, 0);
#elif defined _WIN32 || defined _WIN64
        int ret_send = ::send(sock, ptr_data, (int)size_data, 0);
#endif
        if (-1 == ret_send) {
            ret = get_lasterror(ret_send);
        }
        if (nullptr != size_sent) {
            *size_sent = ret_send;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

bool tcp_client_socket::support_tls() { return false; }

tcp_client_socket& tcp_client_socket::set_wto(uint32 milliseconds) {
    if (milliseconds) {
        _wto = milliseconds;
    }
    return *this;
}

uint32 tcp_client_socket::get_wto() { return _wto; }

udp_client_socket::udp_client_socket() : _wto(1000) {}

udp_client_socket::~udp_client_socket() {}

return_t udp_client_socket::open(socket_t* sock, tls_context_t* tls_handle, const char* address, uint16 port) {
    return_t ret = errorcode_t::success;
    __try2 { ret = create_socket(sock, &_sock_storage, SOCK_DGRAM, address, port); }
    __finally2 {
        // do something
    }
    return ret;
}

return_t udp_client_socket::close(socket_t sock, tls_context_t* tls_handle) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (INVALID_SOCKET == sock) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        close_socket(sock, true, 0);
    }
    __finally2 {
        // do something
    }
    return ret;
}

return_t udp_client_socket::read(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* size_read) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = wait_socket(sock, _wto, SOCK_WAIT_READABLE);
        if (errorcode_t::success == ret) {
#if 1
            int size_peek = recvfrom(sock, ptr_data, size_data, MSG_PEEK, nullptr, nullptr);
            if (size_data < size_peek) {
                ret = errorcode_t::insufficient_buffer;
                __leave2;
            }
#endif

#if defined __linux__
            int ret_recv = recvfrom(sock, ptr_data, size_data, 0, nullptr, nullptr);
#elif defined _WIN32 || defined _WIN64
            int ret_recv = recvfrom(sock, ptr_data, (int)size_data, 0, nullptr, nullptr);
#endif
            if (-1 == ret_recv) {
                ret = get_lasterror(ret_recv);
            } else if (0 == ret_recv) {
                ret = errorcode_t::closed;
            }

            if (nullptr != size_read) {
                *size_read = ret_recv;
            }
        }
    }
    __finally2 {
        // do something
    }
    return ret;
}

return_t udp_client_socket::send(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* size_sent) {
    return_t ret = errorcode_t::success;
    __try2 {
#if defined __linux__
        int ret_send = ::sendto(sock, ptr_data, size_data, 0, (const struct sockaddr*)&_sock_storage, sizeof(sockaddr_storage_t));
#elif defined _WIN32 || defined _WIN64
        int ret_send = ::sendto(sock, ptr_data, (int)size_data, 0, (const struct sockaddr*)&_sock_storage, sizeof(sockaddr_storage_t));
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

return_t udp_client_socket::sendto(socket_t sock, tls_context_t* tls_handle, sockaddr_storage_t* sock_storage, const char* ptr_data, size_t size_data,
                                   size_t* size_sent) {
    return_t ret = errorcode_t::success;
    __try2 {
#if defined __linux__
        int ret_send = ::sendto(sock, ptr_data, size_data, 0, (const struct sockaddr*)&sock_storage, sizeof(sockaddr_storage_t));
#elif defined _WIN32 || defined _WIN64
        int ret_send = ::sendto(sock, ptr_data, (int)size_data, 0, (const struct sockaddr*)&sock_storage, sizeof(sockaddr_storage_t));
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

bool udp_client_socket::support_tls() { return false; }

udp_client_socket& udp_client_socket::set_wto(uint32 milliseconds) {
    if (milliseconds) {
        _wto = milliseconds;
    }
    return *this;
}

uint32 udp_client_socket::get_wto() { return _wto; }

}  // namespace net
}  // namespace hotplace
