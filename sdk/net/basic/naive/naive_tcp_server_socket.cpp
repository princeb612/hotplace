/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/basic/naive/naive_tcp_server_socket.hpp>

namespace hotplace {
namespace net {

naive_tcp_server_socket::naive_tcp_server_socket() : server_socket() {}

naive_tcp_server_socket::~naive_tcp_server_socket() {}

return_t naive_tcp_server_socket::open(socket_context_t** handle, unsigned int family, uint16 port) {
    return_t ret = errorcode_t::success;
    socket_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        socket_t sock = INVALID_SOCKET;
        ret = create_listener(1, &family, &sock, IPPROTO_TCP, port);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        __try_new_catch(context, new socket_context_t(sock, closesocket_ondestroy), ret, __leave2);
        *handle = context;
    }
    __finally2 {}
    return ret;
}

return_t naive_tcp_server_socket::accept(socket_t* client_socket, socket_t listen_socket, struct sockaddr* addr, socklen_t* addrlen) {
    return_t ret = errorcode_t::success;

    __try2 {
        if ((nullptr == client_socket) || (nullptr == addr) || (nullptr == addrlen)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        socket_t socket = INVALID_SOCKET;
        socket = ::accept(listen_socket, addr, addrlen);
        if (INVALID_SOCKET == socket) {
            ret = get_lasterror(socket);
            __leave2;
        }

        *client_socket = socket;
    }
    __finally2 {}
    return ret;
}

return_t naive_tcp_server_socket::read(socket_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto sock = handle->fd;
#if defined _WIN32 || defined _WIN64
        int ret_routine = ::recv(sock, ptr_data, (int)size_data, 0);
#elif defined __linux__
        int ret_routine = ::recv(sock, ptr_data, size_data, 0);
#endif
        if (-1 == ret_routine) {
            ret = get_lasterror(ret_routine);
        } else if (0 == ret_routine) {
            ret = errorcode_t::closed;
        }
        if (nullptr != cbread) {
            *cbread = ret_routine;
        }
    }
    __finally2 {}
    return ret;
}

return_t naive_tcp_server_socket::send(socket_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto sock = handle->fd;
        int flags = 0;
#if defined __linux__
        flags = MSG_NOSIGNAL;
        int ret_routine = ::send(sock, ptr_data, size_data, flags);
#elif defined _WIN32 || defined _WIN64
        int ret_routine = ::send(sock, ptr_data, (int)size_data, flags);
#endif
        if (-1 == ret_routine) {
            ret = get_lasterror(ret_routine);
        } else if (0 == ret_routine) {
            // closed
        }
        if (nullptr != cbsent) {
            *cbsent = ret_routine;
        }
    }
    __finally2 {}

    return ret;
}

int naive_tcp_server_socket::socket_type() { return SOCK_STREAM; }

}  // namespace net
}  // namespace hotplace
