/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/tcp_server_socket.hpp>

namespace hotplace {
namespace net {

tcp_server_socket::tcp_server_socket() : server_socket() {
    // do nothing
}

return_t tcp_server_socket::open(socket_t* sock, unsigned int family, uint16 port) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == sock) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = create_listener(1, &family, sock, IPPROTO_TCP, port);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tcp_server_socket::accept(socket_t sock, socket_t* clisock, struct sockaddr* addr, socklen_t* addrlen) {
    return_t ret = errorcode_t::success;

    __try2 {
        if ((nullptr == clisock) || (nullptr == addr) || (nullptr == addrlen)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        socket_t cli_socket = INVALID_SOCKET;

        cli_socket = ::accept(sock, addr, addrlen);
        if (INVALID_SOCKET == cli_socket) {
            ret = get_lasterror(cli_socket);
            __leave2;
        }

        *clisock = cli_socket;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tcp_server_socket::read(socket_t sock, tls_context_t* tls_handle, int mode, char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;

    __try2 {
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
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tcp_server_socket::send(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* cbsent) {
    return_t ret = errorcode_t::success;

    __try2 {
#if defined _WIN32 || defined _WIN64
        int ret_routine = ::send(sock, ptr_data, (int)size_data, 0);
#elif defined __linux__
        int ret_routine = ::send(sock, ptr_data, size_data, 0);
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
    __finally2 {
        // do nothing
    }

    return ret;
}

int tcp_server_socket::socket_type() { return SOCK_STREAM; }

}  // namespace net
}  // namespace hotplace
