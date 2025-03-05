/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/socket/tcp_client_socket.hpp>

namespace hotplace {
namespace net {

tcp_client_socket::tcp_client_socket() : client_socket(), _fd(INVALID_SOCKET) {}

return_t tcp_client_socket::connect(const char* address, uint16 port, uint32 timeout) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (INVALID_SOCKET != _fd) {
            ret = errorcode_t::already_assigned;
            __leave2;
        }

        auto type = socket_type();
        sockaddr_storage_t sa;
        ret = create_socket(&_fd, &sa, type, address, port);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = connect_socket_addr(_fd, (sockaddr*)&sa, sizeof(sa), timeout);
    }
    __finally2 {}
    return ret;
}

return_t tcp_client_socket::close() {
    return_t ret = errorcode_t::success;
    __try2 {
        if (INVALID_SOCKET == _fd) {
            __leave2;
        }

        ret = close_socket(_fd, true, 0);
        _fd = INVALID_SOCKET;
    }
    __finally2 {}
    return ret;
}

return_t tcp_client_socket::read(char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (INVALID_SOCKET == _fd) {
            ret = errorcode_t::not_open;
            __leave2;
        }

        ret = wait_socket(_fd, get_wto(), SOCK_WAIT_READABLE);
        if (errorcode_t::success == ret) {
            int ret_recv = 0;
#if defined __linux__
            ret_recv = recv(_fd, ptr_data, size_data, 0);
#elif defined _WIN32 || defined _WIN64
            ret_recv = recv(_fd, ptr_data, (int)size_data, 0);
#endif
            if (-1 == ret_recv) {
                ret = get_lasterror(ret_recv);
            } else if (0 == ret_recv) {
                ret = errorcode_t::closed;
            }

            if (cbread) {
                *cbread = (errorcode_t::success == ret) ? ret_recv : 0;
            }
            if (size_data == ret_recv) {
                ret = errorcode_t::more_data;
            }
        }
    }
    __finally2 {}

    return ret;
}

return_t tcp_client_socket::more(char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;
    ret = read(ptr_data, size_data, cbread);
    return ret;
}

return_t tcp_client_socket::send(const char* ptr_data, size_t size_data, size_t* cbsent) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (INVALID_SOCKET == _fd) {
            ret = errorcode_t::not_open;
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

int tcp_client_socket::socket_type() { return SOCK_STREAM; }

}  // namespace net
}  // namespace hotplace
