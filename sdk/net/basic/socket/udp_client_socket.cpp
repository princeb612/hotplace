/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/socket/udp_client_socket.hpp>

namespace hotplace {
namespace net {

udp_client_socket::udp_client_socket() : client_socket(), _fd(INVALID_SOCKET) {}

return_t udp_client_socket::open(sockaddr_storage_t* sa, const char* address, uint16 port) {
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
    }
    __finally2 {}
    return ret;
}

return_t udp_client_socket::close() {
    return_t ret = errorcode_t::success;
    __try2 {
        if (INVALID_SOCKET != _fd) {
            ret = errorcode_t::already_assigned;
            __leave2;
        }
        close_socket(_fd, true, 0);
        _fd = INVALID_SOCKET;
    }
    __finally2 {}
    return ret;
}

return_t udp_client_socket::recvfrom(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (INVALID_SOCKET == _fd) {
            ret = errorcode_t::not_open;
            __leave2;
        }

        ret = wait_socket(_fd, get_wto(), SOCK_WAIT_READABLE);
        if (errorcode_t::success == ret) {
#if defined __linux__
            int ret_recv = ::recvfrom(_fd, ptr_data, size_data, 0, addr, addrlen);
#elif defined _WIN32 || defined _WIN64
            int ret_recv = ::recvfrom(_fd, ptr_data, (int)size_data, 0, addr, addrlen);
#endif
            if (-1 == ret_recv) {
                ret = get_lasterror(ret_recv);
            } else if (0 == ret_recv) {
                ret = errorcode_t::closed;
            }

            if (nullptr != cbread) {
                *cbread = ret_recv;
            }
        }
    }
    __finally2 {
        // do something
    }
    return ret;
}

return_t udp_client_socket::sendto(const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (INVALID_SOCKET == _fd) {
            ret = errorcode_t::not_open;
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

int udp_client_socket::socket_type() { return SOCK_DGRAM; }

socket_t udp_client_socket::get_socket() { return _fd; }

}  // namespace net
}  // namespace hotplace
