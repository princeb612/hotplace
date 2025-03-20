/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/socket/udp_server_socket.hpp>

namespace hotplace {
namespace net {

udp_server_socket::udp_server_socket() : server_socket() {}

return_t udp_server_socket::open(socket_context_t** handle, unsigned int family, uint16 port) {
    return_t ret = errorcode_t::success;
    socket_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        socket_t sock = INVALID_SOCKET;
        ret = create_listener(1, &family, &sock, IPPROTO_UDP, port);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // UDP contains listen socket
        __try_new_catch(context, new socket_context_t(sock, 0), ret, __leave2);
        *handle = context;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t udp_server_socket::recvfrom(socket_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr,
                                     socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto sock = handle->fd;
#if 0
        int size_peek = recvfrom(sock, ptr_data, size_data, MSG_PEEK, nullptr, nullptr);
        if (size_data < size_peek) {
            ret = errorcode_t::insufficient_buffer;
            __leave2;
        }
#endif

#if defined __linux__
        int ret_recv = ::recvfrom(sock, ptr_data, size_data, 0, addr, addrlen);
#elif defined _WIN32 || defined _WIN64
        int ret_recv = ::recvfrom(sock, ptr_data, (int)size_data, 0, addr, addrlen);
#endif
        if (-1 == ret_recv) {
            ret = get_lasterror(ret_recv);
        } else if (0 == ret_recv) {
            ret = errorcode_t::closed;
        }

        if (nullptr != cbread) {
            *cbread = (errorcode_t::success == ret) ? ret_recv : 0;
        }
    }
    __finally2 {
        // do something
    }
    return ret;
}

return_t udp_server_socket::sendto(socket_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr,
                                   socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto sock = handle->fd;

#if defined __linux__
        int ret_send = ::sendto(sock, ptr_data, size_data, 0, addr, addrlen);
#elif defined _WIN32 || defined _WIN64
        int ret_send = ::sendto(sock, ptr_data, (int)size_data, 0, addr, addrlen);
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

int udp_server_socket::socket_type() { return SOCK_DGRAM; }

}  // namespace net
}  // namespace hotplace
