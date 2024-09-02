/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/system/socket.hpp>
#include <sdk/net/basic/udp_client_socket.hpp>

namespace hotplace {
using namespace io;
namespace net {

udp_client_socket::udp_client_socket() : client_socket() {}

return_t udp_client_socket::open(socket_t* sock, tls_context_t* tls_handle, const char* address, uint16 port) {
    return_t ret = errorcode_t::success;
    __try2 { ret = create_socket(sock, &_sock_storage, SOCK_DGRAM, address, port); }
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
#if 0
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

int udp_client_socket::socket_type() { return SOCK_DGRAM; }

}  // namespace net
}  // namespace hotplace
