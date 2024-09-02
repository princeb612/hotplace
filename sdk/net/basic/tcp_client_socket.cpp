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
#include <sdk/net/basic/tcp_client_socket.hpp>

namespace hotplace {
using namespace io;
namespace net {

tcp_client_socket::tcp_client_socket() : client_socket() {
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

int tcp_client_socket::socket_type() { return SOCK_STREAM; }

}  // namespace net
}  // namespace hotplace
