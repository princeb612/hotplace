/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/socket/client_socket.hpp>
#include <hotplace/sdk/net/socket/sdk.hpp>

namespace hotplace {
namespace net {

client_socket::client_socket ()
{
    // do nothing
}

client_socket::~client_socket ()
{
    // do nothing
}

return_t client_socket::connect (socket_t* sock, tls_context_t** tls_handle, const char* address, uint16 port, uint32 timeout)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        ret = connect_socket (sock, SOCK_STREAM, address, port, timeout);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t client_socket::close (socket_t sock, tls_context_t* tls_handle)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (INVALID_SOCKET == sock) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
#if defined __linux__ || defined __APPLE__
        ::close (sock);
#elif defined _WIN32 || defined _WIN64
        closesocket (sock);
#endif
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t client_socket::read (socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* size_read)
{
    return_t ret = errorcode_t::success;

    ret = wait_socket (sock, 1000, SOCK_WAIT_READABLE);
    if (errorcode_t::success == ret) {
#if defined _WIN32 || defined _WIN64
        int ret_recv = recv (sock, ptr_data, (int) size_data, 0);
#elif defined __linux__ || defined __APPLE__
        int ret_recv = recv (sock, ptr_data, size_data, 0);
#endif
        if (SOCKET_ERROR == ret_recv) {
            ret = GetLastError ();
        } else if (0 == ret_recv) {
            ret = errorcode_t::closed;
        }
        if (nullptr != size_read) {
            *size_read = ret_recv;
        }
    }
    return ret;
}

return_t client_socket::send (socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* size_sent)
{
    return_t ret = errorcode_t::success;

    __try2
    {
#if defined _WIN32 || defined _WIN64
        int ret_send = ::send (sock, ptr_data, (int) size_data, 0);
#elif defined __linux__ || defined __APPLE__
        int ret_send = ::send (sock, ptr_data, size_data, 0);
#endif
        if (SOCKET_ERROR == ret_send) {
            ret = GetLastError ();
        } else if (0 == ret_send) {
            // closed
        }
        if (nullptr != size_sent) {
            *size_sent = ret_send;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

}
}  // namespace
