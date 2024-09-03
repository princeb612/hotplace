/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_SERVERSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_SERVERSOCKET__

#include <sdk/io/system/socket.hpp>
#include <sdk/net/types.hpp>

namespace hotplace {
using namespace io;
namespace net {

class server_socket {
   public:
    server_socket() { _shared.make_share(this); }
    virtual ~server_socket() {}

    /**
     * @brief   listen
     * @param   socket_t*       sock            [OUT] listen socket
     * @param   unsigned int    family          [IN] AF_INET, AF_INET6
     * @param   uint16          port            [IN]
     * @return  error code (see error.hpp)
     */
    virtual return_t open(socket_t* sock, unsigned int family, uint16 port) { return errorcode_t::success; }
    /**
     * @brief   close
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @return  error code (see error.hpp)
     * @remarks
     *          tls_svr_sock.accept (listen_socket, &cli_socket, &tls_context, &sockaddr, &sockaddrlen);
     *          // client connection established...
     *          // ...
     *          // socket closed
     *          tls_svr_sock.close (cli_socket, tls_context);
     */
    virtual return_t close(socket_t sock, tls_context_t* tls_handle) {
        return_t ret = errorcode_t::success;
        __try2 {
            if (INVALID_SOCKET == sock) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
            close_socket(sock, true, 0);
        }
        __finally2 {
            // do nothing
        }
        return ret;
    }
    /**
     * @brief   accept
     * @param   socket_t        sock            [IN] listen socket
     * @param   socket_t*       clisock         [OUT] client socket
     * @param   struct sockaddr* addr           [OUT]
     * @param   socklen_t*      addrlen         [IN]
     * @return  error code (see error.hpp)
     */
    virtual return_t accept(socket_t sock, socket_t* clisock, struct sockaddr* addr, socklen_t* addrlen) { return errorcode_t::success; }
    /**
     * @brief   DTLSv1_listen
     */
    virtual return_t dtls_listen(socket_t sock, struct sockaddr* addr, socklen_t addrlen, tls_context_t** tls_handle) { return errorcode_t::success; }
    /**
     * @brief   tls accept
     * @param   socket_t        clisock         [IN] client socket
     * @param   tls_context_t** tls_handle      [OUT] Tls context
     * @return  error code (see error.hpp)
     * @remarks
     *          do nothing, return errorcode_t::success
     */
    virtual return_t tls_accept(socket_t clisock, tls_context_t** tls_handle) { return errorcode_t::not_supported; }
    /**
     * @brief   tls_stop_accept
     */
    virtual return_t tls_stop_accept() { return errorcode_t::success; }
    /**
     * @brief   read
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN] nullptr
     * @param   int             mode            [IN] ignore, it defines operation mode. see also transport_layer_security_server.
     * @param   char*           ptr_data        [OUT]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbread          [OUT]
     * @param   struct sockaddr* addr           [outopt]
     * @param   socklen_t* addrlen              [inopt]
     * @return  error code (see error.hpp)
     * @remarks
     *          ERROR_CONNECTION_CLOSED
     */
    virtual return_t read(socket_t sock, tls_context_t* tls_handle, int mode, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr = nullptr,
                          socklen_t* addrlen = nullptr) {
        return errorcode_t::success;
    }
    /**
     * @brief   send
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @param   const char*     ptr_data        [IN]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbsent          [OUT]
     * @return  error code (see error.hpp)
     */
    virtual return_t send(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* cbsent) { return errorcode_t::success; }

    virtual bool support_tls() { return false; }
    virtual int socket_type() { return 0; } /* override */
    int addref() { return _shared.addref(); }
    int release() { return _shared.delref(); }

   protected:
    t_shared_reference<server_socket> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
