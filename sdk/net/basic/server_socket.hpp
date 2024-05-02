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

#include <sdk/net/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   tcp_server_socket
 * @sa      class transport_layer_security_server : public tcp_server_socket
 */
class tcp_server_socket {
   public:
    tcp_server_socket();
    virtual ~tcp_server_socket();

    /**
     * @brief   listen
     * @param   socket_t*       sock            [OUT] listen socket
     * @param   unsigned int    family          [IN] AF_INET, AF_INET6
     * @param   uint16          port            [IN]
     * @return  error code (see error.hpp)
     */
    virtual return_t listen(socket_t* sock, unsigned int family, uint16 port);
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
    virtual return_t close(socket_t sock, tls_context_t* tls_handle);

    /**
     * @brief   accept
     * @param   socket_t        sock            [IN] listen socket
     * @param   socket_t*       clisock         [OUT] client socket
     * @param   struct sockaddr* addr           [OUT]
     * @param   socklen_t*      addrlen         [IN]
     * @return  error code (see error.hpp)
     */
    virtual return_t accept(socket_t sock, socket_t* clisock, struct sockaddr* addr, socklen_t* addrlen);
    /**
     * @brief   Tls accept
     * @param   socket_t        clisock         [IN] client socket
     * @param   tls_context_t** tls_handle      [OUT] Tls context
     * @return  error code (see error.hpp)
     * @remarks
     *          do nothing, return errorcode_t::success
     */
    virtual return_t tls_accept(socket_t clisock, tls_context_t** tls_handle);
    virtual return_t tls_stop_accept();
    /**
     * @brief   read
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN] nullptr
     * @param   int             mode            [IN] ignore, it defines operation mode. see also transport_layer_security_server.
     * @param   char*           ptr_data        [OUT]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbread          [OUT]
     * @return  error code (see error.hpp)
     * @remarks
     *          ERROR_CONNECTION_CLOSED
     */
    virtual return_t read(socket_t sock, tls_context_t* tls_handle, int mode, char* ptr_data, size_t size_data, size_t* cbread);
    /**
     * @brief   send
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @param   const char*     ptr_data        [IN]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbsent          [OUT]
     * @return  error code (see error.hpp)
     */
    virtual return_t send(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* cbsent);

    virtual bool support_tls();

   protected:
};

}  // namespace net
}  // namespace hotplace

#endif
