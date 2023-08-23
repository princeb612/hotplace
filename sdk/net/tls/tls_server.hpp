/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLSSERVER__
#define __HOTPLACE_SDK_NET_TLS_TLSSERVER__

#include <hotplace/sdk/net/types.hpp>
#include <hotplace/sdk/net/basic/server_socket.hpp>
#include <hotplace/sdk/net/tls/x509.hpp>

namespace hotplace {
namespace net {

class transport_layer_security_server : public server_socket
{
public:
    transport_layer_security_server (transport_layer_security* tls);
    virtual ~transport_layer_security_server ();

    /*
     * @brief   close
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @return  error code (see error.hpp)
     * @remarks
     *          tls_svr_sock.accept(listen_socket, &client_socket, &tls_context, &sockaddr, &sockaddrlen);
     *          // client connection established...
     *          // ...
     *          // socket closed
     *          tls_svr_sock.close(client_socket, tls_context);
     */
    virtual return_t close (socket_t sock, tls_context_t* tls_handle);

    /*
     * @brief   Tls accept
     * @param   socket_t        clisock         [IN] client socket
     * @param   tls_context_t** tls_handle      [OUT] Tls context
     * @return  error code (see error.hpp)
     */
    virtual return_t tls_accept (socket_t clisock, tls_context_t** tls_handle);
    virtual return_t tls_stop_accept ();
    /*
     * @brief   read
     * @param   socket_t        sock        [IN]
     * @param   tls_context_t*  tls_handle  [IN]
     * @param   int             mode        [IN]
     *                                          2 recv
     *                                          1 bio_write
     *                                          0 ssl_read
     * @param   char*           ptr_data    [IN]
     * @param   size_t          size_data   [IN]
     * @param   size_t*         cbread      [OUT]
     * @return  error code (see error.hpp)
     */
    virtual return_t read (socket_t sock, tls_context_t* tls_handle, int mode, char* ptr_data, size_t size_data, size_t* cbread);
    /*
     * @brief   send
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @param   const char*     ptr_data        [IN]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbsent          [OUT]
     * @return  error code (see error.hpp)
     */
    virtual return_t send (socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* cbsent);
    /*
     * @brief   query socket layer spec
     * @param   int         specid          [IN] see SERVER_SOCKET_QUERY
     * @param   arch_t*     data_ptr        [OUT]
     * @return  error code (see error.hpp)
     * @remarks
     *          server_socket.query(SERVER_SOCKET_QUERY_SUPPORT_TLS, &value);
     */
    virtual return_t query (int specid, arch_t* data_ptr);

    int addref ();
    int release ();

protected:
    transport_layer_security* _tls;
    t_shared_reference <transport_layer_security_server> _shared;
};

}
}  // namespace

#endif
