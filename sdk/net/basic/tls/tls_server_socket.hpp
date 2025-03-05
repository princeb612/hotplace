/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_TLS_TLSSERVERSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_TLS_TLSSERVERSOCKET__

#include <sdk/net/basic/socket/tcp_server_socket.hpp>  // tcp_server_socket
#include <sdk/net/basic/tls/tls.hpp>
#include <sdk/net/basic/tls/tlscert.hpp>

namespace hotplace {
namespace net {

class tls_server_socket : public tcp_server_socket {
   public:
    tls_server_socket(transport_layer_security* tls);
    virtual ~tls_server_socket();

    /**
     * @brief   close
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  handle      [IN]
     * @return  error code (see error.hpp)
     * @remarks
     *          tls_svr_sock.accept(listen_socket, &cli_socket, &tls_context, &sockaddr, &sockaddrlen);
     *          // client connection established...
     *          // ...
     *          // socket closed
     *          tls_svr_sock.close(cli_socket, tls_context);
     */
    virtual return_t close(socket_t sock, tls_context_t* handle);

    /**
     * @brief   Tls accept
     * @param   socket_t        clisock         [IN] client socket
     * @param   tls_context_t** handle      [OUT] Tls context
     * @return  error code (see error.hpp)
     */
    virtual return_t tls_accept(socket_t clisock, tls_context_t** handle);
    /**
     * @brief   tls_stop_accept
     */
    virtual return_t tls_stop_accept();
    /**
     * @brief   read
     * @param   socket_t        sock        [IN]
     * @param   tls_context_t*  handle  [IN]
     * @param   int             mode        [IN] see tls_io_flag_t
     * @param   char*           ptr_data    [IN]
     * @param   size_t          size_data   [IN]
     * @param   size_t*         cbread      [OUT]
     * @return  error code (see error.hpp)
     */
    virtual return_t read(socket_t sock, tls_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread);
    /**
     * @brief   send
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  handle      [IN]
     * @param   const char*     ptr_data        [IN]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbsent          [OUT]
     * @return  error code (see error.hpp)
     */
    virtual return_t send(socket_t sock, tls_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent);

    virtual bool support_tls();

   protected:
   private:
    transport_layer_security* _tls;
};

}  // namespace net
}  // namespace hotplace

#endif
