/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_TCPSERVERSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_TCPSERVERSOCKET__

#include <sdk/net/basic/server_socket.hpp>
#include <sdk/net/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   tcp_server_socket
 * @sa      class tls_server_socket : public tcp_server_socket
 */
class tcp_server_socket : public server_socket {
   public:
    tcp_server_socket();

    /**
     * @brief   listen
     * @param   socket_t*       sock            [OUT] listen socket
     * @param   unsigned int    family          [IN] AF_INET, AF_INET6
     * @param   uint16          port            [IN]
     * @return  error code (see error.hpp)
     */
    virtual return_t open(socket_t* sock, unsigned int family, uint16 port);
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
                          socklen_t* addrlen = nullptr);
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
    virtual int socket_type();

   protected:
};

}  // namespace net
}  // namespace hotplace

#endif
