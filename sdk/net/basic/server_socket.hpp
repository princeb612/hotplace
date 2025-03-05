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

#include <sdk/net/basic/basic_socket.hpp>

namespace hotplace {
namespace net {

class server_socket : public basic_socket {
   public:
    virtual ~server_socket();

    /**
     * @brief   listen
     * @param   socket_t*       sock            [OUT] listen socket
     * @param   unsigned int    family          [IN] AF_INET, AF_INET6
     * @param   uint16          port            [IN]
     * @return  error code (see error.hpp)
     */
    virtual return_t open(socket_t* sock, unsigned int family, uint16 port);

    virtual return_t close(socket_t sock, tls_context_t* handle);

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
     * @brief   DTLS
     */
    virtual return_t dtls_open(tls_context_t** handle, socket_t sock);
    /**
     * @brief   handshake
     * @param   tls_context_t* handle [in]
     * @param   sockaddr* addr [inopt]
     * @param   socklen_t addrlen [in]
     */
    virtual return_t dtls_handshake(tls_context_t* handle, sockaddr* addr, socklen_t addrlen);
    /**
     * @brief   tls accept
     * @param   socket_t        clisock         [IN] client socket
     * @param   tls_context_t** handle      [OUT] Tls context
     * @return  error code (see error.hpp)
     * @remarks
     *          do nothing, return errorcode_t::success
     */
    virtual return_t tls_accept(socket_t clisock, tls_context_t** handle);
    /**
     * @brief   tls_stop_accept
     */
    virtual return_t tls_stop_accept();
    /**
     * @brief   read
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  handle      [IN] nullptr
     * @param   int             mode            [IN] ignore, it defines operation mode. see also transport_layer_security_server.
     * @param   char*           ptr_data        [OUT]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbread          [OUT]
     * @return  error code (see error.hpp)
     * @remarks
     *          ERROR_CONNECTION_CLOSED
     */
    virtual return_t read(socket_t sock, tls_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread);
    /**
     * @brief   recvfrom
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  handle      [IN] nullptr
     * @param   int             mode            [IN] ignore, it defines operation mode. see also transport_layer_security_server.
     * @param   char*           ptr_data        [OUT]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbread          [OUT]
     * @param   struct sockaddr* addr           [out]
     * @param   socklen_t*      addrlen         [in]
     * @return  error code (see error.hpp)
     * @remarks
     */
    virtual return_t recvfrom(socket_t sock, tls_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr,
                              socklen_t* addrlen);
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
    /**
     * @brief   send
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  handle      [IN]
     * @param   const char*     ptr_data        [IN]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbsent          [OUT]
     * @param   const struct sockaddr* addr     [in]
     * @param   socklen_t       addrlen         [in]
     * @return  error code (see error.hpp)
     */
    virtual return_t sendto(socket_t sock, tls_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr,
                            socklen_t addrlen);

   protected:
    server_socket();
};

////////////////////////////////////////////////////////////////////////////////

}  // namespace net
}  // namespace hotplace

#endif
