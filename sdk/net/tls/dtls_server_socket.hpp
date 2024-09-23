/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TLS_DTLSSERVERSOCKET__
#define __HOTPLACE_SDK_NET_TLS_DTLSSERVERSOCKET__

#include <sdk/net/basic/udp_server_socket.hpp>
#include <sdk/net/tls/tls.hpp>
#include <sdk/net/tls/x509cert.hpp>

namespace hotplace {
namespace net {

class dtls_server_socket : public udp_server_socket {
   public:
    dtls_server_socket(transport_layer_security* tls);
    virtual ~dtls_server_socket();
    /**
     * @brief   close
     */
    virtual return_t close(socket_t sock, tls_context_t* tls_handle);
    /**
     * @brief   dtls open
     * @param   tls_context_t** tls_handle      [OUT] tls context
     * @param   socket_t        clisock         [IN] client socket
     * @return  error code (see error.hpp)
     */
    virtual return_t dtls_open(tls_context_t** tls_handle, socket_t sock);
    /**
     * @brief   handshake
     * @param   tls_context_t* handle [in]
     * @param   sockaddr* addr [inopt]
     * @param   socklen_t addrlen [in]
     */
    virtual return_t dtls_handshake(tls_context_t* handle, sockaddr* addr, socklen_t addrlen);
    /**
     * @brief   read
     * @param   socket_t        sock        [IN]
     * @param   tls_context_t*  tls_handle  [IN]
     * @param   int             mode        [IN] see tls_io_flag_t
     * @param   char*           ptr_data    [IN]
     * @param   size_t          size_data   [IN]
     * @param   size_t*         cbread      [OUT]
     * @param   struct sockaddr* addr       [out]
     * @param   socklen_t* addrlen          [in]
     * @return  error code (see error.hpp)
     */
    virtual return_t recvfrom(socket_t sock, tls_context_t* tls_handle, int mode, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr,
                              socklen_t* addrlen);
    /**
     * @brief   send
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @param   const char*     ptr_data        [IN]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbsent          [OUT]
     * @param   const struct sockaddr* addr     [in]
     * @param   socklen_t       addrlen         [in]
     * @return  error code (see error.hpp)
     */
    virtual return_t sendto(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr,
                            socklen_t addrlen);

    virtual bool support_tls();

   protected:
    transport_layer_security* _tls;
};

}  // namespace net
}  // namespace hotplace

#endif
