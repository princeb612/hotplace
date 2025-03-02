/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TLS_DTLSCLIENTSOCKET__
#define __HOTPLACE_SDK_NET_TLS_DTLSCLIENTSOCKET__

#include <sdk/net/basic/socket/udp_client_socket.hpp>  // udp_client_socket
#include <sdk/net/basic/tls/tls.hpp>
#include <sdk/net/basic/tls/tlscert.hpp>

namespace hotplace {
namespace net {

class dtls_client_socket : public udp_client_socket {
   public:
    dtls_client_socket(transport_layer_security* tls);
    virtual ~dtls_client_socket();

    /**
     * @brief   connect
     * @oaram   socket_t sock [in]
     * @oaram   tls_context_t** tls_handle [out]
     * @oaram   const char* address [in]
     * @oaram   uint16 port [in]
     * @oaram   uint32 timeout [in[
     */
    virtual return_t connectto(socket_t sock, tls_context_t** tls_handle, const char* address, uint16 port, uint32 timeout);
    /**
     * @brief   connect
     * @param   socket_t sock [in]
     * @param   tls_context_t** tls_handle [out]
     * @param   const sockaddr* addr [in]
     * @param   socklen_t addrlen [in]
     * @param   uint32 timeout [in]
     */
    virtual return_t connectto(socket_t sock, tls_context_t** tls_handle, const sockaddr* addr, socklen_t addrlen, uint32 timeout);
    /**
     * @brief   close
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @return  error code (see error.hpp)
     */
    virtual return_t close(socket_t sock, tls_context_t* tls_handle);
    /**
     * @brief   read
     * @param   socket_t        sock            [IN]
     * @param   tls_context_t*  tls_handle      [IN]
     * @param   char*           ptr_data        [OUT]
     * @param   size_t          size_data       [IN]
     * @param   size_t*         cbread          [OUT]
     * @param   struct sockaddr* addr           [out]
     * @param   socklen_t*      addrlen         [in]
     * @return  error code (see error.hpp)
     */
    virtual return_t recvfrom(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr,
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
   private:
    transport_layer_security* _tls;
};

}  // namespace net
}  // namespace hotplace

#endif
