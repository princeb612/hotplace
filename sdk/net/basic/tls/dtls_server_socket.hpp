/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_TLS_DTLSSERVERSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_TLS_DTLSSERVERSOCKET__

#include <sdk/net/basic/socket/udp_server_socket.hpp>  // udp_server_socket
#include <sdk/net/basic/tls/tls.hpp>
#include <sdk/net/basic/tls/tlscert.hpp>

namespace hotplace {
namespace net {

class dtls_server_socket : public udp_server_socket {
   public:
    dtls_server_socket(transport_layer_security* tls);
    virtual ~dtls_server_socket();

    /**
     * @brief   DTLS session
     * @param   socket_context_t** handle [out]
     * @param   socket_t listen_sock [in]
     */
    virtual return_t dtls_open(socket_context_t** handle, socket_t listen_sock);
    /**
     * @brief   DTLS handshake
     * @param   socket_context_t* handle
     * @param   sockaddr* addr
     * @param   socklen_t addrlen [in]
     */
    virtual return_t dtls_handshake(socket_context_t* handle, sockaddr* addr, socklen_t addrlen);
    /**
     * @brief   recvfrom
     * @param   socket_context_t* handle [in]
     * @param   int mode [in]
     * @param   char* ptr_data [out]
     * @param   size_t size_data [in]
     * @param   size_t* cbread [out]
     * @param   struct sockaddr* addr [in]
     * @param   socklen_t* addrlen [inout]
     */
    virtual return_t recvfrom(socket_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen);
    /**
     * @brief   sendto
     * @param   socket_context_t* handle [in]
     * @param   const char* ptr_data [out]
     * @param   size_t size_data [in]
     * @param   size_t* cbsent [out]
     * @param   const struct sockaddr* addr [in]
     * @param   socklen_t addrlen [in]
     */
    virtual return_t sendto(socket_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr, socklen_t addrlen);

    /**
     * @override
     * @return  return true
     */
    virtual bool support_tls();

   protected:
   private:
    transport_layer_security* _tls;
};

}  // namespace net
}  // namespace hotplace

#endif
