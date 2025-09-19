/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_TRIAL_TRIALDTLSSERVERSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_TRIAL_TRIALDTLSSERVERSOCKET__

#include <hotplace/sdk/net/basic/naive/naive_udp_server_socket.hpp>  // naive_udp_server_socket

namespace hotplace {
namespace net {

/**
 * @brief   DTLS server socket
 */
class trial_dtls_server_socket : public naive_udp_server_socket {
   public:
    trial_dtls_server_socket();
    virtual ~trial_dtls_server_socket();

    /**
     * @brief   DTLS session
     * @param   socket_context_t** handle [out]
     * @param   socket_t listen_sock [in]
     */
    virtual return_t dtls_open(socket_context_t** handle, socket_t listen_sock);
    /**
     * @brief   DTLS handshake
     * @param   netsession_t* sess [in]
     */
    virtual return_t dtls_handshake(netsession_t* sess);

    /**
     * @brief   recvfrom
     * @param   socket_context_t* handle [in]
     * @param   int mode [in]
     *                  mode read_socket_recv - obtain the peer address
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
};

}  // namespace net
}  // namespace hotplace

#endif
