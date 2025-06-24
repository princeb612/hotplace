/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_NAIVE_NAIVEUDPSERVERSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_NAIVE_NAIVEUDPSERVERSOCKET__

#include <sdk/net/basic/server_socket.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   UDP server socket
 * @sa      openssl_dtls_server_socket
 */
class naive_udp_server_socket : public server_socket {
   public:
    naive_udp_server_socket();

    /**
     * @brief   listen
     * @param   socket_context_t** handle [out]
     * @param   unsigned int family [in]
     * @param   uint16 port [in]
     */
    virtual return_t open(socket_context_t** handle, unsigned int family, uint16 port);
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
     * @return  return SOCK_DGRAM
     */
    virtual int socket_type();
};

}  // namespace net
}  // namespace hotplace

#endif
