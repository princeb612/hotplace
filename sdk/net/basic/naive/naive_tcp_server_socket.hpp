/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_NAIVE_NAIVETCPSERVERSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_NAIVE_NAIVETCPSERVERSOCKET__

#include <hotplace/sdk/net/basic/server_socket.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   TCP server socket
 * @sa      openssl_tls_server_socket, trial_tls_server_socket
 */
class naive_tcp_server_socket : public server_socket {
   public:
    naive_tcp_server_socket();
    virtual ~naive_tcp_server_socket();

    /**
     * @brief   listen
     * @param   socket_context_t** handle [out]
     * @param   unsigned int family [in]
     * @param   uint16 port [in]
     */
    virtual return_t open(socket_context_t** handle, unsigned int family, uint16 port);

    /**
     * @brief   accept
     * @param   socket_t* client_socket [out]
     * @param   socket_t listen_socket [in]
     * @param   struct sockaddr* addr [out]
     * @param   socklen_t* addrlen [inout]
     */
    virtual return_t accept(socket_t* client_socket, socket_t listen_socket, struct sockaddr* addr, socklen_t* addrlen);
    /**
     * @brief   read
     * @param   socket_context_t* handle [in]
     * @param   int mode [in]
     * @param   char* ptr_data [out]
     * @param   size_t size_data [in]
     * @param   size_t* cbread [out]
     */
    virtual return_t read(socket_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread);
    /**
     * @brief   send
     * @param   socket_context_t* handle [in]
     * @param   const char* ptr_data [out]
     * @param   size_t size_data [in]
     * @param   size_t* cbsent [out]
     */
    virtual return_t send(socket_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent);

    /**
     * @override
     * @return  return SOCK_STREAM
     */
    virtual int socket_type();

   protected:
};

}  // namespace net
}  // namespace hotplace

#endif
