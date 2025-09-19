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

#include <hotplace/sdk/net/basic/basic_socket.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   server socket
 * @sa
 *          naive_tcp_server_socket
 *          naive_udp_server_socket
 */
class server_socket : public basic_socket {
   public:
    virtual ~server_socket();

    /**
     * @brief   listen
     * @param   socket_context_t** handle [out]
     * @param   unsigned int family [in]
     * @param   uint16 port [in]
     */
    virtual return_t open(socket_context_t** handle, unsigned int family, uint16 port);
    /**
     * @brief   close
     * @param   socket_context_t* handle [in]
     */
    virtual return_t close(socket_context_t* handle);

    /**
     * @brief   accept
     * @param   socket_t* client_socket [out]
     * @param   socket_t listen_socket [in]
     * @param   struct sockaddr* addr [out]
     * @param   socklen_t* addrlen [inout]
     */
    virtual return_t accept(socket_t* client_socket, socket_t listen_socket, struct sockaddr* addr, socklen_t* addrlen);
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
    virtual return_t dtls_handshake(netsession_t* sess);
    /**
     * @brief   tls accept
     * @param   socket_context_t** handle [out]
     * @param   socket_t listen_socket [in]
     */
    virtual return_t tls_accept(socket_context_t** handle, socket_t listen_socket);
    /**
     * @brief   tls_stop_accept
     */
    virtual return_t tls_stop_accept();
    /**
     * @brief   read
     * @param   socket_context_t* handle [in]
     * @param   int mode [in] see tls_io_flag_t
     * @param   char* ptr_data [out]
     * @param   size_t size_data [in]
     * @param   size_t* cbread [out]
     */
    virtual return_t read(socket_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread);
    /**
     * @brief   recvfrom
     * @param   socket_context_t* handle [in]
     * @param   int mode [in] see tls_io_flag_t
     * @param   char* ptr_data [out]
     * @param   size_t size_data [in]
     * @param   size_t* cbread [out]
     * @param   struct sockaddr* addr [in]
     * @param   socklen_t* addrlen [inout]
     */
    virtual return_t recvfrom(socket_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen);
    /**
     * @brief   send
     * @param   socket_context_t* handle [in]
     * @param   const char* ptr_data [out]
     * @param   size_t size_data [in]
     * @param   size_t* cbsent [out]
     */
    virtual return_t send(socket_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent);
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

   protected:
    server_socket();
};

}  // namespace net
}  // namespace hotplace

#endif
