/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_CLIENTSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_CLIENTSOCKET__

#include <sdk/net/basic/basic_socket.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   client socket
 * @sa
 *          TCP - naive_tcp_client_socket
 *          UDP - naive_udp_client_socket
 *          TLS - openssl_tls_client_socket, trial_tls_client_socket
 *          DTLS - openssl_dtls_client_socket, trial_dtls_client_socket
 */
class client_socket : public basic_socket {
   public:
    virtual ~client_socket();

    /**
     * @brief   connect
     */
    virtual return_t connect(const char* address, uint16 port, uint32 timeout);
    /**
     * @brief   open
     */
    virtual return_t open(sockaddr_storage_t* sa, const char* address, uint16 port);
    /**
     * @brief   close
     */
    virtual return_t close();

    /**
     * @brief   read
     */
    virtual return_t read(char* ptr_data, size_t size_data, size_t* cbread);
    /**
     * @brief   more
     */
    virtual return_t more(char* ptr_data, size_t size_data, size_t* cbread);
    /**
     * @brief   send
     */
    virtual return_t send(const char* ptr_data, size_t size_data, size_t* cbsent);

    /**
     * @brief   recvfrom
     */
    virtual return_t recvfrom(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen);
    /**
     * @brief   sendto
     */
    virtual return_t sendto(const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr, socklen_t addrlen);

    virtual socket_t get_socket();
    void set_wto(uint32 milliseconds);
    uint32 get_wto();

   protected:
    client_socket();

   private:
    uint32 _wto;
};

}  // namespace net
}  // namespace hotplace

#endif
