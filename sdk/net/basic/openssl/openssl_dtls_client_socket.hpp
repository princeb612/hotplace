/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_OPENSSL_OPENSSLDTLSCLIENTSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_OPENSSL_OPENSSLDTLSCLIENTSOCKET__

#include <hotplace/sdk/net/basic/naive/naive_udp_client_socket.hpp>  // naive_udp_client_socket
#include <hotplace/sdk/net/basic/openssl/openssl_tls.hpp>
#include <hotplace/sdk/net/basic/openssl/openssl_tls_context.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   DTLS client socket
 */
class openssl_dtls_client_socket : public client_socket {
   public:
    openssl_dtls_client_socket(openssl_tls* tls);
    virtual ~openssl_dtls_client_socket();

    virtual return_t open(sockaddr_storage_t* sa, const char* address, uint16 port);
    virtual return_t close();

    virtual return_t recvfrom(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen);
    virtual return_t sendto(const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr, socklen_t addrlen);

    virtual bool support_tls();
    virtual int socket_type();
    virtual socket_t get_socket();

    virtual uint32 get_scheme();

   protected:
    openssl_tls* _tls;
    socket_context_t* _handle;
};

}  // namespace net
}  // namespace hotplace

#endif
