/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_TLS_TLSCLIENTSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_TLS_TLSCLIENTSOCKET__

#include <sdk/net/basic/socket/tcp_client_socket.hpp>  // tcp_client_socket
#include <sdk/net/basic/tls/openssl_tls.hpp>
#include <sdk/net/basic/tls/openssl_tls_context.hpp>

namespace hotplace {
namespace net {

class tls_client_socket : public client_socket {
   public:
    tls_client_socket(openssl_tls* tls);
    virtual ~tls_client_socket();

    virtual return_t connect(const char* address, uint16 port, uint32 timeout);
    virtual return_t close();

    virtual return_t read(char* ptr_data, size_t size_data, size_t* cbread);
    virtual return_t more(char* ptr_data, size_t size_data, size_t* cbread);
    virtual return_t send(const char* ptr_data, size_t size_data, size_t* cbsent);

    virtual bool support_tls();
    virtual int socket_type();
    virtual socket_t get_socket();

   protected:
   private:
    openssl_tls* _tls;
    socket_context_t* _handle;
};

}  // namespace net
}  // namespace hotplace

#endif
