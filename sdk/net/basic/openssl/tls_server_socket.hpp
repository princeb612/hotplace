/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_OPENSSL_TLSSERVERSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_OPENSSL_TLSSERVERSOCKET__

#include <sdk/net/basic/naive/tcp_server_socket.hpp>  // tcp_server_socket
#include <sdk/net/basic/openssl/openssl_tls.hpp>
#include <sdk/net/basic/openssl/openssl_tls_context.hpp>

namespace hotplace {
namespace net {

class tls_server_socket : public tcp_server_socket {
   public:
    tls_server_socket(openssl_tls* tls);
    virtual ~tls_server_socket();

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
     * @return  return true
     */
    virtual bool support_tls();

   protected:
   private:
    openssl_tls* _tls;
};

}  // namespace net
}  // namespace hotplace

#endif
