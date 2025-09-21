/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_OPENSSL_OPENSSLSERVERSOCKETADAPTER__
#define __HOTPLACE_SDK_NET_BASIC_OPENSSL_OPENSSLSERVERSOCKETADAPTER__

#include <hotplace/sdk/net/basic/server_socket_adapter.hpp>
#include <hotplace/sdk/net/basic/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   TLS server socket adapter
 * @sa      http_server_builder
 */
class openssl_server_socket_adapter : public server_socket_adapter {
   public:
    openssl_server_socket_adapter();
    virtual ~openssl_server_socket_adapter();

    virtual return_t startup_tls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_suites, int verify_peer);
    virtual return_t startup_dtls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_suites, int verify_peer);
    virtual return_t shutdown_tls();
    virtual return_t shutdown_dtls();

    virtual server_socket* get_tcp_server_socket();
    virtual server_socket* get_tls_server_socket();
    virtual server_socket* get_dtls_server_socket();

    virtual return_t enable_alpn(const char* prot);

   protected:
   private:
    // TCP
    naive_tcp_server_socket _server_socket;
    openssl_tls_server_socket* _tls_server_socket;
    openssl_dtls_server_socket* _dtls_server_socket;
};

}  // namespace net
}  // namespace hotplace

#endif
