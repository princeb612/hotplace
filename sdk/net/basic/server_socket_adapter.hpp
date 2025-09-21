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

#ifndef __HOTPLACE_SDK_NET_BASIC_SERVERSOCKETADAPTER__
#define __HOTPLACE_SDK_NET_BASIC_SERVERSOCKETADAPTER__

#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/net/basic/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   server socket adapter
 * @sa      http_server_builder
 * @example
 *          if (use_openssl_libssl) {
 *              builder.builder.set(new openssl_server_socket_adapter);
 *          } else {
 *              builder.builder.set(new trial_server_socket_adapter);
 *          }
 */
class server_socket_adapter {
   public:
    virtual ~server_socket_adapter();

    virtual return_t startup_tls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_list, int verify_peer);
    virtual return_t startup_dtls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_list, int verify_peer);
    virtual return_t startup_quic(const std::string& server_cert, const std::string& server_key, const std::string& cipher_list, int verify_peer);
    virtual return_t shutdown_tls();
    virtual return_t shutdown_dtls();
    virtual return_t shutdown_quic();

    virtual server_socket* get_tcp_server_socket();
    virtual server_socket* get_tls_server_socket();
    virtual server_socket* get_dtls_server_socket();

    virtual return_t enable_alpn(const char* prot);

    void addref();
    void release();

   protected:
    server_socket_adapter();

   private:
    t_shared_reference<server_socket_adapter> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
