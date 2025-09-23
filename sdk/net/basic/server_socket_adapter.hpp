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
#include <hotplace/sdk/net/basic/server_socket_builder.hpp>
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

    virtual uint32 get_adapter_scheme(uint32 scheme, return_t& retcode);

    /**
     * @example
     *          startup(socket_scheme_tls, "server.crt", "server.key", "TLS_CHACHA20_POLY1305_SHA256", 0);
     *          auto svrsock = get_server_socket(socket_scheme_tls);
     *          shutdown(socket_scheme_tls);
     */
    virtual return_t startup(uint32 scheme, const std::string& server_cert, const std::string& server_key, const std::string& cipher_suites, int verify_peer);
    virtual return_t shutdown(uint32 scheme);
    virtual server_socket* get_server_socket(uint32 scheme);

    virtual return_t enable_alpn(const char* prot);

    void addref();
    void release();

   protected:
    server_socket_adapter();

   private:
    critical_section _lock;
    std::map<uint32, server_socket*> _sockets;

    t_shared_reference<server_socket_adapter> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
