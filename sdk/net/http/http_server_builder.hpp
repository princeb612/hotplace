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

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTPSERVERBUILDER__
#define __HOTPLACE_SDK_NET_HTTP_HTTPSERVERBUILDER__

#include <sdk/net/http/http_server.hpp>

namespace hotplace {
namespace net {

/**
 * @example
 *          // sketch
 *          http_server_builder builder;
 *          builder.builder.set(new openssl_server_socket_adapter)
 *                 .enable_http(false)
 *                 .enable_https(true).set_port_https(9000)
 *                 .tls_certificate("server.crt", "server.key")
 *                 .tls_cipher_list("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256")
 *                 .tls_verify_peer(0)
 *                 .enable_ipv4(true).enable_ipv6(true)
 *                 .enable_h2(false)
 *                 .set_handler(network_handler);
 *          builder.get_server_conf()
 *                 .set(netserver_config_t::serverconf_concurrent_tls_accept, 2)
 *                 .set(netserver_config_t::serverconf_concurrent_network, 2)
 *                 .set(netserver_config_t::serverconf_concurrent_consume, 4);
 *          http_server* server = builder.build();
 */
class http_server_builder {
   public:
    http_server_builder();
    ~http_server_builder();

    /**
     * @remarks do not call adapter->release()
     * @sa      clear member method
     */
    http_server_builder& set(server_socket_adapter* adapter);

    http_server_builder& enable_http(bool enable);
    http_server_builder& set_port_http(uint16 port = 80);

    http_server_builder& enable_https(bool enable);
    http_server_builder& set_port_https(uint16 port = 443);
    http_server_builder& set_tls_certificate(const std::string& server_cert, const std::string& server_key);
    http_server_builder& set_tls_cipher_list(const std::string& cipher_list);
    http_server_builder& set_tls_verify_peer(uint16 value);

    http_server_builder& enable_ipv4(bool enable);
    http_server_builder& enable_ipv6(bool enable);

    http_server_builder& enable_h2(bool enable);
    http_server_builder& enable_h3(bool enable);

    /**
     * @brief   content-encoding
     * @remarks turn off deflate, gzip to avoid BREACH attack
     * @sample
     *          builder.allow_content_encoding("deflate, gzip");
     */
    http_server_builder& allow_content_encoding(const std::string& encoding);

    http_server_builder& set_handler(http_server_handler_t handler, void* user_context = nullptr);

    http_server* build();
    server_conf& get_server_conf();
    server_socket_adapter* get_adapter();

   protected:
    void clear();

   private:
    std::string _server_cert;
    std::string _server_key;
    std::string _tls_cipher_list;
    std::string _content_encoding;

    server_conf _config;

    http_server_handler_t _handler;
    void* _user_context;
    server_socket_adapter* _adapter;
};

}  // namespace net
}  // namespace hotplace

#endif
