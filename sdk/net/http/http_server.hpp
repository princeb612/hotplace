/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * spec list
 *      qop=auth
 *      algorithm=MD5|MD5-sess|SHA-256|SHA-256-sess
 *      userhash
 * todo list
 *      qop=auth-int
 *      nextnonce
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTPSERVER__
#define __HOTPLACE_SDK_NET_HTTP_HTTPSERVER__

#include <sdk/net/http/http_router.hpp>
#include <sdk/net/server/network_server.hpp>
#include <sdk/net/tls/tls_server.hpp>

namespace hotplace {
namespace net {

enum http_server_builder_flag_t {
    http_server_enable_http = (1 << 0),
    http_server_enable_https = (1 << 1),
    http_server_enable_ip4 = (1 << 2),
    http_server_enable_ip6 = (1 << 3),
};

typedef TYPE_CALLBACK_HANDLEREXV http_server_handler_t;

class http_server;
/**
 * @example
 *          // sketch
 *          http_server_builder builder;
 *          builder.enable_http(false)
 *                 .enable_https(true).set_port_https(9000)
 *                 .tls_certificate("server.crt", "server.key")
 *                 .tls_cipher_list("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256")
 *                 .tls_verify_peer(0)
 *                 .enable_ip4(true).enable_ip6(true)
 *                 .set_handler(network_handler)
 *                 .set_concurrent(2);
 *          http_server* server = builder.build();
 */
class http_server_builder {
   public:
    http_server_builder();
    ~http_server_builder();

    http_server_builder& enable_http(bool enable);
    http_server_builder& set_port_http(uint16 port = 80);

    http_server_builder& enable_https(bool enable);
    http_server_builder& set_port_https(uint16 port = 443);
    http_server_builder& set_tls_certificate(std::string const& server_cert, std::string const& server_key);
    http_server_builder& set_tls_cipher_list(std::string const& cipher_list);
    http_server_builder& set_tls_verify_peer(int value);

    http_server_builder& enable_ip4(bool enable);
    http_server_builder& enable_ip6(bool enable);

    http_server_builder& set_handler(http_server_handler_t handler);
    http_server_builder& set_concurrent(uint16 concurrent);

    http_server* build();

   protected:
    uint32 _flags;

    uint16 _port_http;

    uint16 _port_https;
    std::string _server_cert;
    std::string _server_key;
    std::string _tls_cipher_list;
    int _tls_verify_peer;

    http_server_handler_t _handler;
    uint16 _concurrent;
};

class http_server {
    friend class http_server_builder;

   public:
    ~http_server();

    return_t start();
    return_t stop();

    network_server& get_network_server();
    http_protocol* get_http_protocol();
    http_router& get_http_router();

   protected:
    http_server();

    return_t set_concurrent(uint16 concurrent);
    return_t startup_tls(std::string const& server_cert, std::string const& server_key, std::string const& cipher_list, int verify_peer);
    return_t shutdown_tls();
    return_t startup_server(uint32 flags, uint16 port, http_server_handler_t handler);
    return_t shutdown_server();

    void shutdown();

   private:
    network_server _server;
    http_protocol _protocol;
    http_router _router;
    uint16 _concurrent;

    server_socket _server_socket;

    x509cert* _cert;
    transport_layer_security* _tls;
    transport_layer_security_server* _tls_server_socket;

    typedef std::map<uint32, network_multiplexer_context_t*> http_handles_t;
    typedef std::pair<http_handles_t::iterator, bool> http_handles_pib_t;
    http_handles_t _http_handles;
};

}  // namespace net
}  // namespace hotplace

#endif
