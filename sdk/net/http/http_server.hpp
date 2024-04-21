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

#include <sdk/net/basic/ipaddr_acl.hpp>
#include <sdk/net/http/http_protocol.hpp>
#include <sdk/net/http/http_router.hpp>
#include <sdk/net/server/network_server.hpp>
#include <sdk/net/tls/tls.hpp>
#include <sdk/net/tls/tls_server.hpp>
#include <sdk/net/types.hpp>  // ws2tcpip.h first

namespace hotplace {
namespace net {

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
 *                 .enable_ipv4(true).enable_ipv6(true)
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

    http_server_builder& enable_http(bool enable);
    http_server_builder& set_port_http(uint16 port = 80);

    http_server_builder& enable_https(bool enable);
    http_server_builder& set_port_https(uint16 port = 443);
    http_server_builder& set_tls_certificate(std::string const& server_cert, std::string const& server_key);
    http_server_builder& set_tls_cipher_list(std::string const& cipher_list);
    http_server_builder& set_tls_verify_peer(uint16 value);

    http_server_builder& enable_ipv4(bool enable);
    http_server_builder& enable_ipv6(bool enable);

    http_server_builder& set_handler(http_server_handler_t handler);

    http_server* build();
    server_conf& get_server_conf();

   protected:
   private:
    std::string _server_cert;
    std::string _server_key;
    std::string _tls_cipher_list;

    server_conf _config;

    http_server_handler_t _handler;
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
    ipaddr_acl& get_ipaddr_acl();
    server_conf& get_server_conf();

   protected:
    http_server();

    static return_t accept_handler(socket_t socket, sockaddr_storage_t* client_addr, CALLBACK_CONTROL* control, void* parameter);

    return_t startup_tls(std::string const& server_cert, std::string const& server_key, std::string const& cipher_list, int verify_peer);
    return_t shutdown_tls();
    return_t startup_server(uint16 tls, uint16 family, uint16 port, http_server_handler_t handler);
    return_t shutdown_server();

    void shutdown();

   private:
    network_server _server;
    http_protocol _protocol;
    http_router _router;
    ipaddr_acl _acl;

    tcp_server_socket _server_socket;

    x509cert* _cert;
    transport_layer_security* _tls;
    tls_server_socket* _tls_server_socket;

    typedef std::list<network_multiplexer_context_t*> http_handles_t;
    http_handles_t _http_handles;
};

}  // namespace net
}  // namespace hotplace

#endif
