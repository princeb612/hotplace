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
#include <sdk/net/http/http2/hpack.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_protocol.hpp>
#include <sdk/net/http/http_router.hpp>
#include <sdk/net/server/network_server.hpp>
#include <sdk/net/tls/tls.hpp>
#include <sdk/net/tls/tls_server.hpp>
#include <sdk/net/types.hpp>  // ws2tcpip.h first

namespace hotplace {
namespace net {

typedef TYPE_CALLBACK_HANDLEREXV http_server_handler_t;

/**
 * @brief   http server
 * @sa      http_server_builder
 */
class http_server {
    friend class http_server_builder;

   public:
    ~http_server();

    return_t start();
    return_t stop();

    network_server& get_network_server();
    http_protocol* get_http_protocol();
    http2_protocol* get_http2_protocol();
    hpack_encoder& get_hpack_encoder();
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

    // TCP
    tcp_server_socket _server_socket;

    // TLS
    x509cert* _cert;
    transport_layer_security* _tls;
    tls_server_socket* _tls_server_socket;

    // ACL
    ipaddr_acl _acl;

    // HTTP/1.1
    http_protocol _protocol;

    // HTTP/2
    http2_protocol _protocol2;
    hpack_encoder _hpack_encoder;

    // route
    http_router _router;
    typedef std::list<network_multiplexer_context_t*> http_handles_t;
    http_handles_t _http_handles;
};

}  // namespace net
}  // namespace hotplace

#endif
