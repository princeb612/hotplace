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

#include <sdk/base/unittest/traceable.hpp>        // traceable
#include <sdk/net/basic/ipaddr_acl.hpp>           // ipaddr_acl
#include <sdk/net/basic/tcp_server_socket.hpp>    // tcp_server_socket
#include <sdk/net/http/http2/http2_protocol.hpp>  // http2_protocol
#include <sdk/net/http/http_protocol.hpp>         // http_protocol
#include <sdk/net/http/http_router.hpp>           // http_router
#include <sdk/net/http/types.hpp>
#include <sdk/net/server/network_server.hpp>  // network_server
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
namespace net {

typedef TYPE_CALLBACK_HANDLEREXV http_server_handler_t;

/**
 * @brief   http server
 * @sa      http_server_builder
 */
class http_server : public traceable {
    friend class http_server_builder;

   public:
    ~http_server();

    return_t start();
    return_t stop();

    network_server& get_network_server();
    server_conf& get_server_conf();

    http_protocol& get_http_protocol();
    http2_protocol& get_http2_protocol();
    http_router& get_http_router();
    ipaddr_acl& get_ipaddr_acl();
    virtual void settrace(std::function<void(trace_category_t, uint32, stream_t*)> f);

   protected:
    http_server();

    static return_t accept_handler(socket_t socket, sockaddr_storage_t* client_addr, CALLBACK_CONTROL* control, void* parameter);

    return_t startup_tls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_list, int verify_peer);
    return_t shutdown_tls();
    return_t startup_dtls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_list, int verify_peer);
    return_t shutdown_dtls();
    return_t startup_server(uint16 tls, uint16 family, uint16 port, http_server_handler_t handler, void* user_context = nullptr);
    return_t shutdown_server();

    void shutdown();

    /**
     * @brief   server handler
     * @param   uint32 type [in] multiplexer_event_type_t
     * @param   uint32 data_count [in] 5
     * @param   void* data_array[] [in]
     *              data_array[0] network_session_socket_t*
     *              data_array[1] transfered buffer
     *              data_array[2] transfered size
     *              data_array[3] network_session*
     *              data_array[4] http_server*
     * @param   CALLBACK_CONTROL* callback_control [in] nullptr
     * @param   void* server_context [in] http_server*
     */
    static return_t consume_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* server_context);
    /**
     * @brief   consume
     * @param   uint32 type [in]
     * @param   uint32 data_count [in]
     * @param   void* data_array[] [in]
     * @param   CALLBACK_CONTROL* callback_control [in]
     * @param   void* user_context [in]
     */
    return_t consume(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context);

   private:
    network_server _server;
    server_conf _conf;

    // TCP
    tcp_server_socket _server_socket;

    // TLS
    tlscert* _tlscert;
    transport_layer_security* _tls;
    tls_server_socket* _tls_server_socket;

    // DTLS
    tlscert* _dtlscert;
    transport_layer_security* _dtls;
    dtls_server_socket* _dtls_server_socket;

    // ACL
    ipaddr_acl _acl;

    // HTTP/1.1
    http_protocol _protocol;

    // HTTP/2
    http2_protocol _protocol2;

    // consume handler
    http_server_handler_t _consumer;
    void* _user_context;

    // route
    http_router _router;
    typedef std::list<network_multiplexer_context_t*> http_handles_t;
    http_handles_t _http_handles;
};

}  // namespace net
}  // namespace hotplace

#endif
