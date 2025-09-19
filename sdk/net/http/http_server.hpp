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

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTPSERVER__
#define __HOTPLACE_SDK_NET_HTTP_HTTPSERVER__

#include <hotplace/sdk/net/basic/server_socket_adapter.hpp>
#include <hotplace/sdk/net/basic/util/ipaddr_acl.hpp>      // ipaddr_acl
#include <hotplace/sdk/net/http/http2/http2_protocol.hpp>  // http2_protocol
#include <hotplace/sdk/net/http/http_protocol.hpp>         // http_protocol
#include <hotplace/sdk/net/http/http_router.hpp>           // http_router
#include <hotplace/sdk/net/http/types.hpp>                 //
#include <hotplace/sdk/net/server/network_server.hpp>      // network_server

namespace hotplace {
namespace net {

enum http_service_t {
    service_http = 0,
    service_https = 1,
    service_http3 = 2,
};

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
    server_conf& get_server_conf();
    skey_value& get_http_conf();

    http_protocol& get_http_protocol();
    http2_protocol& get_http2_protocol();
    http_router& get_http_router();
    ipaddr_acl& get_ipaddr_acl();

   protected:
    http_server(server_socket_adapter* adapter);

    static return_t accept_handler(socket_t socket, sockaddr_storage_t* client_addr, CALLBACK_CONTROL* control, void* parameter);

    return_t startup_tls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_list, int verify_peer);
    return_t shutdown_tls();
    return_t startup_dtls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_list, int verify_peer);
    return_t shutdown_dtls();
    /**
     * @brief   startup
     * @param   http_service_t service [in]
     * @param   uint16 family [in]
     * @param   uint16 port [in]
     * @param   http_server_handler_t handler [in]
     * @param   void* user_context [inopt]
     */
    return_t startup_server(http_service_t service, uint16 family, uint16 port, http_server_handler_t handler, void* user_context = nullptr);
    /**
     * @brief   shutdown
     */
    return_t shutdown_server();

    void shutdown();

    /**
     * @brief   server handler
     * @param   uint32 type [in] multiplexer_event_type_t
     * @param   uint32 data_count [in] 5
     * @param   void* data_array[] [in]
     *              data_array[0] netsocket_t*
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

    server_socket_adapter* get_server_socket_adapter();

   private:
    network_server _server;
    server_conf _conf;
    skey_value _httpconf;  // t_stringkey_value<std::string>

    server_socket_adapter* _server_socket_adapter;

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
