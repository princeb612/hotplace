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

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTPROUTER__
#define __HOTPLACE_SDK_NET_HTTP_HTTPROUTER__

#include <map>
#include <sdk/net/http/auth/oauth2.hpp>             // oauth2_provider
#include <sdk/net/http/html_documents.hpp>          // html_documents
#include <sdk/net/http/http2/http2_serverpush.hpp>  // http2_serverpush
#include <sdk/net/http/http_authentication_provider.hpp>
#include <sdk/net/http/http_authentication_resolver.hpp>  // http_authentication_resolver
#include <sdk/net/http/types.hpp>

namespace hotplace {
namespace net {

typedef void (*http_request_handler_t)(network_session*, http_request*, http_response*, http_router*);
typedef std::function<void(network_session*, http_request*, http_response*, http_router*)> http_request_function_t;

class http_router {
    friend class http_server;  // set_owner
   public:
    http_router();
    ~http_router();

    /**
     * @brief   register a handler
     */
    http_router& add(const char* uri, http_request_handler_t handler, http_authentication_provider* auth_provider = nullptr, bool upref = false);
    http_router& add(const char* uri, http_request_function_t handler, http_authentication_provider* auth_provider = nullptr, bool upref = false);
    http_router& add(const std::string& uri, http_request_handler_t handler, http_authentication_provider* auth_provider = nullptr, bool upref = false);
    http_router& add(const std::string& uri, http_request_function_t handler, http_authentication_provider* auth_provider = nullptr, bool upref = false);
    /**
     * @brief   register a handler
     * @sample
     *          router.add(404, [&](http_request* request, http_response* response) -> void {
     *                  response->compose(404, "text/html", "<html><body>404 Not Found</body></html>";
     *              });
     */
    http_router& add(int status_code, http_request_handler_t handler);
    http_router& add(int status_code, http_request_function_t handler);

    /**
     * @brief   route
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     */
    return_t route(network_session* session, http_request* request, http_response* response);
    /**
     * @brief   default handler (404 Not Found)
     */
    static void status404_handler(network_session* session, http_request* request, http_response* response, http_router* router);
    /**
     * @brief   resolver
     */
    http_authentication_resolver& get_authenticate_resolver();

    html_documents& get_html_documents();

    oauth2_provider& get_oauth2_provider();

    http2_serverpush& get_http2_serverpush();

    http_server* get_http_server();

   protected:
    /**
     * @brief   http_authentication_provider
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @param   http_authentication_provider** provider [out]
     * @return  result
     */
    bool get_auth_provider(http_request* request, http_response* response, http_authentication_provider** provider);

    void set_owner(http_server* server);

   private:
    void clear();

    typedef struct _http_router_t {
        http_request_handler_t handler;
        http_request_function_t stdfunc;

        _http_router_t() : handler(nullptr), stdfunc(nullptr) {}
    } http_router_t;
    typedef std::map<std::string, http_router_t> handler_map_t;
    typedef std::map<int, http_router_t> status_handler_map_t;
    typedef std::map<std::string, http_authentication_provider*> authenticate_map_t;
    typedef std::pair<authenticate_map_t::iterator, bool> authenticate_map_pib_t;

    critical_section _lock;
    handler_map_t _handler_map;
    status_handler_map_t _status_handler_map;
    authenticate_map_t _authenticate_map;
    http_authentication_resolver _resolver;
    oauth2_provider _oauth2;
    html_documents _http_documents;
    http2_serverpush _http2_serverpush;
    http_server* _http_server;
};

}  // namespace net
}  // namespace hotplace

#endif
