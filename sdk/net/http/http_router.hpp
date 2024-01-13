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

#ifndef __HOTPLACE_SDK_NET_HTTP_ROUTER__
#define __HOTPLACE_SDK_NET_HTTP_ROUTER__

#include <map>
#include <sdk/base.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/io/basic/keyvalue.hpp>
#include <sdk/net/http/http.hpp>
#include <sdk/net/http/http_authenticate.hpp>
#include <sdk/net/server/network_protocol.hpp>

namespace hotplace {
using namespace io;
namespace net {

typedef void (*http_request_handler_t)(http_request*, http_response*);
typedef std::function<void(http_request*, http_response*)> http_request_function_t;

class http_router {
   public:
    http_router();
    ~http_router();

    http_router& add(const char* uri, http_request_handler_t handler);
    http_router& add(const char* uri, http_request_function_t handler);
    http_router& add(const char* uri, http_authenticate_provider* handler);
    http_router& add(int status_code, http_request_handler_t handler);
    http_router& add(int status_code, http_request_function_t handler);

    return_t route(const char* uri, network_session* session, http_request* request, http_response* response);

    static void status404_handler(http_request* request, http_response* response);

    http_authenticate_resolver& get_authenticate_resolver();

   protected:
    bool get_auth_provider(const char* uri, http_request* request, http_response* response, http_authenticate_provider** provider);

   private:
    void clear();

    typedef struct _http_router_t {
        http_request_handler_t handler;
        http_request_function_t stdfunc;

        _http_router_t() : handler(nullptr), stdfunc(nullptr) {}
    } http_router_t;
    typedef std::map<std::string, http_router_t> handler_map_t;
    typedef std::map<int, http_router_t> status_handler_map_t;
    typedef std::map<std::string, http_authenticate_provider*> authenticate_map_t;
    typedef std::pair<authenticate_map_t::iterator, bool> authenticate_map_pib_t;

    critical_section _lock;
    handler_map_t _handler_map;
    status_handler_map_t _status_handler_map;
    authenticate_map_t _authenticate_map;
    http_authenticate_resolver _resolver;
};

}  // namespace net
}  // namespace hotplace

#endif
