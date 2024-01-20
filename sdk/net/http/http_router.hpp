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

class html_documents {
   public:
    html_documents();
    html_documents(std::string const& root_uri, std::string const& directory);

    bool test();

    /*
     * @brief   documents
     * @sample
     *          documents.add_documents_root("/", "/opt/htmldocs/")
     *                   .add_content_type(".html", "text/html")
     *                   .set_default_document("index.html);
     */
    html_documents& add_documents_root(std::string const& root_uri, std::string const& directory);
    html_documents& add_content_type(std::string const& dot_ext, std::string const& content_type);
    html_documents& set_default_document(std::string const& document);

    return_t load(std::string const& uri, std::string& content_type, binary_t& content);
    return_t handler(std::string const& uri, network_session* session, http_request* request, http_response* response);

   protected:
    bool map(std::string const& uri, std::string& local);
    return_t search_cache(std::string const& uri, binary_t& content);
    return_t insert_cache(std::string const& uri, binary_t& content);
    return_t loadfile(std::string const& uri, binary_t& content);
    return_t get_content_type(std::string const& uri, std::string& content_type);

   private:
    critical_section _lock;
    std::map<std::string, std::string> _root;           // map(uri, directory)
    std::map<std::string, time_t> _timestamp_map;       // store file timestamp
    std::map<std::string, binary_t> _cache_map;         // cache
    std::map<std::string, std::string> _content_types;  // map(ext, content_type)
    std::string _document;
    bool _use;
};

class http_router {
   public:
    http_router();
    ~http_router();

    /**
     * @brief   register a handler
     */
    http_router& add(const char* uri, http_request_handler_t handler);
    http_router& add(const char* uri, http_request_function_t handler);
    http_router& add(const char* uri, http_authenticate_provider* handler);
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
     * @param   const char* uri [in]
     * @param   network_session* session [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     */
    return_t route(const char* uri, network_session* session, http_request* request, http_response* response);
    /**
     * @brief   default handler (404 Not Found)
     */
    static void status404_handler(http_request* request, http_response* response);
    /**
     * @brief   resolver
     */
    http_authenticate_resolver& get_authenticate_resolver();

    html_documents& get_html_documents();

   protected:
    /**
     * @brief   http_authenticate_provider
     * @param   const char* uri [in]
     * @param   http_request* request [in]
     * @param   http_response* response [in]
     * @param   http_authenticate_provider** provider [out]
     * @return  result
     */
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
    html_documents _http_documents;
};

}  // namespace net
}  // namespace hotplace

#endif
