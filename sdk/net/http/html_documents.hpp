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

#ifndef __HOTPLACE_SDK_NET_HTTP_HTML_DOCUMENTS__
#define __HOTPLACE_SDK_NET_HTTP_HTML_DOCUMENTS__

#include <map>
#include <sdk/base.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/io/basic/keyvalue.hpp>
#include <sdk/net/http/http.hpp>
#include <sdk/net/http/http_authentication_provider.hpp>
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

}  // namespace net
}  // namespace hotplace

#endif
