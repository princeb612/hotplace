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
#include <sdk/io.hpp>
#include <sdk/net/http/http_request.hpp>
#include <sdk/net/http/http_response.hpp>
#include <sdk/net/server/network_session.hpp>

namespace hotplace {
using namespace io;
namespace net {

class html_documents {
   public:
    html_documents();
    html_documents(const std::string& root_uri, const std::string& directory);

    bool test();

    /*
     * @brief   documents
     * @sample
     *          documents.add_documents_root("/", "/opt/htmldocs/")
     *                   .add_content_type(".html", "text/html")
     *                   .set_default_document("index.html);
     */
    html_documents& add_documents_root(const std::string& root_uri, const std::string& directory);
    html_documents& add_content_type(const std::string& dot_ext, const std::string& content_type);
    html_documents& set_default_document(const std::string& document);

    return_t get_content_type(const std::string& uri, std::string& content_type);

    return_t load(const std::string& uri, std::string& content_type, binary_t& content);
    return_t handler(const std::string& uri, network_session* session, http_request* request, http_response* response);

   protected:
    bool map(const std::string& uri, std::string& local);
    return_t search_cache(const std::string& uri, binary_t& content);
    return_t insert_cache(const std::string& uri, binary_t& content);
    return_t loadfile(const std::string& uri, binary_t& content);

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
