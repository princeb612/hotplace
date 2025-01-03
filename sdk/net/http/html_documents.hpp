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

#ifndef __HOTPLACE_SDK_NET_HTTP_HTML_DOCUMENTS__
#define __HOTPLACE_SDK_NET_HTTP_HTML_DOCUMENTS__

#include <map>
#include <sdk/net/http/types.hpp>

namespace hotplace {
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

    /**
     * @brief   content-type
     * @sample
     *          std::string content_type;
     *          docs.get_content_type("/", content_type);           // text/html
     *          docs.get_content_type("/style.css", content_type);  // text/css
     *          docs.get_content_type("/index.json", content_type); // text/json
     */
    return_t get_content_type(const std::string& uri, std::string& content_type);

    /**
     * @brief   load
     * @param   const std::string& uri [in]
     * @param   std::string& content_type [out]
     * @param   binary_t& content [out]
     */
    return_t load(const std::string& uri, std::string& content_type, binary_t& content);
    /**
     * @brief   loadable
     * @param   const std::string& uri [in]
     * @param   std::string& content_type [out]
     */
    return_t loadable(const std::string& uri, std::string& content_type);
    /**
     * @brief   compose response
     * @param   const std::string& uri [in]
     * @param   http_response* response [out]
     */
    return_t compose(const std::string& uri, http_response* response);
    /**
     * @brief   redirect
     * @param   const std::string& uri [in]
     * @param   std::string& local [out]
     * @return  true/false
     * @remarks
     *          get_html_documents().add_documents_root("/", ".").set_default_document("index.html");
     *          get_html_documents().get_local("/", local); // linux-style (../index.html) or window-style (.\index.html)
     */
    bool get_local(const std::string& uri, std::string& local);

   protected:
    return_t search_cache(const std::string& uri, binary_t& content);
    return_t insert_cache(const std::string& uri, binary_t& content);
    return_t loadfile(const std::string& uri, binary_t& content);

   private:
    critical_section _lock;
    std::map<std::string, std::string> _urimap;         // map(uri, directory)
    std::map<std::string, time_t> _timestamp_map;       // store file timestamp
    std::map<std::string, binary_t> _cache_map;         // cache
    std::map<std::string, std::string> _content_types;  // map(ext, content_type)
    std::string _document;
    bool _use;
};

}  // namespace net
}  // namespace hotplace

#endif
