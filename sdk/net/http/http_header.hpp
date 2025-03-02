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

#ifndef __HOTPLACE_SDK_NET_HTTP_HEADER__
#define __HOTPLACE_SDK_NET_HTTP_HEADER__

#include <list>
#include <map>
#include <sdk/base/basic/keyvalue.hpp>
#include <sdk/net/http/types.hpp>

namespace hotplace {
namespace net {

class http_header {
   public:
    http_header();
    http_header(const http_header& object);
    virtual ~http_header();

    /**
     * @brief   add a header
     * @param   const std::string&  name    [IN]
     * @param   const std::string&  value   [IN]
     * @return  *this
     * @remarks
     *          header.add ("WWW-Authenticate", "Basic realm=\"protected\"");
     */
    http_header& add(const std::string& name, const std::string& value);

    /**
     * @brief   clear
     * @return  *this
     */
    http_header& clear();

    /**
     * @brief   conversion
     * @param   const std::string& value [in]
     * @param   skey_value& kv [out]
     * @return  error code (see error.hpp)
     * @sample
     *          const char* auth =
     *              "Digest username=\"user\", realm=\"happiness\", nonce=\"b10d9755f22e0cc887d3b195569dca7a\", uri=\"/auth/digest\", "
     *              "response=\"756ae055c932efce3d1f1a38129aab3b\", opaque=\"553c454bedbdc9bb352df88630663669\", qop=auth, nc=00000002, "
     *              "cnonce=\"f3806458ed81c203\"";
     *
     *          http_header::to_keyvalue(auth, kv);
     *          std::string nonce = kv.get("nonce");
     *          std::string uri = kv.get("uri");
     *          std::string response = kv.get("response");
     *          std::string opaque = kv.get("opaque");
     *          std::string qop = kv.get("qop");
     *          std::string nc = kv.get("nc");
     *          std::string cnonce = kv.get("cnonce");
     */
    static return_t to_keyvalue(const std::string& value, skey_value& kv);

    /**
     * @brief   read a header
     * @param   const std::string& name [in]
     * @param   std::string& value [out]
     * @return  value
     * @sample
     *          header.get ("Content-Length", conent_length);
     */
    std::string get(const std::string& name, std::string& value);
    std::string get(const std::string& name);
    /**
     * @brief   contains
     * @param   const std::string& name [in]
     * @param   const std::string& value [in]
     * @sample
     *          header.add("Content-Type", "text/html;charset=UTF-8");
     *          test = header.contains("Content-Type", "text/html");
     */
    bool contains(const std::string& name, const std::string& value);
    /**
     * @brief   read a header token
     * @param   const std::string& name [in]
     * @param   unsigned index [in]
     * @param   std::string& token [out]
     * @return  token
     * @sample
     *          // Authorization: Bearer 0123-4567-89ab-cdef
     *          header.get ("Authorization", 0, auth_type); // Bearer
     *          header.get ("Authorization", 1, auth_data); // 0123-4567-89ab-cdef
     *          if (auth_type == "Basic") ...
     *          else if (auth_type == "Digest") ...
     */
    const char* get_token(const std::string& name, unsigned index, std::string& token);

    /**
     * @brief read all headers
     * @param std::string& contents [out]
     * @return error code (see error.hpp)
     */
    return_t get_headers(std::string& contents);
    return_t get_headers(std::function<void(const std::string&, const std::string&)> f);

    http_header& operator=(const http_header& object);

    http_header& set_version(uint8 version);
    uint8 get_version();

   protected:
   private:
    typedef std::list<std::string> http_header_list_t;
    typedef std::map<std::string, std::string> http_header_map_t;
    typedef std::pair<http_header_map_t::iterator, bool> http_header_map_pib_t;
    http_header_list_t _names;
    http_header_map_t _headers;
    uint8 _version;
    critical_section _lock;
};

}  // namespace net
}  // namespace hotplace

#endif
