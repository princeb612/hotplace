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

#ifndef __HOTPLACE_SDK_NET_HTTP_HEADER__
#define __HOTPLACE_SDK_NET_HTTP_HEADER__

#include <map>
#include <sdk/base.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/io/basic/keyvalue.hpp>
#include <sdk/io/string/string.hpp>
#include <sdk/net/basic/client_socket.hpp>
#include <sdk/net/http/types.hpp>
#include <sdk/net/server/network_protocol.hpp>
#include <sdk/net/tls/tls_client.hpp>

namespace hotplace {
using namespace io;
namespace net {

class http_header {
   public:
    http_header();
    http_header(const http_header& object);
    virtual ~http_header();

    /**
     * @brief   add a header
     * @param   const char*     header      [IN]
     * @param   const char*     value       [IN]
     * @return  *this
     * @remarks
     *          header.add ("WWW-Authenticate", "Basic realm=\"protected\"");
     */
    http_header& add(const char* header, const char* value);

    /**
     * @brief   add a header
     * @param   std::string     header      [IN]
     * @param   std::string     value       [IN]
     * @return  *this
     */
    http_header& add(std::string header, std::string value);

    /**
     * @brief   clear
     * @return  *this
     */
    http_header& clear();

    /**
     * @brief   conversion
     * @param   std::string const& value [in]
     * @param   key_value& kv [out]
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
    static return_t to_keyvalue(std::string const& value, key_value& kv);

    /**
     * @brief   read a header
     * @param   const char* header [in]
     * @param   std::string& value [out]
     * @return  value
     * @sample
     *          header.get ("Content-Length", conent_length);
     */
    const char* get(const char* header, std::string& value);
    std::string get(const char* header);
    /**
     * @brief   contains
     * @param   const char* header [in]
     * @param   const char* value [in]
     * @sample
     *          header.add("Content-Type", "text/html;charset=UTF-8");
     *          test = header.contains("Content-Type", "text/html");
     */
    bool contains(const char* header, const char* value);
    /**
     * @brief   read a header token
     * @param   const char* header [in]
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
    const char* get_token(const char* header, unsigned index, std::string& token);

    /**
     * @brief read all headers
     * @param std::string& contents [out]
     * @return error code (see error.hpp)
     */
    return_t get_headers(std::string& contents);

    http_header& operator=(http_header const& object);

   protected:
    typedef std::map<std::string, std::string> http_header_map_t;
    typedef std::pair<http_header_map_t::iterator, bool> http_header_map_pib_t;
    http_header_map_t _headers;
    critical_section _lock;
};

}  // namespace net
}  // namespace hotplace

#endif
