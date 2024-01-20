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

#ifndef __HOTPLACE_SDK_NET_HTTP_URI__
#define __HOTPLACE_SDK_NET_HTTP_URI__

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

// class http_request;
class http_uri {
   public:
    http_uri();
    ~http_uri();

    /**
     * @brief open
     * @param std::string const& uri [in]
     * @return error code (see error.hpp)
     */
    return_t open(std::string const& uri);
    return_t open(const char* uri);
    /**
     * @brief close
     */
    void close();

    /**
     * @brief URI
     */
    const char* get_uri();
    const char* get_query();
    /**
     * @brief   query
     * @param   unsigned        index       [IN] 0 <= index < size_parameter ()
     * @param   std::string&    key         [OUT]
     * @param   std::string&    value       [OUT]
     * @return  error code (see error.hpp)
     * @remarks
     *          http_uri url ("/resource/entity?spec=full&period=week")
     *          url.query (0, key, value) return spec and full
     *          url.query (1, key, value) return period and week
     */
    return_t query(unsigned index, std::string& key, std::string& value);
    /**
     * @brief   read a param
     * @param   std::string const& key [in]
     * @param   std::string& value [out]
     * @return  error code (see error.hpp)
     */
    return_t query(std::string const& key, std::string& value);
    /**
     * @brief count of query
     * @remarks
     */
    size_t countof_query();

    /*
     * @brief   conversion
     * @param   std::string const& value [in]
     * @param   key_value& kv [out]
     * @return  error code (see error.hpp)
     * @sample
     *          const char* input = "/resource?client_id=s6BhdRkqt3&client_secret=7Fjfp0ZBr1KtDRbnfVdmIw";
     *          http_uri::to_keyvalue(input, kv);
     *          std::string client_id = kv.get("client_id");
     *          std::string client_secret = kv.get("client_secret");
     */
    static return_t to_keyvalue(std::string const& value, key_value& kv);

    void addref();
    void release();

   protected:
    std::string _uri;
    std::string _query;

    typedef std::map<std::string, std::string> PARAMETERS;
    PARAMETERS _query_kv;

    t_shared_reference<http_uri> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
