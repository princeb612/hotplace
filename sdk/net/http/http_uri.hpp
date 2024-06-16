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
#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/io.hpp>

namespace hotplace {
using namespace io;
namespace net {

// class http_request;
class http_uri {
   public:
    http_uri();
    http_uri(const http_uri& object);
    ~http_uri();

    /**
     * @brief open
     * @param const std::string& uri [in]
     * @return error code (see error.hpp)
     */
    return_t open(const std::string& uri);
    return_t open(const char* uri);
    /**
     * @brief close
     */
    void close();

    return_t set_query(const char* query);
    return_t set_query(const std::string& query);

    /**
     * @brief URI
     */
    const char* get_uri();
    const char* get_uripath();
    const char* get_query();
    /**
     * @brief   read a param
     * @param   const std::string& key [in]
     * @param   std::string& value [out]
     * @return  error code (see error.hpp)
     */
    return_t query(const std::string& key, std::string& value);
    /**
     * @brief count of query
     * @remarks
     */
    size_t countof_query();

    /*
     * @brief   conversion
     * @param   const std::string& value [in]
     * @param   skey_value& kv [out]
     * @return  error code (see error.hpp)
     * @sample
     *          const char* input = "/resource?client_id=s6BhdRkqt3";
     *          http_uri::to_keyvalue(input, kv);
     *          std::string client_id = kv.get("client_id");
     */
    static return_t to_keyvalue(const std::string& value, skey_value& kv);

    /**
     * @brief   keyvalue of query
     * @example
     *          uri.get_query_keyvalue().foreach(
     *              [&](const std::string& key, const std::string& value, void* param) -> void {
     *                  std::cout << key << " : " << value << std::endl;
     *              }
     *          );
     */
    skey_value& get_query_keyvalue();

    http_uri& operator=(const http_uri& rhs);

    void addref();
    void release();

   private:
    std::string _uri;
    std::string _uripath;
    std::string _query;
    skey_value _query_kv;

    t_shared_reference<http_uri> _shared;
};

}  // namespace net
}  // namespace hotplace

#endif
