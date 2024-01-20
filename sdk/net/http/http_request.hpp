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

#ifndef __HOTPLACE_SDK_NET_HTTP_REQUEST__
#define __HOTPLACE_SDK_NET_HTTP_REQUEST__

#include <map>
#include <sdk/base.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/io/basic/keyvalue.hpp>
#include <sdk/io/string/string.hpp>
#include <sdk/net/basic/client_socket.hpp>
#include <sdk/net/http/http_header.hpp>
#include <sdk/net/http/http_uri.hpp>
#include <sdk/net/http/types.hpp>
#include <sdk/net/server/network_protocol.hpp>
#include <sdk/net/tls/tls_client.hpp>

namespace hotplace {
using namespace io;
namespace net {

class http_request {
   public:
    http_request();
    virtual ~http_request();

    /**
     * @brief   open
     * @param   const char*     request         [IN]
     * @param   size_t          size_request    [IN]
     * @param   bool            optimize        [inopt]
     * @return  error code (see error.hpp)
     */
    return_t open(const char* request, size_t size_request, bool optimize = false);
    return_t open(const char* request, bool optimize = false);
    return_t open(basic_stream const& request, bool optimize = false);
    return_t open(std::string const& request, bool optimize = false);
    /**
     * @brief   close
     * @return  error code (see error.hpp)
     */
    return_t close();

    /**
     * @brief   return the http_header object
     */
    http_header& get_http_header();
    /**
     * @brief   return the http_uri object
     */
    http_uri& get_http_uri();
    /**
     * @brief   uri
     */
    const char* get_uri();
    /**
     * @brief   return the method (GET, POST, ...)
     */
    const char* get_method();
    /**
     * @brief   content
     */
    std::string get_content();

    /**
     * @brief   compose
     * @param   http_method_t method [in]
     * @param   std::string const& uri [in]
     * @param   std::string const& body [inopt]
     */
    http_request& compose(http_method_t method, std::string const& uri, std::string const& body = std::string(""));
    /**
     * @brief   load
     * @param   basic_stream& stream [out]
     */
    http_request& get_request(basic_stream& stream);

    virtual std::string get_version();

    void addref();
    void release();

   protected:
    t_shared_reference<http_request> _shared;

   private:
    std::string _method;
    std::string _content;

    http_header _header;
    http_uri _uri;
};

}  // namespace net
}  // namespace hotplace

#endif
