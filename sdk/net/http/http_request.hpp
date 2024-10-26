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

#ifndef __HOTPLACE_SDK_NET_HTTP_REQUEST__
#define __HOTPLACE_SDK_NET_HTTP_REQUEST__

#include <map>
#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/io.hpp>
#include <sdk/net/http/http_header.hpp>  // http_header
#include <sdk/net/http/http_uri.hpp>     // http_uri
#include <sdk/net/http/types.hpp>

namespace hotplace {
using namespace io;
namespace net {

enum http_request_flag_t {
    http_request_compose = (1 << 0),
};

class http_request {
   public:
    http_request();
    http_request(const http_request& object);
    virtual ~http_request();

    /**
     * @brief   open
     * @param   const char*     request         [IN]
     * @param   size_t          size_request    [IN]
     * @return  error code (see error.hpp)
     */
    return_t open(const char* request, size_t size_request, uint32 flags = 0);
    return_t open(const char* request, uint32 flags = 0);
    return_t open(const basic_stream& request, uint32 flags = 0);
    return_t open(const std::string& request, uint32 flags = 0);
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
     * @brief   return the method (GET, POST, ...)
     */
    std::string get_method();
    /**
     * @brief   content
     */
    std::string get_content();

    /**
     * @brief   compose
     * @param   http_method_t method [in]
     * @param   const std::string& uri [in]
     * @param   const std::string& body [inopt]
     * @example
     *          request.get_http_header()
     *                  .clear()
     *                  .add("User-Agent", "client");
     *          request.compose(200, "text/plain", "hello world");
     */
    http_request& compose(http_method_t method, const std::string& uri, const std::string& body = std::string(""));
    /**
     * @brief   load
     * @param   basic_stream& stream [out]
     */
    http_request& get_request(basic_stream& stream);

    virtual std::string get_version_str();

    http_request& operator=(const http_request& rhs);

    http_request& add_content(const char* buf, size_t bufsize);
    http_request& add_content(const binary_t& bin);
    http_request& clear_content();

    http_request& set_hpack_session(hpack_dynamic_table* session);
    http_request& set_version(uint8 version);
    http_request& set_stream_id(uint32 stream_id);
    hpack_dynamic_table* get_hpack_session();
    uint8 get_version();
    uint32 get_stream_id();

    void addref();
    void release();

   protected:
    t_shared_reference<http_request> _shared;

   private:
    std::string _method;
    std::string _content;

    http_header _header;
    http_uri _uri;

    hpack_dynamic_table* _hpsess;
    uint8 _version;
    uint32 _stream_id;
};

}  // namespace net
}  // namespace hotplace

#endif
