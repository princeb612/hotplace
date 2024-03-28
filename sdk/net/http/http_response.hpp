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

#ifndef __HOTPLACE_SDK_NET_HTTP_RESPONSE__
#define __HOTPLACE_SDK_NET_HTTP_RESPONSE__

#include <map>
#include <sdk/base.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/io/basic/keyvalue.hpp>
#include <sdk/io/string/string.hpp>
#include <sdk/net/basic/client_socket.hpp>
#include <sdk/net/http/http_header.hpp>
#include <sdk/net/http/http_request.hpp>
#include <sdk/net/http/http_uri.hpp>
#include <sdk/net/server/network_protocol.hpp>
#include <sdk/net/tls/tls_client.hpp>

namespace hotplace {
using namespace io;
namespace net {

class http_response {
   public:
    http_response();
    http_response(http_request* request);
    http_response(const http_response& object);
    ~http_response();

    /* *
     * @brief   open
     * @param   const char*     response        [IN]
     * @param   size_t          size_response   [IN]
     * @return  error code (see error.hpp)
     */
    return_t open(const char* response, size_t size_response);
    return_t open(const char* response);
    return_t open(basic_stream const& response);
    return_t open(std::string const& response);
    /* *
     * @brief  close
     * @return error code (see error.hpp)
     */
    return_t close();

    /**
     * @brief   compose
     */
    http_response& compose(int status_code);
    http_response& compose(int status_code, const char* content_type, const char* content, ...);
    http_response& compose(int status_code, std::string const& content_type, const char* content, ...);
    /**
     * @brief   respond
     * @example
     *          response.get_http_header().clear();
     *          response.compose(200, "text/html>", "<html><body></body></html>");
     *          basic_stream bs;
     *          response.get_response(bs)
     *          session->send((const char*)bs.data(), bs.size());
     */
    return_t respond(network_session* session);
    /**
     * @brief   Content-Type
     */
    const char* content_type();
    /**
     * @brief   content
     */
    const char* content();
    size_t content_size();
    /**
     * @brief   status code
     */
    int status_code();
    /**
     * @brief   header
     */
    http_header& get_http_header();
    /**
     * @brief   request
     */
    http_request* get_http_request();
    /**
     * @brief   response
     */
    http_response& get_response(basic_stream& bs);

    virtual std::string get_version();

    http_response& operator=(http_response const& object);

    void addref();
    void release();

   protected:
    t_shared_reference<http_response> _shared;

   private:
    http_request* _request;
    http_header _header;
    std::string _content_type;
    std::string _content;
    int _statuscode;
};

}  // namespace net
}  // namespace hotplace

#endif
