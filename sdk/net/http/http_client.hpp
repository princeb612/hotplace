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

#ifndef __HOTPLACE_SDK_NET_HTTP_CLIENT__
#define __HOTPLACE_SDK_NET_HTTP_CLIENT__

#include <map>
#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/io.hpp>
#include <sdk/net/http/http_request.hpp>  // http_request
#include <sdk/net/http/types.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace io;
namespace net {

/**
 * @brief   simple client
 * @sample
 *      // sketch
 *
 *      http_client client;
 *      http_response* response = nullptr;
 *      client.request("https://localhost:9000/", &response); // connect, send, read
 *      // ...
 *      resposne->release();
 *
 *      http_request request;
 *      request.compose(http_method_t::HTTP_GET, "/");
 *      request.get_http_header().add("Accept-Encoding", "gzip, deflate");
 *      client.request(request, &response);
 *      // ...
 *      response->release();
 */
class http_client {
   public:
    http_client();
    ~http_client();

    http_client& set_url(const std::string& url);
    http_client& set_url(const url_info_t& url_info);
    http_client& set_wto(uint32 milliseconds);
    http_client& request(const std::string& url, http_response** response);
    http_client& request(http_request& request, http_response** response);
    http_client& close();

   protected:
    tcp_client_socket* try_connect();

    http_client& do_request_and_response(const url_info_t& url_info, http_request& request, http_response** response);

   private:
    socket_t _socket;
    tcp_client_socket* _client_socket;
    tls_client_socket* _tls_client_socket;
    tls_context_t* _tls_context;
    SSL_CTX* _x509;
    url_info_t _url_info;
    uint32 _wto;
};

}  // namespace net
}  // namespace hotplace

#endif
