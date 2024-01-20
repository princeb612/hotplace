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
#include <sdk/base.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/io/basic/keyvalue.hpp>
#include <sdk/io/string/string.hpp>
#include <sdk/net/basic/client_socket.hpp>
#include <sdk/net/http/http_request.hpp>
#include <sdk/net/http/http_response.hpp>
#include <sdk/net/server/network_protocol.hpp>
#include <sdk/net/tls/tls_client.hpp>

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
 *      request.compose(GET, "/");
 *      request.get_http_header().add("Accept-Encoding", "gzip, deflate");
 *      client.request(request, &response);
 *      // ...
 *      response->release();
 */
class http_client {
   public:
    http_client();
    ~http_client();

    client_socket* connect(std::string const& url);
    client_socket* connect(url_info_t const& url_info);
    http_client& request(std::string const& url, http_response** response);
    http_client& request(http_request& request, http_response** response);
    http_client& close();
    http_client& set_ttl(uint32 milliseconds);
    http_client& set(std::string const& host, uint16 port);

   protected:
    http_client& request_and_response(url_info_t const& url_info, http_request& request, http_response** response);

   private:
    socket_t _socket;
    client_socket* _client_socket;
    transport_layer_security_client* _tls_client_socket;
    tls_context_t* _tls_context;
    SSL_CTX* _x509;
    url_info_t _url_info;
    uint32 _ttl;
    std::string _host;
    uint16 _port;
};

}  // namespace net
}  // namespace hotplace

#endif
