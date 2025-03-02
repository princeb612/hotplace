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

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_SERVERPUSH__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_SERVERPUSH__

#include <map>
#include <sdk/net/http/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   HTTP/2 server push
 * @remarks
 *          scenario
 *              request (stream 1 END_HEADERS END_DATA)
 *                  :method: GET
 *                  :path: /index.html
 *              server push
 *                  push_promise (stream 2)
 *                    fragment
 *                      :method: GET
 *                      :path /style.css
 *                  push_promise (stream 3)
 *                    fragment
 *                      :method: GET
 *                      :path /blah.js
 *                  headers (stream 2, END_HEADERS)
 *                      :status: 200
 *                      content-type: text/css
 *                  data (stream 2, END_DATA)
 *                      ... contents of /style.css ...
 *                  headers (stream 2, END_HEADERS)
 *                      :status: 200
 *                      content-type: application/javascript
 *                  data (stream 3, END_DATA)
 *                      ... contents of /blah.js ...
 *              response
 *                  headers (stream 1, END_HEADERS)
 *                      :status: 200
 *                      content-type: text/html
 *                  data (stream 1, END_DATA)
 *                      ... contents of /index.html ...
 *
 *          sketch
 *              server_push.add("/index.html", "/style.css").add("/index.html", "/blah.js");
 *
 *              if (session->get_http2_session().is_push_enabled()) {
 *                  if (server_push.is_promised(request)) {
 *                      // request for /index.html (stream 1)
 *                      // send  PUSH_PROMISE frame (stream 2, stream 3)
 *                      server_push.push_promise(request, server, session);
 *                      server_push.push(request, server, session);
 *                  }
 *              }
 */
class http2_serverpush {
   public:
    http2_serverpush();

    /**
     * @brief   HTTP/2 Server Push
     */
    http2_serverpush& add(const char* uri, const char* file);
    http2_serverpush& add(const std::string& uri, const std::string& file);

    /**
     * @brief   is promised
     * @param   http_request* request [in]
     * @param   http_server* server [in]
     * @return  number of the promised files
     */
    size_t is_promised(http_request* request, http_server* server);

    /*
     * @brief   PUSH_PROMISE frame
     * @param   http_request* request [in]
     * @param   http_server* server [in]
     * @param   network_session* session [in]
     * @return  error code (see error.hpp)
     */
    return_t push_promise(http_request* request, http_server* server, network_session* session);
    /**
     * @brief   HEADERS, DATA frame
     * @param   http_request* request [in]
     * @param   http_server* server [in]
     * @param   network_session* session [in]
     * @return  error code (see error.hpp)
     */
    return_t push(http_request* request, http_server* server, network_session* session);

   protected:
    return_t do_push_promise(const std::string& promise, uint32 streamid, http_request* request, http_server* server, network_session* session,
                             binary_t& stream);
    return_t do_push(const std::string& promise, uint32 streamid, http_request* request, http_server* server, network_session* session,
                     http_response* response);

   private:
    typedef std::multimap<std::string, std::string> server_push_map_t;
    critical_section _lock;
    server_push_map_t _server_push_map;
};

}  // namespace net
}  // namespace hotplace

#endif
