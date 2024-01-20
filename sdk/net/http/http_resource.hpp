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

#ifndef __HOTPLACE_SDK_NET_HTTP_RESOURCE__
#define __HOTPLACE_SDK_NET_HTTP_RESOURCE__

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

class http_resource {
   public:
    /**
     * @brief   singleton instance
     */
    static http_resource* get_instance();

    /**
     * @brief   status code message
     * @remarks RFC 2616 HTTP/1.1 6.1.1 Status Code and Reason Phrase
     */
    std::string load(int status);
    /**
     * @brief   method
     */
    std::string get_method(http_method_t method);

   protected:
    http_resource();

    static http_resource _instance;
    std::map<int, std::string> _status_codes;
    std::map<http_method_t, std::string> _methods;
};

}  // namespace net
}  // namespace hotplace

#endif
