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

#ifndef __HOTPLACE_SDK_NET_HTTP__
#define __HOTPLACE_SDK_NET_HTTP__

#include <map>
#include <sdk/base.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/io/basic/keyvalue.hpp>
#include <sdk/io/string/string.hpp>
#include <sdk/net/basic/client_socket.hpp>
#include <sdk/net/http/http_client.hpp>
#include <sdk/net/http/http_header.hpp>
#include <sdk/net/http/http_request.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/http/http_response.hpp>
#include <sdk/net/http/http_uri.hpp>
#include <sdk/net/http/types.hpp>
#include <sdk/net/server/network_protocol.hpp>
#include <sdk/net/tls/tls_client.hpp>

namespace hotplace {
using namespace io;
namespace net {

// HTTP/1.1

}  // namespace net
}  // namespace hotplace

#endif
