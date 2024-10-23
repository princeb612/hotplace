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

#ifndef __HOTPLACE_SDK_NET_HTTP_TYPES__
#define __HOTPLACE_SDK_NET_HTTP_TYPES__

#include <map>
#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/io.hpp>
#include <sdk/net/types.hpp>

namespace hotplace {
using namespace io;
namespace net {

enum http_method_t {
    HTTP_OPTIONS = 1,
    HTTP_GET = 2,
    HTTP_HEAD = 3,
    HTTP_POST = 4,
    HTTP_PUT = 5,
    HTTP_DELETE = 6,
    HTTP_TRACE = 7,
};

// net/http
class html_documents;
class http_authentication_provider;
class http_authentication_resolver;
class http_client;
class http_header;
class http_protocol;
class http_request;
class http_resource;
class http_response;
class http_router;
class http_server;
class http_server_builder;
class http_uri;

// net/http/http2
class hpack_session;
class hpack_static_table;
class http_header_compression;
class http_header_compression_table_static;
class http_header_compression_table_dynamic;
class http_huffman_coding;
class http2_frame;
class http2_frame_alt_svc;
class http2_frame_continuation;
class http2_frame_data;
class http2_frame_goaway;
class http2_frame_headers;
class http2_frame_ping;
class http2_frame_priority;
class http2_frame_push_promise;
class http2_frame_rst_stream;
class http2_frame_settings;
class http2_frame_window_update;
class http2_protocol;
class http2_serverpush;
class http2_session;
class qpack_static_table;

}  // namespace net
}  // namespace hotplace

#endif
