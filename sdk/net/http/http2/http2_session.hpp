/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_SESSION__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_SESSION__

#include <sdk/base.hpp>
#include <sdk/net/http/http2/hpack.hpp>
#include <sdk/net/http/http_request.hpp>

namespace hotplace {
namespace net {

class http_server;
class http2_session {
   public:
    http2_session();

    /**
     * @brief   consume
     */
    http2_session& consume(uint32 type, uint32 data_count, void* data_array[], http_server* server, http_request** request);

    hpack_session& get_hpack_session();

    http2_session& trace(std::function<void(stream_t*)> f);

   protected:
   private:
    critical_section _lock;
    typedef std::map<uint32, uint8> flags_t;
    typedef std::map<uint32, http_request> headers_t;
    typedef std::pair<flags_t::iterator, bool> flags_pib_t;
    typedef std::pair<headers_t::iterator, bool> headers_pib_t;
    flags_t _flags;
    headers_t _headers;  // map<stream_identifier, http_request>
    hpack_session _hpack_session;

    // debug
    std::function<void(stream_t*)> _df;
};

}  // namespace net
}  // namespace hotplace

#endif
