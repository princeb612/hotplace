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

#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/base/unittest/traceable.hpp>  // traceable
#include <sdk/net/http/http2/hpack.hpp>     // hpack_session
#include <sdk/net/http/http_request.hpp>    // http_request
#include <sdk/net/http/types.hpp>

namespace hotplace {
namespace net {

class http2_session : public traceable {
   public:
    http2_session();

    /**
     * @brief   consume
     * @param   uint32 type [in]
     * @param   uint32 data_count [in]
     * @param   void* data_array[] [in]
     * @param   http_server* server [in]
     * @param   http_request** request [outopt] can be nullptr if END_HEADERS, END_STREAM is not set
     */
    http2_session& consume(uint32 type, uint32 data_count, void* data_array[], http_server* server, http_request** request);

    hpack_session& get_hpack_session();

    /**
     * @brief   enable push
     * @remarks
     *          RFC 7540 6.5.2.  Defined SETTINGS Parameters
     *            SETTINGS_ENABLE_PUSH (0x2):
     *              This setting can be used to disable server push (Section 8.2).
     *              An endpoint MUST NOT send a PUSH_PROMISE frame if it receives this parameter set to a value of 0.
     */
    http2_session& enable_push(bool enable);
    bool is_push_enabled();

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
    bool _enable_push;
};

}  // namespace net
}  // namespace hotplace

#endif
