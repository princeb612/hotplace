/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMEGOAWAY__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMEGOAWAY__

#include <sdk/net/http/http2/http2_frame.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   goaway frame
 * @see
 *          RFC 7540 6.8. GOAWAY
 */
class http2_frame_goaway : public http2_frame {
   public:
    http2_frame_goaway();
    http2_frame_goaway(const http2_frame_goaway& rhs);
    virtual ~http2_frame_goaway();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

    /**
     * @brief   set error code
     * @param   uint32 errorcode [in] see h2_errorcodes_t
     */
    http2_frame_goaway& set_errorcode(uint32 errorcode);

    void set_debug(const binary_t& debug);
    const binary_t& get_debug();

   private:
    uint32 _last_id;
    uint32 _errorcode;
    binary_t _debug;
};

}  // namespace net
}  // namespace hotplace

#endif
