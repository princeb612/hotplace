/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMECONTINUATION__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMECONTINUATION__

#include <sdk/net/http/http2/http2_frame.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   continuation frame
 * @see
 *          RFC 7540 6.10. CONTINUATION
 */
class http2_frame_continuation : public http2_frame {
   public:
    http2_frame_continuation();
    http2_frame_continuation(const http2_frame_continuation& rhs);
    virtual ~http2_frame_continuation();

    virtual void dump(stream_t* s);

    void set_fragment(const binary_t& fragment);
    const binary_t& get_fragment();

   protected:
    virtual return_t read_body(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write_body(binary_t& body);

   private:
    binary_t _fragment;
};

}  // namespace net
}  // namespace hotplace

#endif
