/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMEPUSHPROMISE__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMEPUSHPROMISE__

#include <sdk/net/http/http2/http2_frame.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   push_promise (PP) frame
 * @see
 *          RFC 7540 6.6. PUSH_PROMISE
 */
class http2_frame_push_promise : public http2_frame {
   public:
    http2_frame_push_promise();
    http2_frame_push_promise(const http2_frame_push_promise& rhs);
    virtual ~http2_frame_push_promise();

    virtual return_t read(http2_frame_header_t const* header, size_t size);
    virtual return_t write(binary_t& frame);
    virtual void dump(stream_t* s);

    void set_fragment(const binary_t& fragment);
    const binary_t& get_fragment();

   private:
    uint8 _padlen;
    uint32 _promised_id;
    binary_t _fragment;
};

}  // namespace net
}  // namespace hotplace

#endif
