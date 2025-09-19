/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMEPRIORITY__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMEPRIORITY__

#include <hotplace/sdk/net/http/http2/http2_frame.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   priority frame
 * @see
 *          RFC 7540 6.3. PRIORITY
 *          RFC 7540 Figure 8: PRIORITY Frame Payload
 */
class http2_frame_priority : public http2_frame {
   public:
    http2_frame_priority();
    http2_frame_priority(const http2_frame_priority& rhs);
    virtual ~http2_frame_priority();

    virtual void dump(stream_t* s);

   protected:
    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(binary_t& body);

   private:
    bool _exclusive;
    uint32 _dependency;
    uint8 _weight;
};

}  // namespace net
}  // namespace hotplace

#endif
