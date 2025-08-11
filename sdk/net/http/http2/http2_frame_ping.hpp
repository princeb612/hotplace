/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMEPING__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMEPING__

#include <sdk/net/http/http2/http2_frame.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   ping frame
 * @see
 *          RFC 7540 6.7. PING
 */
class http2_frame_ping : public http2_frame {
   public:
    http2_frame_ping();
    http2_frame_ping(const http2_frame_ping& rhs);
    virtual ~http2_frame_ping();

    virtual void dump(stream_t* s);

   protected:
    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(binary_t& body);

   private:
    uint64 _opaque;
};

}  // namespace net
}  // namespace hotplace

#endif
