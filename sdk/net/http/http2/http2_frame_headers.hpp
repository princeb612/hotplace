/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMEHEADERS__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMEHEADERS__

#include <hotplace/sdk/net/http/http2/http2_frame.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   headers frame
 * @see
 *          RFC 7540 6.2 HEADERS
 */
class http2_frame_headers : public http2_frame {
   public:
    http2_frame_headers();
    http2_frame_headers(const http2_frame_headers& rhs);
    virtual ~http2_frame_headers();

    virtual void dump(stream_t* s);

    void set_fragment(const binary_t& fragment);
    const binary_t& get_fragment();

   protected:
    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(binary_t& body);

   private:
    uint8 _padlen;
    bool _exclusive;
    uint32 _dependency;
    uint8 _weight;
    binary_t _fragment;
};

}  // namespace net
}  // namespace hotplace

#endif
