/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMERSTSTREAM__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMERSTSTREAM__

#include <sdk/net/http/http2/http2_frame.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   reset_stream (RS) frame
 * @see
 *          RFC 7540 6.4. RST_STREAM
 *          RFC 7540 Figure 9: RST_STREAM Frame Payload
 */
class http2_frame_rst_stream : public http2_frame {
   public:
    http2_frame_rst_stream();
    http2_frame_rst_stream(const http2_frame_rst_stream& rhs);
    virtual ~http2_frame_rst_stream();

    virtual void dump(stream_t* s);

   protected:
    virtual return_t read_body(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write_body(binary_t& body);

   private:
    uint32 _errorcode;
};

}  // namespace net
}  // namespace hotplace

#endif
