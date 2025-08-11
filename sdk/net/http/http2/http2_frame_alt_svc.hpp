/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMEALTSVC__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_HTTP2FRAMEALTSVC__

#include <sdk/net/http/http2/http2_frame.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   The ALTSVC HTTP/2 Frame
 * @see
 *          RFC 7838 4.  The ALTSVC HTTP/2 Frame
 */
class http2_frame_alt_svc : public http2_frame {
   public:
    http2_frame_alt_svc();
    http2_frame_alt_svc(const http2_frame_alt_svc& rhs);
    virtual ~http2_frame_alt_svc();

    virtual void dump(stream_t* s);

    void set_origin(const binary_t& origin);
    void set_altsvc(const binary_t& altsvc);
    const binary_t& get_origin();
    const binary_t& get_altsvc();

   protected:
    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(binary_t& body);

   private:
    binary_t _origin;  // Origin
    binary_t _altsvc;  // Alt-Svc-Field-Value
};

}  // namespace net
}  // namespace hotplace

#endif
