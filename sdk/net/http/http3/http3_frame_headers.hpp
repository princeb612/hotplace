/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAMEHEADERS__
#define __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAMEHEADERS__

#include <sdk/net/http/http3/http3_frame.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 9114 7.2.2.  HEADERS
 */
class http3_frame_headers : public http3_frame {
   public:
    http3_frame_headers(qpack_dynamic_table* dyntable);

   protected:
    virtual return_t do_read_payload(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write(binary_t& bin);

   private:
    qpack_dynamic_table* _dyntable;
};

}  // namespace net
}  // namespace hotplace

#endif
