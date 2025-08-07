/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAMES__
#define __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAMES__

#include <sdk/net/http/http3/http3_frame.hpp>

namespace hotplace {
namespace net {

class http3_frames {
   public:
    http3_frames();

    return_t read(qpack_dynamic_table* dyntable, const byte_t* stream, size_t size, size_t& pos);
    return_t write(qpack_dynamic_table* dyntable, const byte_t* stream, size_t size);
};

}  // namespace net
}  // namespace hotplace

#endif
