/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAMEUNKNOWN__
#define __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAMEUNKNOWN__

#include <hotplace/sdk/net/http/http3/http3_frame.hpp>

namespace hotplace {
namespace net {

class http3_frame_unknown : public http3_frame {
   public:
    http3_frame_unknown(uint64 type);
};

}  // namespace net
}  // namespace hotplace

#endif
