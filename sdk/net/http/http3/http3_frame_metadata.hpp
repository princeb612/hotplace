/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAMEMETADATA__
#define __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAMEMETADATA__

#include <sdk/net/http/http3/http3_frame.hpp>

namespace hotplace {
namespace net {

/**
 * draft
 */
class http3_frame_metadata : public http3_frame {
   public:
    http3_frame_metadata();
};

}  // namespace net
}  // namespace hotplace

#endif
