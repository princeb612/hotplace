/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAMEPUSHPROMISE__
#define __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAMEPUSHPROMISE__

#include <hotplace/sdk/net/http/http3/http3_frame.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 9114 7.2.5.  PUSH_PROMISE
 */
class http3_frame_push_promise : public http3_frame {
   public:
    http3_frame_push_promise();
};

}  // namespace net
}  // namespace hotplace

#endif
