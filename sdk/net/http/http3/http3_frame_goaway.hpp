/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAMEGOAWAY__
#define __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAMEGOAWAY__

#include <sdk/net/http/http3/http3_frame.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 9114 7.2.6.  GOAWAY
 */
class http3_frame_goaway : public http3_frame {
   public:
    http3_frame_goaway();
};

}  // namespace net
}  // namespace hotplace

#endif
