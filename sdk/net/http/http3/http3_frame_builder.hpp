/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAMEBUILDER__
#define __HOTPLACE_SDK_NET_HTTP_HTTP3_HTTP3FRAMEBUILDER__

#include <sdk/net/http/http3/http3_frame.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

class http3_frame_builder {
   public:
    http3_frame_builder();

    http3_frame_builder& set(h3_frame_t type);
    http3_frame_builder& set(tls_session* session);
    http3_frame* build();

    h3_frame_t get_type();

   private:
    h3_frame_t _type;
    tls_session* _session;
};

}  // namespace net
}  // namespace hotplace

#endif
