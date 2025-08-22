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
#include <sdk/net/tls/tls_container.hpp>

namespace hotplace {
namespace net {

class http3_frames {
   public:
    http3_frames();

    return_t read(tls_session* session, const byte_t* stream, size_t size, size_t& pos);
    return_t write(tls_session* session, binary_t& bin);

    return_t add(http3_frame* frame, bool upref = false);
    http3_frames& operator<<(http3_frame* frame);
    return_t for_each(std::function<return_t(http3_frame*)> func);
    http3_frame* getat(size_t index, bool upref = false);
    bool empty();
    size_t size();
    void clear();

   protected:
    t_tls_container<http3_frame*, uint8> _frames;
};

}  // namespace net
}  // namespace hotplace

#endif
