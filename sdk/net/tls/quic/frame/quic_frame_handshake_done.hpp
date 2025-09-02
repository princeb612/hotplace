/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMEHANDSHAKEDONE__
#define __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMEHANDSHAKEDONE__

#include <sdk/net/tls/quic/frame/quic_frame.hpp>

namespace hotplace {
namespace net {

// RFC 9000 19.20.  HANDSHAKE_DONE Frames
class quic_frame_handshake_done : public quic_frame {
   public:
    quic_frame_handshake_done(quic_packet* packet);

   protected:
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
};

}  // namespace net
}  // namespace hotplace

#endif
