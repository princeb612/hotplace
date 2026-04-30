/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   quic_frame_padding.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMEPADDING__
#define __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMEPADDING__

#include <hotplace/sdk/net/tls/quic/frame/quic_frame.hpp>

namespace hotplace {
namespace net {

// RFC 9000 19.1.  PADDING Frames
class quic_frame_padding : public quic_frame {
   public:
    quic_frame_padding(tls_session* session);
    virtual ~quic_frame_padding();

    /**
     * @param   size_t len [in]
     * @param   uint32 flags [inopt] see quic_packet_flag_t
     * @desc
     *          pad(300);               // add a frame 300 bytes
     *          pad(1200, pad_packet);  // make a packet 1200 bytes
     */
    void pad(size_t len, uint32 flags = 0);

   protected:
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    size_t _len;
    uint32 _flags;
};

}  // namespace net
}  // namespace hotplace

#endif
