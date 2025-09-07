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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMEPADDING__
#define __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMEPADDING__

#include <sdk/net/tls/quic/frame/quic_frame.hpp>

namespace hotplace {
namespace net {

// RFC 9000 19.1.  PADDING Frames
class quic_frame_padding : public quic_frame {
   public:
    quic_frame_padding(tls_session* session);

    /**
     * @param   uint16 len [in]
     * @param   uint32 flags [inopt] see quic_packet_flag_t
     * @desc
     *          pad(300);               // add a frame 300 bytes
     *          pad(1200, pad_packet);  // make a packet 1200 bytes
     */
    void pad(uint16 len, uint32 flags = 0);

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    uint16 _len;
    uint32 _flags;
};

}  // namespace net
}  // namespace hotplace

#endif
