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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMEQPACKDECODERSTREAM__
#define __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMEQPACKDECODERSTREAM__

#include <sdk/net/tls/quic/frame/quic_frame_stream.hpp>

namespace hotplace {
namespace net {

class quic_frame_qpack_decoder_stream : public quic_frame_stream {
   public:
    quic_frame_qpack_decoder_stream(tls_session* session, uint8 type);

   protected:
    virtual return_t do_read_control_stream(uint64 stream_id);
};

}  // namespace net
}  // namespace hotplace

#endif
