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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMEHTTP3STREAM__
#define __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMEHTTP3STREAM__

#include <sdk/net/tls/quic/frame/quic_frame_stream.hpp>

namespace hotplace {
namespace net {

class quic_frame_http3_stream : public quic_frame_stream {
   public:
    quic_frame_http3_stream(tls_session* session, uint8 type);

    http3_frames get_frames();

   protected:
    virtual return_t do_read_control_stream(uint64 stream_id);

   private:
    http3_frames _frames;
};

}  // namespace net
}  // namespace hotplace

#endif
