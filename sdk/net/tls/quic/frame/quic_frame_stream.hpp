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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMESTREAM__
#define __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMESTREAM__

#include <hotplace/sdk/net/http/http3/http3_frames.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame.hpp>

namespace hotplace {
namespace net {

// RFC 9000 19.8.  STREAM Frames
class quic_frame_stream : public quic_frame {
   public:
    quic_frame_stream(tls_session* session, uint8 type = quic_frame_type_stream);
    virtual ~quic_frame_stream();

    uint8 get_flags();
    uint64 get_streamid();

    virtual void set(uint64 stream_id, uint8 unitype);
    quic_frame_stream& set(const binary_t& bin);

   protected:
   protected:
    uint64 _stream_id;
    binary_t _stream_data;
};

}  // namespace net
}  // namespace hotplace

#endif
