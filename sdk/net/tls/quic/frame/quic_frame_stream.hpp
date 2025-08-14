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

#include <sdk/net/tls/quic/frame/quic_frame.hpp>

namespace hotplace {
namespace net {

// RFC 9000 19.8.  STREAM Frames
class quic_frame_stream : public quic_frame {
   public:
    quic_frame_stream(quic_packet* packet);

    enum quic_frame_stream_flag_t : uint8 {
        quic_frame_stream_off = 0x04,
        quic_frame_stream_len = 0x02,
        quic_frame_stream_fin = 0x01,
        quic_frame_stream_mask = (quic_frame_stream_off | quic_frame_stream_len | quic_frame_stream_fin),
    };

    uint8 get_flags();
    uint64 get_streamid();
    uint64 get_offset();
    binary_t& get_streamdata();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
    virtual return_t do_postprocess(tls_direction_t dir);

   private:
    uint64 _streamid;
    uint64 _offset;
    binary_t _streamdata;  // fragment
};

}  // namespace net
}  // namespace hotplace

#endif
