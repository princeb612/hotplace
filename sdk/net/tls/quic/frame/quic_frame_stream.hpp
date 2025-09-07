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

#include <sdk/net/http/http3/http3_frames.hpp>
#include <sdk/net/tls/quic/frame/quic_frame.hpp>

namespace hotplace {
namespace net {

// RFC 9000 19.8.  STREAM Frames
class quic_frame_stream : public quic_frame {
   public:
    quic_frame_stream(tls_session* session, uint8 type = quic_frame_type_stream);

    uint8 get_flags();
    uint64 get_streamid();
    uint8 get_unistream_type();

    quic_frame_stream& set_streaminfo(uint64 stream_id, uint8 unitype);

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
    virtual return_t do_write_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t pos, size_t len, binary_t& bin);
    virtual return_t do_postprocess(tls_direction_t dir);

    // read from session->get_quic_session().get_streams()
    virtual return_t do_read_control_stream(uint64 stream_id);

    void set_streamid(uint64 stream_id);
    bool is_beginof_unistream(uint64 stream_id);
    bool is_beginof_unistream(tls_session* session, uint64 stream_id);

   private:
    uint64 _stream_id;
    uint8 _unitype;
};

}  // namespace net
}  // namespace hotplace

#endif
