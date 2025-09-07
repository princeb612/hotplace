/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/http3/http3_frames.hpp>
#include <sdk/net/http/qpack/qpack_encoder.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_qpack_decoder_stream.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic_session.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

quic_frame_qpack_decoder_stream::quic_frame_qpack_decoder_stream(tls_session* session, uint8 type) : quic_frame_stream(session, type) {}

return_t quic_frame_qpack_decoder_stream::do_read_control_stream(uint64 stream_id) {
    return_t ret = errorcode_t::success;
    __try2 {
        //
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
