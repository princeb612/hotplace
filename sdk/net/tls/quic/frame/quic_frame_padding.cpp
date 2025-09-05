/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/stream/segmentation.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_padding.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/quic_packet_publisher.hpp>
#include <sdk/net/tls/quic_session.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 9000 19.1.  PADDING Frames
 *   PADDING Frame {
 *     Type (i) = 0x00,
 *   }
 *   Figure 23: PADDING Frame Format
 */

quic_frame_padding::quic_frame_padding(quic_packet* packet) : quic_frame(quic_frame_type_padding, packet), _len(0), _flags(0) {}

return_t quic_frame_padding::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {}
    __finally2 {}
    return ret;
}

return_t quic_frame_padding::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    // RFC 9001 19.1.  PADDING Frames
    // PADDING Frame {
    //   Type (i) = 0x00,
    // }
    // Figure 23: PADDING Frame Format
    if (quic_pad_packet & _flags) {
        // packet mode - make a packet padded
        auto session = get_packet()->get_session();
        auto fragment = get_packet()->get_fragment();
        auto avail = fragment.available();
        auto len = avail > 0 ? avail : 0;
        if (bin.size() < len) {
            bin.resize(len);
        }
    } else {
        // frame mode - add a frame
        bin.resize(bin.size() + _len);
    }
    return ret;
}

void quic_frame_padding::pad(uint16 len, uint32 flags) {
    _len = len;
    _flags = flags;
}

}  // namespace net
}  // namespace hotplace
