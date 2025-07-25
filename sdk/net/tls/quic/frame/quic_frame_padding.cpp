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
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/quic/frame/quic_frame.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

quic_frame_padding::quic_frame_padding(quic_packet* packet) : quic_frame(quic_frame_type_padding, packet), _len(0) {}

return_t quic_frame_padding::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        // RFC 9001 19.1.  PADDING Frames
        // PADDING Frame {
        //   Type (i) = 0x00,
        // }
        // Figure 23: PADDING Frame Format
#if 0
#if defined DEBUG
        if (istraceable(trace_category_net)) {
            dbs.println("  > frame %s @%zi", constexpr_frame_padding, begin);
            trace_debug_event(trace_category_net, trace_event_quic_frame, &dbs);
        }
#endif
#endif
    }
    __finally2 {}
    return ret;
}

return_t quic_frame_padding::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    bin.resize(bin.size() + _len);
    return ret;
}

void quic_frame_padding::pad(uint16 len) { _len = len; }

}  // namespace net
}  // namespace hotplace
