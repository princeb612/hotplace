/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      RFC 9000 19.20.  HANDSHAKE_DONE Frames
 *      HANDSHAKE_DONE Frame {
 *        Type (i) = 0x1e,
 *      }
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_handshake_done.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_type[] = "type";

quic_frame_handshake_done::quic_frame_handshake_done(quic_packet* packet) : quic_frame(quic_frame_type_handshake_done, packet) {}

return_t quic_frame_handshake_done::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        payload pl;
        pl << new payload_member(new quic_encoded(uint8(get_type())), constexpr_type);
        pl.write(bin);
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
