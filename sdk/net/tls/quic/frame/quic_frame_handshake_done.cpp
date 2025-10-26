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

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_handshake_done.hpp>
#include <hotplace/sdk/net/tls/quic/quic.hpp>
#include <hotplace/sdk/net/tls/quic/quic_encoded.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_type[] = "type";

/**
 * RFC 9000 19.20.  HANDSHAKE_DONE Frames
 *    HANDSHAKE_DONE Frame {
 *      Type (i) = 0x1e,
 *    }
 *    Figure 44: HANDSHAKE_DONE Frame Format
 */

quic_frame_handshake_done::quic_frame_handshake_done(tls_session* session) : quic_frame(quic_frame_type_handshake_done, session) {}

quic_frame_handshake_done::~quic_frame_handshake_done() {}

return_t quic_frame_handshake_done::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto type = get_type();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();

#if 1
        bin.push_back(uint8(type));
#else
        payload pl;
        pl << new payload_member(new quic_encoded(uint8(type)), constexpr_type);
        pl.write(bin);
#endif

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            trace_debug_event(trace_category_net, trace_event_quic_frame, [&](basic_stream& dbs) -> void {
                dbs.println("\e[1;34m  + frame %s 0x%x(%i)\e[0m", tlsadvisor->nameof_quic_frame(type).c_str(), type, type);
            });
        }
#endif
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
