/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      RFC 9001 19.2.  PING Frames
 *      PING Frame {
 *          Type (i) = 0x01,
 *      }
 *      Figure 24: PING Frame Format
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_ping.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 9000 19.2.  PING Frames
 *   PING Frame {
 *     Type (i) = 0x01,
 *   }
 *   Figure 24: PING Frame Format
 */

quic_frame_ping::quic_frame_ping(quic_packet* packet) : quic_frame(quic_frame_type_ping, packet) {}

return_t quic_frame_ping::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {}
    __finally2 {}
    return ret;
}

return_t quic_frame_ping::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto type = get_type();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        bin.push_back(uint8(type));

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("\e[1;34m  + frame %s 0x%x(%i)\e[0m", tlsadvisor->quic_frame_type_string(type).c_str(), type, type);
            trace_debug_event(trace_category_net, trace_event_quic_frame, &dbs);
        }
#endif
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
