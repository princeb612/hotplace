/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      RFC 9000 19.19.  CONNECTION_CLOSE Frames
 *      CONNECTION_CLOSE Frame {
 *        Type (i) = 0x1c..0x1d,
 *        Error Code (i),
 *        [Frame Type (i)],
 *        Reason Phrase Length (i),
 *        Reason Phrase (..),
 *      }
 *      Figure 43: CONNECTION_CLOSE Frame Format
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

constexpr char constexpr_error_code[] = "error code";
constexpr char constexpr_frame_type[] = "frame type";
constexpr char constexpr_reason_phase_len[] = "reason phase len";
constexpr char constexpr_reason_phase[] = "reason phase";

quic_frame_connection_close::quic_frame_connection_close(tls_session* session) : quic_frame(quic_frame_type_ping, session) {}

return_t quic_frame_connection_close::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint64 error_code = 0;
        uint64 frame_type = 0;
        binary_t reason_phase;

        {
            payload pl;
            pl << new payload_member(new quic_encoded(uint64(0)), constexpr_error_code)  //
               << new payload_member(new quic_encoded(uint64(0)), constexpr_frame_type)  //
               << new payload_member(new quic_encoded(binary_t()), constexpr_reason_phase);
            pl.set_reference_value(constexpr_reason_phase, constexpr_reason_phase_len);
            pl.read(stream, size, pos);

            error_code = pl.t_value_of<uint64>(constexpr_error_code);
            frame_type = pl.t_value_of<uint64>(constexpr_frame_type);
            pl.get_binary(constexpr_reason_phase, reason_phase);
        }

        if (istraceable(category_net)) {
            basic_stream dbs;
            dbs.printf("   > %s %I64i\n", constexpr_error_code, error_code);
            dbs.printf("   > %s %I64i\n", constexpr_frame_type, frame_type);
            dbs.printf("   > %s (%zi)\n", constexpr_reason_phase, reason_phase.size());
            dump_memory(reason_phase, &dbs, 16, 5, 0x0, dump_notrunc);
            trace_debug_event(category_net, net_event_quic_dump, &dbs);
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_frame_connection_close::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    return ret;
}

}  // namespace net
}  // namespace hotplace
