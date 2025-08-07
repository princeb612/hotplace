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
#include <sdk/net/tls/quic/frame/quic_frame_stop_sending.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_stream_id[] = "stream id";
constexpr char constexpr_error_code[] = "error code";

quic_frame_stop_sending::quic_frame_stop_sending(quic_packet* packet) : quic_frame(quic_frame_type_stop_sending, packet) {}

return_t quic_frame_stop_sending::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        // 19.5.  STOP_SENDING Frames

        // STOP_SENDING Frame {
        //     Type (i) = 0x05,
        //     Stream ID (i),
        //     Application Protocol Error Code (i),
        // }
        // Figure 29: STOP_SENDING Frame Format
        payload pl;
        pl << new payload_member(new quic_encoded(uint64(0)), constexpr_stream_id)  //
           << new payload_member(new quic_encoded(uint64(0)), constexpr_error_code);
        pl.read(stream, size, pos);

        uint64 stream_id = pl.t_value_of<uint64>(constexpr_stream_id);
        uint64 error_code = pl.t_value_of<uint64>(constexpr_error_code);

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            basic_stream dbs;
            dbs.println("   > %s %I64i", constexpr_stream_id, stream_id);
            dbs.println("   > %s %I64i %s", constexpr_error_code, error_code, tlsadvisor->quic_error_string(error_code).c_str());
            trace_debug_event(trace_category_net, trace_event_quic_frame, &dbs);
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t quic_frame_stop_sending::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    return ret;
}

}  // namespace net
}  // namespace hotplace
