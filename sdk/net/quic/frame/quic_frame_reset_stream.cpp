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
#include <sdk/net/quic/quic.hpp>
#include <sdk/net/quic/quic_encoded.hpp>
#include <sdk/net/quic/quic_frame.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_stream_id[] = "stream id";
constexpr char constexpr_error_code[] = "error code";

quic_frame_reset_stream::quic_frame_reset_stream(tls_session* session) : quic_frame(quic_frame_type_reset_stream, session) {}

return_t quic_frame_reset_stream::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        // 19.4.  RESET_STREAM Frames

        // RESET_STREAM Frame {
        //   Type (i) = 0x04,
        //   Stream ID (i),
        //   Application Protocol Error Code (i),
        //   Final Size (i),
        // }
        // Figure 28: RESET_STREAM Frame Format
        constexpr char constexpr_final_size[] = "final size";

        payload pl;
        pl << new payload_member(new quic_encoded(uint64(0)), constexpr_stream_id) << new payload_member(new quic_encoded(uint64(0)), constexpr_error_code)
           << new payload_member(new quic_encoded(uint64(0)), constexpr_final_size);
        pl.read(stream, size, pos);

        uint64 stream_id = pl.t_value_of<uint64>(constexpr_stream_id);
        uint64 error_code = pl.t_value_of<uint64>(constexpr_error_code);
        uint64 final_size = pl.t_value_of<uint64>(constexpr_final_size);

        if (istraceable(category_net)) {
            basic_stream dbs;
            dbs.printf("   > %s %I64i\n", constexpr_stream_id, stream_id);
            dbs.printf("   > %s %I64i\n", constexpr_error_code, error_code);
            dbs.printf("   > %s %I64i\n", constexpr_final_size, final_size);
            trace_debug_event(category_net, net_event_quic_dump, &dbs);
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_frame_reset_stream::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    return ret;
}

}  // namespace net
}  // namespace hotplace
