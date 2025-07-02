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

quic_frame_stream::quic_frame_stream(tls_session* session) : quic_frame(quic_frame_type_stream, session) {}

return_t quic_frame_stream::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        bool offbit = get_type() & 0x04;
        bool lenbit = get_type() & 0x02;
        bool finbit = get_type() & 0x01;

        constexpr char constexpr_stream_id[] = "stream id";
        constexpr char constexpr_offset[] = "offset";
        constexpr char constexpr_group_offset[] = "offset";
        constexpr char constexpr_length[] = "length";
        constexpr char constexpr_group_length[] = "length";
        constexpr char constexpr_stream_data[] = "stream data";

        payload pl;
        pl << new payload_member(new quic_encoded(uint64(0)), constexpr_stream_id)                      //
           << new payload_member(new quic_encoded(uint64(0)), constexpr_offset, constexpr_group_offset)  //
           << new payload_member(new quic_encoded(uint64(0)), constexpr_length, constexpr_group_length)  //
           << new payload_member(binary_t(), constexpr_stream_data);
        pl.set_condition(constexpr_stream_id, [&](payload* pl, payload_member* item) -> void {
            pl->set_group(constexpr_group_offset, offbit);
            pl->set_group(constexpr_group_length, lenbit);
        });
        pl.read(stream, size, pos);

        uint64 stream_id = pl.t_value_of<uint64>(constexpr_stream_id);
        binary_t stream_data;
        pl.get_binary(constexpr_stream_data, stream_data);

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("   > %s 0x%I64x", constexpr_stream_id, stream_id);
            dbs.println("   > %s 0x%zx", constexpr_stream_data, stream_data.size());
            dump_memory(stream_data, &dbs, 16, 5, 0x0, dump_notrunc);
            trace_debug_event(trace_category_net, trace_event_quic_frame, &dbs);
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t quic_frame_stream::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {}
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
