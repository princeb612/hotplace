/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   quic_frame_reset_stream.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_reset_stream.hpp>
#include <hotplace/sdk/net/tls/quic/quic.hpp>
#include <hotplace/sdk/net/tls/quic/quic_encoded.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_stream_id[] = "stream id";
constexpr char constexpr_error_code[] = "error code";

quic_frame_reset_stream::quic_frame_reset_stream(tls_session* session) : quic_frame(quic_frame_type_reset_stream, session) {}

quic_frame_reset_stream::~quic_frame_reset_stream() {}

/**
 * RFC 9000 19.4.  RESET_STREAM Frames
 * RESET_STREAM Frame {
 *   Type (i) = 0x04,
 *   Stream ID (i),
 *   Application Protocol Error Code (i),
 *   Final Size (i),
 * }
 * Figure 28: RESET_STREAM Frame Format
 */

return_t quic_frame_reset_stream::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .goahead_if_not_fail()
        .test_parameter([&]() -> bool { return (nullptr != stream); })
        .run_trycatch([&]() -> return_t {
            constexpr char constexpr_final_size[] = "final size";

            payload pl;
            pl << new payload_member(new quic_encoded(uint64(0)), constexpr_stream_id)   //
               << new payload_member(new quic_encoded(uint64(0)), constexpr_error_code)  //
               << new payload_member(new quic_encoded(uint64(0)), constexpr_final_size);

            auto rc = pl.read(stream, size, pos);
            if (false == error_traits<return_t>::is_not_fail(rc)) {
                __trace_return(rc);
            }

#if defined DEBUG
            uint64 stream_id = pl.t_value_of<uint64>(constexpr_stream_id);
            uint64 error_code = pl.t_value_of<uint64>(constexpr_error_code);
            uint64 final_size = pl.t_value_of<uint64>(constexpr_final_size);

            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_quic_frame, [&](basic_stream& dbs) -> void {
                    tls_advisor* tlsadvisor = tls_advisor::get_instance();
                    dbs.println("   > %s %I64i", constexpr_stream_id, stream_id);
                    dbs.println("   > %s %I64i %s", constexpr_error_code, error_code, tlsadvisor->nameof_quic_error(error_code).c_str());
                    dbs.println("   > %s %I64i", constexpr_final_size, final_size);
                });
            }
#endif

            return success;
        });
    return pipeline.result();
}

return_t quic_frame_reset_stream::do_write_body(tls_direction_t dir, binary_t& bin) { return errorcode_t::success; }

}  // namespace net
}  // namespace hotplace
