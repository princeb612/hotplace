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
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

quic_frame_ack::quic_frame_ack(tls_session* session) : quic_frame(quic_frame_type_ack, session) {}

return_t quic_frame_ack::do_postprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;

    auto session = get_session();

    // if initial
    //     session->reset_recordno(dir);

    return ret;
}

return_t quic_frame_ack::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto type = get_type();
        // RFC 9001 19.3.  ACK Frames

        // ACK Frame {
        //   Type (i) = 0x02..0x03,
        //   Largest Acknowledged (i),
        //   ACK Delay (i),
        //   ACK Range Count (i),
        //   First ACK Range (i),
        //   ACK Range (..) ...,
        //   [ECN Counts (..)],
        // }
        // Figure 25: ACK Frame Format

        constexpr char constexpr_largest_ack[] = "largest ack";
        constexpr char constexpr_ack_delay[] = "ack delay";
        constexpr char constexpr_ack_range_count[] = "ack range count";
        constexpr char constexpr_first_ack_range[] = "first ack range";

        constexpr char constexpr_ecn_counts[] = "ECN Counts";
        constexpr char constexpr_ect0_count[] = "ect0 count";
        constexpr char constexpr_ect1_count[] = "ect1 count";
        constexpr char constexpr_ectce_count[] = "ect-ce count";

        payload pl;
        pl << new payload_member(new quic_encoded(uint64(0)), constexpr_largest_ack) << new payload_member(new quic_encoded(uint64(0)), constexpr_ack_delay)
           << new payload_member(new quic_encoded(uint64(0)), constexpr_ack_range_count)
           << new payload_member(new quic_encoded(uint64(0)), constexpr_first_ack_range);
        pl.read(stream, size, pos);

        uint64 largest_ack = pl.t_value_of<uint64>(constexpr_largest_ack);
        uint64 ack_delay = pl.t_value_of<uint64>(constexpr_ack_delay);
        uint64 ack_range_count = pl.t_value_of<uint64>(constexpr_ack_range_count);
        uint64 first_ack_range = pl.t_value_of<uint64>(constexpr_first_ack_range);

        basic_stream dbs;

        if (istraceable(category_net)) {
            dbs.printf("   > %s %I64i\n", constexpr_largest_ack, largest_ack);
            dbs.printf("   > %s %I64i\n", constexpr_ack_delay, ack_delay);
            dbs.printf("   > %s %I64i\n", constexpr_ack_range_count, ack_range_count);
            dbs.printf("   > %s %I64i\n", constexpr_first_ack_range, first_ack_range);
        }

        constexpr char constexpr_ack_ranges[] = "ack ranges";
        constexpr char constexpr_gap[] = "gap";
        constexpr char constexpr_range_length[] = "range length";

        // RFC 9001 19.3.1.  ACK Ranges
        for (uint64 i = 0; i < ack_range_count; i++) {
            // ACK Range {
            //   Gap (i),
            //   ACK Range Length (i),
            // }
            // Figure 26: ACK Ranges
            payload ack_ranges;
            ack_ranges << new payload_member(new quic_encoded(uint64(0)), constexpr_gap)
                       << new payload_member(new quic_encoded(uint64(0)), constexpr_range_length);
            ack_ranges.read(stream, size, pos);

            uint64 gap = ack_ranges.t_value_of<uint64>(constexpr_gap);
            uint64 range_length = ack_ranges.t_value_of<uint64>(constexpr_range_length);

            if (istraceable(category_net)) {
                dbs.printf("   > %s\n", constexpr_ack_ranges);
                dbs.printf("    > %s %I64i\n", constexpr_gap, gap);
                dbs.printf("    > %s %I64i\n", constexpr_range_length, range_length);
            }
        }

        // RFC 9001 19.3.2.  ECN Counts
        if ((quic_frame_type_ack + 1) == type) {
            // ECN Counts {
            //   ECT0 Count (i),
            //   ECT1 Count (i),
            //   ECN-CE Count (i),
            // }
            // Figure 27: ECN Count Format
            payload ecn_counts;
            ecn_counts << new payload_member(new quic_encoded(uint64(0)), constexpr_ect0_count)
                       << new payload_member(new quic_encoded(uint64(0)), constexpr_ect1_count)
                       << new payload_member(new quic_encoded(uint64(0)), constexpr_ectce_count);
            ecn_counts.read(stream, size, pos);

            uint64 ect0_count = ecn_counts.t_value_of<uint64>(constexpr_ect0_count);
            uint64 ect1_count = ecn_counts.t_value_of<uint64>(constexpr_ect1_count);
            uint64 ectce_count = ecn_counts.t_value_of<uint64>(constexpr_ectce_count);

            if (istraceable(category_net)) {
                dbs.printf("   > %s\n", constexpr_ecn_counts);
                dbs.printf("    > %s %I64i\n", constexpr_ect0_count, ect0_count);
                dbs.printf("    > %s %I64i\n", constexpr_ect1_count, ect1_count);
                dbs.printf("    > %s %I64i\n", constexpr_ectce_count, ectce_count);
            }
        }

        if (istraceable(category_net)) {
            trace_debug_event(category_net, net_event_quic_dump, &dbs);
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_frame_ack::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    return ret;
}

}  // namespace net
}  // namespace hotplace
