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
#include <sdk/net/tls/quic/frame/quic_frame_new_connection_id.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

quic_frame_new_connection_id::quic_frame_new_connection_id(quic_packet* packet) : quic_frame(quic_frame_type_new_connection_id, packet) {}

return_t quic_frame_new_connection_id::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        constexpr char constexpr_sequence_number[] = "sequence number";
        constexpr char constexpr_retire_prior_to[] = "retire prior to";
        constexpr char constexpr_connection_id_len[] = "connection id length";
        constexpr char constexpr_connection_id[] = "connection id";
        constexpr char constexpr_stateless_reset_token[] = "stateless reset token";

        payload pl;
        pl << new payload_member(new quic_encoded(uint64(0)), constexpr_sequence_number)  //
           << new payload_member(new quic_encoded(uint64(0)), constexpr_retire_prior_to)  //
           << new payload_member(uint8(0), constexpr_connection_id_len)                   //
           << new payload_member(binary_t(), constexpr_connection_id)                     //
           << new payload_member(binary_t(), constexpr_stateless_reset_token);
        pl.set_reference_value(constexpr_connection_id, constexpr_connection_id_len);
        pl.reserve(constexpr_stateless_reset_token, 16);  // 128 >> 3
        pl.read(stream, size, pos);

        uint64 sequence_number = pl.t_value_of<uint64>(constexpr_sequence_number);
        uint64 retire_prior_to = pl.t_value_of<uint64>(constexpr_retire_prior_to);
        binary_t connection_id;
        pl.get_binary(constexpr_connection_id, connection_id);
        binary_t stateless_reset_token;
        pl.get_binary(constexpr_stateless_reset_token, stateless_reset_token);

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("   > %s 0x%I64x (%I64i)", constexpr_sequence_number, sequence_number, sequence_number);
            dbs.println("   > %s 0x%I64x (%I64i)", constexpr_retire_prior_to, retire_prior_to, retire_prior_to);
            dbs.println("   > %s 0x%zx (%zi)", constexpr_connection_id, connection_id.size(), connection_id.size());
            if (check_trace_level(loglevel_debug)) {
                dump_memory(connection_id, &dbs, 16, 5, 0x0, dump_notrunc);
            }
            dbs.println("   > %s 0x%zx (%zi)", constexpr_stateless_reset_token, stateless_reset_token.size(), stateless_reset_token.size());
            if (check_trace_level(loglevel_debug)) {
                dump_memory(stateless_reset_token, &dbs, 16, 5, 0x0, dump_notrunc);
            }
            trace_debug_event(trace_category_net, trace_event_quic_frame, &dbs);
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t quic_frame_new_connection_id::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {}
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
