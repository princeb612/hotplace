/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_new_connection_id.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet.hpp>
#include <hotplace/sdk/net/tls/quic/quic.hpp>
#include <hotplace/sdk/net/tls/quic/quic_encoded.hpp>
#include <hotplace/sdk/net/tls/quic_session.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_type[] = "type";
constexpr char constexpr_sequence_number[] = "sequence number";
constexpr char constexpr_retire_prior_to[] = "retire prior to";
constexpr char constexpr_connection_id_len[] = "connection id length";
constexpr char constexpr_connection_id[] = "connection id";
constexpr char constexpr_stateless_reset_token[] = "stateless reset token";

/**
 * RFC 9000 19.15.  NEW_CONNECTION_ID Frames
 *   NEW_CONNECTION_ID Frame {
 *     Type (i) = 0x18,
 *     Sequence Number (i),
 *     Retire Prior To (i),
 *     Length (8),
 *     Connection ID (8..160),
 *     Stateless Reset Token (128),
 *   }
 *   Figure 39: NEW_CONNECTION_ID Frame Format
 */

quic_frame_new_connection_id::quic_frame_new_connection_id(tls_session* session) : quic_frame(quic_frame_type_new_connection_id, session) {}

quic_frame_new_connection_id::~quic_frame_new_connection_id() {}

return_t quic_frame_new_connection_id::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        payload pl;
        pl << new payload_member(new quic_encoded(uint64(0)), constexpr_sequence_number)  //
           << new payload_member(new quic_encoded(uint64(0)), constexpr_retire_prior_to)  //
           << new payload_member(uint8(0), constexpr_connection_id_len)                   //
           << new payload_member(binary_t(), constexpr_connection_id)                     //
           << new payload_member(binary_t(), constexpr_stateless_reset_token);
        pl.set_reference_value(constexpr_connection_id, constexpr_connection_id_len);
        pl.reserve(constexpr_stateless_reset_token, 16);  // 128 >> 3
        pl.read(stream, size, pos);

        uint64 sequence_number = 0;
        uint64 retire_prior_to = 0;
        binary_t connection_id;
        binary_t stateless_reset_token;

        sequence_number = pl.t_value_of<uint64>(constexpr_sequence_number);
        retire_prior_to = pl.t_value_of<uint64>(constexpr_retire_prior_to);
        pl.get_binary(constexpr_connection_id, connection_id);
        pl.get_binary(constexpr_stateless_reset_token, stateless_reset_token);

        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();

        auto& tracker = session->get_quic_session().get_cid_tracker();
        if (tracker.empty()) {
            throw exception(internal_error);
        }
        uint64 prior = tracker.rbegin()->first;
        if (retire_prior_to != prior) {
            // TODO
            // PROTOCOL_VIOLATION
            throw exception(internal_error);
        }

        tracker.insert({sequence_number, connection_id});
        secrets.assign(tls_context_server_cid, connection_id);
        secrets.assign(tls_context_stateless_reset_token, stateless_reset_token);

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            trace_debug_event(trace_category_net, trace_event_quic_frame, [&](basic_stream& dbs) -> void {
                dbs.println("   > %s 0x%I64x (%I64i)", constexpr_sequence_number, sequence_number, sequence_number);
                dbs.println("   > %s 0x%I64x (%I64i)", constexpr_retire_prior_to, retire_prior_to, retire_prior_to);
                dbs.println("   > %s 0x%zx (%zi) %s", constexpr_connection_id, connection_id.size(), connection_id.size(),
                            base16_encode(connection_id).c_str());
                if (check_trace_level(loglevel_debug)) {
                    dump_memory(connection_id, &dbs, 16, 5, 0x0, dump_notrunc);
                }
                dbs.println("   > %s 0x%zx (%zi) %s", constexpr_stateless_reset_token, stateless_reset_token.size(), stateless_reset_token.size(),
                            base16_encode(stateless_reset_token).c_str());
                if (check_trace_level(loglevel_debug)) {
                    dump_memory(stateless_reset_token, &dbs, 16, 5, 0x0, dump_notrunc);
                }
            });
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t quic_frame_new_connection_id::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto type = get_type();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        auto session = get_session();
        auto& secrets = session->get_tls_protection().get_secrets();
        auto& tracker = session->get_quic_session().get_cid_tracker();
        if (tracker.empty()) {
            throw exception(internal_error);
        }

        uint64 prior = tracker.rbegin()->first;
        uint64 seq = prior + 1;
        binary_t cid;
        binary_t token;
        openssl_prng prng;
        prng.random(cid, 8);
        prng.random(token, 16);

        tracker.insert({seq, cid});
        secrets.assign(tls_context_server_cid, cid);
        secrets.assign(tls_context_stateless_reset_token, token);

        payload pl;
        pl << new payload_member(new quic_encoded(uint8(type)), constexpr_type)       //
           << new payload_member(new quic_encoded(seq), constexpr_sequence_number)    //
           << new payload_member(new quic_encoded(prior), constexpr_retire_prior_to)  //
           << new payload_member(new quic_encoded(cid), constexpr_connection_id)      //
           << new payload_member(new quic_encoded(token), constexpr_stateless_reset_token);
        pl.write(bin);

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            trace_debug_event(trace_category_net, trace_event_quic_frame, [&](basic_stream& dbs) -> void {
                dbs.println("\e[1;34m  + frame %s 0x%x(%i)\e[0m", tlsadvisor->quic_frame_type_string(type).c_str(), type, type);
            });
        }
#endif
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
