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
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_new_token.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_type[] = "type";
constexpr char constexpr_token[] = "token";

/**
 * RFC 9000 19.7.  NEW_TOKEN Frames
 * NEW_TOKEN Frame {
 *   Type (i) = 0x07,
 *   Token Length (i),
 *   Token (..),
 * }
 * Figure 31: NEW_TOKEN Frame Format
 */

quic_frame_new_token::quic_frame_new_token(tls_session* session) : quic_frame(quic_frame_type_new_token, session) {}

return_t quic_frame_new_token::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        payload pl;
        pl << new payload_member(new quic_encoded(binary_t()), constexpr_token);
        pl.read(stream, size, pos);

        binary_t token;
        pl.get_binary(constexpr_token, token);

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("   > %s (%zi) %s", constexpr_token, token.size(), base16_encode(token).c_str());
            if (check_trace_level(loglevel_debug)) {
                dump_memory(token, &dbs, 16, 5, 0x0, dump_notrunc);
            }
            trace_debug_event(trace_category_net, trace_event_quic_frame, &dbs);
        }
#endif
        if (token.empty()) {
            // FRAME_ENCODING_ERROR
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_frame_new_token::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto type = get_type();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        openssl_prng prng;
        binary_t token;
        prng.random(token, 70);

        payload pl;
        pl << new payload_member(new quic_encoded(uint8(type)), constexpr_type)  //
           << new payload_member(new quic_encoded(token), constexpr_token);
        pl.write(bin);

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
