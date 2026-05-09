/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   quic_frame_new_token.cpp
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
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_new_token.hpp>
#include <hotplace/sdk/net/tls/quic/quic.hpp>
#include <hotplace/sdk/net/tls/quic/quic_encoded.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>

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

quic_frame_new_token::~quic_frame_new_token() {}

return_t quic_frame_new_token::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .test_not_fail()
        .test_parameter([&]() -> bool { return (nullptr != stream) && (pos < size); })
        .run_trycatch([&]() -> return_t {
            payload pl;
            pl << new payload_member(new quic_encoded(binary_t()), constexpr_token);

            auto rc = pl.read(stream, size, pos);
            if (false == error_traits<return_t>::is_not_fail(rc)) {
                return rc;
            }

            binary_t token;
            pl.get_binary(constexpr_token, token);

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_quic_frame, [&](basic_stream& dbs) -> void {
                    dbs.println("   > %s (%zi) %s", constexpr_token, token.size(), base16_encode(token).c_str());
                    if (check_trace_level(loglevel_debug)) {
                        dump_memory(token, &dbs, 16, 5, 0x0, dump_notrunc);
                    }
                });
            }
#endif
            if (token.empty()) {
                // FRAME_ENCODING_ERROR
            }

            return success;
        });
    return pipeline.result();
}

return_t quic_frame_new_token::do_write_body(tls_direction_t dir, binary_t& bin) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .test_not_fail()
        .test_parameter([&]() -> bool { return true; })
        .run_trycatch([&]() -> return_t {
            auto type = get_type();

            openssl_prng prng;
            binary_t token;
            prng.random(token, 70);

            payload pl;
            pl << new payload_member(new quic_encoded(uint8(type)), constexpr_type)  //
               << new payload_member(new quic_encoded(token), constexpr_token);

            auto rc = pl.write(bin);
            if (false == error_traits<return_t>::is_not_fail(rc)) {
                return rc;
            }

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_quic_frame, [&](basic_stream& dbs) -> void {
                    tls_advisor* tlsadvisor = tls_advisor::get_instance();
                    dbs.println(ANSI_ESCAPE "1;34m  + frame %s 0x%x(%i)" ANSI_ESCAPE "0m", tlsadvisor->nameof_quic_frame(type).c_str(), type, type);
                });
            }
#endif

            return success;
        });
    return pipeline.result();
}

}  // namespace net
}  // namespace hotplace
