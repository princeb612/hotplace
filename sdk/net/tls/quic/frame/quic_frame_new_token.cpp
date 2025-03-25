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

quic_frame_new_token::quic_frame_new_token(tls_session* session) : quic_frame(quic_frame_type_new_token, session) {}

return_t quic_frame_new_token::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        // 19.7.  NEW_TOKEN Frames

        // NEW_TOKEN Frame {
        //   Type (i) = 0x07,
        //   Token Length (i),
        //   Token (..),
        // }
        // Figure 31: NEW_TOKEN Frame Format
        constexpr char constexpr_token[] = "token";

        payload pl;
        pl << new payload_member(new quic_encoded(binary_t()), constexpr_token);
        pl.read(stream, size, pos);

        binary_t token;
        pl.get_binary(constexpr_token, token);

        if (istraceable(category_net)) {
            basic_stream dbs;
            dbs.println("   > %s (%zi)", constexpr_token, token.size());
            dump_memory(token, &dbs, 16, 5, 0x0, dump_notrunc);
            trace_debug_event(category_net, net_event_quic_dump, &dbs);
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_frame_new_token::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    return ret;
}

}  // namespace net
}  // namespace hotplace
