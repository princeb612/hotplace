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
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshakes.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_type[] = "type";
constexpr char constexpr_length[] = "length";
constexpr char constexpr_offset[] = "offset";
constexpr char constexpr_crypto_data[] = "crypto data";

quic_frame_crypto::quic_frame_crypto(quic_packet* packet) : quic_frame(quic_frame_type_crypto, packet) {}

return_t quic_frame_crypto::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_packet()->get_session();
        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();

        // 19.6.  CRYPTO Frames

        // CRYPTO Frame {
        //   Type (i) = 0x06,
        //   Offset (i),
        //   Length (i),
        //   Crypto Data (..),
        // }
        // Figure 30: CRYPTO Frame Format

        // defragment scenario
        //   packet frame crypto
        //     - offset 0, length 1023
        //       - encrypted_extensions  ... ok
        //       - certificate           ... ok
        //       - certificate_verify    ... error (fragment detection here, offset of the next packet 1023 expected)
        //   packet frame crypto
        //     - offset 1023, length 185 ... expected offset 1023, defragment
        //       - certificate_verify    ... ok

        payload pl;
        pl << new payload_member(new quic_encoded(uint64(0)), constexpr_offset)  //
           << new payload_member(new quic_encoded(uint64(0)), constexpr_length)  //
           << new payload_member(binary_t(), constexpr_crypto_data);
        pl.set_reference_value(constexpr_crypto_data, constexpr_length);
        pl.read(stream, size, pos);

        uint64 offset = pl.t_value_of<uint64>(constexpr_offset);
        uint64 length = pl.t_value_of<uint64>(constexpr_length);
        binary_t crypto_data;
        pl.get_binary(constexpr_crypto_data, crypto_data);

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("   > %s 0x%I64x (%I64i)", constexpr_offset, offset, offset);
            dbs.println("   > %s 0x%I64x (%I64i)", constexpr_length, length, length);
            dbs.println("   > %s 0x%zx (%zi)", constexpr_crypto_data, crypto_data.size(), crypto_data.size());
            dump_memory(crypto_data, &dbs, 16, 5, 0x0, dump_notrunc);
            trace_debug_event(trace_category_net, trace_event_quic_frame, &dbs);
        }
#endif

        if (offset) {
            binary_t defragment;
            secrets.consume(tls_context_fragment, defragment);
            binary_append(defragment, crypto_data);
            crypto_data = std::move(defragment);
        }

        size_t hpos = 0;
        while (errorcode_t::success == tls_dump_handshake(session, dir, &crypto_data[0], crypto_data.size(), hpos)) {
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_frame_crypto::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    auto session = get_packet()->get_session();

    binary_t crypto_data;
    get_handshakes().write(session, dir, crypto_data);

    payload pl;
    pl << new payload_member(new quic_encoded(uint8(get_type())), constexpr_type)             //
       << new payload_member(new quic_encoded(uint64(0)), constexpr_offset)                   //
       << new payload_member(new quic_encoded(uint64(crypto_data.size())), constexpr_length)  //
       << new payload_member(crypto_data, constexpr_crypto_data);
    pl.write(bin);

    return ret;
}

quic_frame_crypto& quic_frame_crypto::operator<<(tls_handshake* handshake) {
    get_handshakes() << handshake;
    return *this;
}

tls_handshakes& quic_frame_crypto::get_handshakes() { return _handshakes; }

}  // namespace net
}  // namespace hotplace
