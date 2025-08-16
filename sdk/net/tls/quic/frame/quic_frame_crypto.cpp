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
#include <sdk/net/tls/quic/frame/quic_frame_crypto.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/quic_session.hpp>
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

quic_frame_crypto::quic_frame_crypto(quic_packet* packet) : quic_frame(quic_frame_type_crypto, packet), _extcd(nullptr) {}

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
            /**
             * about refeeding the tls_context_fragment
             *   see tls_handshake errorcode_t::fragmented
             *   sample scenario.
             *     EE CERT(fragment) CV FIN -> CERT(fragment) CV FIN
             */
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_frame_crypto::refer(external_crypto_data* data) {
    return_t ret = errorcode_t::success;
    if (nullptr == data) {
        ret = errorcode_t::invalid_parameter;
    } else {
        _extcd = data;
    }
    return ret;
}

return_t quic_frame_crypto::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == _extcd) {
            ret = errorcode_t::do_nothing;
            __leave2;
        }
        ret = do_write_body(dir, _extcd->stream, _extcd->size, _extcd->pos, bin);
    }
    __finally2 {}
    return ret;
}

return_t quic_frame_crypto::do_write_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, binary_t& bin) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // sketch
        //   layout
        //     packet header payload tag
        //     frame  header fragment
        //   calc
        //     exclude packet.header, packet.tag, frame.header

        auto session = get_packet()->get_session();
        auto udp_payload_size = session->get_quic_session().get_setting().get(quic_param_max_udp_payload_size);
        auto estsize = get_packet()->get_est_headertag_size();
        auto est_crypto_header_size = 0;
        {
            binary_t temp;
            quic_write_vle_int(get_type(), temp);
            quic_write_vle_int(pos, temp);
            quic_write_vle_int(udp_payload_size, temp);
            est_crypto_header_size = temp.size();
        }
        auto payload_size = udp_payload_size - estsize - est_crypto_header_size - 1;
        uint64 offset = pos;
        uint64 len = (size - pos >= payload_size) ? payload_size : size - pos;
        auto hdrsize = 0;

        payload pl;
        pl << new payload_member(new quic_encoded(uint8(get_type())), constexpr_type)  //
           << new payload_member(new quic_encoded(offset), constexpr_offset)           //
           << new payload_member(new quic_encoded(len), constexpr_length)              //
           << new payload_member(stream + offset, len, false, constexpr_crypto_data);
        pl.write(bin);

        pos += len;

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("\e[1;33m + CRYPTO");
            dbs.println("   > %s 0x%I64x (%I64i)", constexpr_offset, offset, offset);
            dbs.println("   > %s 0x%I64x (%I64i)\e[0m", constexpr_length, len, len);
            trace_debug_event(trace_category_net, trace_event_quic_frame, &dbs);
        }
#endif
    }
    __finally2 {}

    return ret;
}

}  // namespace net
}  // namespace hotplace
