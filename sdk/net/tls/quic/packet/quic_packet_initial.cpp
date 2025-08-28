/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file    {file}
 * @author  Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          RFC 9000 17.2.2.  Initial Packet
 *            Initial Packet {
 *              Header Form (1) = 1,
 *              Fixed Bit (1) = 1,
 *              Long Packet Type (2) = 0,
 *              Reserved Bits (2),
 *              Packet Number Length (2),
 *              Version (32),
 *              Destination Connection ID Length (8),
 *              Destination Connection ID (0..160),
 *              Source Connection ID Length (8),
 *              Source Connection ID (0..160),
 *
 *              Token Length (i),
 *              Token (..),
 *              Length (i),
 *              Packet Number (8..32),
 *              Packet Payload (8..),
 *            }
 *
 *                                Figure 15: Initial Packet
 *
 *          RFC 9001 5.4.2.  Header Protection Sample
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/segmentation.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/quic/frame/quic_frame.hpp>
#include <sdk/net/tls/quic/frame/quic_frames.hpp>
#include <sdk/net/tls/quic/packet/quic_packet_initial.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/quic_session.hpp>
#include <sdk/net/tls/tls_session.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_token[] = "token";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_payload[] = "pn + payload";
constexpr char constexpr_tag[] = "tag";

quic_packet_initial::quic_packet_initial(tls_session* session) : quic_packet(quic_packet_type_initial, session), _length(0), _sizeof_length(0) {}

quic_packet_initial::quic_packet_initial(const quic_packet_initial& rhs)
    : quic_packet(rhs), _token(rhs._token), _length(rhs._length), _sizeof_length(rhs._sizeof_length) {}

quic_packet_initial::~quic_packet_initial() {}

return_t quic_packet_initial::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, size_t& pos_unprotect) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if ((nullptr == session) || (false == is_unidirection(dir))) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();
        auto tagsize = protection.get_tag_size();

        binary_t bin_unprotected_header;
        binary_t bin_protected_header;

        size_t ppos = pos;
        size_t offset_pnpayload = 0;

        {
            payload pl;
            pl << new payload_member(new quic_encoded(binary_t()), constexpr_token)  // Token Length (i), Token (..)
               << new payload_member(new quic_encoded(uint64(0)), constexpr_len)     // Length (i)
               << new payload_member(binary_t(), constexpr_payload)                  // Packet Number (8..32), Packet Payload (8..)
               << new payload_member(binary_t(), constexpr_tag);
            pl.reserve(constexpr_tag, tagsize);
            pl.read(stream, size, pos);

            pl.get_binary(constexpr_token, _token);
            _length = pl.t_value_of<uint64>(constexpr_len);
            pl.get_binary(constexpr_payload, _payload);
            pl.get_binary(constexpr_tag, _tag);

            offset_pnpayload = pl.offset_of(constexpr_payload);
            _sizeof_length = pl.get_space(constexpr_len);  // support longer size

            pos_unprotect = (ppos + offset_pnpayload + 4);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet_initial::do_read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, size_t pos_unprotect) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();

        if (from_client == dir) {
            if (secrets.get(tls_secret_initial_quic_client_hp).empty()) {
                secrets.assign(tls_context_quic_dcid, get_dcid());
                protection.calc(session, tls_hs_client_hello, dir);  // calc initial keys
            } else {
                if (false == get_dcid().empty()) {
                    secrets.assign(tls_context_server_cid, get_dcid());
                }
            }
        } else if (from_server == dir) {
            if (false == get_dcid().empty()) {
                if (secrets.get(tls_context_client_cid).empty()) {
                    secrets.assign(tls_context_client_cid, get_dcid());
                }
            }
        }

        ret = do_unprotect(dir, stream, size, pos_unprotect, protection_initial);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        dump();

        size_t tpos = 0;
        ret = get_quic_frames().read(dir, &_payload[0], _payload.size(), tpos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (get_quic_frames().is_significant()) {
            session->get_quic_session().get_pkns(protection_initial).add(get_pn());
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_packet_initial::do_write_body(tls_direction_t dir, binary_t& body) {
    return_t ret = errorcode_t::success;
    get_quic_frames().write(dir, body);
    return ret;
}

return_t quic_packet_initial::do_estimate() {
    return_t ret = errorcode_t::success;

    auto session = get_session();
    auto& protection = session->get_tls_protection();
    auto tagsize = protection.get_tag_size();
    auto size = session->get_quic_session().get_setting().get(quic_param_max_udp_payload_size);
    auto estimate = estimate_quic_packet_size(get_type(), _dcid.size(), _scid.size(), _token.size(), get_pn_length(), size, tagsize);

    get_fragment().use(estimate - size);  // quic packet header + tag

    return ret;
}

return_t quic_packet_initial::do_write(tls_direction_t dir, binary_t& header, binary_t& ciphertext, binary_t& tag) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto& protection = session->get_tls_protection();
        auto tagsize = protection.get_tag_size();

        binary_t bin_unprotected_header = std::move(header);
        binary_t bin_protected_header;
        uint8 pn_length = 0;
        uint64 len = 0;
        binary_t bin_pn;
        uint8 prefix_len = _sizeof_length >> 1;

        // unprotected header
        {
            // protected header
            bin_protected_header = bin_unprotected_header;

            // packet number length + payload size + AEAD tag size
            pn_length = get_pn_length();
            len = pn_length + get_payload().size() + tagsize;

            // packet number
            binary_load(bin_pn, pn_length, _pn, hton32);

            // unprotected header
            payload pl;
            pl << new payload_member(new quic_encoded(get_token()))      // Token Length (i), Token (..)
               << new payload_member(new quic_encoded(len, prefix_len))  // Length (i)
               << new payload_member(bin_pn);                            // Packet Number (8..32)
            pl.write(bin_unprotected_header);
        }

        /**
         * RFC 9001 5.4.2.  Header Protection Sample
         *
         *  protected payload is at least 4 bytes longer than the sample required for header protection
         *
         *  in sampling header ciphertext for header protection, the Packet Number field is
         *  assumed to be 4 bytes long (its maximum possible encoded length).
         */
        if (is_unidirection(dir) && (get_payload().size() > 0)) {
            auto session = get_session();
            auto& protection = session->get_tls_protection();

            binary_t bin_ciphertext;
            binary_t bin_tag;
            binary_t bin_mask;

            // AEAD
            ret = protection.encrypt(session, dir, get_payload(), bin_ciphertext, bin_unprotected_header, bin_tag, protection_initial);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // Header Protection
            {
                uint8 ht = _ht;
                ret = header_protect(dir, protection_initial, bin_ciphertext, ht, pn_length, bin_pn, bin_protected_header);
                if (errorcode_t::success != ret) {
                    __leave2;
                }

                // encode packet number
                payload pl;
                pl << new payload_member(new quic_encoded(get_token()))      //
                   << new payload_member(new quic_encoded(len, prefix_len))  //
                   << new payload_member(bin_pn);

                // protected header
                pl.write(bin_protected_header);
            }

            header = std::move(bin_protected_header);
            ciphertext = std::move(bin_ciphertext);
            tag = std::move(bin_tag);
        } else {
            header = std::move(bin_unprotected_header);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void quic_packet_initial::dump() {
#if defined DEBUG
    if (istraceable(trace_category_net)) {
        quic_packet::dump();

        auto session = get_session();
        basic_stream dbs;

        // token
        dbs.println(" > token (len %zi)", _token.size());
        if (check_trace_level(loglevel_debug)) {
            dump_memory(_token, &dbs, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
        }
        // length = packet number + payload
        auto len = get_length();
        dbs.println(" > length %I64i", len);
        // packet number
        dbs.println(" > packet number 0x%08x (%i)", get_pn(), get_pn());
        // payload
        dbs.println(" > payload (len %zi)", _payload.size());
        if (check_trace_level(loglevel_debug)) {
            dump_memory(_payload, &dbs, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
        }

        trace_debug_event(trace_category_net, trace_event_quic_packet, &dbs);
    }
#endif
}

quic_packet_initial& quic_packet_initial::set_token(const binary_t& token) {
    _token = token;
    return *this;
}

const binary_t& quic_packet_initial::get_token() { return _token; }

uint64 quic_packet_initial::get_length() {
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    auto tagsize = protection.get_tag_size();
    return get_pn_length() + _payload.size() + tagsize;
}

}  // namespace net
}  // namespace hotplace
