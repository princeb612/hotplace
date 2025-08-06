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
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/quic/frame/quic_frame.hpp>
#include <sdk/net/tls/quic/frame/quic_frames.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/quic_session.hpp>
#include <sdk/net/tls/tls_session.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

quic_packet_initial::quic_packet_initial(tls_session* session) : quic_packet(quic_packet_type_initial, session), _length(0), _sizeof_length(0) {}

quic_packet_initial::quic_packet_initial(const quic_packet_initial& rhs)
    : quic_packet(rhs), _token(rhs._token), _length(rhs._length), _sizeof_length(rhs._sizeof_length) {}

quic_packet_initial::~quic_packet_initial() {}

return_t quic_packet_initial::read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();
        auto tagsize = protection.get_tag_size();

        byte_t ht = stream[pos];
        ret = read_common_header(dir, stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        binary_t bin_unprotected_header;
        binary_t bin_protected_header;
        binary_t bin_tag;

        size_t ppos = pos;
        size_t offset_pnpayload = 0;

        {
            constexpr char constexpr_token[] = "token";
            constexpr char constexpr_len[] = "len";
            constexpr char constexpr_payload[] = "pn + payload";
            constexpr char constexpr_tag[] = "tag";

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
            pl.get_binary(constexpr_tag, bin_tag);

            offset_pnpayload = pl.offset_of(constexpr_payload);
            _sizeof_length = pl.get_space(constexpr_len);  // support longer size
        }

        if (from_any == dir) {
            __leave2;
        }

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

        ret = header_unprotect(dir, stream + (ppos + offset_pnpayload + 4), 16, protection_initial, _ht, _pn, _payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // aad
        write_header(bin_unprotected_header);

        // decrypt
        binary_t bin_plaintext;
        {
            size_t pos = 0;
            ret = protection.decrypt(session, dir, &_payload[0], _payload.size(), pos, bin_plaintext, bin_unprotected_header, bin_tag, protection_initial);
            if (errorcode_t::success == ret) {
                _payload = std::move(bin_plaintext);
            } else {
                _payload.clear();
            }
        }

        dump();

        {
            size_t pos = 0;
            ret = get_quic_frames().read(dir, &_payload[0], _payload.size(), pos);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        session->get_quic_session().get_pkns(protection_initial).add(get_pn());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet_initial::write(tls_direction_t dir, binary_t& header, binary_t& ciphertext, binary_t& tag) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        get_quic_frames().write(dir, _payload);

        auto& protection = session->get_tls_protection();
        auto tagsize = protection.get_tag_size();

        binary_t bin_unprotected_header;
        binary_t bin_protected_header;
        uint8 pn_length = 0;
        uint64 len = 0;
        binary_t bin_pn;
        uint8 prefix_len = _sizeof_length >> 1;

        // unprotected header
        {
            ret = write_common_header(bin_unprotected_header);

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
        if ((from_any != dir) && (get_payload().size() > 0)) {
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
                ret = header_protect(dir, bin_ciphertext, protection_initial, ht, pn_length, bin_pn, bin_protected_header);
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
        dump_memory(_token, &dbs, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
        // length = packet number + payload
        auto len = get_length();
        dbs.println(" > length %I64i", len);
        // packet number
        dbs.println(" > packet number %08x", get_pn());
        // payload
        dbs.println(" > payload (len %zi)", _payload.size());
        dump_memory(_payload, &dbs, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);

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
