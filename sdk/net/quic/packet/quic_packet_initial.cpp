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
#include <sdk/net/quic/quic.hpp>
#include <sdk/net/quic/quic_encoded.hpp>
#include <sdk/net/quic/quic_frame.hpp>
#include <sdk/net/quic/quic_frames.hpp>
#include <sdk/net/quic/quic_packet.hpp>
#include <sdk/net/tls1/tls_session.hpp>
#include <sdk/net/tls1/types.hpp>

namespace hotplace {
namespace net {

quic_packet_initial::quic_packet_initial(tls_session* session) : quic_packet(quic_packet_type_initial, session), _length(0), _sizeof_length(0) {}

quic_packet_initial::quic_packet_initial(const quic_packet_initial& rhs)
    : quic_packet(rhs), _token(rhs._token), _length(rhs._length), _sizeof_length(rhs._sizeof_length) {}

return_t quic_packet_initial::read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto& protection = session->get_tls_protection();
        auto tagsize = protection.get_tag_size();

        ret = quic_packet::read(dir, stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        binary_t bin_unprotected_header;
        binary_t bin_protected_header;
        binary_t bin_pn;
        binary_t plaintext;
        binary_t bin_tag;

        size_t offset_initial = pos;
        size_t offset_pnpayload = 0;
        byte_t ht = stream[0];

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
            pl.select(constexpr_tag)->reserve(tagsize);
            pl.read(stream, size, pos);

            pl.select(constexpr_token)->get_payload_encoded()->get_variant().to_binary(_token);
            _length = pl.select(constexpr_len)->get_payload_encoded()->value();
            pl.select(constexpr_payload)->get_variant().to_binary(_payload);
            pl.select(constexpr_tag)->get_variant().to_binary(bin_tag);

            offset_pnpayload = pl.offset_of(constexpr_payload);
            _sizeof_length = pl.select(constexpr_len)->get_space();  // support longer size
        }

        if (from_any != dir) {
            // protection mask
            binary_t bin_mask;
            ret = protection.protection_mask(session, dir, stream + (offset_initial + offset_pnpayload + 4), 16, bin_mask, 5);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // unprotect ht
            if (quic_packet_field_hf & ht) {
                _ht ^= bin_mask[0] & 0x0f;
            } else {
                _ht ^= bin_mask[0] & 0x1f;
            }
            // unprotect pn
            auto pn_length = get_pn_length(_ht);
            {
                // RFC 9001 5.4.2.  Header Protection Sample
                // Packet Number Length = 2
                //   ... | PN1 PN2 | PL1 PL2 PL3 PL4 ...
                //                 \- pnpad
                // Packet Number Length = 1
                //   ... | PN1 | PL1 PL2 PL3 PL4 PL5 ...
                //              \ pnpad
                // stream
                //   ... | PN1 PN2 PN3 PN4 | PL1 PL2 ...
                binary_append(bin_pn, &_payload[0], 4);
                memxor(&bin_pn[0], &bin_mask[1], 4);
                bin_pn.resize(pn_length);
                _pn = t_binary_to_integer<uint32>(bin_pn);
                _payload.erase(_payload.begin(), _payload.begin() + pn_length);
            }

            // aad
            write(from_any, bin_unprotected_header);

            // decrypt
            binary_t bin_plaintext;
            {
                auto& protection = session->get_tls_protection();
                protection.set_item(tls_context_quic_dcid, get_dcid());
                protection.calc(session, tls_hs_client_hello, dir);  // calc initial keys

                size_t pos = 0;
                ret = protection.decrypt(session, dir, &_payload[0], _payload.size(), pos, bin_plaintext, bin_unprotected_header, bin_tag);
                if (errorcode_t::success == ret) {
                    _payload = std::move(bin_plaintext);
                } else {
                    _payload.clear();
                }
            }

            dump();

            {
                size_t pos = 0;
                quic_frames frames;
                frames.read(session, dir, &_payload[0], _payload.size(), pos);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet_initial::write(tls_direction_t dir, binary_t& packet) {
    return_t ret = errorcode_t::success;
    __try2 {
        binary_t header;
        binary_t ciphertext;
        binary_t tag;

        packet.clear();

        ret = write(dir, header, ciphertext, tag);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        binary_append(packet, header);
        binary_append(packet, ciphertext);
        binary_append(packet, tag);
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
            ret = quic_packet::write(dir, bin_unprotected_header);

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
        if ((from_any != dir) && (get_payload().size() >= 0x10)) {
            binary_t bin_plaintext;
            binary_t bin_tag;
            binary_t bin_mask;

            // AEAD
            protection.encrypt(session, dir, get_payload(), bin_plaintext, bin_unprotected_header, bin_tag);

            // Header Protection
            {
                uint8 ht = _ht;
                auto adj = 4 - pn_length;
                binary_append(bin_pn, &bin_plaintext[0], adj);

                // calcurate mask
                ret = protection.protection_mask(session, dir, &bin_plaintext[adj], bin_plaintext.size(), bin_mask, 5);
                if (errorcode_t::success != ret) {
                    __leave2;
                }

                if (quic_packet_field_hf & ht) {
                    ht ^= bin_mask[0] & 0x0f;
                } else {
                    ht ^= bin_mask[0] & 0x1f;
                }
                memxor(&bin_pn[0], &bin_mask[1], 4);

                // encode packet length
                bin_protected_header[0] = ht;
                bin_pn.resize(pn_length);

                // encode packet number
                payload pl;
                pl << new payload_member(new quic_encoded(get_token()))      //
                   << new payload_member(new quic_encoded(len, prefix_len))  //
                   << new payload_member(bin_pn);

                // protected header
                pl.write(bin_protected_header);
            }

            header = std::move(bin_protected_header);
            ciphertext = std::move(bin_plaintext);
            tag = std::move(bin_tag);

            dump();

            size_t pos = 0;
            quic_frames frames;
            frames.read(session, dir, &_payload[0], _payload.size(), pos);
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
    if (istraceable()) {
        quic_packet::dump();

        auto session = get_session();
        basic_stream dbs;

        // token
        dbs.printf(" > token (len %zi)\n", _token.size());
        dump_memory(_token, &dbs, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
        // length = packet number + payload
        auto len = get_length();
        dbs.printf(" > length %I64i\n", len);
        // packet number
        dbs.printf(" > packet number %08x\n", get_pn());
        // payload
        dbs.printf(" > payload (len %zi)\n", _payload.size());
        dump_memory(_payload, &dbs, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);

        trace_debug_event(category_quic, quic_event_dump, &dbs);
    }
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
