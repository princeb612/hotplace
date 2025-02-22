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
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/quic/quic.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

quic_packet_initial::quic_packet_initial(tls_session* session) : quic_packet(quic_packet_type_initial, session), _length(0) {}

quic_packet_initial::quic_packet_initial(const quic_packet_initial& rhs) : quic_packet(rhs), _token(rhs._token), _length(rhs._length) {}

return_t quic_packet_initial::read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto& protection = session->get_tls_protection();

        ret = quic_packet::read(dir, stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        binary_t bin_unprotected_header;
        binary_t bin_protected_header;
        binary_t bin_pn;
        binary_t decrypted;
        binary_t bin_tag;

        size_t offset_initial = pos;
        byte_t ht = stream[0];

        // RFC 9001 5.4.2.  Header Protection Sample
        uint8 pn_length = dir ? 4 : get_pn_length(stream[0]);

        constexpr char constexpr_token[] = "token";
        constexpr char constexpr_len[] = "len";
        constexpr char constexpr_pn[] = "pn";
        constexpr char constexpr_payload[] = "payload";
        constexpr char constexpr_tag[] = "tag";

        payload pl;
        pl << new payload_member(new quic_encoded(binary_t()), constexpr_token) << new payload_member(new quic_encoded(uint64(0)), constexpr_len)
           << new payload_member(binary_t(), constexpr_pn) << new payload_member(binary_t(), constexpr_payload)
           << new payload_member(binary_t(), constexpr_tag);
        pl.select(constexpr_pn)->reserve(pn_length);
        pl.select(constexpr_tag)->reserve(16);
        pl.read(stream, size, pos);

        pl.select(constexpr_token)->get_payload_encoded()->get_variant().to_binary(_token);
        _length = pl.select(constexpr_len)->get_payload_encoded()->value();
        pl.select(constexpr_pn)->get_variant().to_binary(bin_pn);  // 8..32
        _pn = t_binary_to_integer<uint32>(bin_pn);
        pl.select(constexpr_payload)->get_variant().to_binary(_payload);
        pl.select(constexpr_tag)->get_variant().to_binary(bin_tag);

        if (dir) {
            binary_t bin_mask;
            ret = protection.protection_mask(session, dir, &_payload[0], _payload.size(), bin_mask, 5);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            if (quic_packet_field_hf & ht) {
                _ht ^= bin_mask[0] & 0x0f;
            } else {
                _ht ^= bin_mask[0] & 0x1f;
            }
            memxor(&bin_pn[0], &bin_mask[1], 4);

            // Packet Number Length = 2
            // PN1 PN2 PN3 PN4 | PL1 PL2 ...
            // PN1 PN2 | PL1 PL2 PL3 PL4 ...

            // Packet Number Length = 1
            // PN1 PN2 PN3 PN4 | PL1 PL2 ...
            // PN1 | PL1 PL2 PL3 PL4 PL5 ...

            auto pn_length = get_pn_length(_ht);
            auto adj = 4 - pn_length;
            if (adj) {
                const byte_t* begin = stream + offset_initial + pl.offset_of(constexpr_pn) + pn_length;
                _payload.insert(_payload.begin(), begin, begin + adj);
                bin_pn.resize(pn_length);
            }

            _pn = t_binary_to_integer<uint32>(bin_pn);

            // unprotected header
            write(from_any, bin_unprotected_header);

            // AEAD
            binary_t bin_decrypted;
            {
                // ret = get_protection()->decrypt(dir, _pn, _payload, bin_decrypted, bin_unprotected_header, bin_tag);

                auto& protection = session->get_tls_protection();
                protection.set_item(tls_context_quic_dcid, get_dcid());
                protection.calc(session, tls_hs_client_hello, dir);

                size_t pos = 0;
                ret = protection.decrypt(session, dir, &_payload[0], _payload.size(), pos, bin_decrypted, bin_unprotected_header, bin_tag);
                if (errorcode_t::success == ret) {
                    _payload = std::move(bin_decrypted);
                } else {
                    _payload.clear();
                }
            }

            dump();

            {
                size_t pos = 0;
                while (errorcode_t::success == quic_dump_frame(session, &_payload[0], _payload.size(), pos)) {
                };
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

        binary_t bin_unprotected_header;
        binary_t bin_protected_header;
        uint8 pn_length = 0;
        uint64 len = 0;
        binary_t bin_pn;

        // unprotected header
        {
            ret = quic_packet::write(dir, bin_unprotected_header);

            // protected header
            bin_protected_header = bin_unprotected_header;

            // packet number length + payload size + AEAD tag size
            pn_length = get_pn_length();
            len = pn_length + get_payload().size() + 16;

            // packet number
            binary_load(bin_pn, pn_length, _pn, hton32);

            // unprotected header
            payload pl;
            pl << new payload_member(new quic_encoded(get_token())) << new payload_member(new quic_encoded(len)) << new payload_member(bin_pn);
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
        if (dir && (get_payload().size() >= 0x10)) {
            binary_t bin_ciphertext;
            binary_t bin_tag;
            binary_t bin_mask;

            // AEAD
            protection.encrypt(session, dir, get_payload(), bin_ciphertext, bin_unprotected_header, bin_tag);

            // Header Protection
            {
                uint8 ht = _ht;
                auto adj = 4 - pn_length;
                binary_append(bin_pn, &bin_ciphertext[0], adj);

                // calcurate mask
                ret = protection.protection_mask(session, dir, &bin_ciphertext[adj], bin_ciphertext.size(), bin_mask, 5);
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
                pl << new payload_member(new quic_encoded(get_token()))  //
                   << new payload_member(new quic_encoded(len))          //
                   << new payload_member(bin_pn);

                // protected header
                pl.write(bin_protected_header);
            }

            header = std::move(bin_protected_header);
            ciphertext = std::move(bin_ciphertext);
            tag = std::move(bin_tag);

            dump();

            auto session = get_session();
            size_t pos = 0;
            while (errorcode_t::success == quic_dump_frame(session, &_payload[0], _payload.size(), pos)) {
            };
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

uint64 quic_packet_initial::get_length() { return get_pn_length() + _payload.size() + 16; }

}  // namespace net
}  // namespace hotplace
