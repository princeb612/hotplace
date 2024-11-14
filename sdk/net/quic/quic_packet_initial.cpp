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
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/quic/quic.hpp>

namespace hotplace {
namespace net {

quic_packet_initial::quic_packet_initial() : quic_packet(quic_packet_type_initial), _length(0) {}

quic_packet_initial::quic_packet_initial(const quic_packet_initial& rhs) : quic_packet(rhs), _token(rhs._token), _length(rhs._length) {}

return_t quic_packet_initial::read(const byte_t* stream, size_t size, size_t& pos, uint32 mode) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = quic_packet::read(stream, size, pos);
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
        uint8 pn_length = mode ? 4 : get_pn_length(stream[0]);

        payload pl;
        pl << new payload_member(new quic_encoded(binary_t()), "token") << new payload_member(new quic_encoded(uint64(0)), "length")
           << new payload_member(binary_t(), "packet number") << new payload_member(binary_t(), "payload") << new payload_member(binary_t(), "tag");
        pl.select("packet number")->reserve(pn_length);
        pl.select("tag")->reserve(16);
        pl.read(stream, size, pos);

        pl.select("token")->get_variant().to_binary(_token);
        _length = pl.select("length")->get_payload_encoded()->value();
        pl.select("packet number")->get_variant().to_binary(bin_pn);  // 8..32
        _pn = t_binary_to_integer2<uint32>(bin_pn);
        pl.select("payload")->get_variant().to_binary(_payload);
        pl.select("tag")->get_variant().to_binary(bin_tag);

        if (mode) {
            binary_t bin_mask;
            get_protection()->hpmask(mode, &_payload[0], 16, bin_mask);
            get_protection()->hpencode(mode, bin_mask, _ht, bin_pn);  // update ht

            // Packet Number Length = 2
            // PN1 PN2 PN3 PN4 | PL1 PL2 ...
            // PN1 PN2 | PL1 PL2 PL3 PL4 ...

            // Packet Number Length = 1
            // PN1 PN2 PN3 PN4 | PL1 PL2 ...
            // PN1 | PL1 PL2 PL3 PL4 PL5 ...

            auto pn_length = get_pn_length(_ht);
            auto adj = 4 - pn_length;
            if (adj) {
                const byte_t* begin = stream + offset_initial + pl.offset_of("packet number") + pn_length;
                _payload.insert(_payload.begin(), begin, begin + adj);
                bin_pn.resize(pn_length);
            }

            _pn = t_binary_to_integer2<uint32>(bin_pn);

            // unprotected header
            write(bin_unprotected_header);

            // AEAD
            binary_t bin_decrypted;
            ret = get_protection()->decrypt(mode, _pn, _payload, bin_decrypted, bin_unprotected_header, bin_tag);
            if (errorcode_t::success == ret) {
                _payload = std::move(bin_decrypted);
            } else {
                _payload.clear();
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet_initial::write(binary_t& packet, uint32 mode) {
    return_t ret = errorcode_t::success;
    __try2 {
        binary_t header;
        binary_t encrypted;
        binary_t tag;

        packet.clear();

        ret = write(header, encrypted, tag, mode);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        binary_append(packet, header);
        binary_append(packet, encrypted);
        binary_append(packet, tag);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet_initial::write(binary_t& header, binary_t& encrypted, binary_t& tag, uint32 mode) {
    return_t ret = errorcode_t::success;
    __try2 {
        binary_t bin_unprotected_header;
        binary_t bin_protected_header;
        uint8 pn_length = 0;
        uint64 len = 0;
        binary_t bin_pn;

        // unprotected header
        {
            ret = quic_packet::write(bin_unprotected_header, mode);

            // protected header
            bin_protected_header = bin_unprotected_header;

            // packet number length + payload size + AEAD tag size
            pn_length = get_pn_length();
            len = pn_length + get_payload().size() + 16;

            // packet number
            binary_load(bin_pn, pn_length, _pn, hton32);

            // unprotected header
            payload pl;
            pl << new payload_member(new quic_encoded(get_token()), "token") << new payload_member(new quic_encoded(len), "length")
               << new payload_member(bin_pn, "packet number");
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
        if (mode && get_protection() && (get_payload().size() >= 0x10)) {
            binary_t bin_encrypted;
            binary_t bin_tag;

            // AEAD
            { get_protection()->encrypt(mode, _pn, get_payload(), bin_encrypted, bin_unprotected_header, bin_tag); }

            // Header Protection
            {
                uint8 ht = _ht;
                auto adj = 4 - pn_length;
                binary_append(bin_pn, &bin_encrypted[0], adj);

                // calcurate mask
                binary_t bin_mask;
                get_protection()->hpmask(mode, &bin_encrypted[adj], 0x10, bin_mask);
                get_protection()->hpencode(mode, bin_mask, ht, bin_pn);  // do not update ht
                // encode packet length
                bin_protected_header[0] = ht;
                bin_pn.resize(pn_length);

                // encode packet number
                payload pl;
                pl << new payload_member(new quic_encoded(get_token()), "token") << new payload_member(new quic_encoded(len), "length")
                   << new payload_member(bin_pn, "packet number");

                // protected header
                pl.write(bin_protected_header);
            }

            header = std::move(bin_protected_header);
            encrypted = std::move(bin_encrypted);
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

void quic_packet_initial::dump(stream_t* s) {
    if (s) {
        quic_packet::dump(s);
        // token
        s->printf(" > token (len %zi)\n", _token.size());
        dump_memory(_token, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
        // length = packet number + payload
        auto len = get_length();
        s->printf(" > length %I64i\n", len);
        // packet number
        s->printf(" > packet number %08x\n", get_pn());
        // payload
        s->printf(" > payload (len %zi)\n", _payload.size());
        dump_memory(_payload, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
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
