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
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/quic/quic.hpp>

namespace hotplace {
namespace net {

quic_packet_initial::quic_packet_initial() : quic_packet(quic_packet_type_initial), _length(0), _pn(0) {}

quic_packet_initial::quic_packet_initial(const quic_packet_initial& rhs) : quic_packet(rhs), _length(rhs._length), _pn(rhs._pn) {}

return_t quic_packet_initial::read(const byte_t* stream, size_t size, size_t& pos, uint8 type) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = quic_packet::read(stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        size_t offset_initial = pos;
        byte_t ht = stream[0];

        // RFC 9001 5.4.2.  Header Protection Sample
        uint8 pn_length = type ? 4 : get_pn_length(stream[0]);

        payload pl;
        pl << new payload_member(new quic_integer(binary_t()), "token") << new payload_member(new quic_integer(int(0)), "length")
           << new payload_member(binary_t(), "packet number") << new payload_member(binary_t(), "payload");
        pl.select("packet number")->reserve(pn_length);
        pl.read(stream, size, pos);

        pl.select("token")->get_variant().to_binary(_token);
        _length = pl.select("length")->get_payload_encoded()->value();
        binary_t bin_pn;
        pl.select("packet number")->get_variant().to_binary(bin_pn);  // 8..32
        _pn = t_binary_to_integer2<uint32>(bin_pn);
        pl.select("payload")->get_variant().to_binary(_payload);

        // test
        if (_payload.size() > 32) {  // sampled(16) + tag(16)
            binary_t bin_mask;
            header_protection_mask(type, &_payload[0], 16, bin_mask);
            header_protection_encode(type, bin_mask, _ht, bin_pn);

            auto pn_length = get_pn_length(_ht);
            bin_pn.resize(pn_length);

            _pn = t_binary_to_integer2<uint32>(bin_pn);

#if 0  // studying
            size_t pn_offset = offset_initial + pl.offset_of("packet number");
            // key : quic_client_key
            // iv  : quic_client_iv
            // aad : unprotected header[0:token]
            // tag : payload[end-16:end]
            auto key = get_keys()->get_item(quic_client_key);
            auto iv = get_keys()->get_item(quic_client_iv);
            // binary_t ivvec = iv;
            // uint64 seq = 0;
            // for (auto i = 0; i < 12; i++) {
            //     ivvec[12 - 1 - i] ^= ((seq>>(i*8))&0xFF);
            // }
            crypt_context_t* handle = nullptr;
            openssl_crypt crypt;
            binary_t aad;
            binary_t tag;
            binary_t bin_decrypt;
            binary_append(aad, stream, pn_offset + get_pn_length());
            binary_append(tag, stream + size - 16, 16);
            ret = crypt.open(&handle, "aes-128-gcm", key, iv);
            if (errorcode_t::success == ret) {
                // ret = crypt.decrypt2(handle, &_payload[16], _payload.size() - 32, bin_decrypt, &aad, &tag);
                // ret = crypt.decrypt2(handle, &_payload[0], _payload.size() - 16, bin_decrypt, &aad, &tag);
                crypt.close(handle);
            }
#endif
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet_initial::write(binary_t& packet, uint8 type) {
    return_t ret = errorcode_t::success;
    __try2 {
        size_t offset_packet = packet.size();
        ret = quic_packet::write(packet, type);

        size_t offset_initial = packet.size();
        uint8 pn_length = get_pn_length();
        uint64 len = pn_length + _payload.size();  // len = get_length();

        uint8 ht = _ht;
        binary_t bin_pn;
        binary_load(bin_pn, pn_length, _pn, hton32);
        /**
         * RFC 9001 5.4.2.  Header Protection Sample
         * protected payload is at least 4 bytes longer than the sample required for header protection
         */
        if (type && (_payload.size() >= 0x10)) {  // > 4
            /**
             * RFC 9001 5.4.2.  Header Protection Sample
             *  in sampling packet ciphertext for header protection, the Packet Number field is
             *  assumed to be 4 bytes long (its maximum possible encoded length).
             */
            binary_append(bin_pn, &_payload[0], 4 - pn_length);
            pn_length = 4;

            // sketch ... before the write function (backup/insert not necessary)
            binary_t bin_mask;
            header_protection_mask(type, &_payload[0], 0x10, bin_mask);
            header_protection_encode(type, bin_mask, ht, bin_pn);
            packet[0] = ht;
        }

        payload pl;
        pl << new payload_member(new quic_integer(_token), "token") << new payload_member(new quic_integer(len), "length")
           << new payload_member(bin_pn, "packet number") << new payload_member(_payload, "payload");
        pl.write(packet);

        // sketch ... after the write function
        //   backup payload[0..4-pn_length]
        //   pn_offset = offset_initial + pl.offset_of("packet_number");
        //   for (int i = 0; i < 4; i++)
        //     packet[pn_offset] ^= mask[i + 1];
        //   insert the backup data before the payload
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

return_t quic_packet_initial::header_protection_mask(uint8 type, const byte_t* sampled, size_t size_sampled, binary_t& mask) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == sampled) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == get_keys()) {
            ret = errorcode_t::not_ready;
            __leave2;
        }

        /**
         *
         * RFC 9001 5.4.3.  AES-Based Header Protection
         *
         *  header_protection(hp_key, sample):
         *    mask = AES-ECB(hp_key, sample)
         *
         * RFC 9001 5.4.4.  ChaCha20-Based Header Protection
         *
         *  header_protection(hp_key, sample):
         *    counter = sample[0..3]
         *    nonce = sample[4..15]
         *    mask = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0})
         *
         * RFC 9001 A.2.
         *  sample = d1b1c98dd7689fb8ec11d242b123dc9b
         *  mask = AES-ECB(hp, sample)[0..4]
         *       = 437b9aec36
         */

        crypt_context_t* handle = nullptr;

        // mask = AES-ECB(hp_key, sample)
        {
            openssl_crypt crypt;
            quic_initial_keys_t kty = quic_initial_keys_t::quic_client_hp;
            if (tls_handshake_t::tls_server_hello == type) {
                kty = quic_initial_keys_t::quic_server_hp;
            }
            auto const& key = get_keys()->get_item(kty);
            auto const& iv = binary_t();
            ret = crypt.open(&handle, "aes-128-ecb", key, iv);
            if (errorcode_t::success == ret) {
                ret = crypt.encrypt(handle, sampled, size_sampled, mask);
                crypt.close(handle);
            }
            if (errorcode_t::success != ret) {
                __leave2;
            }
            mask.resize(5);  // [0..4]
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet_initial::header_protection_encode(uint8 type, const binary_t& mask, byte_t& ht, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == get_keys()) {
            ret = errorcode_t::not_ready;
            __leave2;
        }
        if (bin.size() < 4) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        /**
         * RFC 9001 5.4.1.  Header Protection Application
         *
         *  mask = header_protection(hp_key, sample)
         *
         *  pn_length = (packet[0] & 0x03) + 1
         *  if (packet[0] & 0x80) == 0x80:
         *     # Long header: 4 bits masked
         *     packet[0] ^= mask[0] & 0x0f
         *  else:
         *     # Short header: 5 bits masked
         *     packet[0] ^= mask[0] & 0x1f
         *
         *  # pn_offset is the start of the Packet Number field.
         *  packet[pn_offset:pn_offset+pn_length] ^= mask[1:1+pn_length]
         *
         *                  Figure 6: Header Protection Pseudocode
         *
         * RFC 9001 A.2.
         *  header[0] ^= mask[0] & 0x0f
         *          = c0
         *  header[18..21] ^= mask[1..4]
         *          = 7b9aec34
         *  header = c000000001088394c8f03e5157080000449e7b9aec34
         *
         * RFC 9001 A.3 The final protected packet
         *  unprotected header = c1000000010008f067a5502a4262b50040750001
         *  packet number = 1
         *  packet number length = 2
         *  protected header = cf000000010008f067a5502a4262b5004075c0d9
         *           [5a 48]
         *  sample = 2cd0991cd25b0aac406a5816b6394100
         *
         *  The final protected packet
         *      00000000 : CF 00 00 00 01 00 08 F0 67 A5 50 2A 42 62 B5 00 | ........g.P*Bb..
         *      00000010 : 40 75 C0 D9 5A 48 2C D0 99 1C D2 5B 0A AC 40 6A | @u..ZH,....[..@j
         *
         *  5.4.2.  Header Protection Sample
         *  in sampling packet ciphertext for header protection, the Packet Number field is
         *  assumed to be 4 bytes long (its maximum possible encoded length).
         */
        {
            if (quic_packet_field_hf & _ht) {
                ht ^= mask[0] & 0x0f;
            } else {
                ht ^= mask[0] & 0x1f;
            }

            // update packet number

            uint8 token_len = 0;
            quic_length_vle_int(_token.size(), token_len);
            for (auto i = 0; i < 4; i++) {
                bin[i] ^= mask[1 + i];
            }
        }
    }
    __finally2 {
        // do noting
    }
    return ret;
}

void quic_packet_initial::set_pn(uint32 pn, uint8 len) {
    quic_packet::set_pn(pn, len);
    _pn = pn;
}

uint32 quic_packet_initial::get_pn() { return _pn; }

quic_packet_initial& quic_packet_initial::set_token(const binary_t& token) {
    set_binary(_token, token);
    return *this;
}

const binary_t& quic_packet_initial::get_token() { return _token; }

uint64 quic_packet_initial::get_length() { return get_pn_length() + _payload.size(); }

quic_packet_initial& quic_packet_initial::set_payload(const binary_t& payload) {
    set_binary(_payload, payload);
    return *this;
}

quic_packet_initial& quic_packet_initial::set_payload(const byte_t* stream, size_t size) {
    set_binary(_payload, stream, size);
    return *this;
}

const binary_t& quic_packet_initial::get_payload() { return _payload; }

}  // namespace net
}  // namespace hotplace
