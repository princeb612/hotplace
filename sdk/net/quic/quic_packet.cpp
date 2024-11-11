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

quic_packet::quic_packet() : _type(0), _ht(0), _version(1), _keys(nullptr), _pn(0) {}

quic_packet::quic_packet(quic_packet_t type) : _type(type), _ht(0), _version(1), _keys(nullptr), _pn(0) {
    bool is_longheader = true;
    set_type(type, _ht, is_longheader);
}

quic_packet::quic_packet(const quic_packet& rhs)
    : _type(rhs._type), _ht(rhs._ht), _version(rhs._version), _dcid(rhs._dcid), _scid(rhs._scid), _keys(rhs._keys), _pn(rhs._pn) {
    if (_keys) {
        _keys->addref();
    }
}

quic_packet::~quic_packet() {
    if (_keys) {
        _keys->release();
    }
}

uint8 quic_packet::get_type() { return _type; }

void quic_packet::get_type(uint8 hdr, uint8& type, bool& is_longheader) {
    if (quic_packet_field_hf & hdr) {  // Header Form
        is_longheader = true;
        if (quic_packet_field_fb & hdr) {               // Fixed Bit
            switch (quic_packet_field_mask_lh & hdr) {  // Long Packet Type
                case quic_packet_field_initial:
                    type = quic_packet_type_initial;
                    break;
                case quic_packet_field_0_rtt:
                    type = quic_packet_type_0_rtt;
                    break;
                case quic_packet_field_handshake:
                    type = quic_packet_type_handshake;
                    break;
                case quic_packet_field_retry:
                    type = quic_packet_type_retry;
                    break;
            }
        } else {
            type = quic_packet_type_version_negotiation;
        }
    } else {
        is_longheader = false;
        if (quic_packet_field_fb & hdr) {
            type = quic_packet_type_1_rtt;
        }
    }
}

void quic_packet::set_type(uint8 type, uint8& hdr, bool& is_longheader) {
    hdr = 0;
    switch (type) {
        case quic_packet_type_version_negotiation:
            is_longheader = true;
            // 17.2.1.  Version Negotiation Packet
            hdr |= (quic_packet_field_hf);
            break;
        case quic_packet_type_initial:
            is_longheader = true;
            // 17.2.2.  Initial Packet
            hdr |= (quic_packet_field_hf | quic_packet_field_fb | quic_packet_field_initial);
            break;
        case quic_packet_type_0_rtt:
            is_longheader = true;
            // 17.2.3.  0-RTT
            hdr |= (quic_packet_field_hf | quic_packet_field_fb | quic_packet_field_0_rtt);
            break;
        case quic_packet_type_handshake:
            is_longheader = true;
            // 17.2.4.  Handshake Packet
            hdr |= (quic_packet_field_hf | quic_packet_field_fb | quic_packet_field_handshake);
            break;
        case quic_packet_type_retry:
            is_longheader = true;
            // 17.2.5.  Retry Packet
            hdr |= (quic_packet_field_hf | quic_packet_field_fb | quic_packet_field_retry);
            break;
        case quic_packet_type_1_rtt:
            is_longheader = false;
            // 17.3.1.  1-RTT Packet
            hdr |= (quic_packet_field_fb);
            break;
    }
}

quic_packet& quic_packet::set_version(uint32 version) {
    switch (get_type()) {
        case quic_packet_type_version_negotiation:
            // 17.2.1.  Version Negotiation Packet
            break;
        default:
            _version = version;
            break;
    }
    return *this;
}

uint32 quic_packet::get_version() { return _version; }

quic_packet& quic_packet::set_dcid(const binary& cid) {
    _dcid = cid;
    return *this;
}

quic_packet& quic_packet::set_scid(const binary& cid) {
    _scid = cid;
    return *this;
}

const binary_t& quic_packet::get_dcid() { return _dcid; }

const binary_t& quic_packet::get_scid() { return _scid; }

void quic_packet::attach(quic_header_protection_keys* keys) {
    if (keys) {
        keys->addref();
        if (_keys) {
            _keys->release();
        }
        _keys = keys;
    }
}

quic_header_protection_keys* quic_packet::get_keys() { return _keys; }

return_t quic_packet::read(const byte_t* stream, size_t size, size_t& pos, uint32 mode) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if ((size < 6) || (size < pos)) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        byte_t hdr = stream[pos];
        bool is_longheader = true;
        get_type(hdr, _type, is_longheader);

        payload pl;
        pl << new payload_member(uint8(0), "hdr") << new payload_member(uint32(0), true, "version") << new payload_member(uint8(0), "dcid_len", "longheader")
           << new payload_member(binary_t(), "dcid") << new payload_member(uint8(0), "scid_len", "longheader")
           << new payload_member(binary_t(), "scid", "longheader");
        if (is_longheader) {
            pl.set_reference_value("dcid", "dcid_len");
            pl.set_reference_value("scid", "scid_len");
        }
        pl.set_group("longheader", is_longheader);

        pl.read(stream, size, pos);

        _ht = hdr;
        _version = t_to_int<uint32>(pl.select("version"));
        pl.select("dcid")->get_variant().to_binary(_dcid);
        pl.select("scid")->get_variant().to_binary(_scid);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet::read(const binary_t& bin, size_t& pos, uint32 mode) { return read(&bin[0], bin.size(), pos, mode); }

return_t quic_packet::write(binary_t& packet, uint32 mode) {
    return_t ret = errorcode_t::success;
    uint8 hdr = 0;
    bool is_longheader = true;

    if (_ht) {
        uint8 pty = 0;
        get_type(_ht, pty, is_longheader);
    } else {
        set_type(_type, _ht, is_longheader);
    }

    payload pl;
    pl << new payload_member(_ht, "hdr") << new payload_member(_version, true, "version") << new payload_member((uint8)_dcid.size(), "dcidl", "longheader")
       << new payload_member(_dcid, "dcid") << new payload_member((uint8)_scid.size(), "scidl", "longheader")
       << new payload_member(_scid, "scid", "longheader");
    pl.set_group("longheader", is_longheader);
    pl.write(packet);

    return ret;
}

void quic_packet::dump(stream_t* s) {
    if (s) {
        std::map<uint8, std::string> packet_name;
        packet_name.insert({quic_packet_type_version_negotiation, "version negotiation"});
        packet_name.insert({quic_packet_type_initial, "initial"});
        packet_name.insert({quic_packet_type_0_rtt, "0-RTT"});
        packet_name.insert({quic_packet_type_handshake, "handshake"});
        packet_name.insert({quic_packet_type_retry, "retry"});
        packet_name.insert({quic_packet_type_1_rtt, "1-RTT"});

        s->printf("- quic packet %s\n", packet_name[_type].c_str());
        s->printf(" > version %08x\n", get_version());
        s->printf(" > destination connection id\n");
        dump_memory(_dcid, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
        s->printf("\n");
        switch (get_type()) {
            // long header
            case quic_packet_type_version_negotiation:
            case quic_packet_type_initial:
            case quic_packet_type_0_rtt:
            case quic_packet_type_handshake:
            case quic_packet_type_retry:
                s->printf(" > source connection id\n");
                dump_memory(_scid, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
                s->printf("\n");
                break;
            // short header
            case quic_packet_type_1_rtt:
                break;
        }
        switch (get_type()) {
            case quic_packet_type_initial:
            case quic_packet_type_0_rtt:
            case quic_packet_type_handshake:
            case quic_packet_type_1_rtt:
                s->printf(" > packet length %i\n", get_pn_length());
                break;
        }
    }
}

void quic_packet::set_pn(uint32 pn, uint8 len) {
    switch (get_type()) {
        case quic_packet_type_initial:
        case quic_packet_type_0_rtt:
        case quic_packet_type_handshake:
        case quic_packet_type_1_rtt: {
            uint8 elen = (len > 4) ? 4 : len;
            uint8 mlen = 1;
            if (pn > 0x00ffffff) {
                mlen = 4;
            } else if (pn > 0x0000ffff) {
                mlen = 3;
            } else if (pn > 0x000000ff) {
                mlen = 2;
            }
            if (elen > mlen) {
                mlen = elen;
            }
            uint8 l = (mlen - 1) & 0x03;
            _ht = (_ht & 0xfc) | l;
            _pn = pn;
        } break;
        default:
            break;
    }
}

uint8 quic_packet::get_pn_length() { return get_pn_length(_ht); }

uint8 quic_packet::get_pn_length(uint8 ht) {
    uint8 len = 0;
    switch (get_type()) {
        case quic_packet_type_initial:
        case quic_packet_type_0_rtt:
        case quic_packet_type_handshake:
        case quic_packet_type_1_rtt:
            len = (ht & 0x03) + 1;
            break;
        default:
            break;
    }
    return len;
}

uint32 quic_packet::get_pn() { return _pn; }

quic_packet& quic_packet::set_payload(const binary_t& payload) {
    set_binary(_payload, payload);
    return *this;
}

quic_packet& quic_packet::set_payload(const byte_t* stream, size_t size) {
    set_binary(_payload, stream, size);
    return *this;
}

const binary_t& quic_packet::get_payload() { return _payload; }

void quic_packet::set_binary(binary_t& target, const binary_t& stream) { target = stream; }

void quic_packet::set_binary(binary_t& target, const byte_t* stream, size_t size) { binary_load(target, size, stream, size); }

return_t quic_packet::header_protection_mask(uint32 mode, const byte_t* sample, size_t size_sample, binary_t& mask) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == sample) {
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
         *
         * RFC 9001 5.4.4.  ChaCha20-Based Header Protection
         *  header_protection(hp_key, sample):
         *    counter = sample[0..3]
         *    nonce = sample[4..15]
         *    mask = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0})
         */

        crypt_context_t* handle = nullptr;

        // mask = AES-ECB(hp_key, sample)
        {
            openssl_crypt crypt;
            quic_initial_keys_t kty = quic_initial_keys_t::quic_client_hp;
            if (quic_mode_t::quic_mode_server == mode) {
                kty = quic_initial_keys_t::quic_server_hp;
            }
            auto const& key = get_keys()->get_item(kty);
            auto const& iv = binary_t();
            ret = crypt.open(&handle, "aes-128-ecb", key, iv);
            if (errorcode_t::success == ret) {
                ret = crypt.encrypt(handle, sample, size_sample, mask);
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

return_t quic_packet::header_protection_encode(uint32 mode, const binary_t& mask, byte_t& ht, binary_t& bin_pn) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == get_keys()) {
            ret = errorcode_t::not_ready;
            __leave2;
        }
        if (bin_pn.size() < 4) {
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

            for (auto i = 0; i < 4; i++) {
                bin_pn[i] ^= mask[1 + i];
            }
        }
    }
    __finally2 {
        // do noting
    }
    return ret;
}

return_t quic_packet::encrypt(uint32 mode, uint64 pn, const binary_t& payload, binary_t& encrypted, const binary_t& aad, binary_t& tag) {
    return_t ret = errorcode_t::success;
    // TODO
    // - ChaCha20-Poly1305
    __try2 {
        openssl_crypt crypt;
        crypt_context_t* handle = nullptr;
        quic_initial_keys_t kty_key = quic_initial_keys_t::quic_client_key;
        quic_initial_keys_t kty_iv = quic_initial_keys_t::quic_client_iv;
        if (quic_mode_t::quic_mode_server == mode) {
            kty_key = quic_initial_keys_t::quic_server_key;
            kty_iv = quic_initial_keys_t::quic_server_iv;
        }
        const binary_t& bin_key = get_keys()->get_item(kty_key);
        const binary_t& bin_frame = get_payload();
        binary_t bin_nonce = get_keys()->get_item(kty_iv);

        binary_t bin_pn8;
        binary_load(bin_pn8, 8, (uint64)pn, hton64);
        for (int i = 0; i < 8; i++) {
            bin_nonce[i + 12 - 8] ^= bin_pn8[i];
        }

        crypt.open(&handle, "aes-128-gcm", bin_key, bin_nonce);
        crypt.encrypt2(handle, payload, encrypted, &aad, &tag);
        crypt.close(handle);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet::decrypt(uint32 mode, uint64 pn, const binary_t& payload, binary_t& decrypted, const binary_t& aad, const binary_t& tag) {
    return_t ret = errorcode_t::success;
    __try2 {
        openssl_crypt crypt;
        crypt_context_t* handle = nullptr;
        quic_initial_keys_t kty_key = quic_initial_keys_t::quic_client_key;
        quic_initial_keys_t kty_iv = quic_initial_keys_t::quic_client_iv;
        if (quic_mode_t::quic_mode_server == mode) {
            kty_key = quic_initial_keys_t::quic_server_key;
            kty_iv = quic_initial_keys_t::quic_server_iv;
        }
        const binary_t& bin_key = get_keys()->get_item(kty_key);
        const binary_t& bin_frame = get_payload();
        binary_t bin_nonce = get_keys()->get_item(kty_iv);

        binary_t bin_pn8;
        binary_load(bin_pn8, 8, (uint64)pn, hton64);
        for (int i = 0; i < 8; i++) {
            bin_nonce[i + 12 - 8] ^= bin_pn8[i];
        }

        crypt.open(&handle, "aes-128-gcm", bin_key, bin_nonce);
        crypt.decrypt2(handle, payload, decrypted, &aad, &tag);
        crypt.close(handle);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
