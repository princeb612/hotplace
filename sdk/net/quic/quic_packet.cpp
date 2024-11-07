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

quic_packet::quic_packet() : _type(0), _ht(0), _version(1), _keys(nullptr) {}

quic_packet::quic_packet(quic_packet_t type) : _type(type), _ht(0), _version(1), _keys(nullptr) {
    bool is_longheader = true;
    set_type(type, _ht, is_longheader);
}

quic_packet::quic_packet(const quic_packet& rhs)
    : _type(rhs._type), _ht(rhs._ht), _version(rhs._version), _dcid(rhs._dcid), _scid(rhs._scid), _keys(rhs._keys) {
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

return_t quic_packet::read(const byte_t* stream, size_t size, size_t& pos, uint8 type) {
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

return_t quic_packet::read(const binary_t& bin, size_t& pos, uint8 type) { return read(&bin[0], bin.size(), pos, type); }

return_t quic_packet::write(binary_t& packet, uint8 type) {
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
        } break;
        default:
            break;
    }
}

uint8 quic_packet::get_pn_length() {
    uint8 len = 0;
    switch (get_type()) {
        case quic_packet_type_initial:
        case quic_packet_type_0_rtt:
        case quic_packet_type_handshake:
        case quic_packet_type_1_rtt:
            len = (_ht & 0x03) + 1;
            break;
        default:
            break;
    }
    return len;
}

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

void quic_packet::set_binary(binary_t& target, const binary_t& stream) { target = stream; }

void quic_packet::set_binary(binary_t& target, const byte_t* stream, size_t size) { binary_load(target, size, stream, size); }

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

}  // namespace net
}  // namespace hotplace
