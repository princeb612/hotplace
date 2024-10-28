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

quic_packet::quic_packet() : _type(0), _version(0) {}

quic_packet::quic_packet(quic_packet_t type) : _type(type), _version(0) {}

quic_packet::quic_packet(const quic_packet& rhs) : _type(rhs._type), _version(rhs._version), _dcid(rhs._dcid), _scid(rhs._scid) {}

quic_packet& quic_packet::set_version(uint32 version) {
    switch (get_type()) {
        case quic_packet_version_negotiation:
            // 17.2.1.  Version Negotiation Packet
            break;
        default:
            _version = version;
            break;
    }
    return *this;
}

uint32 quic_packet::get_version() { return _version; }

void quic_packet::set_dcid(const binary& cid) { _dcid = cid; }

void quic_packet::set_scid(const binary& cid) { _scid = cid; }

const binary_t& quic_packet::get_dcid() { return _dcid; }

const binary_t& quic_packet::get_scid() { return _scid; }

uint8 quic_packet::get_type() { return _type; }

return_t quic_packet::read(byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (size < 6) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        byte_t hdr = stream[pos++];
        bool is_longheader = true;

        if (quic_packet_field_hf & hdr) {
            is_longheader = true;
            if (quic_packet_field_fb & hdr) {
                switch (quic_packet_field_mask_t & hdr) {
                    case quic_packet_field_initial:
                        _type = quic_packet_initial;
                        break;
                    case quic_packet_field_0_rtt:
                        _type = quic_packet_0_rtt;
                        break;
                    case quic_packet_field_handshake:
                        _type = quic_packet_handshake;
                        break;
                    case quic_packet_field_retry:
                        _type = quic_packet_retry;
                        break;
                }
            } else {
                _type = quic_packet_version_negotiation;
            }
        } else {
            is_longheader = false;
            if (quic_packet_field_fb & hdr) {
                _type = quic_packet_1_rtt;
            }
        }

        payload pl;
        pl << new payload_member(uint8(0), "hdr") << new payload_member(uint32(0), true, "version") << new payload_member(uint8(0), "dcid_len", "longheader")
           << new payload_member(binary_t(), "dcid") << new payload_member(uint8(0), "scid_len", "longheader")
           << new payload_member(binary_t(), "scid", "longheader");
        if (is_longheader) {
            pl.set_reference_value("dcid", "dcid_len");
            pl.set_reference_value("scid", "scid_len");
        }
        pl.set_group("longheader", is_longheader);

        pl.read(stream, size);

        _version = t_to_int<uint32>(pl.select("version"));
        pl.select("dcid")->get_variant().to_binary(_dcid);
        pl.select("scid")->get_variant().to_binary(_scid);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet::write(binary_t& packet) {
    return_t ret = errorcode_t::success;
    byte_t hdr = 0;
    bool is_longheader = true;

    switch (get_type()) {
        case quic_packet_version_negotiation:
            is_longheader = true;
            // 17.2.1.  Version Negotiation Packet
            hdr |= (quic_packet_field_hf);
            break;
        case quic_packet_initial:
            is_longheader = true;
            // 17.2.2.  Initial Packet
            hdr |= (quic_packet_field_hf | quic_packet_field_fb | quic_packet_field_initial);
            break;
        case quic_packet_0_rtt:
            is_longheader = true;
            // 17.2.3.  0-RTT
            hdr |= (quic_packet_field_hf | quic_packet_field_fb | quic_packet_field_0_rtt);
            break;
        case quic_packet_handshake:
            is_longheader = true;
            // 17.2.4.  Handshake Packet
            hdr |= (quic_packet_field_hf | quic_packet_field_fb | quic_packet_field_handshake);
            break;
        case quic_packet_retry:
            is_longheader = true;
            // 17.2.5.  Retry Packet
            hdr |= (quic_packet_field_hf | quic_packet_field_fb | quic_packet_field_retry);
            break;
        case quic_packet_1_rtt:
            is_longheader = false;
            // 17.3.1.  1-RTT Packet
            hdr |= (quic_packet_field_fb);
            break;
    }

    payload pl;
    pl << new payload_member(hdr, "hdr") << new payload_member(_version, true, "version") << new payload_member((uint8)_dcid.size(), "dcidl", "longheader")
       << new payload_member(_dcid, "dcid") << new payload_member((uint8)_scid.size(), "scidl", "longheader")
       << new payload_member(_scid, "scid", "longheader");
    pl.set_group("longheader", is_longheader);

    pl.write(packet);

    return ret;
}

void quic_packet::dump(stream_t* s) {
    if (s) {
        std::map<uint8, std::string> packet_name;
        packet_name.insert({quic_packet_version_negotiation, "version negotiation"});
        packet_name.insert({quic_packet_initial, "initial"});
        packet_name.insert({quic_packet_0_rtt, "0-RTT"});
        packet_name.insert({quic_packet_handshake, "handshake"});
        packet_name.insert({quic_packet_retry, "retry"});
        packet_name.insert({quic_packet_1_rtt, "1-RTT"});

        s->printf("- quic packet %s\n", packet_name[_type].c_str());
        s->printf(" > version %08x\n", get_version());
        s->printf(" > destination connection id\n");
        dump_memory(_dcid, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
        s->printf("\n");
        switch (get_type()) {
            // long header
            case quic_packet_version_negotiation:
            case quic_packet_initial:
            case quic_packet_0_rtt:
            case quic_packet_handshake:
            case quic_packet_retry:
                s->printf(" > source connection id\n");
                dump_memory(_scid, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
                s->printf("\n");
                break;
            // short header
            case quic_packet_1_rtt:
                break;
        }
    }
}

}  // namespace net
}  // namespace hotplace
