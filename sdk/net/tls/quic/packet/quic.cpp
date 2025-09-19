/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <math.h>

#include <hotplace/sdk/net/tls/quic/packet/quic_packet.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_builder.hpp>
#include <hotplace/sdk/net/tls/quic/quic.hpp>

namespace hotplace {
namespace net {

void quic_packet_get_type(uint32 version, uint8 hdr, uint8& type, bool& is_longheader) {
    if (quic_packet_field_hf & hdr) {  // Header Form
        is_longheader = true;
        uint8 pf_initial = 0;
        uint8 pf_0rtt = 0;
        uint8 pf_handshake = 0;
        uint8 pf_retry = 0;
        if (quic_1 == version) {
            pf_initial = quic_packet_field_initial;
            pf_0rtt = quic_packet_field_0_rtt;
            pf_handshake = quic_packet_field_handshake;
            pf_retry = quic_packet_field_retry;
        } else {
            pf_initial = quic2_packet_field_initial;
            pf_0rtt = quic2_packet_field_0_rtt;
            pf_handshake = quic2_packet_field_handshake;
            pf_retry = quic2_packet_field_retry;
        }

        if (quic_packet_field_fb & hdr) {                    // Fixed Bit
            uint8 mask = (quic_packet_field_mask_lh & hdr);  // Long Packet Type
            if (pf_initial == mask) {
                type = quic_packet_type_initial;
            } else if (pf_0rtt == mask) {
                type = quic_packet_type_0_rtt;
            } else if (pf_handshake == mask) {
                type = quic_packet_type_handshake;
            } else if (pf_retry == mask) {
                type = quic_packet_type_retry;
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

void quic_packet_set_type(uint32 version, uint8 type, uint8& hdr, bool& is_longheader) {
    hdr = 0;

    uint8 pf_initial = 0;
    uint8 pf_0rtt = 0;
    uint8 pf_handshake = 0;
    uint8 pf_retry = 0;

    if (quic_1 == version) {
        pf_initial = quic_packet_field_initial;
        pf_0rtt = quic_packet_field_0_rtt;
        pf_handshake = quic_packet_field_handshake;
        pf_retry = quic_packet_field_retry;
    } else if (quic_2 == version) {
        pf_initial = quic2_packet_field_initial;
        pf_0rtt = quic2_packet_field_0_rtt;
        pf_handshake = quic2_packet_field_handshake;
        pf_retry = quic2_packet_field_retry;
    }

    switch (type) {
        case quic_packet_type_version_negotiation:
            is_longheader = true;
            // RFC 9000 17.2.1.  Version Negotiation Packet
            hdr |= (quic_packet_field_hf);
            break;
        case quic_packet_type_initial:
            is_longheader = true;
            // RFC 9000 17.2.2.  Initial Packet
            hdr |= (quic_packet_field_hf | quic_packet_field_fb | pf_initial);
            break;
        case quic_packet_type_0_rtt:
            is_longheader = true;
            // RFC 9000 17.2.3.  0-RTT
            hdr |= (quic_packet_field_hf | quic_packet_field_fb | pf_0rtt);
            break;
        case quic_packet_type_handshake:
            is_longheader = true;
            // RFC 9000 17.2.4.  Handshake Packet
            hdr |= (quic_packet_field_hf | quic_packet_field_fb | pf_handshake);
            break;
        case quic_packet_type_retry:
            is_longheader = true;
            // RFC 9000 17.2.5.  Retry Packet
            hdr |= (quic_packet_field_hf | quic_packet_field_fb | pf_retry);
            break;
        case quic_packet_type_1_rtt:
            is_longheader = false;
            // RFC 9000 17.3.1.  1-RTT Packet
            hdr |= (quic_packet_field_fb);
            break;
    }
}

return_t quic_read_packet(uint8& type, tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        type = 0;

        if (pos > size) {
            ret = errorcode_t::no_more;
            __leave2;
        }

        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto msb = stream[pos];

        quic_packet_builder builder;
        auto packet = builder.set_msb(msb).set(session).build();
        if (packet) {
            ret = packet->read(dir, stream, size, pos);
            type = packet->get_type();
            packet->release();
        } else {
            ret = errorcode_t::not_supported;
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_read_packet(uint8& type, tls_session* session, tls_direction_t dir, const binary_t& packet) {
    size_t pos = 0;
    return quic_read_packet(type, session, dir, &packet[0], packet.size(), pos);
}

uint32 estimate_quic_packet_size(uint8 type, uint8 dcidlen, uint8 scidlen, uint8 tokenlen, uint8 pnl, uint16 payload, uint8 taglen) {
    uint32 ret_value = 0;
    switch (type) {
        case quic_packet_type_initial: {
            // RFC 9000 17.2.2.  Initial Packet
            binary_t temp;
            quic_write_vle_int(payload, temp);
            ret_value = sizeof(uint8) + sizeof(uint32) + 1 + dcidlen + 1 + scidlen + 1 + tokenlen + temp.size() + pnl + payload + taglen;
        } break;
        case quic_packet_type_handshake: {
            // RFC 9000 17.2.4.  Handshake Packet
            binary_t temp;
            quic_write_vle_int(payload, temp);
            ret_value = sizeof(uint8) + sizeof(uint32) + 1 + dcidlen + 1 + scidlen + temp.size() + pnl + payload + taglen;
        } break;
        case quic_packet_type_1_rtt: {
            // RFC 9000 17.3.1.  1-RTT Packet
            ret_value = sizeof(uint8) + dcidlen + pnl + payload + taglen;
        } break;
    }
    return ret_value;
}

}  // namespace net
}  // namespace hotplace
