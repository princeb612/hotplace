/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/packet/quic_packet_builder.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

quic_packet_builder::quic_packet_builder() : _type(0), _msb(0), _session(nullptr) {}

quic_packet_builder& quic_packet_builder::set(quic_packet_t type) {
    _type = type;
    return *this;
}

quic_packet_builder& quic_packet_builder::set_msb(uint8 msb) {
    _msb = msb;
    return *this;
}

quic_packet_builder& quic_packet_builder::set_session(tls_session* session) {
    _session = session;
    return *this;
}

quic_packet* quic_packet_builder::build() {
    quic_packet* packet = nullptr;

    __try2 {
        tls_session* session = get_session();
        if (nullptr == session) {
            __leave2;
        }

        uint8 type = _type;
        if (0 == type) {
            bool is_longheader = false;
            auto session_type = session->get_type();
            uint32 version = (session_type_quic == session_type) ? quic_1 : quic_2;
            quic_packet_get_type(version, get_msb(), type, is_longheader);
        }
        switch (type) {
            case quic_packet_type_version_negotiation: {
                __try_new_catch_only(packet, new quic_packet_version_negotiation(session));
            } break;
            case quic_packet_type_initial: {
                __try_new_catch_only(packet, new quic_packet_initial(session));
            } break;
            case quic_packet_type_0_rtt: {
                __try_new_catch_only(packet, new quic_packet_0rtt(session));
            } break;
            case quic_packet_type_handshake: {
                __try_new_catch_only(packet, new quic_packet_handshake(session));
            } break;
            case quic_packet_type_retry: {
                __try_new_catch_only(packet, new quic_packet_retry(session));
            } break;
            case quic_packet_type_1_rtt: {
                __try_new_catch_only(packet, new quic_packet_1rtt(session));
            } break;
        }
    }
    __finally2 {}

    return packet;
}

uint8 quic_packet_builder::get_msb() { return _msb; }

tls_session* quic_packet_builder::get_session() { return _session; }

}  // namespace net
}  // namespace hotplace
