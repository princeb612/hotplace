/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   quic_packet_builder.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_0rtt.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_1rtt.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_builder.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_handshake.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_initial.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_retry.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_version_negotiation.hpp>
#include <hotplace/sdk/net/tls/quic/quic.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

quic_packet_builder::quic_packet_builder() : _type(0), _msb(0), _session(nullptr), _dir(from_any), _concat(0), _construct(false) {}

quic_packet_builder& quic_packet_builder::set(quic_packet_t type) {
    _type = type;
    return *this;
}

quic_packet_builder& quic_packet_builder::set(protection_space_t space) {
    switch (space) {
        case protection_initial: {
            _type = quic_packet_type_initial;
        } break;
        case protection_handshake: {
            _type = quic_packet_type_handshake;
        } break;
        case protection_application: {
            _type = quic_packet_type_1_rtt;
        } break;
        default:
            break;
    }
    return *this;
}

quic_packet_builder& quic_packet_builder::set_msb(uint8 msb) {
    _msb = msb;
    return *this;
}

quic_packet_builder& quic_packet_builder::set(tls_session* session) {
    _session = session;
    return *this;
}

quic_packet_builder& quic_packet_builder::set(tls_direction_t dir) {
    _dir = dir;
    return *this;
}

uint8 quic_packet_builder::get_msb() { return _msb; }

tls_session* quic_packet_builder::get_session() { return _session; }

tls_direction_t quic_packet_builder::get_direction() { return _dir; }

quic_packet_builder& quic_packet_builder::construct() {
    _construct = true;
    return *this;
}

bool quic_packet_builder::is_construct() { return _construct; }

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
                packet = new quic_packet_version_negotiation(session);
            } break;
            case quic_packet_type_initial: {
                packet = new quic_packet_initial(session);
                if (is_construct() && (is_unidirection(get_direction()))) {
                    openssl_prng prng;
                    uint32 pn = t_narrow_cast(session->get_recordno(get_direction(), false, protection_initial));
                    uint8 pnl = uint8((prng.rand32() % 4) + 1);
                    packet->set_pn(pn, pnl);
                }
            } break;
            case quic_packet_type_0_rtt: {
                packet = new quic_packet_0rtt(session);
            } break;
            case quic_packet_type_handshake: {
                packet = new quic_packet_handshake(session);
                if (is_construct() && (is_unidirection(get_direction()))) {
                    openssl_prng prng;
                    uint32 pn = t_narrow_cast(session->get_recordno(get_direction(), false, protection_handshake));
                    uint8 pnl = uint8((prng.rand32() % 4) + 1);
                    packet->set_pn(pn, pnl);
                }
            } break;
            case quic_packet_type_retry: {
                packet = new quic_packet_retry(session);
            } break;
            case quic_packet_type_1_rtt: {
                packet = new quic_packet_1rtt(session);
                if (is_construct()) {
                    openssl_prng prng;
                    uint32 pn = t_narrow_cast(session->get_recordno(get_direction(), false, protection_application));
                    uint8 pnl = uint8((prng.rand32() % 4) + 1);
                    packet->set_pn(pn, pnl);
                }
            } break;
        }
#if defined DEBUG
        if (packet && is_construct()) {
            auto tlsadvisor = tls_advisor::get_instance();
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_quic_packet, [&](basic_stream& dbs) -> void {
                    dbs.println(ANSI_ESCAPE "1;33m+ quic packet %s" ANSI_ESCAPE "0m", tlsadvisor->nameof_quic_packet(type).c_str());
                });
            }
        }
#endif
    }
    __finally2 {}

    return packet;
}

}  // namespace net
}  // namespace hotplace
