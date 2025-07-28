/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/quic.hpp>

namespace hotplace {
namespace net {

// studying

quic_packet_version_negotiation::quic_packet_version_negotiation(tls_session* session) : quic_packet(quic_packet_type_version_negotiation, session) {}

quic_packet_version_negotiation::quic_packet_version_negotiation(const quic_packet_version_negotiation& rhs) : quic_packet(rhs) {}

quic_packet_version_negotiation::~quic_packet_version_negotiation() {}

}  // namespace net
}  // namespace hotplace
