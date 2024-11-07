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

// studying

quic_packet_version_negotiation::quic_packet_version_negotiation() : quic_packet(quic_packet_type_version_negotiation) {}

quic_packet_version_negotiation::quic_packet_version_negotiation(const quic_packet_version_negotiation& rhs) : quic_packet(rhs) {}

}  // namespace net
}  // namespace hotplace
