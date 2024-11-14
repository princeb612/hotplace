/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_QUIC_TYPES__
#define __HOTPLACE_SDK_NET_QUIC_TYPES__

#include <sdk/net/basic/types.hpp>
#include <sdk/net/http/types.hpp>
#include <sdk/net/server/types.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

class quic_protection;
class quic_packet;
class quic_packet_version_negotiation;
class quic_packet_initial;
class quic_packet_0rtt;
class quic_packet_handshake;
class quic_packet_retry;
class quic_packet_1rtt;
class quic_encoded;

}  // namespace net
}  // namespace hotplace

#endif
