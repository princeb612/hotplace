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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKETVERSIONNEGOTIATION__
#define __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKETVERSIONNEGOTIATION__

#include <hotplace/sdk/net/tls/quic/packet/quic_packet.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   RFC 9000 17.2.1.  Version Negotiation Packet
 */
class quic_packet_version_negotiation : public quic_packet {
   public:
    quic_packet_version_negotiation(tls_session* session);
    quic_packet_version_negotiation(const quic_packet_version_negotiation& rhs);
    virtual ~quic_packet_version_negotiation();

   protected:
   private:
    /**
     * Figure 14: Version Negotiation Packet
     *  Supported Version (32) ...,
     */
    std::vector<uint32> _version;
};

}  // namespace net
}  // namespace hotplace

#endif
