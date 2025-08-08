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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKET0RTT__
#define __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKET0RTT__

#include <sdk/net/tls/quic/packet/quic_packet.hpp>

namespace hotplace {
namespace net {

/**
 * @breif   RFC 9000 17.2.3.  0-RTT
 */
class quic_packet_0rtt : public quic_packet {
   public:
    quic_packet_0rtt(tls_session* session);
    quic_packet_0rtt(const quic_packet_0rtt& rhs);
    virtual ~quic_packet_0rtt();

    virtual return_t read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t write(tls_direction_t dir, binary_t& header, binary_t& ciphertext, binary_t& tag);

   protected:
   private:
    /**
     * Figure 16: 0-RTT Packet
     *  Length (i),
     *  Packet Number (8..32),
     *  Packet Payload (8..),
     */
    uint32 _pn;
    binary_t _payload;
};

}  // namespace net
}  // namespace hotplace

#endif
