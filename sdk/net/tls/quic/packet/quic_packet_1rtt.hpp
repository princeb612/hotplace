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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKET1RTT__
#define __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKET1RTT__

#include <sdk/net/tls/quic/packet/quic_packet.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   RFC 9000 17.3.1.  1-RTT Packet
 * @remarks
 *          Figure 19: 1-RTT Packet
 *           Packet Number (8..32),
 *           Packet Payload (8..),
 */
class quic_packet_1rtt : public quic_packet {
   public:
    quic_packet_1rtt(tls_session* session);
    quic_packet_1rtt(const quic_packet_1rtt& rhs);
    virtual ~quic_packet_1rtt();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, size_t& pos_unprotect);
    virtual return_t do_read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, size_t pos_unprotect);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& body);
    virtual return_t do_write(tls_direction_t dir, binary_t& header, binary_t& ciphertext, binary_t& tag);
};

}  // namespace net
}  // namespace hotplace

#endif
