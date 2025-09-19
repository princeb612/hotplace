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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKETHANDSHAKE__
#define __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKETHANDSHAKE__

#include <hotplace/sdk/net/tls/quic/packet/quic_packet.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   RFC 9000 17.2.4.  Handshake Packet
 */
class quic_packet_handshake : public quic_packet {
   public:
    quic_packet_handshake(tls_session* session);
    quic_packet_handshake(const quic_packet_handshake& rhs);
    virtual ~quic_packet_handshake();

    uint64 get_bodysize();
    virtual size_t estimate_overhead();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, size_t& pos_unprotect);
    virtual return_t do_read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, size_t pos_unprotect);
    virtual return_t do_write(tls_direction_t dir, binary_t& header, binary_t& ciphertag);
    virtual void dump();

   private:
    /**
     * Figure 17: Handshake Protected Packet
     *  Length (i),
     *  Packet Number (8..32),
     *  Packet Payload (8..),
     */
    uint64 _length;
    uint8 _sizeof_length;
};

}  // namespace net
}  // namespace hotplace

#endif
