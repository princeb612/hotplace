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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKETINITIAL__
#define __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKETINITIAL__

#include <sdk/net/tls/quic/packet/quic_packet.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   RFC 9000 17.2.2.  Initial Packet
 */
class quic_packet_initial : public quic_packet {
   public:
    quic_packet_initial(tls_session* session);
    quic_packet_initial(const quic_packet_initial& rhs);
    virtual ~quic_packet_initial();

    quic_packet_initial& set_token(const binary_t& token);
    const binary_t& get_token();
    uint64 get_length();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, size_t& pos_unprotect);
    virtual return_t do_read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, size_t pos_unprotect);
    virtual return_t do_estimate();
    virtual return_t do_write_body(tls_direction_t dir, binary_t& body);
    virtual return_t do_write(tls_direction_t dir, binary_t& header, binary_t& ciphertag);
    virtual void dump();

   private:
    /**
     * Figure 15: Initial Packet
     *  Token Length (i),
     *  Token (..),
     *  Length (i),
     *  Packet Number (8..32),
     *  Packet Payload (8..),
     */
    binary_t _token;
    uint64 _length;
    uint8 _sizeof_length;
};

}  // namespace net
}  // namespace hotplace

#endif
