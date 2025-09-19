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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKETRETRY__
#define __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKETRETRY__

#include <hotplace/sdk/net/tls/quic/packet/quic_packet.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   RFC 9000 17.2.5.  Retry Packet
 */
class quic_packet_retry : public quic_packet {
   public:
    quic_packet_retry(tls_session* session);
    quic_packet_retry(const quic_packet_retry& rhs);
    virtual ~quic_packet_retry();

    virtual return_t write(tls_direction_t dir, binary_t& packet);

    quic_packet_retry& set_retry_token(const binary_t& token);
    quic_packet_retry& set_integrity_tag(const binary_t& tag);

    const binary_t& get_retry_token();
    const binary_t& get_integrity_tag();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, size_t& pos_unprotect);

    virtual void dump();

    /**
     * @brief   retry packet
     * @param   const quic_packet_retry& retry_packet [in]
     * @param   binary_t& tag [out]
     */
    return_t retry_integrity_tag(const quic_packet_retry& retry_packet, binary_t& tag);

   private:
    /**
     * Figure 18: Retry Packet
     *  Retry Token (..),
     *  Retry Integrity Tag (128),
     */
    binary_t _retry_token;
    binary_t _retry_integrity_tag;
};

}  // namespace net
}  // namespace hotplace

#endif
