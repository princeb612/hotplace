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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKETS__
#define __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKETS__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/quic/types.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

class quic_packets {
   public:
    quic_packets();
    ~quic_packets();

    return_t read(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    return_t read(tls_session* session, tls_direction_t dir, const binary_t& bin);

    return_t write(tls_session* session, tls_direction_t dir, binary_t& bin);

    return_t add(quic_packet* handshake, bool upref = false);
    quic_packets& operator<<(quic_packet* handshake);

    void for_each(std::function<void(quic_packet*)> func);

    quic_packet* getat(size_t index, bool upref = false);

    size_t size();

    void clear();

   protected:
   private:
    critical_section _lock;
    std::vector<quic_packet*> _packets;
};

}  // namespace net
}  // namespace hotplace

#endif
