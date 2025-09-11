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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKETBUILDER__
#define __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_QUICPACKETBUILDER__

#include <sdk/base/stream/types.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/types.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

class quic_packet_builder {
   public:
    quic_packet_builder();

    quic_packet_builder& set(quic_packet_t type);
    quic_packet_builder& set(protection_space_t space);
    quic_packet_builder& set_msb(uint8 msb);
    quic_packet_builder& set(tls_session* session);
    quic_packet_builder& set(tls_direction_t dir);
    quic_packet_builder& set(segmentation* segment, size_t concat = 0);
    quic_packet_builder& construct();

    quic_packet* build();

   protected:
    tls_direction_t get_direction();
    uint8 get_msb();
    tls_session* get_session();
    bool is_construct();

   private:
    uint8 _type;
    uint8 _msb;
    tls_session* _session;
    tls_direction_t _dir;
    segmentation* _segment;
    size_t _concat;
    bool _construct;
};

}  // namespace net
}  // namespace hotplace

#endif
