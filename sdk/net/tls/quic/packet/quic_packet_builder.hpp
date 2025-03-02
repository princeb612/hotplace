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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_BUILDER__
#define __HOTPLACE_SDK_NET_TLS_QUIC_PACKET_BUILDER__

#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/types.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

class quic_packet_builder {
   public:
    quic_packet_builder();

    quic_packet_builder& set_msb(uint8 msb);
    quic_packet_builder& set_session(tls_session* session);

    quic_packet* build();

   protected:
    uint8 get_msb();
    tls_session* get_session();

   private:
    uint8 _msb;
    tls_session* _session;
};

}  // namespace net
}  // namespace hotplace

#endif
