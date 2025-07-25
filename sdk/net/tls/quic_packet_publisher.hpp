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

#ifndef __HOTPLACE_SDK_NET_TLS_QUICPACKETPUBLISHER__
#define __HOTPLACE_SDK_NET_TLS_QUICPACKETPUBLISHER__

#include <queue>
#include <sdk/base/nostd/ovl.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/net/tls/quic/types.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

/**
 *  // sketch
 *
 *  auto& publisher = get_quic_packet_publisher();
 *  publisher.set_max_udp_payload_size(1200);  // set payload size
 *  auto lambda = [](quic_packet* packet, tls_session* session, tls_direction_t dir) -> return_t { do_something };
 *
 *  // client
 *  publisher.add(client_hello);
 *  publisher.publish(session, from_client, func);  // Initial[CRYPTO[CH], PADDING]
 *
 *  // server
 *  publisher.ack(protection_initial, 1);
 *  publisher.add(server_hello);
 *  publisher.publish(session, from_server, func);  //Initial[ACK, CRYPTO[SH], PADDING]
 *
 *  publisher.add(encrypted_extensions).add(certificate).add(certificate_verify).add(finished);
 *  publisher.publish(session, from_server, func);
 *  // publish the followings
 *  //   Handshake1(CRYPTO[EE, CERT(Fragment)]);
 *  //   Handshake2(CRYPTO[CERT(Fragment)]);
 *  //   ...
 *  //   HandshakeN(CRYPTO[CERT(Fragment), CV, FIN]);  // also ACK may be included
 */
class quic_packet_publisher {
   public:
    quic_packet_publisher();
    ~quic_packet_publisher();

    quic_packet_publisher& add(tls_hs_type_t handshake, std::function<return_t(tls_handshake*, tls_direction_t)> hook);
    quic_packet_publisher& add(const binary_t& stream);
    quic_packet_publisher& ack(protection_level_t level, uint64 pkn);
    quic_packet_publisher& operator<<(tls_hs_type_t handshake);
    quic_packet_publisher& operator<<(const binary_t& stream);

    return_t publish(tls_session* session, tls_direction_t dir, std::function<return_t(quic_packet*, tls_session*, tls_direction_t)> func);

   protected:
   private:
    critical_section _lock;
    struct handshake_t {
        tls_hs_type_t type;
        std::function<return_t(tls_handshake*, tls_direction_t)> hook;
    };
    std::queue<handshake_t> _handshakes;
    std::queue<binary_t> _queue;
    std::map<protection_level_t, t_ovl_points<uint64>> _ack;
};

}  // namespace net
}  // namespace hotplace

#endif
