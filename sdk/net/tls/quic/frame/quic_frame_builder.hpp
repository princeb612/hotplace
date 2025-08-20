/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * reference
 *  https://github.com/martinduke/quic-test-vector
 *  https://quic.xargs.org/
 *
 * studying...
 *
 * RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport
 * RFC 9001 Using TLS to Secure QUIC
 *
 * OpenSSL 3.2 and later features support for the QUIC transport protocol.
 * Currently, only client connectivity is supported.
 * This man page describes the usage of QUIC client functionality for both existing and new applications.
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMEBUILDER__
#define __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMEBUILDER__

#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/quic/types.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   quic_frame_builder
 * @remarks
 *          quic_frame_builder builder;
 *          auto frame = builder.set(type).set(packet).build();
 *          if (frame) {
 *              frame->release();
 *          }
 */
class quic_frame_builder {
   public:
    quic_frame_builder();

    quic_frame_builder& set(quic_frame_t type);
    quic_frame_builder& set(quic_packet* packet);
    quic_frame_builder& set(tls_direction_t dir);
    quic_frame_builder& set_streaminfo(uint64 streamid, uint8 unitype);
    quic_frame_builder& construct();

    quic_frame* build();

   protected:
    quic_frame_t get_type();
    quic_packet* get_packet();
    tls_direction_t get_direction();
    uint64 get_streamid();
    bool is_construct();

   private:
    quic_frame_t _type;
    quic_packet* _packet;
    tls_direction_t _dir;
    uint64 _streamid;
    uint8 _unitype;
    bool _construct;
};

}  // namespace net
}  // namespace hotplace

#endif
