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

class quic_frame_builder {
   public:
    quic_frame_builder();

    quic_frame_builder& set(quic_frame_t type);
    quic_frame_builder& set(tls_session* session);
    quic_frame* build();

    quic_frame_t get_type();
    tls_session* get_session();

   private:
    quic_frame_t _type;
    tls_session* _session;
};

}  // namespace net
}  // namespace hotplace

#endif
