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

#ifndef __HOTPLACE_SDK_NET_QUIC_FRAMES__
#define __HOTPLACE_SDK_NET_QUIC_FRAMES__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/quic/types.hpp>
#include <sdk/net/tls1/types.hpp>

namespace hotplace {
namespace net {

class quic_frames {
   public:
    quic_frames();
    ~quic_frames();

    return_t read(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    return_t read(tls_session* session, tls_direction_t dir, const binary_t& bin);

    return_t write(tls_session* session, tls_direction_t dir, binary_t& bin);

    return_t add(quic_frame* handshake, bool upref = false);
    quic_frames& operator<<(quic_frame* handshake);

    void for_each(std::function<void(quic_frame*)> func);

    quic_frame* get(uint8 type, bool upref = false);
    quic_frame* getat(size_t index, bool upref = false);

    size_t size();

    void clear();

   protected:
    critical_section _lock;
    std::map<uint8, quic_frame*> _dictionary;  // tls_hs_type_t
    std::vector<quic_frame*> _frames;          // ordered
};

}  // namespace net
}  // namespace hotplace

#endif
