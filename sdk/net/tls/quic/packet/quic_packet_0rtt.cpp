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

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

quic_packet_0rtt::quic_packet_0rtt(tls_session* session) : quic_packet(quic_packet_type_1_rtt, session) {}

quic_packet_0rtt::quic_packet_0rtt(const quic_packet_0rtt& rhs) : quic_packet(rhs) {}

return_t quic_packet_0rtt::read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    return ret;
}

return_t quic_packet_0rtt::write(tls_direction_t dir, binary_t& header, binary_t& ciphertext, binary_t& tag) {
    return_t ret = errorcode_t::success;
    return ret;
}

}  // namespace net
}  // namespace hotplace
