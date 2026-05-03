/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   quic_packet_0rtt.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/crypto/basic/openssl_crypt.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_0rtt.hpp>
#include <hotplace/sdk/net/tls/quic/quic.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

quic_packet_0rtt::quic_packet_0rtt(tls_session* session) : quic_packet(quic_packet_type_0_rtt, session) {}

quic_packet_0rtt::quic_packet_0rtt(const quic_packet_0rtt& other) : quic_packet(other) {}

quic_packet_0rtt::~quic_packet_0rtt() {}

}  // namespace net
}  // namespace hotplace
