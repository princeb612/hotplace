/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/http/http3/http3_frames.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_stream.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic_session.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

quic_session::quic_session() { get_setting().set(quic_param_max_udp_payload_size, 1200); }

quic_session::~quic_session() {}

t_key_value<uint64, uint64>& quic_session::get_setting() { return _setting; }

qpack_dynamic_table& quic_session::get_dynamic_table() { return _qpack_dyntable; }

t_ovl_points<uint32>& quic_session::get_pkns(protection_space_t space) { return _pkn[space]; }

t_quic_streams<uint64, uint8>& quic_session::get_streams() { return _streams; }

}  // namespace net
}  // namespace hotplace
