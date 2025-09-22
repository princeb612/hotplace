/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/tls/quic_session.hpp>

namespace hotplace {
namespace net {

quic_session::quic_session() { get_setting().set(quic_param_max_udp_payload_size, 1200); }

quic_session::~quic_session() {}

std::map<uint64, binary_t>& quic_session::get_cid_tracker() { return _cid_tracker; }

t_key_value<uint64, uint64>& quic_session::get_setting() { return _setting; }

qpack_dynamic_table& quic_session::get_dynamic_table() { return _qpack_dyntable; }

t_ovl_points<uint32>& quic_session::get_pkns(protection_space_t space) { return _pkn[space]; }

quic_streams& quic_session::get_streams() { return _streams; }

quic_packet_publisher& quic_session::get_quic_packet_publisher() { return _quic_packet_publisher; }

}  // namespace net
}  // namespace hotplace
