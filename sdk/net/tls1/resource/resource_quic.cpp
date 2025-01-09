/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/quic/quic.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>

namespace hotplace {
namespace net {

// keep single line
#define ENTRY(x, y) \
    { x, y }

define_tls_variable(quic_trans_param_code) = {
    ENTRY(0x00, "original_destination_connection_id"),
    ENTRY(0x01, "max_idle_timeout"),
    ENTRY(0x02, "stateless_reset_token"),
    ENTRY(0x03, "max_udp_payload_size"),
    ENTRY(0x04, "initial_max_data"),
    ENTRY(0x05, "initial_max_stream_data_bidi_local"),
    ENTRY(0x06, "initial_max_stream_data_bidi_remote"),
    ENTRY(0x07, "initial_max_stream_data_uni"),
    ENTRY(0x08, "initial_max_streams_bidi"),
    ENTRY(0x09, "initial_max_streams_uni"),
    ENTRY(0x0a, "ack_delay_exponent"),
    ENTRY(0x0b, "max_ack_delay"),
    ENTRY(0x0c, "disable_active_migration"),
    ENTRY(0x0d, "preferred_address"),
    ENTRY(0x0e, "active_connection_id_limit"),
    ENTRY(0x0f, "initial_source_connection_id"),
    ENTRY(0x10, "retry_source_connection_id"),
    ENTRY(0x11, "version_information"),
    ENTRY(0x20, "max_datagram_frame_size"),
    ENTRY(0x173e, "discard"),
    ENTRY(0x26ab, "google handshake message"),
    ENTRY(0x2ab2, "grease_quic_bit"),
    ENTRY(0x3127, "initial_rtt"),
    ENTRY(0x3128, "google_connection_options"),
    ENTRY(0x3129, "user_agent"),
    ENTRY(0x4752, "google_version"),
    ENTRY(0xff04de1b, "min_ack_delay"),
    ENTRY(0x0f739bbc1b666d05, "enable_multipath"),
    ENTRY(0x0f739bbc1b666d06, "enable_multipath(-06)"),
    ENTRY(0x4143414213370002, "bdp_frame"),
};
define_tls_sizeof_variable(quic_trans_param_code);

}  // namespace net
}  // namespace hotplace
