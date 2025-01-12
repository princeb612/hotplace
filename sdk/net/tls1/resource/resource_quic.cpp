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

#define ENDOF_DATA

define_tls_variable(quic_trans_param_code) = {
    {0x00, "original_destination_connection_id", ENDOF_DATA},
    {0x01, "max_idle_timeout", ENDOF_DATA},
    {0x02, "stateless_reset_token", ENDOF_DATA},
    {0x03, "max_udp_payload_size", ENDOF_DATA},
    {0x04, "initial_max_data", ENDOF_DATA},
    {0x05, "initial_max_stream_data_bidi_local", ENDOF_DATA},
    {0x06, "initial_max_stream_data_bidi_remote", ENDOF_DATA},
    {0x07, "initial_max_stream_data_uni", ENDOF_DATA},
    {0x08, "initial_max_streams_bidi", ENDOF_DATA},
    {0x09, "initial_max_streams_uni", ENDOF_DATA},
    {0x0a, "ack_delay_exponent", ENDOF_DATA},
    {0x0b, "max_ack_delay", ENDOF_DATA},
    {0x0c, "disable_active_migration", ENDOF_DATA},
    {0x0d, "preferred_address", ENDOF_DATA},
    {0x0e, "active_connection_id_limit", ENDOF_DATA},
    {0x0f, "initial_source_connection_id", ENDOF_DATA},
    {0x10, "retry_source_connection_id", ENDOF_DATA},
    {0x11, "version_information", ENDOF_DATA},
    {0x20, "max_datagram_frame_size", ENDOF_DATA},
    {0x173e, "discard", ENDOF_DATA},
    {0x26ab, "google handshake message", ENDOF_DATA},
    {0x2ab2, "grease_quic_bit", ENDOF_DATA},
    {0x3127, "initial_rtt", ENDOF_DATA},
    {0x3128, "google_connection_options", ENDOF_DATA},
    {0x3129, "user_agent", ENDOF_DATA},
    {0x4752, "google_version", ENDOF_DATA},
    {0xff04de1b, "min_ack_delay", ENDOF_DATA},
    {0x0f739bbc1b666d05, "enable_multipath", ENDOF_DATA},
    {0x0f739bbc1b666d06, "enable_multipath(-06)", ENDOF_DATA},
    {0x4143414213370002, "bdp_frame", ENDOF_DATA},
};
define_tls_sizeof_variable(quic_trans_param_code);

}  // namespace net
}  // namespace hotplace
