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

define_tls_variable(quic_frame_type_code) = {
    {0x00, "PADDING"},
    {0x01, "PING"},
    {0x02, "ACK"},
    {0x03, "ACK+1"},
    {0x04, "RESET_STREAM"},
    {0x05, "STOP_SENDING"},
    {0x06, "CRYPTO"},
    {0x07, "NEW_TOKEN"},
    {0x08, "STREAM"},
    {0x09, "STREAM+1"},
    {0x0a, "STREAM+2"},
    {0x0b, "STREAM+3"},
    {0x0c, "STREAM+4"},
    {0x0d, "STREAM+5"},
    {0x0e, "STREAM+6"},
    {0x0f, "STREAM+7"},
    {0x10, "MAX_DATA"},
    {0x11, "MAX_STREAM_DATA"},
    {0x12, "MAX_STREAMS"},
    {0x13, "MAX_STREAMS+1"},
    {0x14, "DATA_BLOCKED"},
    {0x15, "STREAM_DATA_BLOCKED"},
    {0x16, "STREAMS_BLOCKED"},
    {0x17, "STREAMS_BLOCKED+1"},
    {0x18, "NEW_CONNECTION_ID"},
    {0x19, "RETIRE_CONNECTION_ID"},
    {0x1a, "PATH_CHALLENGE"},
    {0x1b, "PATH_RESPONSE"},
    {0x1c, "CONNECTION_CLOSE"},
    {0x1d, "CONNECTION_CLOSE+1"},
    {0x1e, "HANDSHAKE_DONE"},
    {0x1f, "IMMEDIATE_ACK"},
    {0x30, "DATAGRAM"},
    {0x31, "DATAGRAM+1"},
    {0xaf, "ACK_FREQUENCY"},
    {0x15228c00, "ACK_MP"},
    {0x15228c01, "ACK_MP+1"},
    {0x15228c05, "PATH_ABANDON"},
    {0x15228c06, "PATH_STATUS"},
    {0x15228c07, "PATH_STANDBY"},
    {0x15228c08, "PATH_AVAILABLE"},
};
define_tls_sizeof_variable(quic_frame_type_code);

define_tls_variable(quic_trans_error_code) = {
    {0x00, "NO_ERROR"},
    {0x01, "INTERNAL_ERROR"},
    {0x02, "CONNECTION_REFUSED"},
    {0x03, "FLOW_CONTROL_ERROR"},
    {0x04, "STREAM_LIMIT_ERROR"},
    {0x05, "STREAM_STATE_ERROR"},
    {0x06, "FINAL_SIZE_ERROR"},
    {0x07, "FRAME_ENCODING_ERROR"},
    {0x08, "TRANSPORT_PARAMETER_ERROR"},
    {0x09, "CONNECTION_ID_LIMIT_ERROR"},
    {0x0a, "PROTOCOL_VIOLATION"},
    {0x0b, "INVALID_TOKEN"},
    {0x0c, "APPLICATION_ERROR"},
    {0x0d, "CRYPTO_BUFFER_EXCEEDED"},
    {0x0e, "KEY_UPDATE_ERROR"},
    {0x0f, "AEAD_LIMIT_REACHED"},
    {0x10, "NO_VIABLE_PATH"},
    {0x11, "VERSION_NEGOTIATION_ERROR"},
    {0x0100, "CRYPTO_ERROR"},  // -0x01ff
    {0x1001d76d3ded42f3, "MP_PROTOCOL_VIOLATION"},
    {0x4143414213370002, "BDP_TOKEN_ERROR"},
};
define_tls_sizeof_variable(quic_trans_error_code);

}  // namespace net
}  // namespace hotplace
