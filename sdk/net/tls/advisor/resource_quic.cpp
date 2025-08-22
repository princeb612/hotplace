/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/quic/quic.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls/quic/types.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

define_tls_variable(quic_trans_param_code) = {
    {quic_param_original_destination_connection_id, "original_destination_connection_id"},
    {quic_param_max_idle_timeout, "max_idle_timeout"},
    {quic_param_stateless_reset_token, "stateless_reset_token"},
    {quic_param_max_udp_payload_size, "max_udp_payload_size"},
    {quic_param_initial_max_data, "initial_max_data"},
    {quic_param_initial_max_stream_data_bidi_local, "initial_max_stream_data_bidi_local"},
    {quic_param_initial_max_stream_data_bidi_remote, "initial_max_stream_data_bidi_remote"},
    {quic_param_initial_max_stream_data_uni, "initial_max_stream_data_uni"},
    {quic_param_initial_max_streams_bidi, "initial_max_streams_bidi"},
    {quic_param_initial_max_streams_uni, "initial_max_streams_uni"},
    {quic_param_ack_delay_exponent, "ack_delay_exponent"},
    {quic_param_max_ack_delay, "max_ack_delay"},
    {quic_param_disable_active_migration, "disable_active_migration"},
    {quic_param_preferred_address, "preferred_address"},
    {quic_param_active_connection_id_limit, "active_connection_id_limit"},
    {quic_param_initial_source_connection_id, "initial_source_connection_id"},
    {quic_param_retry_source_connection_id, "retry_source_connection_id"},
    {quic_param_version_information, "version_information"},
    {quic_param_max_datagram_frame_size, "max_datagram_frame_size"},
    {quic_param_discard, "discard"},
    {quic_param_google_handshake_message, "google handshake message"},
    {quic_param_grease_quic_bit, "grease_quic_bit"},
    {quic_param_initial_rtt, "initial_rtt"},
    {quic_param_google_connection_options, "google_connection_options"},
    {quic_param_user_agent, "user_agent"},
    {quic_param_google_version, "google_version"},
    {quic_param_version_information_draft, "version_information_draft"},
    {quic_param_min_ack_delay, "min_ack_delay"},
    {quic_param_enable_multipath, "enable_multipath"},
    {quic_param_enable_multipath_06, "enable_multipath(-06)"},
    {quic_param_initial_max_path_id, "initial_max_path_id"},
    {quic_param_bdp_frame, "bdp_frame"},
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
    {0x09, "STREAM+1(F)"},
    {0x0a, "STREAM+2(L)"},
    {0x0b, "STREAM+3(FL)"},
    {0x0c, "STREAM+4(O)"},
    {0x0d, "STREAM+5(FO)"},
    {0x0e, "STREAM+6(LO)"},
    {0x0f, "STREAM+7(FLO)"},
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
    {0x1d, "CONNECTION_CLOSE+1 (Application)"},
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

define_tls_variable(quic_packet_type_code) = {
    {quic_packet_type_initial, "initial"},
    {quic_packet_type_0_rtt, "0-RTT"},
    {quic_packet_type_handshake, "handshake"},
    {quic_packet_type_retry, "retry"},
    {quic_packet_type_version_negotiation, "version negotiation"},
    {quic_packet_type_1_rtt, "1-RTT"},
};
define_tls_sizeof_variable(quic_packet_type_code);

}  // namespace net
}  // namespace hotplace
