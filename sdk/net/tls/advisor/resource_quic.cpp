/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/quic/quic.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/tls/quic/types.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>

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
    {quic_frame_type_padding, "PADDING"},
    {quic_frame_type_ping, "PING"},
    {quic_frame_type_ack, "ACK"},
    {quic_frame_type_ack1, "ACK+1"},
    {quic_frame_type_reset_stream, "RESET_STREAM"},
    {quic_frame_type_stop_sending, "STOP_SENDING"},
    {quic_frame_type_crypto, "CRYPTO"},
    {quic_frame_type_new_token, "NEW_TOKEN"},
    {quic_frame_type_stream, "STREAM"},
    {quic_frame_type_stream1, "STREAM+1(F)"},
    {quic_frame_type_stream2, "STREAM+2(L)"},
    {quic_frame_type_stream3, "STREAM+3(FL)"},
    {quic_frame_type_stream4, "STREAM+4(O)"},
    {quic_frame_type_stream5, "STREAM+5(FO)"},
    {quic_frame_type_stream6, "STREAM+6(LO)"},
    {quic_frame_type_stream7, "STREAM+7(FLO)"},
    {quic_frame_type_max_data, "MAX_DATA"},
    {quic_frame_type_max_stream_data, "MAX_STREAM_DATA"},
    {quic_frame_type_max_streams, "MAX_STREAMS"},
    {quic_frame_type_max_streams1, "MAX_STREAMS+1"},
    {quic_frame_type_data_blocked, "DATA_BLOCKED"},
    {quic_frame_type_stream_data_blocked, "STREAM_DATA_BLOCKED"},
    {quic_frame_type_stream_blocked, "STREAMS_BLOCKED"},
    {quic_frame_type_stream_blocked1, "STREAMS_BLOCKED+1"},
    {quic_frame_type_new_connection_id, "NEW_CONNECTION_ID"},
    {quic_frame_type_retire_connection_id, "RETIRE_CONNECTION_ID"},
    {quic_frame_type_path_challenge, "PATH_CHALLENGE"},
    {quic_frame_type_path_response, "PATH_RESPONSE"},
    {quic_frame_type_connection_close, "CONNECTION_CLOSE"},
    {quic_frame_type_connection_close1, "CONNECTION_CLOSE+1 (Application)"},
    {quic_frame_type_handshake_done, "HANDSHAKE_DONE"},
    {quic_frame_type_immediate_ack, "IMMEDIATE_ACK"},
    {quic_frame_type_datagram, "DATAGRAM"},
    {quic_frame_type_datagram1, "DATAGRAM+1"},
    {quic_frame_type_ack_frequency, "ACK_FREQUENCY"},
    {quic_frame_type_ack_mp, "ACK_MP"},
    {quic_frame_type_ack_mp1, "ACK_MP+1"},
    {quic_frame_type_path_abandon, "PATH_ABANDON"},
    {quic_frame_type_path_status, "PATH_STATUS"},
    {quic_frame_type_path_standby, "PATH_STANDBY"},
    {quic_frame_type_path_available, "PATH_AVAILABLE"},
};
define_tls_sizeof_variable(quic_frame_type_code);

define_tls_variable(quic_trans_error_code) = {
    {quic_no_error, "NO_ERROR"},
    {quic_internal_error, "INTERNAL_ERROR"},
    {quic_connection_refused, "CONNECTION_REFUSED"},
    {quic_flow_control_error, "FLOW_CONTROL_ERROR"},
    {quic_stream_limit_error, "STREAM_LIMIT_ERROR"},
    {quic_stream_state_error, "STREAM_STATE_ERROR"},
    {quic_final_size_error, "FINAL_SIZE_ERROR"},
    {quic_frame_encoding_error, "FRAME_ENCODING_ERROR"},
    {quic_transport_parameter_error, "TRANSPORT_PARAMETER_ERROR"},
    {quic_connection_id_limit_error, "CONNECTION_ID_LIMIT_ERROR"},
    {quic_protocol_violation, "PROTOCOL_VIOLATION"},
    {quic_invalid_token, "INVALID_TOKEN"},
    {quic_application_error, "APPLICATION_ERROR"},
    {quic_crypto_buffer_exceeded, "CRYPTO_BUFFER_EXCEEDED"},
    {quic_key_update_error, "KEY_UPDATE_ERROR"},
    {quic_aead_limit_reached, "AEAD_LIMIT_REACHED"},
    {quic_no_viable_path, "NO_VIABLE_PATH"},
    {quic_version_negotiation_error, "VERSION_NEGOTIATION_ERROR"},
    {quic_crypto_error, "CRYPTO_ERROR"},  // -0x01ff
    {quic_mp_protocol_violation, "MP_PROTOCOL_VIOLATION"},
    {quic_bdp_token_error, "BDP_TOKEN_ERROR"},
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
