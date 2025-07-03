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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_TYPES__
#define __HOTPLACE_SDK_NET_TLS_QUIC_TYPES__

#include <sdk/net/http/types.hpp>
#include <sdk/net/server/types.hpp>
#include <sdk/net/types.hpp>

namespace hotplace {
namespace net {

enum quic_version_t : uint32 {
    quic_1 = 0x00000001,  // RFC 9000
    quic_2 = 0x6b3343cf,  // RFC 9369
};

/**
 * RFC 9000 17.  Packet Formats
 * 17.2.  Long Header Packets
 * 17.3.  Short Header Packets
 */
enum quic_packet_field_t : uint8 {
    quic_packet_field_hf = 0x80,          // RFC 9000 Figure 13, Header Form
    quic_packet_field_fb = 0x40,          // RFC 9000 Figure 13, Fixed Bit
    quic_packet_field_mask_lh = 0x30,     // RFC 9000 Figure 13, Long Packet Type
    quic_packet_field_initial = 0x00,     // RFC 9000 Table 5, 17.2.2, Initial Packet
    quic_packet_field_0_rtt = 0x10,       // RFC 9000 Table 5, 17.2.3, 0-RTT
    quic_packet_field_handshake = 0x20,   // RFC 9000 Table 5, 17.2.4, Handshake Packet
    quic_packet_field_retry = 0x30,       // RFC 9000 Table 5, 17.2.5, Retry Packet
    quic_packet_field_sb = 0x20,          // RFC 9000 Figure 19: 1-RTT Packet, 17.4.  Latency Spin Bit
    quic_packet_field_kp = 0x04,          // RFC 9000 Figure 19: 1-RTT Packet, Key Phase
    quic_packet_field_mask_pnl = 0x03,    // RFC 9000 Figure 19: 1-RTT Packet, Packet Number Length
    quic2_packet_field_initial = 0x10,    // RFC 9369 3.2.  Long Header Packet Types
    quic2_packet_field_0_rtt = 0x20,      // RFC 9369 3.2.  Long Header Packet Types
    quic2_packet_field_handshake = 0x30,  // RFC 9369 3.2.  Long Header Packet Types
    quic2_packet_field_retry = 0x00,      // RFC 9369 3.2.  Long Header Packet Types

};

/**
 * RFC 9000 17. Packet Formats
 *          17.2.1.  Version Negotiation Packet
 *          17.2.2.  Initial Packet
 *          17.2.3.  0-RTT
 *          17.2.4.  Handshake Packet
 *          17.2.5.  Retry Packet
 *          17.3.1.  1-RTT Packet
 * RFC 9369 3.2.  Long Header Packet Types
 */
enum quic_packet_t : uint8 {
    quic_packet_type_initial = 0,
    quic_packet_type_0_rtt = 1,
    quic_packet_type_handshake = 2,
    quic_packet_type_retry = 3,
    quic_packet_type_version_negotiation = 4,
    quic_packet_type_1_rtt = 5,
};

/*
 * RFC 9000 12.4.  Frames and Frame Types
 */
enum quic_frame_t : uint64 {
    quic_frame_type_padding = 0,  // RFC 9000 19.1  IH01
    quic_frame_type_ping = 1,     // RFC 9000 19.2  IH01
    quic_frame_type_ack = 2,      // RFC 9000 19.3  IH_1 0x02-0x03
    quic_frame_type_ack1 = 3,
    quic_frame_type_reset_stream = 4,  // RFC 9000 19.4  __01
    quic_frame_type_stop_sending = 5,  // RFC 9000 19.5  __01
    quic_frame_type_crypto = 6,        // RFC 9000 19.6  IH_1
    quic_frame_type_new_token = 7,     // RFC 9000 19.7  ___1
    quic_frame_type_stream = 8,        // RFC 9000 19.8  __01 0x08-0x0f
    quic_frame_type_stream1 = 9,
    quic_frame_type_stream2 = 0xa,
    quic_frame_type_stream3 = 0xb,
    quic_frame_type_stream4 = 0xc,
    quic_frame_type_stream5 = 0xd,
    quic_frame_type_stream6 = 0xe,
    quic_frame_type_stream7 = 0xf,
    quic_frame_type_max_data = 0x10,              // RFC 9000 19.9  __01
    quic_frame_type_max_stream_data = 0x11,       // RFC 9000 19.10 __01
    quic_frame_type_max_streams = 0x12,           // RFC 9000 19.11 __01 0x12-0x13
    quic_frame_type_data_blocked = 0x14,          // RFC 9000 19.12 __01
    quic_frame_type_stream_data_blocked = 0x15,   // RFC 9000 19.13 __01
    quic_frame_type_stream_blocked = 0x16,        // RFC 9000 19.14 __01 0x16-0x17
    quic_frame_type_new_connection_id = 0x18,     // RFC 9000 19.15 __01
    quic_frame_type_retire_connection_id = 0x19,  // RFC 9000 19.16 __01
    quic_frame_type_path_challenge = 0x1a,        // RFC 9000 19.17 __01
    quic_frame_type_path_response = 0x1b,         // RFC 9000 19.18 ___1
    quic_frame_type_connection_close = 0x1c,      // RFC 9000 19.19 ih01 0x1c-0x1d
    quic_frame_type_connection_close1 = 0x1d,     //
    quic_frame_type_handshake_done = 0x1e,        // RFC 9000 19.20 ___1
};

/**
 * RFC 9000 18.  Transport Parameter Encoding
 */
enum quic_param_t {
    quic_param_original_destination_connection_id = 0x00,
    quic_param_max_idle_timeout = 0x01,
    quic_param_stateless_reset_token = 0x02,
    quic_param_max_udp_payload_size = 0x03,
    quic_param_initial_max_data = 0x04,
    quic_param_initial_max_stream_data_bidi_local = 0x05,
    quic_param_initial_max_stream_data_bidi_remote = 0x06,
    quic_param_initial_max_stream_data_uni = 0x07,
    quic_param_initial_max_streams_bidi = 0x08,
    quic_param_initial_max_streams_uni = 0x09,
    quic_param_ack_delay_exponent = 0x0a,
    quic_param_max_ack_delay = 0x0b,
    quic_param_disable_active_migration = 0x0c,
    quic_param_preferred_address = 0x0d,
    quic_param_active_connection_id_limit = 0x0e,
    quic_param_initial_source_connection_id = 0x0f,
    quic_param_retry_source_connection_id = 0x10,
};

/**
 * RFC 9000 20.  Error Codes
 */
enum h3_errorcodes_t {
    h3_no_error = 0x00,
    h3_internal_error = 0x01,
    h3_connection_refused = 0x02,
    h3_flow_control_error = 0x03,
    h3_stream_limit_error = 0x04,
    h3_stream_state_error = 0x05,
    h3_final_size_error = 0x06,
    h3_frame_encoding_error = 0x07,
    h3_transport_parameter_error = 0x08,
    h3_connection_id_limit_error = 0x09,
    h3_protocol_violation = 0x0a,
    h3_invalid_token = 0x0b,
    h3_application_error = 0x0c,
    h3_crypto_buffer_exceeded = 0x0d,
    h3_key_update_error = 0x0e,
    h3_aead_limit_reached = 0x0f,
    h3_no_viable_path = 0x10,
    h3_crypto_error = 0x0100,  // 0x0100-0x01ff
};

class quic_frame;
class quic_frame_ack;
class quic_frame_builder;
class quic_frame_connection_close;
class quic_frame_crypto;
class quic_frame_data_blocked;
class quic_frame_handshake_done;
class quic_frame_max_data;
class quic_frame_max_stream_data;
class quic_frame_new_token;
class quic_frame_new_connection_id;
class quic_frame_padding;
class quic_frame_path_challenge;
class quic_frame_path_response;
class quic_frame_ping;
class quic_frame_reset_stream;
class quic_frame_retire_connection_id;
class quic_frame_stream;
class quic_frame_stream_blocked;
class quic_frame_stream_data_blocked;
class quic_frame_stop_sending;
class quic_frames;

class quic_packet;
class quic_packet_version_negotiation;
class quic_packet_initial;
class quic_packet_0rtt;
class quic_packet_handshake;
class quic_packet_retry;
class quic_packet_1rtt;
class quic_encoded;

}  // namespace net
}  // namespace hotplace

#endif
