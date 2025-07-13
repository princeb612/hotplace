/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      https://www.iana.org/assignments/http3-parameters/http3-parameters.xhtml
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP3_TYPES__
#define __HOTPLACE_SDK_NET_HTTP_HTTP3_TYPES__

#include <sdk/net/http/types.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 9114 6.  Stream Mapping and Usage
 */
enum h3_stream_t : uint8 {
    h3_control_stream = 0x00,        // RFC 9114 6.2.1.  Control Streams
    h3_push_stream = 0x01,           // RFC 9114 6.2.2.  Push Streams
    h3_qpack_encoder_stream = 0x02,  // RFC 9204 4.2.  Encoder and Decoder Streams
    h3_qpack_decoder_stream = 0x03,  // RFC 9204 4.2.  Encoder and Decoder Streams
};

/**
 * RFC 9114 7.2.  Frame Definitions
 */
enum h3_frame_t : uint64 {
    h3_frame_data = 0x0,          // RFC 9114 7.2.1
    h3_frame_headers = 0x1,       // RFC 9114 7.2.2
    h3_frame_cancel_push = 0x3,   // RFC 9114 7.2.3
    h3_frame_settings = 0x4,      // RFC 9114 7.2.4
    h3_frame_push_promise = 0x5,  // RFC 9114 7.2.5
    h3_frame_goaway = 0x7,        // RFC 9114 7.2.6
    h3_frame_origin = 0x0c,       //
    h3_frame_max_push_id = 0x0d,  // RFC 9114 7.2.7
    h3_frame_metadata = 0x4d,
    h3_frame_priority_update = 0xf0700,
    h3_frame_priority_update1 = 0xf0701,
};

/**
 * RFC 9114 7.2.4.1.  Defined SETTINGS Parameters
 */
enum h3_settings_param_t : uint16 {
    h3_settings_qpack_max_table_capacity = 0x1,
    h3_settings_max_field_section_size = 0x6,
    h3_settings_qpack_blocked_streams = 0x7,
    h3_settings_enable_connect_protocol = 0x8,
    h3_settings_h3_datagram = 0x33,
    h3_settings_enable_metadata = 0x4d44,
};

/**
 * RFC 9114 8.1.  HTTP/3 Error Codes
 */
enum h3_errorcodes_t : uint16 {
    h3_datagram_error = 0x33,
    h3_no_error = 0x0100,
    h3_general_protocol_error = 0x0101,
    h3_internal_error = 0x0102,
    h3_stream_creation_error = 0x0103,
    h3_closed_critical_stream = 0x0104,
    h3_frame_unexpected = 0x0105,
    h3_frame_error = 0x0106,
    h3_excessive_load = 0x0107,
    h3_id_error = 0x0108,
    h3_settings_error = 0x0109,
    h3_missing_settings = 0x010a,
    h3_request_rejected = 0x010b,
    h3_request_cancelled = 0x010c,
    h3_request_incomplete = 0x010d,
    h3_message_error = 0x010e,
    h3_connect_error = 0x010f,
    h3_version_fallback = 0x0110,
    qpack_decompression_failed = 0x0200,
    qpack_encoder_stream_error = 0x0201,
    qpack_decoder_stream_error = 0x0202,
};

}  // namespace net
}  // namespace hotplace

#endif
