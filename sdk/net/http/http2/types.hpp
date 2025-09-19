/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_HTTP2_TYPES__
#define __HOTPLACE_SDK_NET_HTTP_HTTP2_TYPES__

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/net/http/types.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   frame type
 * @see
 *          RFC 7540 4. HTTP Frames
 *          RFC 7540 11.2. Frame Type Registry
 */
enum h2_frame_t : uint8 {
    h2_frame_data = 0x0,           // RFC 7540 6.1. DATA
    h2_frame_headers = 0x1,        // RFC 7540 6.2. HEADERS
    h2_frame_priority = 0x2,       // RFC 7540 6.3. PRIORITY
    h2_frame_rst_stream = 0x3,     // RFC 7540 6.4. RST_STREAM
    h2_frame_settings = 0x4,       // RFC 7540 6.5. SETTINGS
    h2_frame_push_promise = 0x5,   // RFC 7540 6.6. PUSH_PROMISE
    h2_frame_ping = 0x6,           // RFC 7540 6.7. PING
    h2_frame_goaway = 0x7,         // RFC 7540 6.8. GOAWAY
    h2_frame_window_update = 0x8,  // RFC 7540 6.9. WINDOW_UPDATE
    h2_frame_continuation = 0x9,   // RFC 7540 6.10. CONTINUATION
    h2_frame_altsvc = 0xa,         // RFC 7838 4.  The ALTSVC HTTP/2 Frame
};

/**
 * @brief   frame flag
 * @see
 *          RFC 7540 6. Frame Definitions
 */
enum h2_flag_t {
    h2_flag_end_stream = 0x1,   // DATA, HEADERS
    h2_flag_end_headers = 0x4,  // HEADERS, PUSH_PROMISE, CONTINUATION
    h2_flag_padded = 0x8,       // DATA, HEADERS, PUSH_PROMISE
    h2_flag_priority = 0x20,    // HEADERS

    h2_flag_ack = 0x1,  // SETTINGS, PING
};

/**
 * @brief   settings frame parameters
 * @see
 *          RFC 7540 6.5.2. Defined Settings Parameters
 *          RFC 7540 11.3. Settings Registry
 */
enum h2_settings_param_t : uint16 {
    h2_settings_header_table_size = 0x1,
    h2_settings_enable_push = 0x2,
    h2_settings_max_concurrent_streams = 0x3,
    h2_settings_initial_window_size = 0x4,
    h2_settings_max_frame_size = 0x5,
    h2_settings_max_header_list_size = 0x6,
};

/**
 * @brief   error codes
 * @see
 *          RFC 7540 7. Error Codes
 *          RFC 7540 11.4. Error Code Registry
 */
enum h2_errorcodes_t {
    h2_no_error = 0x0,
    h2_protocol_error = 0x1,
    h2_internal_error = 0x2,
    h2_flow_control_error = 0x3,
    h2_settings_timeout = 0x4,
    h2_stream_closed = 0x5,
    h2_frame_size_error = 0x6,
    h2_refused_stream = 0x7,
    h2_cancel = 0x8,
    h2_compression_error = 0x9,
    h2_connect_error = 0xa,
    h2_enhance_your_calm = 0xb,
    h2_inadequate_security = 0xc,
    h2_http_1_1_required = 0xd,
};

#pragma pack(push, 1)

/**
 * @brief   frame
 * @see
 *          RFC 7540 6. Frame Definitionsz
 */
typedef struct _http2_frame_header_t {
    byte_t len[3];     // length (24), 2^14, SETTINGS_MAX_FRAME_SIZE 2^24-1
    uint8 type;        // type (8)
    uint8 flags;       // flags (8)
    uint32 stream_id;  // reserved (1), stream identifier (31), client odd-number, server even-number
} http2_frame_header_t;

typedef struct _http2_setting_t {
    uint16 id;
    uint32 value;
} http2_setting_t;

#pragma pack(pop)

}  // namespace net
}  // namespace hotplace

#endif
