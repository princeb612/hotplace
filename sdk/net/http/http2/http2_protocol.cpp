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
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/net/basic/openssl/openssl_tls.hpp>
#include <sdk/net/http/http2/http2_frame.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>

namespace hotplace {
namespace net {

http2_protocol::http2_protocol() : network_protocol() {}

http2_protocol::~http2_protocol() {}

return_t http2_protocol::is_kind_of(void* stream, size_t stream_size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // RFC 7540 3.5. HTTP/2 Connection Preface
        // 0x505249202a20485454502f322e300d0a0d0a534d0d0a0d0a
        constexpr char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const uint16 sizeof_preface = 24;
        const uint16 sampling_size = 5;

        // check frame header
        if (stream_size >= sampling_size) {
            if (0 == strncmp(preface, (char*)stream, sampling_size)) {
                // if preface exists ...
                __leave2;
            } else {
                // check frame
                http2_frame_header_t* frame = (http2_frame_header_t*)(stream);
                if (stream_size >= sampling_size) {
                    byte_t type = frame->type;
                    byte_t flags = frame->flags;

                    byte_t mask_flags = ~(h2_flag_end_stream | h2_flag_end_headers | h2_flag_padded | h2_flag_priority);
                    if (flags & mask_flags) {
                        ret = errorcode_t::mismatch;
                    } else {
                        if ((h2_frame_data <= type) || (type <= h2_frame_continuation)) {
                            __leave2;
                        } else {
                            ret = errorcode_t::mismatch;
                        }
                    }
                } else {
                    ret = errorcode_t::more_data;
                }
            }
        } else {
            ret = errorcode_t::more_data;
        }
    }
    __finally2 {}
    return ret;
}

return_t http2_protocol::read_stream(basic_stream* stream, size_t* request_size, protocol_state_t* state, int* priority) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream || nullptr == request_size || nullptr == state) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (priority) {
            *priority = 0;
        }

        byte_t* stream_data = stream->data();
        uint32 stream_size = stream->size();

        // RFC 7540 3.5. HTTP/2 Connection Preface
        // 0x505249202a20485454502f322e300d0a0d0a534d0d0a0d0a
        constexpr char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const uint16 sizeof_preface = 24;
        const uint16 sampling_size = 5;

        if (stream_size < sampling_size) {
            *state = protocol_state_t::protocol_state_data;
            __leave2;
        }

        uint32 pos = 0;

        if (0 == strncmp(preface, (char*)stream_data, sampling_size)) {
            if ((stream_size >= sizeof_preface) && (0 == strncmp(preface, (char*)stream_data, sizeof_preface))) {
                // connection preface
                http2_frame_header_t* frame = (http2_frame_header_t*)(stream_data + sizeof_preface);
                if (stream_size >= sizeof_preface + RTL_FIELD_SIZE(http2_frame_header_t, len)) {
                    if (h2_frame_t::h2_frame_settings == frame->type) {
                        pos = sizeof_preface;
                    } else {
                        // This sequence MUST be followed by a SETTINGS frame (Section 6.5), which MAY be empty.
                        *state = protocol_state_t::protocol_state_crash;
                        __leave2;
                    }
                } else {
                    *state = protocol_state_t::protocol_state_data;
                    __leave2;
                }
            } else {
                *state = protocol_state_t::protocol_state_data;
                __leave2;
            }
        }

        if (stream_size >= RTL_FIELD_SIZE(http2_frame_header_t, len) + pos) {
            http2_frame_header_t* frame = (http2_frame_header_t*)(stream_data + pos);
            uint32 max_frame_size = get_constraints(protocol_constraints_t::protocol_packet_size);
            const uint32 frame_header_size = sizeof(http2_frame_header_t);
            uint32 len = 0;  // the length of the frame payload
            b24_i32(stream_data + pos, RTL_FIELD_SIZE(http2_frame_header_t, len), len);

            if (max_frame_size && (len > max_frame_size)) {
                *state = protocol_state_t::protocol_state_large;
                __leave2;
            }

            if (stream_size < frame_header_size + pos) {
                *state = protocol_state_t::protocol_state_data;
            } else if (stream_size < frame_header_size + len + pos) {
                *state = protocol_state_t::protocol_state_header;
            } else {
                *request_size = frame_header_size + len + pos;
                *state = protocol_state_t::protocol_state_complete;
            }
        }
    }
    __finally2 {}
    return ret;
}

const char* http2_protocol::protocol_id() { return "h2"; }

}  // namespace net
}  // namespace hotplace
