/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/http3/types.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

void http_resource::doload_resources_h3() {
    if (_h3_error_codes.empty()) {
        // https://www.iana.org/assignments/http3-parameters/http3-parameters.xhtml
        _h3_error_codes.insert({h3_datagram_error, "H3_DATAGRAM_ERROR"});
        _h3_error_codes.insert({h3_no_error, "H3_NO_ERROR"});
        _h3_error_codes.insert({h3_general_protocol_error, "H3_GENERAL_PROTOCOL_ERROR"});
        _h3_error_codes.insert({h3_internal_error, "H3_INTERNAL_ERROR"});
        _h3_error_codes.insert({h3_stream_creation_error, "H3_STREAM_CREATION_ERROR"});
        _h3_error_codes.insert({h3_closed_critical_stream, "H3_CLOSED_CRITICAL_STREAM"});
        _h3_error_codes.insert({h3_frame_unexpected, "H3_FRAME_UNEXPECTED"});
        _h3_error_codes.insert({h3_frame_error, "H3_FRAME_ERROR"});
        _h3_error_codes.insert({h3_excessive_load, "H3_EXCESSIVE_LOAD"});
        _h3_error_codes.insert({h3_id_error, "H3_ID_ERROR"});
        _h3_error_codes.insert({h3_settings_error, "H3_SETTINGS_ERROR"});
        _h3_error_codes.insert({h3_missing_settings, "H3_MISSING_SETTINGS"});
        _h3_error_codes.insert({h3_request_rejected, "H3_REQUEST_REJECTED"});
        _h3_error_codes.insert({h3_request_cancelled, "H3_REQUEST_CANCELLED"});
        _h3_error_codes.insert({h3_request_incomplete, "H3_REQUEST_INCOMPLETE"});
        _h3_error_codes.insert({h3_message_error, "H3_MESSAGE_ERROR"});
        _h3_error_codes.insert({h3_connect_error, "H3_CONNECT_ERROR"});
        _h3_error_codes.insert({h3_version_fallback, "H3_VERSION_FALLBACK"});
        _h3_error_codes.insert({qpack_decompression_failed, "QPACK_DECOMPRESSION_FAILED"});
        _h3_error_codes.insert({qpack_encoder_stream_error, "QPACK_ENCODER_STREAM_ERROR"});
        _h3_error_codes.insert({qpack_decoder_stream_error, "QPACK_DECODER_STREAM_ERROR"});
    }
    if (_h3_frame_names.empty()) {
        _h3_frame_names.insert({h3_frame_data, "DATA"});
        _h3_frame_names.insert({h3_frame_headers, "HEADERS"});
        _h3_frame_names.insert({h3_frame_cancel_push, "CANCEL_PUSH"});
        _h3_frame_names.insert({h3_frame_settings, "SETTINGS"});
        _h3_frame_names.insert({h3_frame_push_promise, "PUSH_PROMISE"});
        _h3_frame_names.insert({h3_frame_goaway, "GOAWAY"});
        _h3_frame_names.insert({h3_frame_origin, "ORIGIN"});
        _h3_frame_names.insert({h3_frame_max_push_id, "MAX_PUSH_ID"});
        _h3_frame_names.insert({h3_frame_metadata, "METADATA"});
        _h3_frame_names.insert({h3_frame_priority_update, "PRIOIRY_UPDATE"});
        _h3_frame_names.insert({h3_frame_priority_update1, "PRIOIRY_UPDATE + 1"});
    }
    if (_h3_frame_settings.empty()) {
        // RFC 9114 A.3.  HTTP/2 SETTINGS Parameters
        // https://www.iana.org/assignments/http3-parameters/http3-parameters.xhtml
        _h3_frame_settings.insert({h3_settings_qpack_max_table_capacity, "QPACK_MAX_TABLE_CAPACITY"});
        _h3_frame_settings.insert({h3_settings_max_field_section_size, "MAX_FIELD_SECTION_SIZE"});
        _h3_frame_settings.insert({h3_settings_qpack_blocked_streams, "QPACK_BLOCKED_STREAMS"});
        _h3_frame_settings.insert({h3_settings_enable_connect_protocol, "ENABLE_CONNECT_PROTOCOL"});
        _h3_frame_settings.insert({h3_settings_h3_datagram, "H3_DATAGRAM"});
        _h3_frame_settings.insert({h3_settings_enable_metadata, "ENABLE_METADATA"});
    }
    if (_h3_stream_names.empty()) {
        _h3_stream_names.insert({h3_control_stream, "CONTROL_STREAM"});
        _h3_stream_names.insert({h3_push_stream, "PUSH_STREAM"});
        _h3_stream_names.insert({h3_qpack_encoder_stream, "QPACK_ENCODER_STREAM"});
        _h3_stream_names.insert({h3_qpack_decoder_stream, "QPACK_DECODER_STREAM"});
    }
}

http_static_table_entry quic_static_entries[] = {
    {0, ":authority"},
    {1, ":path", "/"},
    {2, "age", "0"},
    {3, "content-disposition"},
    {4, "content-length", "0"},
    {5, "cookie"},
    {6, "date"},
    {7, "etag"},
    {8, "if-modified-since"},
    {9, "if-none-match"},
    {10, "last-modified"},
    {11, "link"},
    {12, "location"},
    {13, "referer"},
    {14, "set-cookie"},
    {15, ":method", "CONNECT"},
    {16, ":method", "DELETE"},
    {17, ":method", "GET"},
    {18, ":method", "HEAD"},
    {19, ":method", "OPTIONS"},
    {20, ":method", "POST"},
    {21, ":method", "PUT"},
    {22, ":scheme", "http"},
    {23, ":scheme", "https"},
    {24, ":status", "103"},
    {25, ":status", "200"},
    {26, ":status", "304"},
    {27, ":status", "404"},
    {28, ":status", "503"},
    {29, "accept", "*/*"},
    {30, "accept", "application/dns-message"},
    {31, "accept-encoding", "gzip, deflate, br"},
    {32, "accept-ranges", "bytes"},
    {33, "access-control-allow-headers", "cache-control"},
    {34, "access-control-allow-headers", "content-type"},
    {35, "access-control-allow-origin", "*"},
    {36, "cache-control", "max-age=0"},
    {37, "cache-control", "max-age=2592000"},
    {38, "cache-control", "max-age=604800"},
    {39, "cache-control", "no-cache"},
    {40, "cache-control", "no-store"},
    {41, "cache-control", "public, max-age=31536000"},
    {42, "content-encoding", "br"},
    {43, "content-encoding", "gzip"},
    {44, "content-type", "application/dns-message"},
    {45, "content-type", "application/javascript"},
    {46, "content-type", "application/json"},
    {47, "content-type", "application/x-www-form-urlencoded"},
    {48, "content-type", "image/gif"},
    {49, "content-type", "image/jpeg"},
    {50, "content-type", "image/png"},
    {51, "content-type", "text/css"},
    {52, "content-type", "text/html;charset=utf-8"},
    {53, "content-type", "text/plain"},
    {54, "content-type", "text/plain;charset=utf-8"},
    {55, "range", "bytes=0-"},
    {56, "strict-transport-security", "max-age=31536000"},
    {57, "strict-transport-security", "max-age=31536000;includesubdomains"},
    {58, "strict-transport-security", "max-age=31536000;includesubdomains;preload"},
    {59, "vary", "accept-encoding"},
    {60, "vary", "origin"},
    {61, "x-content-type-options", "nosniff"},
    {62, "x-xss-protection", "1; mode=block"},
    {63, ":status", "100"},
    {64, ":status", "204"},
    {65, ":status", "206"},
    {66, ":status", "302"},
    {67, ":status", "400"},
    {68, ":status", "403"},
    {69, ":status", "421"},
    {70, ":status", "425"},
    {71, ":status", "500"},
    {72, "accept-language"},
    {73, "access-control-allow-credentials", "FALSE"},
    {74, "access-control-allow-credentials", "TRUE"},
    {75, "access-control-allow-headers", "*"},
    {76, "access-control-allow-methods", "get"},
    {77, "access-control-allow-methods", "get, post, options"},
    {78, "access-control-allow-methods", "options"},
    {79, "access-control-expose-headers", "content-length"},
    {80, "access-control-request-headers", "content-type"},
    {81, "access-control-request-method", "get"},
    {82, "access-control-request-method", "post"},
    {83, "alt-svc", "clear"},
    {84, "authorization"},
    {85, "content-security-policy", "script-src 'none';object-src 'none';base-uri 'none'"},
    {86, "early-data", "1"},
    {87, "expect-ct"},
    {88, "forwarded"},
    {89, "if-range"},
    {90, "origin"},
    {91, "purpose", "prefetch"},
    {92, "server"},
    {93, "timing-allow-origin", "*"},
    {94, "upgrade-insecure-requests", "1"},
    {95, "user-agent"},
    {96, "x-forwarded-for"},
    {97, "x-frame-options", "deny"},
    {98, "x-frame-options", "sameorigin"},
};

void http_resource::for_each_qpack_static_table(std::function<void(uint32 index, const char* name, const char* value)> func) {
    /**
     * RFC 9204 QPACK: Field Compression for HTTP/3
     * Appendix A.  Static Table
     */

    if (func) {
        for (size_t i = 0; i < RTL_NUMBER_OF(quic_static_entries); i++) {
            http_static_table_entry* item = quic_static_entries + i;
            func(item->index, item->name, item->value);
        }
    }
}

size_t http_resource::sizeof_qpack_static_table_entries() { return RTL_NUMBER_OF(quic_static_entries); }

std::string http_resource::get_h3_stream_name(uint8 type) {
    std::string ret_value;
    auto iter = _h3_stream_names.find(type);
    if (_h3_stream_names.end() != iter) {
        ret_value = iter->second;
    }
    return ret_value;
}

std::string http_resource::get_h3_frame_name(uint64 type) {
    std::string ret_value;
    auto iter = _h3_frame_names.find(type);
    if (_h3_frame_names.end() != iter) {
        ret_value = iter->second;
    }
    return ret_value;
}

std::string http_resource::get_h3_error_string(uint16 code) {
    std::string ret_value;
    auto iter = _h3_error_codes.find(code);
    if (_h3_error_codes.end() != iter) {
        ret_value = iter->second;
    }
    return ret_value;
}

std::string http_resource::get_h3_settings_name(uint64 id) {
    std::string ret_value;
    auto iter = _h3_frame_settings.find(id);
    if (_h3_frame_settings.end() != iter) {
        ret_value = iter->second;
    } else {
        ret_value = "draft";
    }
    return ret_value;
}

}  // namespace net
}  // namespace hotplace
