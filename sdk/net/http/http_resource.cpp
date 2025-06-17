/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 2068 Hypertext Transfer Protocol -- HTTP/1.1
 *  RFC 2616 Hypertext Transfer Protocol -- HTTP/1.1
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/http2/http2_frame.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http_resource http_resource::_instance;

http_resource* http_resource::get_instance() {
    _instance.load_resources();
    return &_instance;
}

http_resource::http_resource() {}

void http_resource::load_resources() {
    if (_status_codes.empty()) {
        critical_section_guard guard(_lock);
        if (_status_codes.empty()) {
            doload_resources();
        }
    }
}

void http_resource::doload_resources() {
    // RFC 2616 HTTP/1.1
    // 6.1.1 Status Code and Reason Phrase
    if (_status_codes.empty()) {
        // 10.1 Informational 1xx
        _status_codes.insert(std::make_pair(100, "Continue"));
        _status_codes.insert(std::make_pair(101, "Switching Protocols"));
        // 10.2 Successful 2xx
        _status_codes.insert(std::make_pair(200, "OK"));
        _status_codes.insert(std::make_pair(201, "Created"));
        _status_codes.insert(std::make_pair(202, "Accepted"));
        _status_codes.insert(std::make_pair(203, "Non-Authoritative Information"));
        _status_codes.insert(std::make_pair(204, "No Content"));
        _status_codes.insert(std::make_pair(205, "Reset Content"));
        _status_codes.insert(std::make_pair(206, "Partial Content"));
        // 10.3 Redirection 3xx
        _status_codes.insert(std::make_pair(300, "Multiple Choices"));
        _status_codes.insert(std::make_pair(301, "Moved Permanently"));
        _status_codes.insert(std::make_pair(302, "Found"));
        _status_codes.insert(std::make_pair(303, "See Other"));
        _status_codes.insert(std::make_pair(304, "Not Modified"));
        _status_codes.insert(std::make_pair(305, "Use Proxy"));
        _status_codes.insert(std::make_pair(307, "Temporary Redirect"));
        // 10.4 Client Error 4xx
        _status_codes.insert(std::make_pair(400, "Bad Request"));
        _status_codes.insert(std::make_pair(401, "Unauthorized"));
        _status_codes.insert(std::make_pair(402, "Payment Required"));
        _status_codes.insert(std::make_pair(403, "Forbidden"));
        _status_codes.insert(std::make_pair(404, "Not Found"));
        _status_codes.insert(std::make_pair(405, "Method Not Allowed"));
        _status_codes.insert(std::make_pair(406, "Not Acceptable"));
        _status_codes.insert(std::make_pair(407, "Proxy Authentication Required"));
        _status_codes.insert(std::make_pair(408, "Request Timeout"));
        _status_codes.insert(std::make_pair(409, "Conflict"));
        _status_codes.insert(std::make_pair(410, "Gone"));
        _status_codes.insert(std::make_pair(411, "Length Required"));
        _status_codes.insert(std::make_pair(412, "Precondition Failed"));
        _status_codes.insert(std::make_pair(413, "Request Entity Too Large"));
        _status_codes.insert(std::make_pair(414, "Request-URI Too Long"));
        _status_codes.insert(std::make_pair(415, "Unsupported Media Type"));
        _status_codes.insert(std::make_pair(416, "Requested Range Not Satisfiable"));
        _status_codes.insert(std::make_pair(417, "Expectation Failed"));
        _status_codes.insert(std::make_pair(426, "Upgrade Required"));
        // 10.5 Server Error 5xx
        _status_codes.insert(std::make_pair(500, "Internal Server Error"));
        _status_codes.insert(std::make_pair(501, "Not Implemented"));
        _status_codes.insert(std::make_pair(502, "Bad Gateway"));
        _status_codes.insert(std::make_pair(503, "Service Unavailable"));
        _status_codes.insert(std::make_pair(504, "Gateway Timeout"));
        _status_codes.insert(std::make_pair(505, "HTTP Version Not Supported"));
    }

    // 5.1.1 Method
    if (_methods.empty()) {
        _methods.insert(std::make_pair(http_method_t::HTTP_OPTIONS, "OPTIONS"));
        _methods.insert(std::make_pair(http_method_t::HTTP_GET, "GET"));
        _methods.insert(std::make_pair(http_method_t::HTTP_HEAD, "HEAD"));
        _methods.insert(std::make_pair(http_method_t::HTTP_POST, "POST"));
        _methods.insert(std::make_pair(http_method_t::HTTP_PUT, "PUT"));
        _methods.insert(std::make_pair(http_method_t::HTTP_DELETE, "DELETE"));
        _methods.insert(std::make_pair(http_method_t::HTTP_TRACE, "TRACE"));
    }

    if (_frame_names.empty()) {
        _frame_names.insert(std::make_pair(h2_frame_t::h2_frame_data, "DATA"));
        _frame_names.insert(std::make_pair(h2_frame_t::h2_frame_headers, "HEADERS"));
        _frame_names.insert(std::make_pair(h2_frame_t::h2_frame_priority, "PRIORITY"));
        _frame_names.insert(std::make_pair(h2_frame_t::h2_frame_rst_stream, "RST_STREAM"));
        _frame_names.insert(std::make_pair(h2_frame_t::h2_frame_settings, "SETTINGS"));
        _frame_names.insert(std::make_pair(h2_frame_t::h2_frame_push_promise, "PUSH_PROMISE"));
        _frame_names.insert(std::make_pair(h2_frame_t::h2_frame_ping, "PING"));
        _frame_names.insert(std::make_pair(h2_frame_t::h2_frame_goaway, "GOAWAY"));
        _frame_names.insert(std::make_pair(h2_frame_t::h2_frame_window_update, "WINDOW_UPDATE"));
        _frame_names.insert(std::make_pair(h2_frame_t::h2_frame_continuation, "CONTINUATION"));
        _frame_names.insert(std::make_pair(h2_frame_t::h2_frame_altsvc, "ALTSVC"));
    }

    if (_frame_flags.empty()) {
        _frame_flags.insert(std::make_pair(h2_flag_t::h2_flag_end_stream, "END_STREAM"));
        _frame_flags.insert(std::make_pair(h2_flag_t::h2_flag_end_headers, "END_HEADERS"));
        _frame_flags.insert(std::make_pair(h2_flag_t::h2_flag_padded, "PADDED"));
        _frame_flags.insert(std::make_pair(h2_flag_t::h2_flag_priority, "PRIORITY"));
    }
    if (_frame_flags2.empty()) {
        _frame_flags2.insert(std::make_pair(h2_flag_t::h2_flag_ack, "ACK"));
    }
    if (_frame_settings.empty()) {
        _frame_settings.insert({h2_settings_header_table_size, "SETTINGS_HEADER_TABLE_SIZE"});
        _frame_settings.insert({h2_settings_enable_push, "SETTINGS_ENABLE_PUSH"});
        _frame_settings.insert({h2_settings_max_concurrent_streams, "SETTINGS_MAX_CONCURRENT_STREAMS"});
        _frame_settings.insert({h2_settings_initial_window_size, "SETTINGS_INITIAL_WINDOW_SIZE"});
        _frame_settings.insert({h2_settings_max_frame_size, "SETTINGS_MAX_FRAME_SIZE"});
        _frame_settings.insert({h2_settings_max_header_list_size, "SETTINGS_MAX_HEADER_LIST_SIZE"});
    }
}

std::string http_resource::load(int status) {
    std::string message;
    t_maphint<int, std::string> hint(_status_codes);
    hint.find(status, &message);
    return message;
}

std::string http_resource::get_method(http_method_t method) {
    std::string resource;
    t_maphint<http_method_t, std::string> hint(_methods);
    hint.find(method, &resource);
    return resource;
}

std::string http_resource::get_frame_name(uint8 type) {
    std::string name;
    t_maphint<uint8, std::string> hint(_frame_names);
    hint.find(type, &name);
    return name;
}

std::string http_resource::get_frame_flag(uint8 flag) {
    std::string flag_name;
    t_maphint<uint8, std::string> hint(_frame_flags);
    hint.find(flag, &flag_name);
    return flag_name;
}

void http_resource::for_each_frame_flag_names(uint8 type, uint8 flags, std::function<void(uint8, const std::string&)> func) {
    if (flags && func) {
        switch (type) {
            case h2_frame_t::h2_frame_settings:
            case h2_frame_t::h2_frame_ping:
                for (auto item : _frame_flags2) {
                    uint8 flag = item.first;
                    if (flags & flag) {
                        func(flag, item.second);
                    }
                }
                break;
            default:
                for (auto item : _frame_flags) {
                    uint8 flag = item.first;
                    if (flags & flag) {
                        func(flag, item.second);
                    }
                }
                break;
        }
    }
}

struct static_table_entry {
    uint32 index;
    const char* name;
    const char* value;
};

static_table_entry h2_static_entries[] = {
    {1, ":authority"},
    {2, ":method", "GET"},
    {3, ":method", "POST"},
    {4, ":path", "/"},
    {5, ":path", "/index.html"},
    {6, ":scheme", "http"},
    {7, ":scheme", "https"},
    {8, ":status", "200"},
    {9, ":status", "204"},
    {10, ":status", "206"},
    {11, ":status", "304"},
    {12, ":status", "400"},
    {13, ":status", "404"},
    {14, ":status", "500"},
    {15, "accept-charset"},
    {16, "accept-encoding", "gzip,deflate"},
    {17, "accept-language"},
    {18, "accept-ranges"},
    {19, "accept"},
    {20, "access-control-allow-origin"},
    {21, "age"},
    {22, "allow"},
    {23, "authorization"},
    {24, "cache-control"},
    {25, "content-disposition"},
    {26, "content-encoding"},
    {27, "content-language"},
    {28, "content-length"},
    {29, "content-location"},
    {30, "content-range"},
    {31, "content-type"},
    {32, "cookie"},
    {33, "date"},
    {34, "etag"},
    {35, "expect"},
    {36, "expires"},
    {37, "from"},
    {38, "host"},
    {39, "if-match"},
    {40, "if-modified-since"},
    {41, "if-none-match"},
    {42, "if-range"},
    {43, "if-unmodified-since"},
    {44, "last-modified"},
    {45, "link"},
    {46, "location"},
    {47, "max-forwards"},
    {48, "proxy-authenticate"},
    {49, "proxy-authorization"},
    {50, "range"},
    {51, "referer"},
    {52, "refresh"},
    {53, "retry-after"},
    {54, "server"},
    {55, "set-cookie"},
    {56, "strict-transport-security"},
    {57, "transfer-encoding"},
    {58, "user-agent"},
    {59, "vary"},
    {60, "via"},
    {61, "www-authenticate"},
};

void http_resource::for_each_hpack_static_table(std::function<void(uint32 index, const char* name, const char* value)> func) {
    /**
     * RFC 7541 HPACK: Header Compression for HTTP/2
     * Appendix A.  Static Table Definition
     */

    if (func) {
        for (size_t i = 0; i < RTL_NUMBER_OF(h2_static_entries); i++) {
            static_table_entry* item = h2_static_entries + i;
            func(item->index, item->name, item->value);
        }
    }
}

size_t http_resource::sizeof_hpack_static_table_entries() { return RTL_NUMBER_OF(h2_static_entries); }

static_table_entry quic_static_entries[] = {
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
            static_table_entry* item = quic_static_entries + i;
            func(item->index, item->name, item->value);
        }
    }
}

size_t http_resource::sizeof_qpack_static_table_entries() { return RTL_NUMBER_OF(quic_static_entries); }

std::string http_resource::get_h2_settings_name(uint16 type) {
    std::string name;
    t_maphint<uint16, std::string> hint(_frame_settings);
    hint.find(type, &name);
    return name;
}

}  // namespace net
}  // namespace hotplace
