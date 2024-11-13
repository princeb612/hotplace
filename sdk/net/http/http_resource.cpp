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

void http_resource::for_each_hpack_static_table(std::function<void(uint32 index, const char* name, const char* value)> func) {
#define HPACK_ENTRY(index, header_name, header_value) \
    { index, header_name, header_value }

    /**
     * RFC 7541 HPACK: Header Compression for HTTP/2
     * Appendix A.  Static Table Definition
     */

    struct static_table_entry {
        uint32 index;
        const char* name;
        const char* value;
    } entries[] = {
        HPACK_ENTRY(1, ":authority", nullptr),
        HPACK_ENTRY(2, ":method", "GET"),
        HPACK_ENTRY(3, ":method", "POST"),
        HPACK_ENTRY(4, ":path", "/"),
        HPACK_ENTRY(5, ":path", "/index.html"),
        HPACK_ENTRY(6, ":scheme", "http"),
        HPACK_ENTRY(7, ":scheme", "https"),
        HPACK_ENTRY(8, ":status", "200"),
        HPACK_ENTRY(9, ":status", "204"),
        HPACK_ENTRY(10, ":status", "206"),
        HPACK_ENTRY(11, ":status", "304"),
        HPACK_ENTRY(12, ":status", "400"),
        HPACK_ENTRY(13, ":status", "404"),
        HPACK_ENTRY(14, ":status", "500"),
        HPACK_ENTRY(15, "accept-charset", nullptr),
        HPACK_ENTRY(16, "accept-encoding", "gzip,deflate"),
        HPACK_ENTRY(17, "accept-language", nullptr),
        HPACK_ENTRY(18, "accept-ranges", nullptr),
        HPACK_ENTRY(19, "accept", nullptr),
        HPACK_ENTRY(20, "access-control-allow-origin", nullptr),
        HPACK_ENTRY(21, "age", nullptr),
        HPACK_ENTRY(22, "allow", nullptr),
        HPACK_ENTRY(23, "authorization", nullptr),
        HPACK_ENTRY(24, "cache-control", nullptr),
        HPACK_ENTRY(25, "content-disposition", nullptr),
        HPACK_ENTRY(26, "content-encoding", nullptr),
        HPACK_ENTRY(27, "content-language", nullptr),
        HPACK_ENTRY(28, "content-length", nullptr),
        HPACK_ENTRY(29, "content-location", nullptr),
        HPACK_ENTRY(30, "content-range", nullptr),
        HPACK_ENTRY(31, "content-type", nullptr),
        HPACK_ENTRY(32, "cookie", nullptr),
        HPACK_ENTRY(33, "date", nullptr),
        HPACK_ENTRY(34, "etag", nullptr),
        HPACK_ENTRY(35, "expect", nullptr),
        HPACK_ENTRY(36, "expires", nullptr),
        HPACK_ENTRY(37, "from", nullptr),
        HPACK_ENTRY(38, "host", nullptr),
        HPACK_ENTRY(39, "if-match", nullptr),
        HPACK_ENTRY(40, "if-modified-since", nullptr),
        HPACK_ENTRY(41, "if-none-match", nullptr),
        HPACK_ENTRY(42, "if-range", nullptr),
        HPACK_ENTRY(43, "if-unmodified-since", nullptr),
        HPACK_ENTRY(44, "last-modified", nullptr),
        HPACK_ENTRY(45, "link", nullptr),
        HPACK_ENTRY(46, "location", nullptr),
        HPACK_ENTRY(47, "max-forwards", nullptr),
        HPACK_ENTRY(48, "proxy-authenticate", nullptr),
        HPACK_ENTRY(49, "proxy-authorization", nullptr),
        HPACK_ENTRY(50, "range", nullptr),
        HPACK_ENTRY(51, "referer", nullptr),
        HPACK_ENTRY(52, "refresh", nullptr),
        HPACK_ENTRY(53, "retry-after", nullptr),
        HPACK_ENTRY(54, "server", nullptr),
        HPACK_ENTRY(55, "set-cookie", nullptr),
        HPACK_ENTRY(56, "strict-transport-security", nullptr),
        HPACK_ENTRY(57, "transfer-encoding", nullptr),
        HPACK_ENTRY(58, "user-agent", nullptr),
        HPACK_ENTRY(59, "vary", nullptr),
        HPACK_ENTRY(60, "via", nullptr),
        HPACK_ENTRY(61, "www-authenticate", nullptr),
    };

    if (func) {
        for (size_t i = 0; i < RTL_NUMBER_OF(entries); i++) {
            static_table_entry* item = entries + i;
            func(item->index, item->name, item->value);
        }
    }
}

size_t http_resource::sizeof_hpack_static_table_entries() { return 61; }

void http_resource::for_each_qpack_static_table(std::function<void(uint32 index, const char* name, const char* value)> func) {
#define QPACK_ENTRY(index, header_name, header_value) \
    { index, header_name, header_value }

    /**
     * RFC 9204 QPACK: Field Compression for HTTP/3
     * Appendix A.  Static Table
     */

    struct static_table_entry {
        uint32 index;
        const char* name;
        const char* value;
    } entries[] = {
        QPACK_ENTRY(0, ":authority", nullptr),
        QPACK_ENTRY(1, ":path", "/"),
        QPACK_ENTRY(2, "age", "0"),
        QPACK_ENTRY(3, "content-disposition", nullptr),
        QPACK_ENTRY(4, "content-length", "0"),
        QPACK_ENTRY(5, "cookie", nullptr),
        QPACK_ENTRY(6, "date", nullptr),
        QPACK_ENTRY(7, "etag", nullptr),
        QPACK_ENTRY(8, "if-modified-since", nullptr),
        QPACK_ENTRY(9, "if-none-match", nullptr),
        QPACK_ENTRY(10, "last-modified", nullptr),
        QPACK_ENTRY(11, "link", nullptr),
        QPACK_ENTRY(12, "location", nullptr),
        QPACK_ENTRY(13, "referer", nullptr),
        QPACK_ENTRY(14, "set-cookie", nullptr),
        QPACK_ENTRY(15, ":method", "CONNECT"),
        QPACK_ENTRY(16, ":method", "DELETE"),
        QPACK_ENTRY(17, ":method", "GET"),
        QPACK_ENTRY(18, ":method", "HEAD"),
        QPACK_ENTRY(19, ":method", "OPTIONS"),
        QPACK_ENTRY(20, ":method", "POST"),
        QPACK_ENTRY(21, ":method", "PUT"),
        QPACK_ENTRY(22, ":scheme", "http"),
        QPACK_ENTRY(23, ":scheme", "https"),
        QPACK_ENTRY(24, ":status", "103"),
        QPACK_ENTRY(25, ":status", "200"),
        QPACK_ENTRY(26, ":status", "304"),
        QPACK_ENTRY(27, ":status", "404"),
        QPACK_ENTRY(28, ":status", "503"),
        QPACK_ENTRY(29, "accept", "*/*"),
        QPACK_ENTRY(30, "accept", "application/dns-message"),
        QPACK_ENTRY(31, "accept-encoding", "gzip, deflate, br"),
        QPACK_ENTRY(32, "accept-ranges", "bytes"),
        QPACK_ENTRY(33, "access-control-allow-headers", "cache-control"),
        QPACK_ENTRY(34, "access-control-allow-headers", "content-type"),
        QPACK_ENTRY(35, "access-control-allow-origin", "*"),
        QPACK_ENTRY(36, "cache-control", "max-age=0"),
        QPACK_ENTRY(37, "cache-control", "max-age=2592000"),
        QPACK_ENTRY(38, "cache-control", "max-age=604800"),
        QPACK_ENTRY(39, "cache-control", "no-cache"),
        QPACK_ENTRY(40, "cache-control", "no-store"),
        QPACK_ENTRY(41, "cache-control", "public, max-age=31536000"),
        QPACK_ENTRY(42, "content-encoding", "br"),
        QPACK_ENTRY(43, "content-encoding", "gzip"),
        QPACK_ENTRY(44, "content-type", "application/dns-message"),
        QPACK_ENTRY(45, "content-type", "application/javascript"),
        QPACK_ENTRY(46, "content-type", "application/json"),
        QPACK_ENTRY(47, "content-type", "application/x-www-form-urlencoded"),
        QPACK_ENTRY(48, "content-type", "image/gif"),
        QPACK_ENTRY(49, "content-type", "image/jpeg"),
        QPACK_ENTRY(50, "content-type", "image/png"),
        QPACK_ENTRY(51, "content-type", "text/css"),
        QPACK_ENTRY(52, "content-type", "text/html;charset=utf-8"),
        QPACK_ENTRY(53, "content-type", "text/plain"),
        QPACK_ENTRY(54, "content-type", "text/plain;charset=utf-8"),
        QPACK_ENTRY(55, "range", "bytes=0-"),
        QPACK_ENTRY(56, "strict-transport-security", "max-age=31536000"),
        QPACK_ENTRY(57, "strict-transport-security", "max-age=31536000;includesubdomains"),
        QPACK_ENTRY(58, "strict-transport-security", "max-age=31536000;includesubdomains;preload"),
        QPACK_ENTRY(59, "vary", "accept-encoding"),
        QPACK_ENTRY(60, "vary", "origin"),
        QPACK_ENTRY(61, "x-content-type-options", "nosniff"),
        QPACK_ENTRY(62, "x-xss-protection", "1; mode=block"),
        QPACK_ENTRY(63, ":status", "100"),
        QPACK_ENTRY(64, ":status", "204"),
        QPACK_ENTRY(65, ":status", "206"),
        QPACK_ENTRY(66, ":status", "302"),
        QPACK_ENTRY(67, ":status", "400"),
        QPACK_ENTRY(68, ":status", "403"),
        QPACK_ENTRY(69, ":status", "421"),
        QPACK_ENTRY(70, ":status", "425"),
        QPACK_ENTRY(71, ":status", "500"),
        QPACK_ENTRY(72, "accept-language", nullptr),
        QPACK_ENTRY(73, "access-control-allow-credentials", "FALSE"),
        QPACK_ENTRY(74, "access-control-allow-credentials", "TRUE"),
        QPACK_ENTRY(75, "access-control-allow-headers", "*"),
        QPACK_ENTRY(76, "access-control-allow-methods", "get"),
        QPACK_ENTRY(77, "access-control-allow-methods", "get, post, options"),
        QPACK_ENTRY(78, "access-control-allow-methods", "options"),
        QPACK_ENTRY(79, "access-control-expose-headers", "content-length"),
        QPACK_ENTRY(80, "access-control-request-headers", "content-type"),
        QPACK_ENTRY(81, "access-control-request-method", "get"),
        QPACK_ENTRY(82, "access-control-request-method", "post"),
        QPACK_ENTRY(83, "alt-svc", "clear"),
        QPACK_ENTRY(84, "authorization", nullptr),
        QPACK_ENTRY(85, "content-security-policy", "script-src 'none';object-src 'none';base-uri 'none'"),
        QPACK_ENTRY(86, "early-data", "1"),
        QPACK_ENTRY(87, "expect-ct", nullptr),
        QPACK_ENTRY(88, "forwarded", nullptr),
        QPACK_ENTRY(89, "if-range", nullptr),
        QPACK_ENTRY(90, "origin", nullptr),
        QPACK_ENTRY(91, "purpose", "prefetch"),
        QPACK_ENTRY(92, "server", nullptr),
        QPACK_ENTRY(93, "timing-allow-origin", "*"),
        QPACK_ENTRY(94, "upgrade-insecure-requests", "1"),
        QPACK_ENTRY(95, "user-agent", nullptr),
        QPACK_ENTRY(96, "x-forwarded-for", nullptr),
        QPACK_ENTRY(97, "x-frame-options", "deny"),
        QPACK_ENTRY(98, "x-frame-options", "sameorigin"),
    };

    if (func) {
        for (size_t i = 0; i < RTL_NUMBER_OF(entries); i++) {
            static_table_entry* item = entries + i;
            func(item->index, item->name, item->value);
        }
    }
}

size_t http_resource::sizeof_qpack_static_table_entries() { return 99; }

}  // namespace net
}  // namespace hotplace
