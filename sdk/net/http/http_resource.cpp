/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base.hpp>
#include <sdk/io.hpp>
#include <sdk/net/http/http2/http2_frame.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
using namespace io;
namespace net {

http_resource http_resource::_instance;

http_resource* http_resource::get_instance() { return &_instance; }

http_resource::http_resource() {}

void http_resource::load_resources() {
    // RFC 2616 HTTP/1.1
    // 6.1.1 Status Code and Reason Phrase
    if (_status_codes.empty()) {
        _status_codes.insert(std::make_pair(100, "Continue"));
        _status_codes.insert(std::make_pair(101, "Switching Protocols"));
        _status_codes.insert(std::make_pair(200, "OK"));
        _status_codes.insert(std::make_pair(201, "Created"));
        _status_codes.insert(std::make_pair(202, "Accepted"));
        _status_codes.insert(std::make_pair(203, "Non-Authoritative Information"));
        _status_codes.insert(std::make_pair(204, "No Content"));
        _status_codes.insert(std::make_pair(205, "Reset Content"));
        _status_codes.insert(std::make_pair(206, "Partial Content"));
        _status_codes.insert(std::make_pair(300, "Multiple Choices"));
        _status_codes.insert(std::make_pair(301, "Moved Permanently"));
        _status_codes.insert(std::make_pair(302, "Found"));
        _status_codes.insert(std::make_pair(303, "See Other"));
        _status_codes.insert(std::make_pair(304, "Not Modified"));
        _status_codes.insert(std::make_pair(305, "Use Proxy"));
        _status_codes.insert(std::make_pair(307, "Temporary Redirect"));
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
    load_resources();

    std::string message;
    maphint<int, std::string> hint(_status_codes);
    hint.find(status, &message);
    return message;
}

std::string http_resource::get_method(http_method_t method) {
    load_resources();

    std::string resource;
    maphint<http_method_t, std::string> hint(_methods);
    hint.find(method, &resource);
    return resource;
}

std::string http_resource::get_frame_name(uint8 type) {
    load_resources();

    std::string name;
    maphint<uint8, std::string> hint(_frame_names);
    hint.find(type, &name);
    return name;
}

std::string http_resource::get_frame_flag(uint8 flag) {
    load_resources();

    std::string flag_name;
    maphint<uint8, std::string> hint(_frame_flags);
    hint.find(flag, &flag_name);
    return flag_name;
}

void http_resource::for_each_frame_flag_names(uint8 type, uint8 flags, std::function<void(uint8, std::string const&)> func) {
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

}  // namespace net
}  // namespace hotplace
