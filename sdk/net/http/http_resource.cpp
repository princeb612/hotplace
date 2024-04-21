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

void http_resource::for_each_frame_flags(uint8 flags, std::string& flag_string, std::function<void(uint8, std::string&)> func) {
    if (func) {
        for (auto item : _frame_flags) {
            uint8 flag = item.first;
            if (flags & flag) {
                func(flag, flag_string);
            }
        }
    }
}

void http_resource::for_each_frame_flags(uint8 flags, stream_t* flag_string, std::function<void(uint8, stream_t*)> func) {
    if (flag_string && func) {
        for (auto item : _frame_flags) {
            uint8 flag = item.first;
            if (flags & flag) {
                func(flag, flag_string);
            }
        }
    }
}

}  // namespace net
}  // namespace hotplace
