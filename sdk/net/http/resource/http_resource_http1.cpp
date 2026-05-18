/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   http_resource_http1.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 2068 Hypertext Transfer Protocol -- HTTP/1.1
 *  RFC 2616 Hypertext Transfer Protocol -- HTTP/1.1
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

void http_resource::doload_resources_h1() {
    // RFC 2616 HTTP/1.1
    // 6.1.1 Status Code and Reason Phrase
    if (_status_codes.empty()) {
        // 10.1 Informational 1xx
        _status_codes.emplace(100, "Continue");
        _status_codes.emplace(101, "Switching Protocols");
        // 10.2 Successful 2xx
        _status_codes.emplace(200, "OK");
        _status_codes.emplace(201, "Created");
        _status_codes.emplace(202, "Accepted");
        _status_codes.emplace(203, "Non-Authoritative Information");
        _status_codes.emplace(204, "No Content");
        _status_codes.emplace(205, "Reset Content");
        _status_codes.emplace(206, "Partial Content");
        // 10.3 Redirection 3xx
        _status_codes.emplace(300, "Multiple Choices");
        _status_codes.emplace(301, "Moved Permanently");
        _status_codes.emplace(302, "Found");
        _status_codes.emplace(303, "See Other");
        _status_codes.emplace(304, "Not Modified");
        _status_codes.emplace(305, "Use Proxy");
        _status_codes.emplace(307, "Temporary Redirect");
        // 10.4 Client Error 4xx
        _status_codes.emplace(400, "Bad Request");
        _status_codes.emplace(401, "Unauthorized");
        _status_codes.emplace(402, "Payment Required");
        _status_codes.emplace(403, "Forbidden");
        _status_codes.emplace(404, "Not Found");
        _status_codes.emplace(405, "Method Not Allowed");
        _status_codes.emplace(406, "Not Acceptable");
        _status_codes.emplace(407, "Proxy Authentication Required");
        _status_codes.emplace(408, "Request Timeout");
        _status_codes.emplace(409, "Conflict");
        _status_codes.emplace(410, "Gone");
        _status_codes.emplace(411, "Length Required");
        _status_codes.emplace(412, "Precondition Failed");
        _status_codes.emplace(413, "Request Entity Too Large");
        _status_codes.emplace(414, "Request-URI Too Long");
        _status_codes.emplace(415, "Unsupported Media Type");
        _status_codes.emplace(416, "Requested Range Not Satisfiable");
        _status_codes.emplace(417, "Expectation Failed");
        _status_codes.emplace(426, "Upgrade Required");
        // 10.5 Server Error 5xx
        _status_codes.emplace(500, "Internal Server Error");
        _status_codes.emplace(501, "Not Implemented");
        _status_codes.emplace(502, "Bad Gateway");
        _status_codes.emplace(503, "Service Unavailable");
        _status_codes.emplace(504, "Gateway Timeout");
        _status_codes.emplace(505, "HTTP Version Not Supported");
    }

    // 5.1.1 Method
    if (_methods.empty()) {
        _methods.emplace(http_method_t::HTTP_OPTIONS, "OPTIONS");
        _methods.emplace(http_method_t::HTTP_GET, "GET");
        _methods.emplace(http_method_t::HTTP_HEAD, "HEAD");
        _methods.emplace(http_method_t::HTTP_POST, "POST");
        _methods.emplace(http_method_t::HTTP_PUT, "PUT");
        _methods.emplace(http_method_t::HTTP_DELETE, "DELETE");
        _methods.emplace(http_method_t::HTTP_TRACE, "TRACE");
    }
}

std::string http_resource::get_method(http_method_t method) {
    std::string resource;
    t_maphint<http_method_t, std::string> hint(_methods);
    hint.find(method, &resource);
    return resource;
}

}  // namespace net
}  // namespace hotplace
