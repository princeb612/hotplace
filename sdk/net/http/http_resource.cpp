/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/system/critical_section.hpp>
#include <sdk/io/basic/zlib.hpp>
#include <sdk/io/string/string.hpp>
#include <sdk/net/basic/sdk.hpp>
#include <sdk/net/http/http.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace io;
namespace net {

http_resource http_resource::_instance;

http_resource* http_resource::get_instance() { return &_instance; }

http_resource::http_resource() {
    // RFC 2616 HTTP/1.1
    // 6.1.1 Status Code and Reason Phrase
    _status_codes.insert(std::make_pair(100, "Continue"));
    _status_codes.insert(std::make_pair(101, "Switching Protocols"));
    _status_codes.insert(std::make_pair(200, "OK"));
    _status_codes.insert(std::make_pair(201, "Created"));
    _status_codes.insert(std::make_pair(202, "Accepted"));
    _status_codes.insert(std::make_pair(204, "No Content"));
    _status_codes.insert(std::make_pair(205, "Reset Content"));
    _status_codes.insert(std::make_pair(206, "Partial Content"));
    _status_codes.insert(std::make_pair(300, "Multiple Choices"));
    _status_codes.insert(std::make_pair(301, "Moved Permanently"));
    _status_codes.insert(std::make_pair(302, "Moved Temporarily"));
    _status_codes.insert(std::make_pair(303, "See Other"));
    _status_codes.insert(std::make_pair(304, "Not Modified"));
    _status_codes.insert(std::make_pair(305, "Use Proxy"));
    _status_codes.insert(std::make_pair(400, "Bad Request"));
    _status_codes.insert(std::make_pair(401, "Unauthorized"));
    _status_codes.insert(std::make_pair(403, "Forbidden"));
    _status_codes.insert(std::make_pair(404, "Not Found"));
    _status_codes.insert(std::make_pair(405, "Method Not Allowed"));
    _status_codes.insert(std::make_pair(406, "Not Acceptable"));
    _status_codes.insert(std::make_pair(407, "Proxy Authentication Required"));
    _status_codes.insert(std::make_pair(408, "Request Time-out"));
    _status_codes.insert(std::make_pair(409, "Conflict"));
    _status_codes.insert(std::make_pair(410, "Gone"));
    _status_codes.insert(std::make_pair(411, "Length Required"));
    _status_codes.insert(std::make_pair(412, "Precondition Failed"));
    _status_codes.insert(std::make_pair(413, "Request Entity Too Large"));
    _status_codes.insert(std::make_pair(414, "Request-URI Too Large"));
    _status_codes.insert(std::make_pair(415, "Unsupported Media Type"));
    _status_codes.insert(std::make_pair(426, "Upgrade Required"));
    _status_codes.insert(std::make_pair(500, "Internal Server Error"));
    _status_codes.insert(std::make_pair(501, "Not Implemented"));
    _status_codes.insert(std::make_pair(502, "Bad Gateway"));
    _status_codes.insert(std::make_pair(503, "Service Unavailable"));
    _status_codes.insert(std::make_pair(504, "Gateway Time-out"));
    _status_codes.insert(std::make_pair(505, "HTTP Version not supported"));

    // 5.1.1 Method
    _methods.insert(std::make_pair(http_method_t::HTTP_OPTIONS, "OPTIONS"));
    _methods.insert(std::make_pair(http_method_t::HTTP_GET, "GET"));
    _methods.insert(std::make_pair(http_method_t::HTTP_HEAD, "HEAD"));
    _methods.insert(std::make_pair(http_method_t::HTTP_POST, "POST"));
    _methods.insert(std::make_pair(http_method_t::HTTP_PUT, "PUT"));
    _methods.insert(std::make_pair(http_method_t::HTTP_DELETE, "DELETE"));
    _methods.insert(std::make_pair(http_method_t::HTTP_TRACE, "TRACE"));
}

std::string http_resource::load(int status) {
    std::string message;
    message = _status_codes.find(status)->second;
    return message;
}

std::string http_resource::get_method(http_method_t method) {
    std::string resource;
    resource = _methods.find(method)->second;
    return resource;
}

}  // namespace net
}  // namespace hotplace
