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

http_response::http_response() : _request(nullptr), _statuscode(0) {
    // do nothing
}

http_response::http_response(http_request* request) : _request(request) {
    // do nothing
}

http_response::~http_response() {
    // do nothing
}

http_response& http_response::compose(const char* content_type, int status_code, const char* content, ...) {
    _content_type.clear();
    _content.clear();

    if (nullptr != content_type) {
        _content_type = content_type;
    }
    if (nullptr != content) {
        va_list ap;
        va_start(ap, content);
        _content = format(content, ap);
        va_end(ap);
    }
    _statuscode = status_code;
    return *this;
}

const char* http_response::content_type() { return _content_type.c_str(); }

const char* http_response::content() { return _content.c_str(); }

size_t http_response::content_size() { return _content.size(); }

int http_response::status_code() { return _statuscode; }

http_header* http_response::get_header() { return &_header; }

http_request* http_response::get_request() { return _request; }

http_response& http_response::get_response(basic_stream& bs) {
    bs.clear();

    std::string accept_encoding;
    basic_stream method;
    if (_request) {
        _request->get_header()->get("Accept-Encoding", accept_encoding);
        method = _request->get_method();
    }

    std::string headers;
    get_header()->add("Content-Type", content_type());
    get_header()->add("Connection", "Keep-Alive");
    if (0 == strcmp("HEAD", method.c_str())) {
        get_header()->add("Content-Length", "0");
        get_header()->get_headers(headers);
        bs.printf("HTTP/1.1 %3i %s\r\n%s\r\n", status_code(), http_resource::get_instance()->load(status_code()).c_str(), headers.c_str());
    } else {
        if (std::string::npos != accept_encoding.find("deflate")) {
            basic_stream encoded;
            zlib_deflate(zlib_windowbits_t::windowbits_deflate, (byte_t*)content(), content_size(), &encoded);

            get_header()->add("Content-Encoding", "deflate");
            get_header()->add("Content-Length", format("%zi", encoded.size()));
            get_header()->get_headers(headers);
            bs.printf("HTTP/1.1 %3i %s\r\n%s\r\n", status_code(), http_resource::get_instance()->load(status_code()).c_str(), headers.c_str());
            bs.write(encoded.data(), encoded.size());
        } else if (std::string::npos != accept_encoding.find("gzip")) {
            basic_stream encoded;
            zlib_deflate(zlib_windowbits_t::windowbits_zlib, (byte_t*)content(), content_size(), &encoded);

            get_header()->add("Content-Encoding", "gzip");
            get_header()->add("Content-Length", format("%zi", encoded.size()));
            get_header()->get_headers(headers);
            bs.printf("HTTP/1.1 %3i %s\r\n%s\r\n", status_code(), http_resource::get_instance()->load(status_code()).c_str(), headers.c_str());
            bs.write(encoded.data(), encoded.size());
        } else /* "identity" */ {
            get_header()->add("Content-Length", format("%zi", content_size()));
            get_header()->get_headers(headers);

            bs.printf("HTTP/1.1 %3i %s\r\n%s\r\n%.*s", status_code(), http_resource::get_instance()->load(status_code()).c_str(), headers.c_str(),
                      content_size(), content());
        }
    }

    return *this;
}

}  // namespace net
}  // namespace hotplace
