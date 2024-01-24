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

http_response::http_response() : _request(nullptr), _statuscode(0) { _shared.make_share(this); }

http_response::http_response(http_request* request) : _request(request), _statuscode(0) {
    _shared.make_share(this);
    if (_request) {
        _request->addref();
    }
}

http_response::http_response(const http_response& object) {
    _shared.make_share(this);
    _request = object._request;
    if (_request) {
        _request->addref();
    }
    _header = object._header;
    _content_type = object._content_type;
    _content = object._content;
    _statuscode = object._statuscode;
}

http_response::~http_response() {
    close();

    if (_request) {
        _request->release();
    }
}

return_t http_response::open(const char* response, size_t size_response) {
    return_t ret = errorcode_t::success;
    return_t ret_getline = errorcode_t::success;

    __try2 {
        if (nullptr == response) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        close();

        size_t line = 1;
        size_t pos = 0, epos = 0;
        while (true) {
            ret_getline = getline(response, size_response, pos, &epos);
            if (errorcode_t::success != ret_getline) {
                break;
            }

            std::string token, str(response + pos, epos - pos);
            size_t tpos = 0;
            token = tokenize(str, ": ", tpos);
            token = rtrim(token);

            if (0 == token.size()) {
                break;
            }

            if ((epos <= size_response) && (tpos < size_response)) { /* if token (space, colon) not found */
                while (isspace(str[tpos])) {
                    tpos++; /* swallow trailing spaces */
                }
                if (1 == line) {
                    size_t lpos = 0;
                    tokenize(str, " ", lpos);
                    std::string status = tokenize(str, " ", lpos);
                    _statuscode = atoi(status.c_str());
                } else {
                    std::string remain = tokenize(str, "\r\n", tpos);  // std::string remain = str.substr(tpos);
                    _header.add(token, remain);
                }
            }

            pos = epos;
            line++;
        }

        if (size_response > epos) {
            byte_t* content = (byte_t*)response + epos;
            size_t content_size = size_response - epos;

            std::string encoding = get_http_header().get("Content-Encoding");
            if ("deflate" == encoding) {
                basic_stream inflated;
                zlib_inflate(zlib_windowbits_t::windowbits_deflate, content, content_size, &inflated);
                _content.assign(inflated.c_str(), inflated.size());
            } else if ("gzip" == encoding) {
                basic_stream inflated;
                zlib_inflate(zlib_windowbits_t::windowbits_gzip, content, content_size, &inflated);
                _content.assign(inflated.c_str(), inflated.size());
            } else {
                _content.assign((char*)content, content_size);
            }
        }

        _header.get("Content-Type", _content_type);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t http_response::open(const char* response) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == response) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = open(response, strlen(response));
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_response::open(basic_stream const& response) { return open(response.c_str(), response.size()); }

return_t http_response::open(std::string const& response) { return open(response.c_str(), response.size()); }

return_t http_response::close() {
    return_t ret = errorcode_t::success;

    _content_type.clear();
    _content.clear();

    return ret;
}

http_response& http_response::compose(int status_code) {
    close();
    _statuscode = status_code;
    return *this;
}

http_response& http_response::compose(int status_code, const char* content_type, const char* content, ...) {
    close();

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

http_response& http_response::compose(int status_code, std::string const& content_type, const char* content, ...) {
    close();

    _content_type = content_type;
    if (nullptr != content) {
        va_list ap;
        va_start(ap, content);
        _content = format(content, ap);
        va_end(ap);
    }
    _statuscode = status_code;
    return *this;
}

return_t http_response::respond(network_session* session) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        basic_stream bs;
        get_response(bs);
        session->send((const char*)bs.data(), bs.size());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

const char* http_response::content_type() { return _content_type.c_str(); }

const char* http_response::content() { return _content.c_str(); }

size_t http_response::content_size() { return _content.size(); }

int http_response::status_code() { return _statuscode; }

http_header& http_response::get_http_header() { return _header; }

http_request* http_response::get_http_request() { return _request; }

http_response& http_response::get_response(basic_stream& bs) {
    bs.clear();

    std::string accept_encoding;
    basic_stream method;
    if (_request) {
        _request->get_http_header().get("Accept-Encoding", accept_encoding);
        method = _request->get_method();
    }

    http_resource* resource = http_resource::get_instance();

    std::string headers;
    if (_content_type.size() && content_size()) {
        get_http_header().add("Content-Type", content_type());
    }
    get_http_header().add("Connection", "Keep-Alive");

    if (0 == strcmp("HEAD", method.c_str())) {
        get_http_header().add("Content-Length", "0").get_headers(headers);
        bs << get_version() << " " << status_code() << " " << resource->load(status_code()) << "\r\n" << headers << "\r\n";
    } else {
        if (std::string::npos != accept_encoding.find("deflate")) {
            basic_stream encoded;
            zlib_deflate(zlib_windowbits_t::windowbits_deflate, (byte_t*)content(), content_size(), &encoded);

            get_http_header().add("Content-Encoding", "deflate").add("Content-Length", format("%zi", encoded.size())).get_headers(headers);
            bs << get_version() << " " << status_code() << " " << resource->load(status_code()) << "\r\n" << headers << "\r\n";
            bs.write(encoded.data(), encoded.size());
        } else if (std::string::npos != accept_encoding.find("gzip")) {
            basic_stream encoded;
            zlib_deflate(zlib_windowbits_t::windowbits_gzip, (byte_t*)content(), content_size(), &encoded);

            get_http_header().add("Content-Encoding", "gzip").add("Content-Length", format("%zi", encoded.size())).get_headers(headers);
            bs << get_version() << " " << status_code() << " " << resource->load(status_code()) << "\r\n" << headers << "\r\n";
            bs.write(encoded.data(), encoded.size());
        } else /* "identity" */ {
            get_http_header().add("Content-Length", format("%zi", content_size())).get_headers(headers);

            bs << get_version() << " " << status_code() << " " << resource->load(status_code()) << "\r\n" << headers << "\r\n";
            bs.write(content(), content_size());
        }
    }

    return *this;
}

std::string http_response::get_version() { return "HTTP/1.1"; }

void http_response::addref() { _shared.addref(); }

void http_response::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
