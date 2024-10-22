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

#include <sdk/io.hpp>
#include <sdk/net/http/http2/http2_frame.hpp>
#include <sdk/net/http/http_request.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
using namespace io;
namespace net {

constexpr char constexpr_content_type[] = "Content-Type";
constexpr char constexpr_url_encoded[] = "application/x-www-form-urlencoded";

http_request::http_request() : _hpsess(nullptr), _version(1), _stream_id(0) { _shared.make_share(this); }

http_request::http_request(const http_request& object) {
    _shared.make_share(this);
    _hpsess = object._hpsess;
    _version = object._version;
    _stream_id = object._stream_id;
    _method = object._method;
    _content = object._content;
    _header = object._header;
    _uri = object._uri;

    get_http_header().set_version(_version);
}

http_request::~http_request() { close(); }

return_t http_request::open(const char* request, size_t size_request, uint32 flags) {
    return_t ret = errorcode_t::success;
    return_t ret_getline = errorcode_t::success;

    __try2 {
        if (nullptr == request) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        close();

        std::string uri;
        size_t pos = 0;

        if (1 == get_version()) {
            /*
             * 1. request format
             *  GET /resource?a=1&b=2\r\n
             *  Content-Type: application/json\r\n
             *  \r\n
             *
             * 2. loop
             * while getline and tokenize(space or colon) do insert into map
             * line 1 -> GET /resource?a=1&b=2
             *           first token GET -> method
             *           next token /resource?a=1&b=2 -> uri
             * line 2 -> Content-Type: application/json
             *           insert(make_pair("Content-Type", "application/json"))
             * line 3 -> break loop if no space nor colon
             */

            size_t line = 1;
            size_t epos = 0;
            while (true) {
                ret_getline = getline(request, size_request, pos, &epos);
                if (errorcode_t::success != ret_getline) {
                    break;
                }

                std::string token, str(request + pos, epos - pos);
                size_t tpos = 0;
                token = tokenize(str, ": ", tpos);
                token = rtrim(token);

                if (0 == token.size()) {
                    break;
                }

                if ((epos <= size_request) && (tpos < size_request)) { /* if token (space, colon) not found */
                    while (isspace(str[tpos])) {
                        tpos++; /* swallow trailing spaces */
                    }
                    if (1 == line) {
                        _method = token; /* first token aka GET, POST, ... */

                        size_t zpos = tpos;
                        uri = tokenize(str, " ", zpos);
                        _uri.open(uri);
                    } else {
                        std::string remain = tokenize(str, "\r\n", tpos);  // std::string remain = str.substr(tpos);
                        _header.add(token, remain);
                    }
                }

                pos = epos;
                line++;
            }

            if (size_request > epos) {
                _content.assign(request + epos, size_request - epos);
            }
        } else if (2 == get_version()) {
            _method = get_http_header().get(":method");
            _uri.open(get_http_header().get(":path"));
        }

        // RFC 2616 3.7 Media Types
        // RFC 2616 14.17 Content-Type
        if (_content.empty()) {
            if (http_request_flag_t::http_request_compose & flags) {
                if ((std::string::npos != uri.find("?")) && (false == _header.contains(constexpr_content_type, constexpr_url_encoded))) {
                    // RFC 6750 2.2.  Form-Encoded Body Parameter
                    _header.add(constexpr_content_type, constexpr_url_encoded);
                    _content = _uri.get_query();

                    pos = 0;
                    _uri.open(tokenize(uri, "?", pos));  // uri wo param
                    _uri.set_query(_content);            // set param
                }
            }
        } else {
            if (_header.contains(constexpr_content_type, constexpr_url_encoded)) {
                _uri.set_query(_content);
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t http_request::open(const char* request, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == request) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = open(request, strlen(request), flags);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_request::open(const basic_stream& request, uint32 flags) { return open(request.c_str(), request.size(), flags); }

return_t http_request::open(const std::string& request, uint32 flags) { return open(request.c_str(), request.size(), flags); }

return_t http_request::close() {
    return_t ret = errorcode_t::success;

    _method.clear();
    _content.clear();
    _uri.close();
    return ret;
}

http_header& http_request::get_http_header() { return _header; }

http_uri& http_request::get_http_uri() { return _uri; }

std::string http_request::get_method() {
    // RFC 2616
    // 9.3 GET
    // 9.4 HEAD
    // 9.5 POST
    // 9.6 PUT
    // 9.7 DELETE
    // 9.8 TRACE
    std::string m;
    if (1 == _version) {
        m = _method;
    } else if (2 == _version) {
        m = get_http_header().get(":method");  // HTTP/2
    }
    return m;
}

http_request& http_request::compose(http_method_t method, const std::string& uri, const std::string& body) {
    if (1 == _version) {
        http_resource* resource = http_resource::get_instance();
        basic_stream stream;

        stream << resource->get_method(method) << " " << uri << " " << get_version() << "\r\n";
        // RFC 2616 14.13 Content-Length
        if (body.size()) {
            stream << "Content-Length: " << body.size() << "\r\n";
        }
        stream << "\r\n" << body;

        open(stream, http_request_flag_t::http_request_compose);  // reform if body is empty
    } else {
        // TODO
    }
    return *this;
}

std::string http_request::get_content() { return _content; }

http_request& http_request::get_request(basic_stream& bs) {
    if (1 == _version) {
        // RFC 2616 14.13 Content-Length
        std::string headers;
        bs.clear();
        get_http_header().add("Content-Length", format("%zi", _content.size())).add("Connection", "Keep-Alive").get_headers(headers);

        bs << get_method() << " " << get_http_uri().get_uri() << " " << get_version() << "\r\n" << headers << "\r\n" << get_content();
    }
    return *this;
}

std::string http_request::get_version_str() {
    constexpr char ver1[] = "HTTP/1.1";  // RFC 2616 3.1 HTTP Version
    constexpr char ver2[] = "HTTP/2";

    return (1 == _version) ? ver1 : ver2;
}

http_request& http_request::operator=(const http_request& rhs) {
    _method = rhs._method;
    _content = rhs._content;

    _header = rhs._header;
    _uri = rhs._uri;

    return *this;
}

http_request& http_request::add_content(const char* buf, size_t bufsize) {
    for (size_t i = 0; buf && (i < bufsize); i++) {
        _content += buf[i];
    }
    return *this;
}

http_request& http_request::add_content(const binary_t& bin) { return add_content((char*)&bin[0], bin.size()); }

http_request& http_request::clear_content() {
    _content.clear();
    return *this;
}

http_request& http_request::set_hpack_session(hpack_session* session) {
    _hpsess = session;
    return *this;
}

http_request& http_request::set_version(uint8 version) {
    switch (version) {
        case 2:
        case 1:
            _version = version;
            get_http_header().set_version(version);
            break;
        default:
            break;
    }
    return *this;
}

http_request& http_request::set_stream_id(uint32 stream_id) {
    _stream_id = stream_id;
    return *this;
}

hpack_session* http_request::get_hpack_session() { return _hpsess; }

uint8 http_request::get_version() { return _version; }

uint32 http_request::get_stream_id() { return _stream_id; }

void http_request::addref() { _shared.addref(); }

void http_request::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
