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

http_request::http_request() { _shared.make_share(this); }

http_request::~http_request() { close(); }

return_t http_request::open(const char* request, size_t size_request) {
    return_t ret = errorcode_t::success;
    return_t ret_getline = errorcode_t::success;

    __try2 {
        if (nullptr == request) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        close();

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
        size_t pos = 0, epos = 0;
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
                    _uri.open(tokenize(str, " ", zpos));
                    /*
                       _uri = tokenize (str, " ", zpos);
                       zpos = 0;
                       _url = tokenize (_uri, "?", zpos);
                     */
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
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t http_request::open(const char* request) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == request) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = open(request, strlen(request));
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_request::open(basic_stream const& request) { return open(request.c_str(), request.size()); }

return_t http_request::open(std::string const& request) { return open(request.c_str(), request.size()); }

return_t http_request::close() {
    return_t ret = errorcode_t::success;

    _method.clear();
    _content.clear();
    _header.clear();
    _uri.close();
    return ret;
}

http_header& http_request::get_http_header() { return _header; }

http_uri& http_request::get_http_uri() { return _uri; }

const char* http_request::get_uri() { return get_http_uri().get_uri(); }

const char* http_request::get_method() { return _method.c_str(); }

http_request& http_request::compose(http_method_t method, std::string const& uri, std::string const& body) {
    close();

    http_resource* resource = http_resource::get_instance();
    _method = resource->get_method(method);
    get_http_uri().open(uri);
    _content = body;
    return *this;
}

std::string http_request::get_content() { return _content; }

http_request& http_request::get_request(basic_stream& bs) {
    std::string headers;
    bs.clear();
    get_http_header().add("Content-Length", format("%zi", _content.size())).add("Connection", "Keep-Alive").get_headers(headers);

    bs.printf("%s %s HTTP/1.1\r\n%s\r\n%s", get_method(), get_uri(), headers.c_str(), get_content().c_str());

    return *this;
}

void http_request::addref() { _shared.addref(); }

void http_request::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
