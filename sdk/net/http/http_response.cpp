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
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/http/http_response.hpp>

namespace hotplace {
using namespace io;
namespace net {

http_response::http_response() : _request(nullptr), _statuscode(0), _encoder(nullptr), _hpsess(nullptr), _version(1), _stream_id(0) {
    _shared.make_share(this);
}

http_response::http_response(http_request* request) : _request(request), _statuscode(0), _encoder(nullptr), _hpsess(nullptr), _version(1), _stream_id(0) {
    _shared.make_share(this);
    if (request) {
        request->addref();
        _encoder = request->get_hpack_encoder();
        _hpsess = request->get_hpack_session();
        _version = request->get_version();
        _stream_id = request->get_stream_id();

        get_http_header().set_version(_version);
    }
}

http_response::http_response(const http_response& object) {
    _shared.make_share(this);
    _request = object._request;
    if (_request) {
        _request->addref();
    }
    _encoder = object._encoder;
    _hpsess = object._hpsess;
    _version = object._version;
    _stream_id = object._stream_id;
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

        if (1 != _version) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

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

            // RFC 2616 3.5 Content Codings
            // RFC 2616 14.11 Content-Encoding
            std::string encoding = get_http_header().get("Content-Encoding");
            if ("deflate" == encoding) {
                basic_stream inflated;
                zlib_inflate(zlib_windowbits_t::windowbits_deflate, content, content_size, &inflated);
                _content = inflated;
            } else if ("gzip" == encoding) {
                basic_stream inflated;
                zlib_inflate(zlib_windowbits_t::windowbits_gzip, content, content_size, &inflated);
                _content = inflated;
            } else {
                _content.write(content, content_size);
            }
        }

        // RFC 2616 3.7 Media Types
        // RFC 2616 14.17 Content-Type
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

return_t http_response::open(const basic_stream& response) { return open(response.c_str(), response.size()); }

return_t http_response::open(const std::string& response) { return open(response.c_str(), response.size()); }

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
        _content.vprintf(content, ap);
        va_end(ap);
    }
    _statuscode = status_code;
    return *this;
}

http_response& http_response::compose(int status_code, const std::string& content_type, const char* content, ...) {
    close();

    _content_type = content_type;
    if (nullptr != content) {
        va_list ap;
        va_start(ap, content);
        _content.vprintf(content, ap);
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

        if (1 == _version) {
            basic_stream bs;
            get_response(bs);
            session->send(bs.data(), bs.size());
        } else if (2 == _version) {
            binary_t bin;
            get_response_h2(bin);
            session->send(&bin[0], bin.size());
        }
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

    if (1 == _version) {
        std::string accept_encoding;
        basic_stream method;
        if (_request) {
            // RFC 2616 3.5 Content Codings
            // RFC 2616 14.3 Accept-Encoding
            _request->get_http_header().get("Accept-Encoding", accept_encoding);
            method = _request->get_method();
        }

        http_resource* resource = http_resource::get_instance();

        std::string headers;
        if (_content_type.size() && content_size()) {
            // RFC 2616 3.7 Media Types
            // RFC 2616 14.17 Content-Type
            get_http_header().add("Content-Type", content_type());
        }
        get_http_header().add("Connection", "Keep-Alive");

        // RFC 2616 5.1.1 Method
        if (0 == strcmp("HEAD", method.c_str())) {
            get_http_header().add("Content-Length", "0").get_headers(headers);
            bs << get_version_str() << " " << status_code() << " " << resource->load(status_code()) << "\r\n" << headers << "\r\n";
        } else {
            // RFC 2616 3.5 Content Codings
            // RFC 2616 14.11 Content-Encoding
            if (std::string::npos != accept_encoding.find("deflate")) {
                basic_stream encoded;
                zlib_deflate(zlib_windowbits_t::windowbits_deflate, (byte_t*)content(), content_size(), &encoded);

                get_http_header().add("Content-Encoding", "deflate").add("Content-Length", format("%zi", encoded.size())).get_headers(headers);
                bs << get_version_str() << " " << status_code() << " " << resource->load(status_code()) << "\r\n" << headers << "\r\n";
                bs.write(encoded.data(), encoded.size());
            } else if (std::string::npos != accept_encoding.find("gzip")) {
                basic_stream encoded;
                zlib_deflate(zlib_windowbits_t::windowbits_gzip, (byte_t*)content(), content_size(), &encoded);

                get_http_header().add("Content-Encoding", "gzip").add("Content-Length", format("%zi", encoded.size())).get_headers(headers);
                bs << get_version_str() << " " << status_code() << " " << resource->load(status_code()) << "\r\n" << headers << "\r\n";
                bs.write(encoded.data(), encoded.size());
            } else /* "identity" */ {
                get_http_header().add("Content-Length", format("%zi", content_size())).get_headers(headers);

                bs << get_version_str() << " " << status_code() << " " << resource->load(status_code()) << "\r\n" << headers << "\r\n";
                bs.write(content(), content_size());
            }
        }
        if (_df) {
            basic_stream dbs;
            datetime dt;
            datetime_t t;
            dt.getlocaltime(&t);

            dbs.printf("%04d-%02d-%02d %02d:%02d:%02d.%03d\n", t.year, t.month, t.day, t.hour, t.minute, t.second, t.milliseconds);
            dump_memory(bs.data(), bs.size(), &dbs, 16, 2, 0, dump_notrunc);
            dbs.printf("\n");

            _df(&dbs);
        }
    }
    return *this;
}

http_response& http_response::get_response_h2(binary_t& bin) {
    if ((2 == _version) && get_hpack_encoder() && get_hpack_session()) {
        std::string accept_encoding;
        std::string method;
        if (_request) {
            _request->get_http_header().get("accept-encoding", accept_encoding);
            _request->get_http_header().get(":method", method);
        }

        std::string encoding;
        binary_t encoded;
        bool header_only = false;

        // RFC 2616 5.1.1 Method
        if (0 == strcmp("HEAD", method.c_str())) {
            header_only = true;
        } else if (content_size()) {
            header_only = false;

            // RFC 2616 3.5 Content Codings
            if (std::string::npos != accept_encoding.find("deflate")) {
                encoding = "deflate";
            } else if (std::string::npos != accept_encoding.find("gzip")) {
                encoding = "gzip";
            } else /* "identity" */ {
                // do nothing
            }
        }

        std::string altsvc_fieldvalue;
        hpack hp;
        hp.set_encoder(get_hpack_encoder())
            .set_session(get_hpack_session())
            .set_encode_flags(hpack_wo_indexing | hpack_huffman)  // chrome test
            .encode_header(":status", format("%i", status_code()).c_str())
            .encode_header("content-type", content_type());
        auto lambda_enc_headder = [&](const std::string& name, const std::string& value) -> void {
            if ("Alt-Svc" == name) {
                altsvc_fieldvalue = value;
            } else {
                hp.encode_header(name, value);
            }
        };
        get_http_header().get_headers(lambda_enc_headder);
        if (encoding.size()) {
            hp.encode_header("content-encoding", encoding);
        } else {
            // do nothing
        }

        http2_frame_headers headers;
        http2_frame_data data;

        uint8 flags = h2_flag_end_headers;
        if (true == header_only) {
            flags |= h2_flag_end_stream;
        }

        headers.set_flags(flags).set_stream_id(get_stream_id()).load_hpack(hp);
        data.set_flags(h2_flag_end_stream).set_stream_id(get_stream_id()).load_hpack(hp);

        if (false == header_only) {
            if (encoding.empty()) {
                data.get_data().insert(data.get_data().end(), content(), content() + content_size());
            } else {
                // RFC 2616 3.5 Content Codings
                if ("deflate" == encoding) {
                    zlib_deflate(zlib_windowbits_t::windowbits_deflate, (byte_t*)content(), content_size(), data.get_data());
                } else if ("gzip" == encoding) {
                    zlib_deflate(zlib_windowbits_t::windowbits_gzip, (byte_t*)content(), content_size(), data.get_data());
                }
            }
        }

        auto lambda_debug = [&](http2_frame* frame) -> void {
            if (_df) {
                basic_stream dbs;
                datetime dt;
                datetime_t t;
                dt.getlocaltime(&t);

                dbs.printf("%04d-%02d-%02d %02d:%02d:%02d.%03d\n", t.year, t.month, t.day, t.hour, t.minute, t.second, t.milliseconds);
                frame->dump(&dbs);
                dbs.printf("\n");

                _df(&dbs);
            }
        };

        // ALT_SVC
        if (altsvc_fieldvalue.size()) {
            http2_frame_alt_svc alt_svc;
            alt_svc.get_altsvc() = strtobin(altsvc_fieldvalue);

            alt_svc.write(bin);

            lambda_debug(&alt_svc);
        }

        // HEADERS
        {
            hp.encode_header("content-length", format("%zi", data.get_data().size()));
            headers.get_fragment() = hp.get_binary();

            headers.write(bin);

            lambda_debug(&headers);
        }

        // DATA
        if (false == header_only) {
            data.write(bin);

            lambda_debug(&data);
        }
    }
    return *this;
}

std::string http_response::get_version_str() {
    constexpr char ver1[] = "HTTP/1.1";  // RFC 2616 3.1 HTTP Version
    constexpr char ver2[] = "HTTP/2";

    return (1 == _version) ? ver1 : ver2;
}

http_response& http_response::operator=(const http_response& object) {
    _header = object._header;
    _request = object._request;
    _content_type = object._content_type;
    _content = object._content;
    _statuscode = object._statuscode;
    return *this;
}

http_response& http_response::set_hpack_encoder(hpack_encoder* encoder) {
    _encoder = encoder;
    return *this;
}

http_response& http_response::set_hpack_session(hpack_session* session) {
    _hpsess = session;
    return *this;
}

http_response& http_response::set_version(uint8 version) {
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

http_response& http_response::set_stream_id(uint32 stream_id) {
    _stream_id = stream_id;
    return *this;
}

hpack_encoder* http_response::get_hpack_encoder() { return _encoder; }

hpack_session* http_response::get_hpack_session() { return _hpsess; }

uint8 http_response::get_version() { return _version; }

uint32 http_response::get_stream_id() { return _stream_id; }

http_response& http_response::trace(std::function<void(stream_t*)> f) {
    _df = f;
    return *this;
}

void http_response::addref() { _shared.addref(); }

void http_response::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
