/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/string/string.hpp>
#include <hotplace/sdk/net/basic/sdk.hpp>
#include <hotplace/sdk/net/http/http.hpp>
#include <hotplace/sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace io;
namespace net {

http_header::http_header ()
{
    // do nothing
}

http_header::~http_header ()
{
    // do nothing
}

return_t http_header::add (const char* header, const char* value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        _lock.enter ();
        if (nullptr == header || nullptr == value) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        _headers.insert (std::make_pair (header, value));
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret;
}

return_t http_header::add (std::string header, std::string value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        _lock.enter ();

        _headers.insert (std::make_pair (header, value));
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret;
}

return_t http_header::clear ()
{
    return_t ret = errorcode_t::success;

    _lock.enter ();
    _headers.clear ();
    _lock.leave ();
    return ret;
}

const char* http_header::get (const char* header, std::string& content)
{
    const char* ret_value = nullptr;

    if (nullptr != header) {
        http_header_map_t::iterator iter = _headers.find (std::string (header));
        if (_headers.end () != iter) {
            content = iter->second;
            ret_value = content.c_str ();
        }
    }

    return ret_value;
}

const char* http_header::get_token (const char* header, unsigned index, std::string& token)
{
    const char* ret_value = nullptr;

    std::string content;
    std::string temp;

    if (nullptr != header) {
        http_header_map_t::iterator iter = _headers.find (std::string (header));
        if (_headers.end () != iter) {
            content = iter->second;

            size_t pos = 0;
            size_t current = 0;
            while (current <= index) {
                temp = tokenize (content, _T (" "), pos);
                if (true == temp.empty ()) {
                    break;
                }
                if (current == index) {
                    token = temp;
                    ret_value = token.c_str ();
                }
                current++;
            }
        }
    }

    return ret_value;
}

return_t http_header::get_headers (std::string& contents)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        //_tclean(contents);

        _lock.enter ();
        for (http_header_map_t::iterator it = _headers.begin (); it != _headers.end (); it++) {
            std::string key = it->first;
            std::string value = it->second;

            contents.append (format ("%s: %s\n", key.c_str (), value.c_str ()));
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret;
}

http_request::http_request ()
{
    // do nothing
}

http_request::~http_request ()
{
    close ();
}

return_t http_request::open (const char* request, size_t size_request)
{
    return_t ret = errorcode_t::success;
    return_t ret_getline = errorcode_t::success;

    __try2
    {
        if (nullptr == request) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        close ();

        /*
         * 1. request format
         *  GET /resource?a=1&b=2\n
         *  Content-Type: application/json\n
         *  \n
         *
         * 2. loop
         * while getline and tokenize(space or colon) do insert into map
         * line 1 -> GET /resource?a=1&b=2
         *           first token GET -> method
         *           next token /resource?a=1&b=2 -> uri
         * line 2 -> Content-Type: application/json
         *           insert(make_pair("Content-Type", "application/json"))
         * line 3 -> break loop cause of no space nor colon
         */

        size_t line = 1;
        size_t pos = 0, epos = 0;
        while (true) {
            ret_getline = getline (request, size_request, pos, &epos);
            if (errorcode_t::success != ret_getline) {
                break;
            }

            std::string token, str (request + pos, epos - pos);
            size_t tpos = 0;
            token = tokenize (str, ": ", tpos);
            token = rtrim (token);

            if (0 == token.size ()) {
                break;
            }

            if ((epos < size_request) && (tpos < size_request)) {   /* if token (space, colon) not found */
                while (isspace (str[tpos])) {
                    tpos++;                                         /* swallow trailing spaces */
                }
                if (1 == line) {
                    _method = token;                                /* first token aka GET, POST, ... */

                    size_t zpos = tpos;
                    __uri.open (tokenize (str, " ", zpos));
                    /*
                       _uri = tokenize (str, " ", zpos);
                       zpos = 0;
                       _url = tokenize (_uri, "?", zpos);
                     */
                }

                std::string remain = tokenize (str, "\r\n", tpos); //std::string remain = str.substr(tpos);
                __header.add (token, remain);
            }

            pos = epos;
            line++;
        }

        if (size_request > epos) {
            _request.assign (request + epos, size_request - epos);
        }
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

return_t http_request::close ()
{
    return_t ret = errorcode_t::success;

    _method.clear ();
    _request.clear ();
    __header.clear ();
    __uri.close ();
    return ret;
}

http_header* http_request::get_header ()
{
    return &__header;
}

http_uri* http_request::get_uri ()
{
    return &__uri;
}

const char* http_request::get_url ()
{
    return __uri.get_url ();
}

const char* http_request::get_method ()
{
    return _method.c_str ();
}

const char* http_request::get_request ()
{
    return _request.c_str ();
}

http_response::http_response ()
    : _statuscode (0)
{
    // do nothing
}

http_response::~http_response ()
{
    // do nothing
}

return_t http_response::compose (const char* content_type, const char* content, int status_code)
{
    return_t ret = errorcode_t::success;

    if (nullptr != content_type) {
        _content_type = content_type;
    }
    if (nullptr != content) {
        _content = content;
    }
    _statuscode = status_code;
    return ret;
}

const char* http_response::content_type ()
{
    return _content_type.c_str ();
}

const char* http_response::content ()
{
    return _content.c_str ();
}

size_t http_response::content_size ()
{
    return _content.size ();
}

int http_response::status_code ()
{
    return _statuscode;
}

http_uri::http_uri ()
{
    _shared.make_share (this);
}

http_uri::~http_uri ()
{
    // do nothing
}

return_t http_uri::open (std::string uri)
{
    return open (uri.c_str ());
}

return_t http_uri::open (const char* uri)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == uri) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string param;
        std::string token;
        std::string item;
        size_t pos = 0;
        size_t ppos = 0;

        _url = tokenize (uri, "?", pos); /* until '?' character */

        /* parameters */
        param = tokenize (uri, "?", pos);
        if (param.size ()) {
            pos = 0;
            while (true) {
                token = tokenize (param, "&", pos);
                if (true == token.empty ()) {
                    break;
                }

                ppos = 0;
                item = tokenize (token, "=", ppos);
                if (ppos > token.size ()) {
                    ppos = 0;
                }

                _query.insert (std::make_pair (item, token.substr (ppos)));
            }
        }
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

void http_uri::close ()
{
    _url.clear ();
    _query.clear ();
}

const char* http_uri::get_url ()
{
    const char* ret_value = nullptr;

    ret_value = _url.c_str ();
    return ret_value;
}

return_t http_uri::query (unsigned index, std::string& key, std::string& value)
{
    return_t ret = errorcode_t::success;

    if (index < _query.size ()) {
        PARAMETERS::iterator iter = _query.begin ();
        std::advance (iter, index);
        key = iter->first;
        value = iter->second;
    } else {
        ret = errorcode_t::out_of_range;
    }
    return ret;
}

return_t http_uri::query (std::string key, std::string& value)
{
    return_t ret = errorcode_t::success;

    PARAMETERS::iterator iter = _query.find (key);

    if (_query.end () != iter) {
        value = iter->second;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

size_t http_uri::countof_query ()
{
    return _query.size ();
}

void http_uri::addref ()
{
    _shared.addref ();
}

void http_uri::release ()
{
    _shared.delref ();
}

}
}  // namespace
