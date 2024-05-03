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
#include <sdk/net/http/http_uri.hpp>

namespace hotplace {
using namespace io;
namespace net {

http_uri::http_uri() { _shared.make_share(this); }

http_uri::http_uri(const http_uri& object) {
    _shared.make_share(this);
    _uri = object._uri;
    _uripath = object._uripath;
    _query = object._query;
    _query_kv = object._query_kv;
}

http_uri::~http_uri() {
    // do nothing
}

return_t http_uri::open(const std::string& uri) { return open(uri.c_str()); }

return_t http_uri::open(const char* uri) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == uri) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        close();

        url_info_t url_info;
        split_url(uri, &url_info);

        _uri = url_info.uri;
        _uripath = url_info.uripath;
        _query = url_info.query;
        to_keyvalue(_query, _query_kv);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

void http_uri::close() {
    _uri.clear();
    _query.clear();
    _query_kv.clear();
}

return_t http_uri::set_query(const char* query) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == query) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // _query = query;
        ret = to_keyvalue(query, _query_kv);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_uri::set_query(const std::string& query) {
    return_t ret = errorcode_t::success;
    ret = to_keyvalue(query, _query_kv);
    return ret;
}

const char* http_uri::get_uri() {
    const char* ret_value = nullptr;

    ret_value = _uri.c_str();
    return ret_value;
}

const char* http_uri::get_uripath() {
    const char* ret_value = nullptr;

    ret_value = _uripath.c_str();
    return ret_value;
}

const char* http_uri::get_query() {
    const char* ret_value = nullptr;

    ret_value = _query.c_str();
    return ret_value;
}

return_t http_uri::query(const std::string& key, std::string& value) {
    return_t ret = errorcode_t::success;
    ret = _query_kv.query(key, value);
    return ret;
}

size_t http_uri::countof_query() { return _query_kv.size(); }

return_t http_uri::to_keyvalue(const std::string& value, key_value& kv) {
    return_t ret = errorcode_t::success;

    std::string input;
    std::string token;
    std::string k;
    std::string v;
    size_t pos = 0;

    input = tokenize(value, "?", pos); /* until '?' character */
    if (std::string::npos != pos) {
        input = value.substr(pos);
    }

    pos = 0;
    while (true) {
        token = tokenize(input, "&", pos);

        if (token.size() && (std::string::npos != token.find("="))) {
            ltrim(rtrim(token));

            size_t tpos = 0;
            k = tokenize(token, "=", tpos);
            v = tokenize(token, "=", tpos);

            kv.set(k, v);
        }

        if ((size_t)-1 == pos) {
            break;
        }
    }
    return ret;
}

key_value& http_uri::get_query_keyvalue() { return _query_kv; }

void http_uri::addref() { _shared.addref(); }

void http_uri::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
