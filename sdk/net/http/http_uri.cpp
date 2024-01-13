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

http_uri::http_uri() { _shared.make_share(this); }

http_uri::~http_uri() {
    // do nothing
}

return_t http_uri::open(std::string uri) { return open(uri.c_str()); }

return_t http_uri::open(const char* uri) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == uri) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        close();

        std::string input = uri;
        std::string token;
        std::string item;
        size_t pos = 0;
        size_t ppos = 0;

        _uri = tokenize(input, "?", pos); /* until '?' character */
        if (std::string::npos != pos) {
            _query = input.substr(pos);
            if (ends_with(_query, "\r\n\r\n")) {
                _query.erase(_query.end() - 4);
            }
        }

        /* parameters */
        _query = tokenize(uri, "?", pos);
        if (_query.size()) {
            pos = 0;
            while (true) {
                token = tokenize(_query, "&", pos);
                if (true == token.empty()) {
                    break;
                }

                ppos = 0;
                item = tokenize(token, "=", ppos);
                if (ppos > token.size()) {
                    ppos = 0;
                }

                _query_kv.insert(std::make_pair(item, token.substr(ppos)));
            }
        }
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

const char* http_uri::get_uri() {
    const char* ret_value = nullptr;

    ret_value = _uri.c_str();
    return ret_value;
}

const char* http_uri::get_query() {
    const char* ret_value = nullptr;

    ret_value = _query.c_str();
    return ret_value;
}

return_t http_uri::query(unsigned index, std::string& key, std::string& value) {
    return_t ret = errorcode_t::success;

    if (index < _query_kv.size()) {
        PARAMETERS::iterator iter = _query_kv.begin();
        std::advance(iter, index);
        key = iter->first;
        value = iter->second;
    } else {
        ret = errorcode_t::out_of_range;
    }
    return ret;
}

return_t http_uri::query(std::string key, std::string& value) {
    return_t ret = errorcode_t::success;

    PARAMETERS::iterator iter = _query_kv.find(key);

    if (_query_kv.end() != iter) {
        value = iter->second;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

size_t http_uri::countof_query() { return _query_kv.size(); }

void http_uri::addref() { _shared.addref(); }

void http_uri::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
