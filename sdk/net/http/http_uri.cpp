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

        std::string param;
        std::string token;
        std::string item;
        size_t pos = 0;
        size_t ppos = 0;

        _url = tokenize(uri, "?", pos); /* until '?' character */

        /* parameters */
        param = tokenize(uri, "?", pos);
        if (param.size()) {
            pos = 0;
            while (true) {
                token = tokenize(param, "&", pos);
                if (true == token.empty()) {
                    break;
                }

                ppos = 0;
                item = tokenize(token, "=", ppos);
                if (ppos > token.size()) {
                    ppos = 0;
                }

                _query.insert(std::make_pair(item, token.substr(ppos)));
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

void http_uri::close() {
    _url.clear();
    _query.clear();
}

const char* http_uri::get_uri() {
    const char* ret_value = nullptr;

    ret_value = _url.c_str();
    return ret_value;
}

return_t http_uri::query(unsigned index, std::string& key, std::string& value) {
    return_t ret = errorcode_t::success;

    if (index < _query.size()) {
        PARAMETERS::iterator iter = _query.begin();
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

    PARAMETERS::iterator iter = _query.find(key);

    if (_query.end() != iter) {
        value = iter->second;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

size_t http_uri::countof_query() { return _query.size(); }

void http_uri::addref() { _shared.addref(); }

void http_uri::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
