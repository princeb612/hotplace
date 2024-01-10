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

http_header::http_header() {
    // do nothing
}

http_header::~http_header() {
    // do nothing
}

http_header& http_header::add(const char* header, const char* value) {
    __try2 {
        if (nullptr == header || nullptr == value) {
            __leave2;
        }

        critical_section_guard guard(_lock);
        _headers.insert(std::make_pair(header, value));
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

http_header& http_header::add(std::string header, std::string value) {
    critical_section_guard guard(_lock);
    _headers.insert(std::make_pair(header, value));

    return *this;
}

http_header& http_header::clear() {
    critical_section_guard guard(_lock);
    _headers.clear();

    return *this;
}

const char* http_header::get(const char* header, std::string& content) {
    const char* ret_value = nullptr;

    if (nullptr != header) {
        http_header_map_t::iterator iter = _headers.find(std::string(header));
        if (_headers.end() != iter) {
            content = iter->second;
            ret_value = content.c_str();
        }
    }

    return ret_value;
}

const char* http_header::get_token(const char* header, unsigned index, std::string& token) {
    const char* ret_value = nullptr;

    std::string content;
    std::string temp;

    if (nullptr != header) {
        http_header_map_t::iterator iter = _headers.find(std::string(header));
        if (_headers.end() != iter) {
            content = iter->second;

            size_t pos = 0;
            size_t current = 0;
            while (current <= index) {
                temp = tokenize(content, _T (" "), pos);
                if (true == temp.empty()) {
                    break;
                }
                if (current == index) {
                    token = temp;
                    ret_value = token.c_str();
                }
                current++;
            }
        }
    }

    return ret_value;
}

return_t http_header::get_headers(std::string& contents) {
    return_t ret = errorcode_t::success;

    __try2 {
        //_tclean(contents);

        critical_section_guard guard(_lock);
        for (http_header_map_t::iterator it = _headers.begin(); it != _headers.end(); it++) {
            std::string key = it->first;
            std::string value = it->second;

            contents.append(format("%s: %s\r\n", key.c_str(), value.c_str()));
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_header::to_keyvalue(std::string const& value, key_value& kv) {
    return_t ret = errorcode_t::success;

    std::string token;
    std::string k;
    std::string v;
    size_t pos = 0;
    while (true) {
        token = tokenize(value, " ", pos, tokenize_mode_t::token_quoted);

        if (token.size() && (std::string::npos != token.find("="))) {
            ltrim(rtrim(token));
            if (ends_with(token, ",")) {
                token.erase(token.end() - 1);
            }

            size_t tpos = 0;
            k = tokenize(token, "=", tpos);   // key1="value1", key2="value2, value3", key3=value4
            v = tokenize(token, "\"", tpos);  // unquot

            kv.set(k, v);
        }

        if ((size_t)-1 == pos) {
            break;
        }
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
