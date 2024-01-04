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

return_t http_header::add(const char* header, const char* value) {
    return_t ret = errorcode_t::success;

    __try2 {
        critical_section_guard guard(_lock);
        if (nullptr == header || nullptr == value) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        _headers.insert(std::make_pair(header, value));
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_header::add(std::string header, std::string value) {
    return_t ret = errorcode_t::success;

    __try2 {
        critical_section_guard guard(_lock);

        _headers.insert(std::make_pair(header, value));
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_header::clear() {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);
    _headers.clear();
    return ret;
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

}  // namespace net
}  // namespace hotplace
