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

#include <sdk/io/string/string.hpp>
#include <sdk/net/http/http_header.hpp>

namespace hotplace {
namespace net {

http_header::http_header() : _version(1) {}

http_header::http_header(const http_header& object) {
    _names = object._names;
    _headers = object._headers;
    _version = object._version;
}

http_header::~http_header() {}

http_header& http_header::add(const std::string& name, const std::string& value) {
    __try2 {
        critical_section_guard guard(_lock);

        std::string key = (1 == get_version()) ? name : lowername(name);

        http_header_map_pib_t pib = _headers.insert(std::make_pair(key, value));
        if (true == pib.second) {
            _names.push_back(key);
        } else {
            // pib.first->second = value;
        }
    }
    __finally2 {}
    return *this;
}

http_header& http_header::clear() {
    critical_section_guard guard(_lock);
    _names.clear();
    _headers.clear();
    return *this;
}

std::string http_header::get(const std::string& name, std::string& value) {
    std::string ret_value;

    value.clear();

    std::string key = (1 == get_version()) ? name : lowername(name);

    http_header_map_t::iterator iter = _headers.find(key);
    if (_headers.end() != iter) {
        value = iter->second;
        ret_value = value.c_str();
    }

    return ret_value;
}

std::string http_header::get(const std::string& name) {
    std::string ret_value;

    std::string key = (1 == get_version()) ? name : lowername(name);

    http_header_map_t::iterator iter = _headers.find(key);
    if (_headers.end() != iter) {
        ret_value = iter->second;
    }
    return ret_value;
}

bool http_header::contains(const std::string& name, const std::string& value) {
    bool ret_value = false;

    std::string key = (1 == get_version()) ? name : lowername(name);

    http_header_map_t::iterator iter = _headers.find(key);
    if (_headers.end() != iter) {
        std::string body = iter->second;
        size_t pos = body.find(value);
        if (std::string::npos != pos) {
            ret_value = true;
        }
    }
    return ret_value;
}

const char* http_header::get_token(const std::string& name, unsigned index, std::string& token) {
    const char* ret_value = nullptr;

    token.clear();

    std::string content;
    std::string temp;

    std::string key = (1 == get_version()) ? name : lowername(name);

    http_header_map_t::iterator iter = _headers.find(key);
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

    return ret_value;
}

return_t http_header::get_headers(std::string& contents) {
    return_t ret = errorcode_t::success;

    auto lambda = [&](const std::string& name, const std::string& value) -> void { contents += format("%s: %s\r\n", name.c_str(), value.c_str()); };
    get_headers(lambda);

    return ret;
}

return_t http_header::get_headers(std::function<void(const std::string&, const std::string&)> f) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == f) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_lock);
        t_maphint<std::string, std::string> hint(_headers);
        for (const auto& key : _names) {
            std::string value;
            hint.find(key, &value);
            f(key, value);
        }
    }
    __finally2 {}
    return ret;
}

return_t http_header::to_keyvalue(const std::string& value, skey_value& kv) {
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

http_header& http_header::operator=(const http_header& object) {
    critical_section_guard guard(_lock);
    _names = object._names;
    _headers = object._headers;
    return *this;
}

http_header& http_header::set_version(uint8 version) {
    switch (version) {
        case 2:
        case 1:
            _version = version;
            break;
        default:
            break;
    }
    return *this;
}

uint8 http_header::get_version() { return _version; }

}  // namespace net
}  // namespace hotplace
