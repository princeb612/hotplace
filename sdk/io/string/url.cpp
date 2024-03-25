/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <regex>
#include <sdk/base/basic/base16.hpp>
#include <sdk/io/string/string.hpp>
#if (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 9)) || (__GNUC__ > 4))
#else
#include <pcre.h>
#endif

namespace hotplace {
namespace io {

void regex_token(std::string const& input, std::string const& expr, size_t& pos, std::list<std::string>& tokens) {
    tokens.clear();

#if (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 9)) || (__GNUC__ > 4))
    // Regular expressions library (since C++11) https://en.cppreference.com/w/cpp/regex
    // The GNU C++ standard library supports <regex>, but not until GCC version 4.9.0.
    // undefined reference to re_expr/sregex_iterator/smatch in GCC 4.8.5 (fixed in GCC 4.9.0)

    std::regex re_expr(expr);
    auto re_begin = std::sregex_iterator(input.begin() + pos, input.end(), re_expr);
    auto re_end = std::sregex_iterator();

    // size_t count = std::distance(re_begin, re_end);

    for (std::sregex_iterator i = re_begin; i != re_end; ++i) {
        std::smatch match = *i;
        std::string token = match.str();
        if (token.size()) {
            tokens.push_back(token);
            pos += (match.position() + match.str().size());
        }
    }
#else
    pcre* re = nullptr;
    int rc = 0;
    int eoffset = 0;
    const char* err = nullptr;
    const char* sub = nullptr;

    std::vector<int> ovector;
    ovector.resize(30);

    __try2 {
        re = pcre_compile(expr.c_str(), 0, &err, &eoffset, nullptr);
        if (nullptr == re) {
            __leave2;
        }

        while (1) {
            const char* subj = input.c_str() + pos;
            size_t subjlen = input.size() - pos;

            rc = pcre_exec(re, nullptr, subj, subjlen, 0, PCRE_NOTEMPTY, &ovector[0], ovector.size());

            if (PCRE_ERROR_NOMATCH == rc) {
                break;
            } else if (rc < -1) {
                break;
            } else {
                for (int i = 0; i < rc; i++) {
                    pcre_get_substring(subj, &ovector[0], rc, i, &sub);
                    if (sub) {
                        tokens.push_back(sub);
                        pos += ovector[i + 1];
                        pcre_free_substring(sub);
                    }
                }
            }
        }
    }
    __finally2 {
        if (re) {
            pcre_free(re);
        }
    }
#endif
}

return_t escape_url(const char* url, stream_t* s, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == url || nullptr == s) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        s->clear();

        // RFC 2396 URI Generic Syntax
        std::set<char> charmap;
        constexpr char lowalpha[] = "abcdefghijklmnopqrstuvwxyz";
        constexpr char upalpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        constexpr char digit[] = "0123456789";
        constexpr char reserved[] = ";/?:@&=+$,";  // 2.2. Reserved Characters
        constexpr char mark[] = "-_.!~*'()";       // 2.3. Unreserved Characters
        constexpr char delims[] = "<>#%%\"";       // 2.4.3. Excluded US-ASCII Characters

        for (auto elem : lowalpha) {
            charmap.insert(elem);
        }
        for (auto elem : upalpha) {
            charmap.insert(elem);
        }
        for (auto elem : digit) {
            charmap.insert(elem);
        }

        for (auto elem : reserved) {
            charmap.insert(elem);
        }
        for (auto elem : mark) {
            charmap.insert(elem);
        }

        for (auto elem : delims) {
            charmap.insert(elem);
        }

        size_t size = strlen(url);

        for (unsigned i = 0; i < size; i++) {
            char c = url[i];
            std::set<char>::iterator iter = charmap.find(c);
            if (charmap.end() == iter) {
                // 2.4.1. Escaped Encoding
                s->printf("%%");
                base16_encode((byte_t*)&c, 1, s, base16_flag_t::base16_notrunc | base16_flag_t::base16_capital);
            } else {
                s->printf("%c", c);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t unescape_url(const char* url, stream_t* s) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == url || nullptr == s) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        s->clear();

        size_t size = strlen(url);

        for (unsigned i = 0; i < size; i++) {
            char c = url[i];
            if ('%' == c) {
                if (size >= i + 2) {
                    base16_decode(url + (i + 1), 2, s, base16_flag_t::base16_notrunc);
                    i += 2;
                }
            } else {
                s->printf("%c", c);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t split_url(const char* src, url_info_t* info) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == src || nullptr == info) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        info->clear();

        basic_stream stream;
        unescape_url(src, &stream);
        const char* url = stream.c_str();

        /*
         *  http_URL       = "http:" "//" host [ ":" port ] [ abs_path ]
         *  URI            = ( absoluteURI | relativeURI ) [ "#" fragment ]
         *  absoluteURI    = scheme ":" *( uchar | reserved )
         *  relativeURI    = net_path | abs_path | rel_path
         *  net_path       = "//" net_loc [ abs_path ]
         *  abs_path       = "/" rel_path
         *  rel_path       = [ path ] [ ";" params ] [ "?" query ]
         */

        size_t pos = 0;
        std::list<std::string> tokens;

        regex_token(url, "^[a-z].*://[a-zA-Z0-9@:._]*", pos, tokens);
        if (tokens.size()) {
            size_t tpos = 0;
            std::list<std::string> tokens1;
            regex_token(*tokens.begin(), "[a-zA-Z0-9.]*", tpos, tokens1);

            if (tokens1.size() >= 2) {
                std::list<std::string>::iterator iter;
                iter = tokens1.begin();
                info->scheme = *iter++;
                info->host = *iter++;
                if (tokens1.size() > 2) {
                    info->port = atoi(iter->c_str());
                } else {
                    if ("http" == info->scheme) {
                        info->port = 80;
                    } else if ("https" == info->scheme) {
                        info->port = 443;
                    } else if ("ftp" == info->scheme) {
                        info->port = 21;
                    }
                }
            }
        }

        info->uri = url + pos;

        regex_token(url, "^/[a-zA-Z0-9./]*", pos, tokens);
        if (tokens.size()) {
            info->uripath = *tokens.begin();
        }

        regex_token(url, "[?][a-zA-Z0-9&%+./:=_]*", pos, tokens);
        if (tokens.size()) {
            info->query = *tokens.begin();
            info->query.erase(info->query.begin());  // "?" query
        }

        regex_token(url, "[#][a-zA-Z0-9+_]*", pos, tokens);
        if (tokens.size()) {
            info->fragment = *tokens.begin();
            info->fragment.erase(info->fragment.begin());  // "#" fragment
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace io
}  // namespace hotplace
