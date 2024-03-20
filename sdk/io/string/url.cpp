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

namespace hotplace {
namespace io {

void regex_token(std::string const& input, std::string const& expr, size_t& pos, std::list<std::string>& tokens) {
    tokens.clear();

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
        constexpr char reserved[] = ";/?:@&=+$,";
        constexpr char mark[] = "-_.!~*'()";
        constexpr char delims[] = "<>#%%\"";

        for (auto elem : lowalpha) {
            charmap.insert(elem);
        }
        for (auto elem : upalpha) {
            charmap.insert(elem);
        }
        for (auto elem : digit) {
            charmap.insert(elem);
        }

        // 2.2. Reserved Characters
        // If the data for a URI component would conflict with the reserved purpose, then ...
        // if (escapeurl_t::escape_reserved & flags) {
        for (auto elem : reserved) {
            charmap.insert(elem);
        }
        // }
        // 2.3. Unreserved Characters
        // if (escapeurl_t::escape_unreserved & flags) {
        for (auto elem : mark) {
            charmap.insert(elem);
        }
        // }

        // 2.4.3. Excluded US-ASCII Characters
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
