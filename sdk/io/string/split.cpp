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

return_t split_url(const char* url, url_info_t* info) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == url || nullptr == info) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        info->clear();

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

        regex_token(url, "^/[a-zA-Z0-9/.]*", pos, tokens);
        if (tokens.size()) {
            info->uripath = *tokens.begin();
        }

        regex_token(url, "[?][a-zA-Z0-9&=%_+]*", pos, tokens);
        if (tokens.size()) {
            info->query = *tokens.begin();
        }

        regex_token(url, "[#][a-zA-Z0-9_+]*", pos, tokens);
        if (tokens.size()) {
            info->fragment = *tokens.begin();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace io
}  // namespace hotplace
