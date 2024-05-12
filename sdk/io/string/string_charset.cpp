/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <string.h>

#include <list>
#include <sdk/io/string/string.hpp>
#include <string>

namespace hotplace {
namespace io {

#if defined _MBCS || defined MBCS
std::string tokenize(const std::string& source, const std::string& tokens, size_t& pos, int mode)
#elif defined _UNICODE || defined UNICODE
std::wstring tokenize(const std::wstring& source, const std::wstring& tokens, size_t& pos, int mode)
#endif
{
#if defined _MBCS || defined MBCS
    std::string ret_value;
    size_t npos = std::string::npos;
#elif defined _UNICODE || defined UNICODE
    std::wstring ret_value;
    size_t npos = std::wstring::npos;
#endif
    size_t startpos = 0;
    std::list<size_t> tokenpos;
    size_t sizetoken = tokens.size();

    if ((npos != pos) || (pos < source.size())) {
        tokenpos.clear();
        startpos = pos;

        size_t temppos = 0;
        size_t quotpos = 0;
        if (tokenize_mode_t::token_quoted & mode) {
            quotpos = source.find_first_of('\"', startpos);  // check quoted
        }

        // find first token
        for (size_t i = 0; i < sizetoken; i++) {
            temppos = source.find_first_of(tokens[i], startpos);
            if ((size_t)-1 == temppos) {
                continue;
            }
            if (tokenize_mode_t::token_quoted & mode) {
                if (quotpos < temppos) {
                    temppos = source.find_first_of('\"', quotpos + 1);
                    temppos = source.find_first_of(tokens[i], temppos + 1);
                    if ((size_t)-1 == temppos) {
                        continue;
                    }
                }
            }

            tokenpos.push_back(temppos);
        }

        // search first token
        tokenpos.sort();

        if (tokenpos.empty()) {
            if (startpos < source.size()) {
                ret_value.assign(source.substr(startpos));
            }
            pos = (size_t)(-1);
        } else {
            size_t first = tokenpos.front();
            if (first == startpos) {
                pos++;
                ret_value = tokenize(source, tokens, pos);
            } else {
                ret_value.assign(source.substr(startpos, first - startpos));
                pos = startpos + (first - startpos) + 1;
            }
        }
    }

    return ret_value;
}

#if defined _MBCS || defined MBCS
bool gettoken(const std::string& source, const std::string& token, size_t index, std::string& value)
#elif defined _UNICODE || defined UNICODE
bool gettoken(const std::wstring& source, const std::wstring& token, size_t index, std::wstring& value)
#endif
{
    bool ret = false;
    size_t pos = 0;

#if defined _MBCS || defined MBCS
    std::string item;
#elif defined _UNICODE || defined UNICODE
    std::wstring item;
#endif
    value.clear();

    for (size_t i = 0;; i++) {
        item = tokenize(source, token, pos);
        if (index == i) {
            value = item;
            ret = true;
            break;
        }
        if ((size_t)-1 == pos) {
            break;
        }
    }
    return ret;
}

}  // namespace io
}  // namespace hotplace
