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
#if (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 9)) || (__GNUC__ > 4))
#else
#include <pcre.h>
#endif

namespace hotplace {
namespace io {

void regex_token(const std::string& input, const std::string& expr, size_t& pos, std::list<std::string>& tokens) {
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

}  // namespace io
}  // namespace hotplace
