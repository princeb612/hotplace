/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   regex.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/pattern/regex.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>

#if defined __GNUC__
#if (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 9)) || (__GNUC__ > 4))
#define USE_STDREGEX 1
#else
#define USE_PCRE 1
#endif
#elif defined _MSC_VER
#define USE_STDREGEX 1
#endif

#if defined USE_STDREGEX
#include <regex>
#elif defined USE_PCRE
#include <pcre.h>
#endif

// Regular expressions library (since C++11) https://en.cppreference.com/w/cpp/regex
// The GNU C++ standard library supports <regex>, but not until GCC version 4.9.0.
// undefined reference to re_expr/sregex_iterator/smatch in GCC 4.8.5 (fixed in GCC 4.9.0)

namespace hotplace {

void regex_token(const std::string& input, const std::string& expr, size_t& pos, std::list<std::string>& tokens) {
    tokens.clear();

    std::list<std::map<size_t, range_t>> ranges;
    regex_tokens(input.c_str(), input.size(), expr.c_str(), pos, ranges);

    for (auto range : ranges) {
        auto match = range[0];  // full match
        tokens.push_back(input.substr(match.begin, match.end - match.begin));
    }
}

void regex_token(const char* input, size_t len, const char* expr, size_t& pos, std::list<range_t>& tokens) {
    tokens.clear();

    if (input && expr) {
        std::list<std::map<size_t, range_t>> ranges;
        regex_tokens(input, len, expr, pos, ranges);

        for (auto range : ranges) {
            tokens.push_back(range[0]);
        }
    }
}

void regex_tokens(const char* input, size_t len, const char* expr, size_t& pos, std::list<std::map<size_t, range_t>>& tokens) {
    tokens.clear();

#if defined USE_STDREGEX
    if (input && expr && (pos < len)) {
        std::regex re_expr(expr);
        auto start = pos;
        auto re_begin = std::cregex_iterator(input + start, input + len, re_expr);
        auto re_end = std::cregex_iterator();

        for (std::cregex_iterator iter = re_begin; iter != re_end; ++iter) {
            const std::cmatch& match = *iter;

            std::map<size_t, range_t> item;
            for (size_t i = 0; i < match.size(); ++i) {
                if (match[i].matched) {
                    size_t begin = start + match.position(i);
                    size_t end = begin + match.length(i);

                    if (begin != end) {
                        item.emplace(i, range_t(begin, end));

#if defined DEBUG
                        if (istraceable(trace_category_internal, loglevel_debug)) {
                            trace_debug_event(trace_category_internal, trace_event_internal,
                                              [&](basic_stream& dbs) -> void { dbs.printf("- match[%zi] %s\n", i, std::string(input + begin, end - begin).c_str()); });
                        }
#endif
                    }
                }
            }

            if (false == item.empty()) {
                tokens.push_back(std::move(item));
                pos = start + match.position(0) + match.length(0);
            }
        }
    }
#elif defined USE_PCRE
    pcre* re = nullptr;
    int rc = 0;
    int eoffset = 0;
    const char* err = nullptr;

    std::vector<int> ovector;
    ovector.resize(30);  // multiples of 3

    __try2 {
        if (nullptr == input || nullptr == expr) {
            __leave2;
        }

        re = pcre_compile(expr, 0, &err, &eoffset, nullptr);
        if (nullptr == re) {
            __leave2;
        }

        while (pos < len) {
            rc = pcre_exec(re, nullptr, input, len, pos, PCRE_NOTEMPTY, ovector.data(), ovector.size());

            if (PCRE_ERROR_NOMATCH == rc) {
                break;
            } else if (rc < 0) {
                break;
            } else {
                std::map<size_t, range_t> item;
                for (int i = 0; i < rc; ++i) {
                    auto begin = ovector[2 * i];
                    auto end = ovector[2 * i + 1];
                    if (begin != -1) {
                        item.emplace(i, range_t(pos + begin, pos + end));

#if defined DEBUG
                        if (istraceable(trace_category_internal, loglevel_debug)) {
                            trace_debug_event(trace_category_internal, trace_event_internal, [&](basic_stream& dbs) -> void {
                                dbs.printf("- match[%zi] %s\n", i, std::string(input + pos + begin, end - begin).c_str());
                            });
                        }
#endif
                    }
                }
                if (false == item.empty()) {
                    tokens.push_back(std::move(item));
                }

                size_t fin = ovector[1];
                if (fin == pos) {
                    ++pos;
                } else {
                    pos = fin;
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

}  // namespace hotplace
