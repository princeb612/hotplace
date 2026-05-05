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

namespace hotplace {

void regex_token(const std::string& input, const std::string& expr, size_t& pos, std::list<std::string>& tokens) {
    tokens.clear();

#if defined USE_STDREGEX
    // Regular expressions library (since C++11) https://en.cppreference.com/w/cpp/regex
    // The GNU C++ standard library supports <regex>, but not until GCC version 4.9.0.
    // undefined reference to re_expr/sregex_iterator/smatch in GCC 4.8.5 (fixed in GCC 4.9.0)

    std::regex re_expr(expr);
    auto re_begin = std::sregex_iterator(input.begin() + pos, input.end(), re_expr);
    auto re_end = std::sregex_iterator();

    for (std::sregex_iterator iter = re_begin; iter != re_end; ++iter) {
        std::smatch match = *iter;
        std::string token = match.str();  // match[0] : full match

#if defined DEBUG
        if (istraceable(trace_category_internal, loglevel_debug)) {
            trace_debug_event(trace_category_internal, trace_event_internal, [&](basic_stream& dbs) -> void {
                for (size_t i = 0; i < match.size(); ++i) {
                    if (match[i].matched) {
                        size_t begin = match.position(i);
                        size_t end = begin + match.length(i);
                        dbs.printf("- match[%zi] %s\n", i, input.substr(begin, end - begin).c_str());
                    }
                }
            });
        }
#endif

        if (token.size()) {
            tokens.push_back(token);
            pos += (match.position() + match.str().size());
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
        re = pcre_compile(expr.c_str(), 0, &err, &eoffset, nullptr);
        if (nullptr == re) {
            __leave2;
        }

        size_t len = input.size();
        const char* stream = input.c_str();
        while (pos < len) {
            rc = pcre_exec(re, nullptr, stream, t_narrow_cast(len), t_narrow_cast(pos), PCRE_NOTEMPTY, ovector.data(), ovector.size());

            if (PCRE_ERROR_NOMATCH == rc) {
                break;
            } else if (rc < 0) {
                break;
            } else {
                for (int i = 0; i < rc; ++i) {
                    int begin = ovector[2 * i];
                    int end = ovector[2 * i + 1];
                    if (begin != -1) {
                        tokens.emplace_back(stream + begin, end - begin);
                    }
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

void regex_token(const char* input, size_t len, const char* expr, size_t& pos, std::list<range_t>& tokens) {
    tokens.clear();

#if defined USE_STDREGEX
    if (input && expr) {
        // Regular expressions library (since C++11) https://en.cppreference.com/w/cpp/regex
        // The GNU C++ standard library supports <regex>, but not until GCC version 4.9.0.
        // undefined reference to re_expr/sregex_iterator/smatch in GCC 4.8.5 (fixed in GCC 4.9.0)

        std::regex re_expr(expr);
        auto re_begin = std::cregex_iterator(input + pos, input + len, re_expr);
        auto re_end = std::cregex_iterator();

        for (std::cregex_iterator iter = re_begin; iter != re_end; ++iter) {
            const std::cmatch& match = *iter;

#if defined DEBUG
            if (istraceable(trace_category_internal, loglevel_debug)) {
                trace_debug_event(trace_category_internal, trace_event_internal, [&](basic_stream& dbs) -> void {
                    for (size_t i = 0; i < match.size(); ++i) {
                        if (match[i].matched) {
                            size_t begin = match.position(i);
                            size_t end = begin + match.length(i);
                            dbs.printf("- match[%zi] %s\n", i, std::string(input + begin, end - begin).c_str());
                        }
                    }
                });
            }
#endif

            if (match[0].matched) {
                size_t begin = match.position(0);
                size_t end = begin + match.length(0);

                tokens.emplace_back(pos + begin, pos + end);
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
                for (int i = 0; i < rc; ++i) {
                    auto begin = ovector[2 * i];
                    auto end = ovector[2 * i + 1];
                    if (begin != -1) {
                        tokens.emplace_back(begin, end);
                    }
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

void regex_tokens(const char* input, size_t len, const char* expr, size_t& pos, std::list<std::map<size_t, range_t>>& tokens) {
    tokens.clear();

#if defined USE_STDREGEX
    if (input && expr) {
        // Regular expressions library (since C++11) https://en.cppreference.com/w/cpp/regex
        // The GNU C++ standard library supports <regex>, but not until GCC version 4.9.0.
        // undefined reference to re_expr/sregex_iterator/smatch in GCC 4.8.5 (fixed in GCC 4.9.0)

        std::regex re_expr(expr);
        auto re_begin = std::cregex_iterator(input + pos, input + len, re_expr);
        auto re_end = std::cregex_iterator();

        for (std::cregex_iterator iter = re_begin; iter != re_end; ++iter) {
            const std::cmatch& match = *iter;

            std::map<size_t, range_t> item;
            for (size_t i = 0; i < match.size(); ++i) {
                if (match[i].matched) {
                    size_t begin = match.position(i);
                    size_t end = begin + match.length(i);
                    item.emplace(i, range_t(pos + begin, pos + end));
#if defined DEBUG
                    if (istraceable(trace_category_internal, loglevel_debug)) {
                        trace_debug_event(trace_category_internal, trace_event_internal,
                                          [&](basic_stream& dbs) -> void { dbs.printf("- match[%zi] %s\n", i, std::string(input + begin, end - begin).c_str()); });
                    }
#endif
                }
            }
            if (false == item.empty()) {
                tokens.push_back(std::move(item));
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
