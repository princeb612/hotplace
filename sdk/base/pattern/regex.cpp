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
#include <hotplace/sdk/base/system/trace.hpp>

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

    for (auto& range : ranges) {
        auto match = range[0];  // full match
        tokens.push_back(input.substr(match.begin, match.end - match.begin));
    }
}

void regex_token(const char* input, size_t size, const char* expr, size_t& pos, std::list<range_t>& tokens) {
    tokens.clear();

    if (input && expr) {
        std::list<std::map<size_t, range_t>> ranges;
        regex_tokens(input, size, expr, pos, ranges);

        for (auto& range : ranges) {
            tokens.push_back(range[0]);
        }
    }
}

void regex_tokens(const char* input, size_t size, const char* expr, size_t& pos, std::list<std::map<size_t, range_t>>& tokens) {
    tokens.clear();

#if defined USE_STDREGEX
    if (input && expr && (pos < size)) {
        std::regex re_expr(expr);
        auto start = pos;
        auto re_begin = std::cregex_iterator(input + start, input + size, re_expr);
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

        while (pos < size) {
            rc = pcre_exec(re, nullptr, input, size, pos, PCRE_NOTEMPTY, ovector.data(), ovector.size());

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
                        item.emplace(i, range_t(begin, end));
                    }
                }
                if (false == item.empty()) {
                    tokens.push_back(std::move(item));
                }

                pos = ovector[1];
                if (ovector[0] == ovector[1]) {
                    if (pos < size) {
                        ++pos;
                    } else {
                        break;
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

#if defined USE_STDREGEX
struct regex_context_t {
    std::regex re;
};
#elif defined USE_PCRE
struct regex_context_t {
    pcre* re = {nullptr};
};
#endif

return_t regex::open(regex_context_t** context, const char* expr) {
    return_t ret = errorcode_t::success;
    regex_context_t* handle = nullptr;
    __try2 {
        if (nullptr == context || nullptr == expr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        try {
            handle = new regex_context_t;
        } catch (const std::bad_alloc&) {
            ret = errorcode_t::out_of_memory;
            __leave2;
        }

#if defined USE_STDREGEX
        std::regex re(expr);
        handle->re = std::move(re);
#elif defined USE_PCRE
        int eoffset = 0;
        const char* err = nullptr;
        re = pcre_compile(expr, 0, &err, &eoffset, nullptr);
        if (nullptr == re) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        handle->re = re;
#endif
        *context = handle;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (nullptr != handle) {
                delete handle;
            }
        }
    }
    return ret;
}

return_t regex::search(regex_context_t* context, const char* input, size_t size, std::list<range_t>& tokens) {
    size_t pos = 0;
    return search(context, input, size, pos, tokens);
}

return_t regex::search(regex_context_t* context, const char* input, size_t size, size_t& pos, std::list<range_t>& tokens) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == context || nullptr == input || 0 == size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tokens.clear();

#if defined USE_STDREGEX
        auto start = pos;
        auto re_begin = std::cregex_iterator(input + start, input + size, context->re);
        auto re_end = std::cregex_iterator();

        for (std::cregex_iterator iter = re_begin; iter != re_end; ++iter) {
            const std::cmatch& match = *iter;

            if (false == match.empty()) {
                if (match[0].matched) {
                    size_t begin = start + match.position(0);
                    size_t end = begin + match.length(0);

                    if (begin != end) {
                        tokens.push_back(range_t(begin, end));
                    }
                }
            }
        }
#elif defined USE_PCRE
        while (pos < size) {
            rc = pcre_exec(re, nullptr, input, size, pos, PCRE_NOTEMPTY, ovector.data(), ovector.size());

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
                        item.emplace(i, range_t(begin, end));
                    }
                }
                if (false == item.empty()) {
                    tokens.push_back(std::move(item));
                }

                pos = ovector[1];
                if (ovector[0] == ovector[1]) {
                    if (pos < size) {
                        ++pos;
                    } else {
                        break;
                    }
                }
            }
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t regex::close(regex_context_t* context) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
#if defined USE_STDREGEX
        // do nothing
#elif defined USE_PCRE
        if (context->re) {
            pcre_free(context->re);
        }
#endif
        delete context;
    }
    __finally2 {}
    return ret;
}

}  // namespace hotplace
