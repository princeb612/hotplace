/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_INLINE__
#define __HOTPLACE_SDK_BASE_INLINE__

#include <string.h>

#include <algorithm>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/types.hpp>
#include <list>
#include <string>
#include <vector>

namespace hotplace {

static inline void memcpy_inline(void* dest, size_t size_dest, const void* src, size_t size_src) {
#ifdef __STDC_WANT_SECURE_LIB__
    memcpy_s(dest, size_dest, src, size_src);
#else
    memcpy(dest, src, size_src);
#endif
}

static inline int vsnprintf_inline(char* buffer, size_t size, const char* fmt, va_list ap) {
    int ret = 0;

#ifdef __GNUC__
    ret = vsnprintf(buffer, size, fmt, ap);
#else
#if defined __STDC_WANT_SECURE_LIB__
    ret = _vsnprintf_s(buffer, size, _TRUNCATE, fmt, ap);
#else
    ret = _vsnprintf(buffer, size, fmt, ap);
#endif
#endif
    return ret;
}

static inline std::string& ltrim(std::string& source) {
#if __cplusplus >= 201103L  // c++11
    source.erase(source.begin(), std::find_if(source.begin(), source.end(), [](int c) { return !std::isspace(c); }));
#else
    source.erase(source.begin(), std::find_if(source.begin(), source.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
#endif

    return source;
}

static inline std::string& rtrim(std::string& source) {
#if __cplusplus >= 201103L  // c++11
    source.erase(std::find_if(source.rbegin(), source.rend(), [](int c) { return !std::isspace(c); }).base(), source.end());
#else
    source.erase(std::find_if(source.rbegin(), source.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), source.end());
#endif

    return source;
}

static inline bool ends_with(std::string const& source, std::string const& suffix) { return source.rfind(suffix) == (source.size() - suffix.size()); }

static inline bool ends_with(std::wstring const& source, std::wstring const& suffix) { return source.rfind(suffix) == (source.size() - suffix.size()); }

/**
 * @brief tolower
 * @param const char* input [in]
 */
static inline std::string lowername(const char* input) {
    std::string ret_value;

    __try2 {
        if (nullptr == input) {
            __leave2;
        }
        ret_value = input;
        std::transform(ret_value.begin(), ret_value.end(), ret_value.begin(), tolower);
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

static inline std::string uppername(const char* input) {
    std::string ret_value;

    __try2 {
        if (nullptr == input) {
            __leave2;
        }
        ret_value = input;
        std::transform(ret_value.begin(), ret_value.end(), ret_value.begin(), toupper);
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

/**
 * @brief tolower
 * @param std::string source [in]
 */
static inline std::string lowername(std::string const& input) {
    std::string ret_value;

    __try2 {
        ret_value = input;
        std::transform(ret_value.begin(), ret_value.end(), ret_value.begin(), tolower);
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

static inline std::string uppername(std::string const& input) {
    std::string ret_value;

    __try2 {
        ret_value = input;
        std::transform(ret_value.begin(), ret_value.end(), ret_value.begin(), toupper);
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

static inline std::string base_name(std::string const& path) {
    std::string ret_value = path;

    return ret_value.substr(ret_value.find_last_of("/\\") + 1);
}

static inline std::wstring base_name(std::wstring const& path) {
    std::wstring ret_value = path;

    return ret_value.substr(ret_value.find_last_of(L"/\\") + 1);
}

static inline std::string dir_name(std::string const& path) {
    std::string ret_value = path;

    return ret_value.substr(0, ret_value.find_last_of("/\\"));
}

static inline std::wstring dir_name(std::wstring const& path) {
    std::wstring ret_value = path;

    return ret_value.substr(0, ret_value.find_last_of(L"/\\"));
}

/**
 * @brief append
 * @param binary_t& lhs [inout]
 * @param char* rhs [in]
 */
static inline binary_t& operator<<(binary_t& lhs, char* rhs) {
    if (rhs) {
        lhs.insert(lhs.end(), rhs, rhs + strlen(rhs));
    }
    return lhs;
}

/**
 * @brief append
 * @param binary_t& lhs [inout]
 * @param std::string rhs [in]
 */
static inline binary_t& operator<<(binary_t& lhs, std::string const& rhs) {
    lhs.insert(lhs.end(), rhs.begin(), rhs.end());
    return lhs;
}

/**
 * @brief append
 * @param binary_t& lhs [inout]
 * @param binary_t rhs [in]
 */
static inline binary_t& operator<<(binary_t& lhs, binary_t const& rhs) {
    lhs.insert(lhs.end(), rhs.begin(), rhs.end());
    return lhs;
}

static inline std::string convert(binary_t const& bin) {
    std::string result;

    result.assign((char*)&bin[0], bin.size());
    return result;
}

static inline binary_t convert(std::string const& source) {
    binary_t result;

    result.insert(result.end(), source.begin(), source.end());
    return result;
}

#if defined _WIN32
#define DIR_SEP_CA '\\'
#define DIR_SEP_TA "\\"
#define DIR_SEP_CW L'\\'
#define DIR_SEP_TW L"\\"
#elif defined __linux__
#define DIR_SEP_CA '/'
#define DIR_SEP_TA "/"
#define DIR_SEP_CW L'/'
#define DIR_SEP_TW L"/"
#endif

#if defined _MBCS || defined MBCS
#define DIR_SEP_C DIR_SEP_CA
#define DIR_SEP_T DIR_SEP_TA
#elif defined _UNICODE || defined UNICODE
#define DIR_SEP_C DIR_SEP_CW
#define DIR_SEP_T DIR_SEP_TW
#endif

static inline std::string concat_filepath(const char* path, const char* file) {
    std::string result;

    if (file) {
        if (path) {
            result = path;
            bool test = ends_with(path, DIR_SEP_TA);

            if (false == test) {
                result += DIR_SEP_TA;
            }
        }
        result += file;
    }
    return result;
}

static inline std::wstring concat_filepath(const wchar_t* path, const wchar_t* file) {
    std::wstring result;

    if (file) {
        if (path) {
            result = path;
            bool test = ends_with(path, DIR_SEP_TW);

            if (false == test) {
                result += DIR_SEP_TW;
            }
        }
        result += file;
    }
    return result;
}

static inline std::string concat_filepath(std::string const& path, std::string const& file) {
    std::string result;

    if (file.size()) {
        if (path.size()) {
            result = path;
            bool test = ends_with(path, DIR_SEP_TA);

            if (false == test) {
                result += DIR_SEP_TA;
            }
        }
        result += file;
    }
    return result;
}

static inline std::wstring concat_filepath(std::wstring const& path, std::wstring const& file) {
    std::wstring result;

    if (file.size()) {
        if (path.size()) {
            result = path;
            bool test = ends_with(path, DIR_SEP_TW);

            if (false == test) {
                result += DIR_SEP_TW;
            }
        }
        result += file;
    }
    return result;
}

}  // namespace hotplace

#endif
