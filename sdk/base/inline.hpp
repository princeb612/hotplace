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
#include <list>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
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

static inline bool ends_with(const std::string& source, const std::string& suffix) { return source.rfind(suffix) == (source.size() - suffix.size()); }

static inline bool ends_with(const std::wstring& source, const std::wstring& suffix) { return source.rfind(suffix) == (source.size() - suffix.size()); }

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
static inline std::string lowername(const std::string& input) {
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

static inline std::string uppername(const std::string& input) {
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

static inline std::string base_name(const std::string& path) {
    std::string ret_value = path;

    return ret_value.substr(ret_value.find_last_of("/\\") + 1);
}

static inline std::wstring base_name(const std::wstring& path) {
    std::wstring ret_value = path;

    return ret_value.substr(ret_value.find_last_of(L"/\\") + 1);
}

static inline std::string dir_name(const std::string& path) {
    std::string ret_value = path;

    return ret_value.substr(0, ret_value.find_last_of("/\\"));
}

static inline std::wstring dir_name(const std::wstring& path) {
    std::wstring ret_value = path;

    return ret_value.substr(0, ret_value.find_last_of(L"/\\"));
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

static inline std::string concat_filepath(const std::string& path, const std::string& file) {
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

static inline std::wstring concat_filepath(const std::wstring& path, const std::wstring& file) {
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

static inline uint16 convert_endian(uint16 value) { return (((((uint16)(value)&0xFF)) << 8) | (((uint16)(value)&0xFF00) >> 8)); }
static inline uint16 convert_endian(int16 value) { return (((((int16)(value)&0xFF)) << 8) | (((int16)(value)&0xFF00) >> 8)); }

#define static_inline_convert_endian(T1, T2)    \
    static inline T1 convert_endian(T1 value) { \
        union temp {                            \
            T1 value;                           \
            struct {                            \
                T2 high;                        \
                T2 low;                         \
            } p;                                \
        };                                      \
        union temp x, y;                        \
        x.value = value;                        \
        y.p.high = convert_endian(x.p.low);     \
        y.p.low = convert_endian(x.p.high);     \
        return y.value;                         \
    }

static_inline_convert_endian(uint32, uint16);
static_inline_convert_endian(uint64, uint32);
static_inline_convert_endian(uint128, uint64);
static_inline_convert_endian(int32, int16);
static_inline_convert_endian(int64, int32);
static_inline_convert_endian(int128, int64);

}  // namespace hotplace

#endif
