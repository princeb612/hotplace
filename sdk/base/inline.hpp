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
#include <hotplace/sdk/base/charset.hpp>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/template.hpp>
#include <hotplace/sdk/base/types.hpp>
#include <list>
#include <string>
#include <vector>

namespace hotplace {

/**
 * @brief   bit length
 * @remarks gcc builtin clz - count leading zeros (ex. 0000000011111111 return 8)
 */
static inline int bit_length(uint16 v) {
    uint32 temp = v;
    return __builtin_clz(temp) - 16;
}

static inline int bit_length(uint32 v) { return __builtin_clz(v); }

static inline int bit_length(uint64 v) { return __builtin_clzll(v); }

#if defined __SIZEOF_INT128__
static inline int bit_length(uint128 v) {
    int b = 128;
    uint64 hi = (v >> 64);
    uint64 lo = 0;
    if (hi) {
        b = __builtin_clzll(hi);
    } else if (lo = (v & ~0ULL)) {
        b = __builtin_clzll(lo) + 64;
    }
    return b;
}
#endif

/**
 * @brief   bytes
 * @example
 *          00000000000000000000000000000001 1 byte
 *          00000000000000000000000000000080 1 byte
 *          00000000000000000000000000008000 2 bytes
 *          00000000000000000000000800000000 5 bytes
 *          00080000000000000000000000000000 15 bytes
 *          08000000000000000000000000000000 16 bytes
 */

static inline int byte_capacity(uint16 v) { return ((sizeof(v) << 3) - bit_length(v) + 7) >> 3; }

static inline int byte_capacity(uint32 v) { return ((sizeof(v) << 3) - bit_length(v) + 7) >> 3; }

static inline int byte_capacity(uint64 v) { return ((sizeof(v) << 3) - bit_length(v) + 7) >> 3; }

#if defined __SIZEOF_INT128__
static inline int byte_capacity(uint128 v) { return ((sizeof(v) << 3) - bit_length(v) + 7) >> 3; }
#endif

static inline int byte_capacity(int16 v) { return byte_capacity_signed<int16>(v); }

static inline int byte_capacity(int32 v) { return byte_capacity_signed<int32>(v); }

static inline int byte_capacity(int64 v) { return byte_capacity_signed<int64>(v); }

#if defined __SIZEOF_INT128__
static inline int byte_capacity(int128 v) { return byte_capacity_signed<int128>(v); }
#endif

// secure functions

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

/**
 * @brief   left trim
 */
static inline std::string& ltrim(std::string& source) {
#if __cplusplus >= 201103L  // c++11
    source.erase(source.begin(), std::find_if(source.begin(), source.end(), [](int c) { return !std::isspace(c); }));
#else
    source.erase(source.begin(), std::find_if(source.begin(), source.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
#endif

    return source;
}

/**
 * @brief   right trim
 */
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
    __finally2 {}
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
    __finally2 {}
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
    __finally2 {}
    return ret_value;
}

static inline std::string uppername(const std::string& input) {
    std::string ret_value;

    __try2 {
        ret_value = input;
        std::transform(ret_value.begin(), ret_value.end(), ret_value.begin(), toupper);
    }
    __finally2 {}
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

/**
 * @brief xor
 * @param byte_t* target [inout] sizeof target >= len
 * @paramconst byte_t* mask [in] sizeof mask >= len
 */
static inline return_t memxor(byte_t* target, const byte_t* mask, size_t len) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == target) || (nullptr == mask)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        for (auto i = 0; i < len; i++) {
            target[i] ^= mask[i];
        }
    }
    __finally2 {}
    return ret;
}

static inline return_t memxor(binary_t& target, const binary_t& mask, size_t len) { return memxor(&target[0], &mask[0], len); }

}  // namespace hotplace

#endif
