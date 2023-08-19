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

//#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <string.h>
#include <algorithm>
#include <list>
#include <string>
#include <vector>

namespace hotplace {

static inline void memcpy_inline (void* dest, size_t size_dest, const void* src, size_t size_src)
{
#ifdef __STDC_WANT_SECURE_LIB__
    memcpy_s (dest, size_dest, src, size_src);
#else
    memcpy (dest, src, size_src);
#endif
}

static inline std::string& ltrim (std::string& source)
{
#if __cplusplus >= 201103L // c++11
    source.erase (source.begin (), std::find_if (source.begin (), source.end (), [] (int c) {
            return !std::isspace (c);
        }));
#else
    source.erase (source.begin (), std::find_if (source.begin (), source.end (), std::not1 (std::ptr_fun<int, int>(std::isspace))));
#endif

    return source;
}

static inline std::string& rtrim (std::string& source)
{
#if __cplusplus >= 201103L // c++11
    source.erase (std::find_if (source.rbegin (), source.rend (), [] (int c) {
            return !std::isspace (c);
        }).base (), source.end ());
#else
    source.erase (std::find_if (source.rbegin (), source.rend (), std::not1 (std::ptr_fun<int, int>(std::isspace))).base (), source.end ());
#endif

    return source;
}

static inline bool ends_with (const std::string& source, const std::string& suffix)
{
    return source.rfind (suffix) == (source.size () - suffix.size ());
}

/*
 * @brief tolower
 * @param const char* input [in]
 */
static inline std::string lowername (const char* input)
{
    std::string ret_value;

    __try2
    {
        if (nullptr == input) {
            __leave2;
        }
        ret_value = input;
        std::transform (ret_value.begin (), ret_value.end (), ret_value.begin (), tolower);
    }
    __finally2
    {
        // do nothing
    }
    return ret_value;
}

/*
 * @brief tolower
 * @param std::string source [in]
 */
static inline std::string lowername (std::string input)
{
    std::string ret_value;

    __try2
    {
        ret_value = input;
        std::transform (ret_value.begin (), ret_value.end (), ret_value.begin (), tolower);
    }
    __finally2
    {
        // do nothing
    }
    return ret_value;
}

/*
 * @brief append
 * @param binary_t& lhs [inout]
 * @param char* rhs [in]
 */
static inline binary_t& operator << (binary_t& lhs, char* rhs)
{
    if (rhs) {
        lhs.insert (lhs.end (), rhs, rhs + strlen (rhs));
    }
    return lhs;
}

/*
 * @brief append
 * @param binary_t& lhs [inout]
 * @param std::string rhs [in]
 */
static inline binary_t& operator << (binary_t& lhs, std::string rhs)
{
    lhs.insert (lhs.end (), rhs.begin (), rhs.end ());
    return lhs;
}

/*
 * @brief append
 * @param binary_t& lhs [inout]
 * @param binary_t rhs [in]
 */
static inline binary_t& operator << (binary_t& lhs, binary_t rhs)
{
    lhs.insert (lhs.end (), rhs.begin (), rhs.end ());
    return lhs;
}

#ifndef DIRECTORY_SEPARATOR

    #if defined _WIN32
        #define DIRECTORY_SEPARATORA          '\\'
        #define DIRECTORY_SEPARATOR_STRINGA   "\\"
    #elif defined __linux__
        #define DIRECTORY_SEPARATORA          '/'
        #define DIRECTORY_SEPARATOR_STRINGA   "/"
    #endif

    #define DIRECTORY_SEPARATOR         DIRECTORY_SEPARATORA
    #define DIRECTORY_SEPARATOR_STRING  DIRECTORY_SEPARATOR_STRINGA

#endif

static inline std::string concat_filepath (const std::string& path, const std::string& file)
{
    std::string result;

    result = path;
    bool test = ends_with (path, DIRECTORY_SEPARATOR_STRING);

    if (false == test) {
        result += DIRECTORY_SEPARATOR_STRING;
    }
    result += file;
    return result;
}

}  // namespace

#endif
