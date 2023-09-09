/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_TYPES__
#define __HOTPLACE_SDK_BASE_TYPES__

#if defined __linux__
#include <hotplace/sdk/base/system/linux/types.hpp>
#elif defined _WIN32 || defined _WIN64
#include <hotplace/sdk/base/system/windows/types.hpp>
#endif

#include <string>
#include <vector>

namespace hotplace {

template <typename RETURN_T, typename TYPE> RETURN_T type_cast (TYPE param)
{
    return static_cast <RETURN_T> (param);
}

typedef unsigned char byte_t;
typedef std::vector<byte_t> binary_t;

#ifndef _WIN32 // winnt.h
#define RTL_NUMBER_OF(x) (sizeof (x) / sizeof (x[0]))
#define RTL_FIELD_SIZE(type, field) (sizeof (((type *) 0)->field))
#define FIELD_OFFSET(type, field) ((int32) (arch_t) &(((type *) 0)->field))
#endif

#define __min(a, b) (((a) < (b)) ? (a) : (b))
#define __max(a, b) (((a) > (b)) ? (a) : (b))
#define adjust_range(var, minimum, maximum) { var = __max (var, minimum); var = __min (var, maximum); }

/**
 * @brief format
 * @example
 *  std::string text = format ("%s %d %1.1f\n", "sample", 1, 1.1f);
 */
std::string format (const char* fmt, ...);
#if __cplusplus > 199711L    // c++98
std::string format (const char* fmt, va_list ap);
#endif

#if __cplusplus >= 201402L    // c++14
/*
 * @brief   obfuscate a string at compile time
 * @sa      obfuscate_string
 * @example
 *          constexpr auto temp1 = constexpr_obf <25>("ninety nine red balloons");
 *          constexpr auto temp2 = CONSTEXPR_OBF ("wild wild world");
 *          define_constexpr_obf (temp3, "still a man hears what he wants to hear and disregards the rest");
 *          std::cout << CONSTEXPR_OBF_CSTR(temp1) << std::endl;
 *          std::cout << CONSTEXPR_OBF_CSTR(temp2) << std::endl;
 *          std::cout << CONSTEXPR_OBF_CSTR(temp3) << std::endl;
 */
#define define_constexpr_obf(var, x) constexpr auto var = CONSTEXPR_OBF (x)
#define CONSTEXPR_OBF(x) constexpr_obf <RTL_NUMBER_OF (x) + 1>(x)
#define CONSTEXPR_OBF_STR(x) x.load_string ()
#define CONSTEXPR_OBF_CSTR(x) x.load_string ().c_str ()

template <uint32 N, uint8 F = 0x30>
class constexpr_obf {
public:
    constexpr constexpr_obf (const char* source)
    {
        for (unsigned int i = 0; i < N; i++) {
            char c = source[i];
            buf[i] = c + factor;
            if (0 == c) {
                break;
            }
        }
    }
    std::string load_string () const
    {
        std::string temp;

        temp.resize (N);
        char* ptr = &temp[0];
        for (unsigned int i = 0; i < N; i++) {
            char c = buf[i] - factor;
            ptr[i] = c;
            if (0 == c) {
                break;
            }
        }
        return temp;
    }
private:
    char buf [N] = { 0, };
    uint8 factor = F;
};
#endif

} // namespace

#endif
