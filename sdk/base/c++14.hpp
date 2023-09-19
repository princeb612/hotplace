/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_CPP14__
#define __HOTPLACE_SDK_BASE_CPP14__

#include <hotplace/sdk/base/types.hpp>

namespace hotplace {

#if __cplusplus >= 201402L    // c++14
/*
 * @brief   obfuscate a string at compile time
 * @sa      obfuscate_string
 * @example
 *          constexpr auto temp1 = constexpr_obf <24>("ninety nine red balloons");
 *          constexpr auto temp2 = CONSTEXPR_OBF ("wild wild world");
 *          define_constexpr_obf (temp3, "still a man hears what he wants to hear and disregards the rest");
 *          std::cout << CONSTEXPR_OBF_CSTR(temp1) << std::endl;
 *          std::cout << CONSTEXPR_OBF_CSTR(temp2) << std::endl;
 *          std::cout << CONSTEXPR_OBF_CSTR(temp3) << std::endl;
 */
#define define_constexpr_obf(var, x) constexpr auto var = CONSTEXPR_OBF (x)
#define CONSTEXPR_OBF(x) constexpr_obf <RTL_NUMBER_OF (x)>(x)
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
        for (unsigned int i = 0; i < N + 1; i++) {
            char c = buf[i] - factor;
            ptr[i] = c;
            if (0 == c) {
                break;
            }
        }
        return temp;
    }
    size_t size () const
    {
        return N;
    }
private:
    char buf [N + 1] = { 0, };
    uint8 factor = F;
};
#endif

} // namespace

#endif
