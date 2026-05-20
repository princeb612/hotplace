/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   cast.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_CAST__
#define __HOTPLACE_SDK_BASE_NOSTD_CAST__

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/nostd/traits.hpp>
#include <type_traits>

namespace hotplace {

/**
 * @brief   narrow cast
 * @refer   Gemini
 */
template <typename SOURCE, bool debug_except = false>
struct t_narrow_cast_t {
    const SOURCE value;

    template <typename TYPE>
    operator TYPE() const {
#ifdef DEBUG
        if (debug_except) {
            TYPE converted = static_cast<TYPE>(value);
            if (static_cast<SOURCE>(converted) != value) {
                /**
                 * case.1
                 *  int32 i32 = -1;
                 *  uint8 ui8 = t_intended_narrow_cast(i32);
                 * case.2
                 *  int32 i32 = 300;
                 *  int8 i8 = t_intended_narrow_cast(i32);
                 */
                throw exception(errorcode_t::miscast_narrow);
            }
            if (typename t_is_signed<SOURCE>::type() != typename t_is_signed<TYPE>::type()) {
                if ((value < 0) != (converted < 0)) {
                    /**
                     * case.3
                     *  uint32 ui32 = 4294967295;
                     *  int32 i32 = t_intended_narrow_cast(ui32);
                     */
                    throw exception(errorcode_t::miscast_narrow);
                }
            }
        }
#endif
        return static_cast<TYPE>(value);
    }
};

template <typename TYPE>
constexpr t_narrow_cast_t<TYPE, true> t_narrow_cast(TYPE v) {
    return {v};
}

template <typename TYPE>
constexpr t_narrow_cast_t<TYPE, false> t_justdoit(TYPE v) {
    return {v};
}

}  // namespace hotplace

#endif
