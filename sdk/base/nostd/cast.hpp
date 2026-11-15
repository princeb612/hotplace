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
struct t_narrow_cast_proxy_t {
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
            if (typename custom::is_signed<SOURCE>::type() != typename custom::is_signed<TYPE>::type()) {
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

/**
 * @brief   narrow cast with an explicitly selected destination type.
 *
 * The conversion is performed when the wrapper is constructed, so the
 * resulting value behaves like TYPE in comparisons and other expressions.
 */
template <typename TYPE>
struct t_narrow_cast_t {
    TYPE value;

    template <typename SOURCE>
    t_narrow_cast_t(SOURCE source) : value(cast(source)) {}

    operator TYPE() const { return value; }

   private:
    template <typename SOURCE>
    static TYPE cast(SOURCE source) {
#ifdef DEBUG
        TYPE converted = static_cast<TYPE>(source);
        if (static_cast<SOURCE>(converted) != source) {
            throw exception(errorcode_t::miscast_narrow);
        }
        if (typename custom::is_signed<SOURCE>::type() != typename custom::is_signed<TYPE>::type()) {
            if ((source < 0) != (converted < 0)) {
                throw exception(errorcode_t::miscast_narrow);
            }
        }
#endif
        return static_cast<TYPE>(source);
    }
};

template <typename TYPE>
constexpr t_narrow_cast_proxy_t<TYPE, true> t_narrow_cast(TYPE v) {
    return {v};
}

template <typename TYPE>
constexpr t_narrow_cast_proxy_t<TYPE, false> t_justdoit(TYPE v) {
    return {v};
}

}  // namespace hotplace

#endif
