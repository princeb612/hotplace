/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   enumclass.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_ENUMCLASS__
#define __HOTPLACE_SDK_BASE_NOSTD_ENUMCLASS__

#include <hotplace/sdk/base/basic/types.hpp>
#include <type_traits>

namespace hotplace {

template <typename T, typename enable_t = typename std::enable_if<std::is_enum<T>::value, typename std::underlying_type<T>::type>::type>
struct t_enum_type {
    using enum_type = T;
    using type = typename std::underlying_type<T>::type;

    T value;

    constexpr explicit t_enum_type() noexcept : value(T{}) {}
    constexpr explicit t_enum_type(T v) noexcept : value(v) {}
    constexpr explicit t_enum_type(type v) noexcept : value(static_cast<T>(v)) {}

    constexpr operator T() const noexcept { return value; }
    constexpr operator type() const noexcept { return static_cast<type>(value); }

    constexpr T get() const noexcept { return value; }
    constexpr type underlying() const noexcept { return static_cast<type>(value); }

    t_enum_type& operator=(T v) noexcept {
        value = v;
        return *this;
    }

    constexpr bool operator==(const t_enum_type& rhs) const noexcept { return value == rhs.value; }
    constexpr bool operator!=(const t_enum_type& rhs) const noexcept { return value != rhs.value; }

    constexpr bool operator<(const t_enum_type& rhs) const noexcept { return underlying() < rhs.underlying(); }
    constexpr bool operator>(const t_enum_type& rhs) const noexcept { return rhs < *this; }
    constexpr bool operator<=(const t_enum_type& rhs) const noexcept { return !(*this > rhs); }
    constexpr bool operator>=(const t_enum_type& rhs) const noexcept { return !(*this < rhs); }
};

}  // namespace hotplace

#endif
