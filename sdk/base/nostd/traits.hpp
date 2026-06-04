/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   traits.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_TRAITS__
#define __HOTPLACE_SDK_BASE_NOSTD_TRAITS__

#include <hotplace/sdk/base/basic/types.hpp>
#include <type_traits>

namespace hotplace {

namespace custom {

// clang-format off

/**
 * @brief   custom type traits
 * @refer   Gemini
 * @remarks
 *          std::is_signed<__int128>
 *          std::numeric_limits<__int128>::is_signed
 *
 *          false  UBUNTU 20  GCC 9.4.0
 *          true   MINGW64    GCC 15.2.0
 */
template <typename T> struct is_signed : std::is_signed<T> {};
template <typename T> struct is_unsigned : std::is_unsigned<T> {};

template <> struct is_signed<int8> : std::true_type {};
template <> struct is_signed<uint8> : std::false_type {};
template <> struct is_unsigned<int8> : std::false_type {};
template <> struct is_unsigned<uint8> : std::true_type {};
template <> struct is_signed<int16> : std::true_type {};
template <> struct is_signed<uint16> : std::false_type {};
template <> struct is_unsigned<int16> : std::false_type {};
template <> struct is_unsigned<uint16> : std::true_type {};
template <> struct is_signed<int32> : std::true_type {};
template <> struct is_signed<uint32> : std::false_type {};
template <> struct is_unsigned<int32> : std::false_type {};
template <> struct is_unsigned<uint32> : std::true_type {};
template <> struct is_signed<int64> : std::true_type {};
template <> struct is_signed<uint64> : std::false_type {};
template <> struct is_unsigned<int64> : std::false_type {};
template <> struct is_unsigned<uint64> : std::true_type {};
#ifdef __SIZEOF_INT128__
template <> struct is_signed<__int128> : std::true_type {};
template <> struct is_signed<unsigned __int128> : std::false_type {};
template <> struct is_unsigned<__int128> : std::false_type {};
template <> struct is_unsigned<unsigned __int128> : std::true_type {};
#endif

// clang-format on

namespace detail {

// integral, enum
template <typename T, bool is_enum_v = std::is_enum<T>::value>
struct is_integral {
    static const bool value = std::is_integral<T>::value;
    static const bool is_signed = std::is_signed<T>::value;
};

// if enum, determine by tracking the internal integer type
template <typename T>
struct is_integral<T, true> {
    using underlying = typename std::underlying_type<T>::type;
    static const bool value = true;
    static const bool is_signed = std::is_signed<underlying>::value;
};

}  // namespace detail

template <typename T>
struct is_integral {
    using raw_t = typename std::remove_cv<typename std::remove_reference<T>::type>::type;
    static const bool value = detail::is_integral<raw_t>::value;
    static const bool is_signed = detail::is_integral<raw_t>::is_signed;
};

template <>
struct is_integral<int8> {
    static const bool value = true;
    static const bool is_signed = true;
};
template <>
struct is_integral<uint8> {
    static const bool value = true;
    static const bool is_signed = false;
};
template <>
struct is_integral<int16> {
    static const bool value = true;
    static const bool is_signed = true;
};
template <>
struct is_integral<uint16> {
    static const bool value = true;
    static const bool is_signed = false;
};
template <>
struct is_integral<int32> {
    static const bool value = true;
    static const bool is_signed = true;
};
template <>
struct is_integral<uint32> {
    static const bool value = true;
    static const bool is_signed = false;
};
template <>
struct is_integral<int64> {
    static const bool value = true;
    static const bool is_signed = true;
};
template <>
struct is_integral<uint64> {
    static const bool value = true;
    static const bool is_signed = false;
};

#ifdef __SIZEOF_INT128__
template <>
struct is_integral<__int128> {
    static const bool value = true;
    static const bool is_signed = true;
};
template <>
struct is_integral<unsigned __int128> {
    static const bool value = true;
    static const bool is_signed = false;
};
#endif

// clang-format off

template <typename T> struct make_unsigned : std::make_unsigned<T> {};
template <> struct make_unsigned<int8> { using type = uint8; };
template <> struct make_unsigned<uint8> { using type = uint8; };
template <> struct make_unsigned<int16> { using type = uint16; };
template <> struct make_unsigned<uint16> { using type = uint16; };
template <> struct make_unsigned<int32> { using type = uint32; };
template <> struct make_unsigned<uint32> { using type = uint32; };
template <> struct make_unsigned<int64> { using type = uint64; };
template <> struct make_unsigned<uint64> { using type = uint64; };
#ifdef __SIZEOF_INT128__
template <> struct make_unsigned<int128> { using type = uint128; };
template <> struct make_unsigned<uint128> { using type = uint128; };
#endif

// clang-format on

}  // namespace custom

}  // namespace hotplace

#endif
