/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   traits_printf.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026.05.22   Soo Han and Gemini  Refined with guidance and collaboration from Gemini
 *
 * @note
 *          [Refactoring History]
 *          - Restructured redundant SFINAE (enable_if) and std::conditional pipelines
 *            into a centralized Type Traits structure (printf_traits).
 *          - Consolidated integral, enum, and floating-point stream pipelines.
 *          - Resolved type-ambiguity and operator associativity (+=) corner cases.
 *          - Refined with guidance and collaboration from Gemini (AI Peer).
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_TRAITSPRINTF__
#define __HOTPLACE_SDK_BASE_NOSTD_TRAITSPRINTF__

#include <hotplace/sdk/base/nostd/traits.hpp>
#include <type_traits>

/**
 * @refer   Gemini
 */

namespace hotplace {

namespace custom {

/**
 * @brief   format specifier
 * @sa      printf_traits
 */
template <typename BT, typename T>
struct format_specifier_traits {
    static constexpr bool value = false;
};

template <>
struct format_specifier_traits<char, int8> {
    static constexpr bool value = true;
    static constexpr const char* spec = "%d";
};

template <>
struct format_specifier_traits<char, uint8> {
    static constexpr bool value = true;
    static constexpr const char* spec = "%u";
};

template <>
struct format_specifier_traits<char, int16> {
    static constexpr bool value = true;
    static constexpr const char* spec = "%d";
};

template <>
struct format_specifier_traits<char, uint16> {
    static constexpr bool value = true;
    static constexpr const char* spec = "%u";
};

template <>
struct format_specifier_traits<char, int32> {
    static constexpr bool value = true;
    static constexpr const char* spec = "%d";
};

template <>
struct format_specifier_traits<char, uint32> {
    static constexpr bool value = true;
    static constexpr const char* spec = "%u";
};

template <>
struct format_specifier_traits<char, int64> {
    static constexpr bool value = true;
    static constexpr const char* spec = "%lld";
};

template <>
struct format_specifier_traits<char, uint64> {
    static constexpr bool value = true;
    static constexpr const char* spec = "%llu";
};

#ifdef __SIZEOF_INT128__
template <>
struct format_specifier_traits<char, int128> {
    static constexpr bool value = true;
    static constexpr const char* spec = "%I128i";
};

template <>
struct format_specifier_traits<char, uint128> {
    static constexpr bool value = true;
    static constexpr const char* spec = "%I128u";
};
#endif

template <>
struct format_specifier_traits<char, float> {
    static constexpr bool value = true;
    static constexpr const char* spec = "%f";
};

template <>
struct format_specifier_traits<char, double> {
    static constexpr bool value = true;
    static constexpr const char* spec = "%f";
};

template <>
struct format_specifier_traits<char, const char*> {
    static constexpr bool value = true;
    static constexpr const char* spec = "%s";
};

template <>
struct format_specifier_traits<wchar_t, int8> {
    static constexpr bool value = true;
    static constexpr const wchar_t* spec = L"%d";
};

template <>
struct format_specifier_traits<wchar_t, uint8> {
    static constexpr bool value = true;
    static constexpr const wchar_t* spec = L"%u";
};

template <>
struct format_specifier_traits<wchar_t, int16> {
    static constexpr bool value = true;
    static constexpr const wchar_t* spec = L"%d";
};

template <>
struct format_specifier_traits<wchar_t, uint16> {
    static constexpr bool value = true;
    static constexpr const wchar_t* spec = L"%u";
};

template <>
struct format_specifier_traits<wchar_t, int32> {
    static constexpr bool value = true;
    static constexpr const wchar_t* spec = L"%d";
};

template <>
struct format_specifier_traits<wchar_t, uint32> {
    static constexpr bool value = true;
    static constexpr const wchar_t* spec = L"%u";
};

template <>
struct format_specifier_traits<wchar_t, int64> {
    static constexpr bool value = true;
    static constexpr const wchar_t* spec = L"%lld";
};

template <>
struct format_specifier_traits<wchar_t, uint64> {
    static constexpr bool value = true;
    static constexpr const wchar_t* spec = L"%llu";
};

#ifdef __SIZEOF_INT128__
template <>
struct format_specifier_traits<wchar_t, int128> {
    static constexpr bool value = true;
    static constexpr const wchar_t* spec = L"%I128i";
};

template <>
struct format_specifier_traits<wchar_t, uint128> {
    static constexpr bool value = true;
    static constexpr const wchar_t* spec = L"%I128u";
};
#endif

template <>
struct format_specifier_traits<wchar_t, float> {
    static constexpr bool value = true;
    static constexpr const wchar_t* spec = L"%f";
};

template <>
struct format_specifier_traits<wchar_t, double> {
    static constexpr bool value = true;
    static constexpr const wchar_t* spec = L"%f";
};

template <>
struct format_specifier_traits<wchar_t, const wchar_t*> {
    static constexpr bool value = true;
    static constexpr const wchar_t* spec = L"%s";
};

template <typename T, bool enum_type>
struct integral_type {
    using type = T;
};

template <typename T>
struct integral_type<T, true> {
    using type = typename std::underlying_type<T>::type;
};

/**
 * @breif   printf_traits
 * @sa      basic_stream, ansi_string, wide_string
 */
template <typename BT, typename T, typename enable_t = void>
struct printf_traits;

template <typename BT, typename T>
struct printf_traits<BT, T, typename std::enable_if<is_integral<typename std::decay<T>::type>::value || std::is_enum<typename std::decay<T>::type>::value>::type> {
    using decay_type = typename std::decay<T>::type;
    using integral_type = typename integral_type<decay_type, std::is_enum<decay_type>::value>::type;

    static constexpr size_t N = sizeof(integral_type);
    static constexpr bool is_signed = std::is_signed<integral_type>::value;

    // warning: format '%u' expects argument of type 'unsigned int', but argument 2 has type 'final_type' {aka 'long unsigned int'} [-Wformat=]
    // see cast_type

#if defined __SIZEOF_INT128__
    using final_type = typename std::conditional<
        is_signed,
        typename std::conditional<
            N == 1, int8,
            typename std::conditional<N == 2, int16, typename std::conditional<N == 4, int32, typename std::conditional<N == 8, int64, int128>::type>::type>::type>::type,
        typename std::conditional<
            N == 1, uint8,
            typename std::conditional<N == 2, uint16,
                                      typename std::conditional<N == 4, uint32, typename std::conditional<N == 8, uint64, uint128>::type>::type>::type>::type>::type;

    using cast_type = typename std::conditional<
        is_signed,
        typename std::conditional<
            N == 1, int,
            typename std::conditional<N == 2, int, typename std::conditional<N == 4, int, typename std::conditional<N == 8, long long, int128>::type>::type>::type>::type,
        typename std::conditional<
            N == 1, unsigned int,
            typename std::conditional<
                N == 2, unsigned int,
                typename std::conditional<N == 4, unsigned int, typename std::conditional<N == 8, unsigned long long, uint128>::type>::type>::type>::type>::type;
#else
    using final_type = typename std::conditional<
        is_signed, typename std::conditional<N == 1, int8, typename std::conditional<N == 2, int16, typename std::conditional<N == 4, int32, int64>::type>::type>::type,
        typename std::conditional<N == 1, uint8, typename std::conditional<N == 2, uint16, typename std::conditional<N == 4, uint32, uint64>::type>::type>::type>::type;

    using cast_type = typename std::conditional<
        is_signed, typename std::conditional<N == 1, int, typename std::conditional<N == 2, int, typename std::conditional<N == 4, int, long long>::type>::type>::type,
        typename std::conditional<
            N == 1, unsigned int,
            typename std::conditional<N == 2, unsigned int, typename std::conditional<N == 4, unsigned int, unsigned long long>::type>::type>::type>::type;
#endif

    static constexpr const BT* spec() { return format_specifier_traits<BT, final_type>::spec; }
};

template <typename BT, typename T>
struct printf_traits<BT, T, typename std::enable_if<std::is_floating_point<typename std::decay<T>::type>::value>::type> {
    using decay_type = typename std::decay<T>::type;

    using final_type = decay_type;
    using cast_type = typename std::conditional<std::is_same<decay_type, long double>::value, long double, double>::type;

    static constexpr const BT* spec() { return format_specifier_traits<BT, final_type>::spec; }
};

}  // namespace custom

}  // namespace hotplace

#endif
