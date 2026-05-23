/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   traits.hpp
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

#ifndef __HOTPLACE_SDK_BASE_NOSTD_TRAIS__
#define __HOTPLACE_SDK_BASE_NOSTD_TRAIS__

#include <hotplace/sdk/base/basic/types.hpp>
#include <type_traits>

/**
 * @refer   Gemini
 */

namespace hotplace {

namespace custom {

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
template <typename T>
struct is_signed_traits : std::is_signed<T> {};
template <typename T>
struct is_unsigned_traits : std::is_unsigned<T> {};

template <>
struct is_signed_traits<int8> : std::true_type {};
template <>
struct is_signed_traits<uint8> : std::false_type {};
template <>
struct is_unsigned_traits<int8> : std::false_type {};
template <>
struct is_unsigned_traits<uint8> : std::true_type {};
template <>
struct is_signed_traits<int16> : std::true_type {};
template <>
struct is_signed_traits<uint16> : std::false_type {};
template <>
struct is_unsigned_traits<int16> : std::false_type {};
template <>
struct is_unsigned_traits<uint16> : std::true_type {};
template <>
struct is_signed_traits<int32> : std::true_type {};
template <>
struct is_signed_traits<uint32> : std::false_type {};
template <>
struct is_unsigned_traits<int32> : std::false_type {};
template <>
struct is_unsigned_traits<uint32> : std::true_type {};
template <>
struct is_signed_traits<int64> : std::true_type {};
template <>
struct is_signed_traits<uint64> : std::false_type {};
template <>
struct is_unsigned_traits<int64> : std::false_type {};
template <>
struct is_unsigned_traits<uint64> : std::true_type {};
#ifdef __SIZEOF_INT128__
template <>
struct is_signed_traits<int128> : std::true_type {};
template <>
struct is_signed_traits<uint128> : std::false_type {};
template <>
struct is_unsigned_traits<int128> : std::false_type {};
template <>
struct is_unsigned_traits<uint128> : std::true_type {};
#endif

template <typename T>
struct is_integral_traits : std::is_integral<T> {};

template <>
struct is_integral_traits<int8> : std::true_type {};
template <>
struct is_integral_traits<uint8> : std::true_type {};
template <>
struct is_integral_traits<int16> : std::true_type {};
template <>
struct is_integral_traits<uint16> : std::true_type {};
template <>
struct is_integral_traits<int32> : std::true_type {};
template <>
struct is_integral_traits<uint32> : std::true_type {};
template <>
struct is_integral_traits<int64> : std::true_type {};
template <>
struct is_integral_traits<uint64> : std::true_type {};
#ifdef __SIZEOF_INT128__
template <>
struct is_integral_traits<int128> : std::true_type {};
template <>
struct is_integral_traits<uint128> : std::true_type {};
#endif

template <typename T, bool enum_type>
struct integral_type {
    using type = T;
};

template <typename T>
struct integral_type<T, true> {
    using type = typename std::underlying_type<T>::type;
};

template <typename T>
struct make_unsigned_traits : std::make_unsigned<T> {};

template <>
struct make_unsigned_traits<int8> {
    using type = uint8;
};
template <>
struct make_unsigned_traits<uint8> {
    using type = uint8;
};
template <>
struct make_unsigned_traits<int16> {
    using type = uint16;
};
template <>
struct make_unsigned_traits<uint16> {
    using type = uint16;
};
template <>
struct make_unsigned_traits<int32> {
    using type = uint32;
};
template <>
struct make_unsigned_traits<uint32> {
    using type = uint32;
};
template <>
struct make_unsigned_traits<int64> {
    using type = uint64;
};
template <>
struct make_unsigned_traits<uint64> {
    using type = uint64;
};
#ifdef __SIZEOF_INT128__
template <>
struct make_unsigned_traits<int128> {
    using type = uint128;
};
template <>
struct make_unsigned_traits<uint128> {
    using type = uint128;
};
#endif

template <size_t size>
struct half_type_traits;

template <>
struct half_type_traits<2> {
    using type = uint8;
};
template <>
struct half_type_traits<4> {
    using type = uint16;
};
template <>
struct half_type_traits<8> {
    using type = uint32;
};
#ifdef __SIZEOF_INT128__
template <>
struct half_type_traits<16> {
    using type = uint64;
};
#endif

/**
 * @brief   format specifier
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

template <typename BT, typename T, typename enable_t = void>
struct printf_traits;

template <typename BT, typename T>
struct printf_traits<
    BT, T, typename std::enable_if<custom::is_integral_traits<typename std::decay<T>::type>::value || std::is_enum<typename std::decay<T>::type>::value>::type> {
    using decay_type = typename std::decay<T>::type;
    using integral_type = typename custom::integral_type<decay_type, std::is_enum<decay_type>::value>::type;

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

    static constexpr const BT* spec() { return custom::format_specifier_traits<BT, final_type>::spec; }
};

template <typename BT, typename T>
struct printf_traits<BT, T, typename std::enable_if<std::is_floating_point<typename std::decay<T>::type>::value>::type> {
    using decay_type = typename std::decay<T>::type;

    using final_type = decay_type;
    using cast_type = typename std::conditional<std::is_same<decay_type, long double>::value, long double, double>::type;

    static constexpr const BT* spec() { return custom::format_specifier_traits<BT, final_type>::spec; }
};

/**
 * @brief   encoder stream
 * @refer   GPT
 * @remarks
 *          // std::string, binary_t, ...
 *          size_t size = 0;
 *          base16_encode(source, size_source, nullptr, &size);
 *          buf.resize(size);
 *          base16_encode(source, size_source, buf.data(), &size);
 *
 *          // extend
 *          base16_encode(source, size_source, stringbuf);
 *          base16_encode(source, size_source, vectorbuf);
 *          // ...
 */
template <typename T>
struct encoder_stream_traits {
    static constexpr bool value = false;
};

template <>
struct encoder_stream_traits<std::string> {
    typedef char value_type;

    static constexpr bool value = true;
    static void trunc(std::string& buf) { buf.resize(0); }
    static value_type* reserve(std::string& buf, size_t size_reserve) {
        size_t pos = buf.size();
        buf.resize(pos + size_reserve);
        return &buf[pos];
    }
    static void commit(std::string& buf, size_t size_reserve, size_t size_written) {
        if (size_written < size_reserve) {
            buf.resize(buf.size() - (size_reserve - size_written));
        }
    }
};

template <>
struct encoder_stream_traits<binary_t> {
    typedef byte_t value_type;

    static constexpr bool value = true;
    static void trunc(binary_t& buf) { buf.resize(0); }
    static value_type* reserve(binary_t& buf, size_t size_reserve) {
        size_t pos = buf.size();
        buf.resize(pos + size_reserve);
        return &buf[pos];
    }
    static void commit(binary_t& buf, size_t size_reserve, size_t size_written) {
        if (size_written < size_reserve) {
            buf.resize(buf.size() - (size_reserve - size_written));
        }
    }
};

template <typename T, typename enable_t = void>
struct remove_ptr_const {
    using type = typename std::decay<T>::type;
};

// is_pointer const char*, const char*&
template <typename T>
struct remove_ptr_const<T, typename std::enable_if<std::is_pointer<typename std::remove_reference<T>::type>::value>::type> {
    // const char*& -> const char*
    using unreferenced_type = typename std::remove_reference<T>::type;
    // const char* -> const char
    using base_type = typename std::remove_pointer<unreferenced_type>::type;
    // const char -> char
    using unconst_type = typename std::remove_const<base_type>::type;
    // char -> char*
    using type = typename std::add_pointer<unconst_type>::type;
};

template <typename T>
using remove_ptr_const_t = typename remove_ptr_const<T>::type;

}  // namespace custom

}  // namespace hotplace

#endif
