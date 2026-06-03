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

template <typename T>
struct is_pure_integral {
   private:
    // remove cv-qualifier(const, volatile), reference
    using raw_type = typename std::remove_cv<typename std::remove_reference<T>::type>::type;

   public:
    static const bool value = is_integral<raw_type>::value && !std::is_pointer<typename std::remove_reference<T>::type>::value && !std::is_same<raw_type, bool>::value &&
                              !std::is_same<raw_type, wchar_t>::value;
};

// clang-format off

template <typename T> using is_pure_integral_t = typename std::enable_if<is_pure_integral<T>::value>::type;
template <typename T> using is_pure_signed_integral = typename std::enable_if<is_pure_integral<T>::value && is_integral<T>::is_signed>::type;
template <typename T> using is_pure_unsigned_integral = typename std::enable_if<is_pure_integral<T>::value && !is_integral<T>::is_signed>::type;

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

template <size_t size> struct half_type_traits;
template <> struct half_type_traits<2> { using type = uint8; };
template <> struct half_type_traits<4> { using type = uint16; };
template <> struct half_type_traits<8> { using type = uint32; };
#ifdef __SIZEOF_INT128__
template <> struct half_type_traits<16> { using type = uint64; };
#endif

// clang-format on

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

/**
 * @brief   encoder stream
 * @refer   GPT
 * @sa      base16, base64
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
struct vt_remove_ptr_const {
    using type = typename std::decay<T>::type;
};

/**
 * @sa  variant
 */
// is_pointer const char*, const char*&
template <typename T>
struct vt_remove_ptr_const<T, typename std::enable_if<std::is_pointer<typename std::remove_reference<T>::type>::value>::type> {
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
using vt_remove_ptr_const_t = typename vt_remove_ptr_const<T>::type;

/**
 * @sa  bignumber
 */
template <typename T, bool is_enum_v = std::is_enum<T>::value>
struct bn_underlying_type {
    using type = T;
};

template <typename T>
struct bn_underlying_type<T, true> {
    using type = typename std::underlying_type<T>::type;
};

}  // namespace custom

}  // namespace hotplace

#endif
