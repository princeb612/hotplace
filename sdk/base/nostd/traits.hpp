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

#ifndef __HOTPLACE_SDK_BASE_NOSTD_TRAIS__
#define __HOTPLACE_SDK_BASE_NOSTD_TRAIS__

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <type_traits>

namespace hotplace {

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
struct t_is_signed : std::is_signed<T> {};
template <typename T>
struct t_is_unsigned : std::is_unsigned<T> {};

template <>
struct t_is_signed<int8> : std::true_type {};
template <>
struct t_is_signed<uint8> : std::false_type {};
template <>
struct t_is_unsigned<int8> : std::false_type {};
template <>
struct t_is_unsigned<uint8> : std::true_type {};
template <>
struct t_is_signed<int16> : std::true_type {};
template <>
struct t_is_signed<uint16> : std::false_type {};
template <>
struct t_is_unsigned<int16> : std::false_type {};
template <>
struct t_is_unsigned<uint16> : std::true_type {};
template <>
struct t_is_signed<int32> : std::true_type {};
template <>
struct t_is_signed<uint32> : std::false_type {};
template <>
struct t_is_unsigned<int32> : std::false_type {};
template <>
struct t_is_unsigned<uint32> : std::true_type {};
template <>
struct t_is_signed<int64> : std::true_type {};
template <>
struct t_is_signed<uint64> : std::false_type {};
template <>
struct t_is_unsigned<int64> : std::false_type {};
template <>
struct t_is_unsigned<uint64> : std::true_type {};
#ifdef __SIZEOF_INT128__
template <>
struct t_is_signed<int128> : std::true_type {};
template <>
struct t_is_signed<uint128> : std::false_type {};
template <>
struct t_is_unsigned<int128> : std::false_type {};
template <>
struct t_is_unsigned<uint128> : std::true_type {};
#endif

template <typename T>
struct t_is_integral : std::is_integral<T> {};

template <>
struct t_is_integral<int8> : std::true_type {};
template <>
struct t_is_integral<uint8> : std::true_type {};
template <>
struct t_is_integral<int16> : std::true_type {};
template <>
struct t_is_integral<uint16> : std::true_type {};
template <>
struct t_is_integral<int32> : std::true_type {};
template <>
struct t_is_integral<uint32> : std::true_type {};
template <>
struct t_is_integral<int64> : std::true_type {};
template <>
struct t_is_integral<uint64> : std::true_type {};
#ifdef __SIZEOF_INT128__
template <>
struct t_is_integral<int128> : std::true_type {};
template <>
struct t_is_integral<uint128> : std::true_type {};
#endif

template <typename T>
struct t_make_unsigned : std::make_unsigned<T> {};

template <>
struct t_make_unsigned<int8> {
    using type = uint8;
};
template <>
struct t_make_unsigned<uint8> {
    using type = uint8;
};
template <>
struct t_make_unsigned<int16> {
    using type = uint16;
};
template <>
struct t_make_unsigned<uint16> {
    using type = uint16;
};
template <>
struct t_make_unsigned<int32> {
    using type = uint32;
};
template <>
struct t_make_unsigned<uint32> {
    using type = uint32;
};
template <>
struct t_make_unsigned<int64> {
    using type = uint64;
};
template <>
struct t_make_unsigned<uint64> {
    using type = uint64;
};
#ifdef __SIZEOF_INT128__
template <>
struct t_make_unsigned<int128> {
    using type = uint128;
};
template <>
struct t_make_unsigned<uint128> {
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
struct encoder_stream_traits;

template <>
struct encoder_stream_traits<std::string> {
    typedef char value_type;

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

template <>
struct encoder_stream_traits<basic_stream> {
    typedef byte_t value_type;

    static void trunc(basic_stream& buf) { buf.resize(0); }
    static value_type* reserve(basic_stream& buf, size_t size_reserve) {
        size_t pos = buf.size();
        buf.resize(pos + size_reserve);
        return buf.data() + pos;
    }
    static void commit(basic_stream& buf, size_t size_reserve, size_t size_written) {
        if (size_written < size_reserve) {
            buf.resize(buf.size() - (size_reserve - size_written));
        }
    }
};

template <>
struct encoder_stream_traits<stream_t*> {
    typedef char value_type;

    static void trunc(stream_t* buf) { buf->resize(0); }
    static value_type* reserve(stream_t* buf, size_t size_reserve) {
        size_t pos = buf->size();
        buf->resize(pos + size_reserve);
        return (char*)buf->data() + pos;
    }
    static void commit(stream_t* buf, size_t size_reserve, size_t size_written) {
        if (size_written < size_reserve) {
            buf->resize(buf->size() - (size_reserve - size_written));
        }
    }
};

}  // namespace hotplace

#endif
