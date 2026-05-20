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
