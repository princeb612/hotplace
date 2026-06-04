/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   traits_encoder.hpp
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

#ifndef __HOTPLACE_SDK_BASE_NOSTD_TRAITSENCODER__
#define __HOTPLACE_SDK_BASE_NOSTD_TRAITSENCODER__

#include <hotplace/sdk/base/nostd/traits.hpp>

/**
 * @refer   Gemini
 */

namespace hotplace {

namespace custom {

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

    static void preempt(std::string& buf, size_t size) { buf.reserve(size); }
    static void push(std::string& buf, value_type c) { buf.push_back(c); }
    static void append(std::string& buf, const char* msg) {
        if (msg) buf += msg;
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
    static void preempt(binary_t& buf, size_t size) { buf.reserve(size); }
    static void push(binary_t& buf, value_type c) { buf.push_back(c); }
    static void append(binary_t& buf, const char* msg) {
        if (msg) {
            auto len = strlen(msg);
            buf.insert(buf.end(), msg, msg + len);
        }
    }
};

}  // namespace custom

}  // namespace hotplace

#endif
