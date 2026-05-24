/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   basic_stream.hpp
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

#ifndef __HOTPLACE_SDK_BASE_STREAM_BASICSTREAM__
#define __HOTPLACE_SDK_BASE_STREAM_BASICSTREAM__

#include <stdarg.h>
#include <string.h>

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/traits.hpp>
#include <hotplace/sdk/base/stream/bufferio.hpp>
#include <hotplace/sdk/base/system/types.hpp>
#include <iostream>
#include <ostream>

namespace hotplace {
class valist;

/**
 * @brief   basic_stream
 */
class basic_stream : public stream_t {
   public:
    basic_stream();
    /**
     * @brief   constructor
     * @param   const char* data [in]
     */
    basic_stream(const char* data, ...);
    /**
     * copy/move
     */
    basic_stream(const basic_stream& other);
    basic_stream(basic_stream&& other) noexcept;
    basic_stream& operator=(const basic_stream& other);
    basic_stream& operator=(basic_stream&& other) noexcept;
    /**
     * @brief   destructor
     */
    virtual ~basic_stream();

    /**
     * @brief   c-style string
     */
    const char* c_str() const;
    operator const char*();
    operator char*() const;
    /**
     * @brief   data
     */
    virtual byte_t* data() const;
    /**
     * @brief   size
     */
    virtual uint64 size() const;
    /**
     * @brief   write
     * @param   void* data [in]
     * @param   size_t size [in]
     */
    virtual return_t write(const void* data, size_t size);
    return_t cut(size_t begin_pos, size_t length);
    return_t insert(size_t begin, const void* data, size_t data_size);
    /**
     * @brief   fill
     * @param   size_t l [in]
     * @param   char c [in]
     */
    virtual return_t fill(size_t l, char c);
    /**
     * @brief   clear
     */
    virtual return_t clear();
    virtual bool empty();
    virtual bool occupied();

    /**
     * @brief   printf
     * @param   const char* buf [in]
     */
    return_t printf(const char* buf, ...);
    /**
     * @brief   vprintf
     * @param   const char* buf [in]
     */
    virtual return_t vprintf(const char* buf, va_list ap);
    return_t println(const char* buf, ...);
#if defined _WIN32 || defined _WIN64
    virtual return_t printf(const wchar_t* buf, ...);
    return_t vwprintf(const wchar_t* buf, va_list ap);
    return_t println(const wchar_t* buf, ...);
#endif

    /**
     * @brief   format string syntax
     * @remarks
     *          - {n} n MUST be in 1..arg
     *          - string argument {n}, {n:-10s}, {n:10s}
     *          - integer argument {n}, {n:10d}, {n:10i}, {n:08x}
     *          - floating point argument {n}, {n:le}, {n:lf}, {n:lg}
     * @example
     *          valist va;
     *          va << 256 << "hello world" << 3.141592;
     *
     *          bs.clear();
     *          bs.sprintf(R"(value={1}, value={1:04x}, value={1:04d})", va);
     *          // value=256, value=0x0100, value=0256
     *          bs.clear();
     *          bs.sprintf(R"(value="{2}", value="{2:-15s}", value="{2:15s}")", va);
     *          // value="hello world", value="hello world    ", value="    hello world"
     *          bs.clear();
     *          bs.sprintf(R"(value={3}, value={3:le}, value={3:lg})", va);
     *          // value=3.141592, value=3.141592e+00, value=3.14159
     *          bs.clear();
     *          // {n} n MUST be in 1..arg so {-1} is ignored
     *          // {2} is a string so 10d is ignored
     *          // {3} is an integer so s is ignored
     *          bs.sprintf({R"(value={-1}, value="{2:10d}", value={3:s})", va);
     *          // value={-1}, value="hello world", value=3.141592
     */
    return_t vaprintf(const char* fmt, valist ap);
    return_t vaprintln(const char* fmt, valist ap);

    /**
     * @brief   compare
     * @param   basic_stream other [in]
     */
    int compare(const basic_stream& other);
    /**
     * @brief   compare
     * @param   basic_stream lhs [in]
     * @param   basic_stream rhs [in]
     */
    int compare(const basic_stream& lhs, const basic_stream& rhs) const;
    int compare(const basic_stream& lhs, const char* rhs) const;

    virtual void autoindent(uint8 indent);
    void resize(size_t size) override;

    /**
     * delegation
     */
    template <typename T>
    basic_stream& add(T&& value) {
        return *this << std::forward<T>(value);
    }

    /**
     * operator =
     * delegation
     */
    template <typename T>
    basic_stream& operator=(T&& value) {
        clear();
        return *this << std::forward<T>(value);
    }

    /**
     * operator +=
     * delegation
     */
    template <typename T>
    basic_stream& operator+=(T&& value) {
        return *this << std::forward<T>(value);
    }

    /**
     * stream implementation
     */
    template <typename T,                                                                          //
              typename std::enable_if<custom::is_integral<typename std::decay<T>::type>::value ||  //
                                          std::is_enum<typename std::decay<T>::type>::value ||     //
                                          std::is_floating_point<typename std::decay<T>::type>::value,
                                      int>::type = 0>
    basic_stream& operator<<(T value) {
        using traits = custom::printf_traits<char, T>;
        using cast_type = typename traits::cast_type;

        printf(traits::spec(), static_cast<cast_type>(value));
        return *this;
    }

    /**
     * stream implementation
     * operator <<
     */
    basic_stream& operator<<(char value);         // due to performance (write is faster than printf)
    basic_stream& operator<<(const char* value);  // due to performance (write is faster than printf)
#if defined _WIN32 || defined _WIN64
    basic_stream& operator<<(const wchar_t value);
    basic_stream& operator<<(const wchar_t* value);
#endif
    basic_stream& operator<<(const variant& value);
    basic_stream& operator<<(const basic_stream& value);
    basic_stream& operator<<(const std::string& value);
    basic_stream& operator<<(const binary_t& value);
    basic_stream& operator<<(const bignumber& value);

    /**
     * @brief   operator <
     * @param   basic_stream other [in]
     */
    bool operator<(const basic_stream& other) const;
    /**
     * @brief   operator <
     * @param   basic_stream other [in]
     */
    bool operator>(const basic_stream& other) const;

    bool operator==(const basic_stream& other) const;
    bool operator==(const char* other) const;
    bool operator==(const std::string& other) const;
    bool operator!=(const basic_stream& other) const;
    bool operator!=(const char* other) const;
    bool operator!=(const std::string& other) const;

    friend std::string& operator+=(std::string& lhs, const basic_stream& rhs);
    friend std::string& operator<<(std::string& lhs, const basic_stream& rhs);
    friend std::ostream& operator<<(std::ostream& lhs, const basic_stream& rhs);

   protected:
   private:
    bufferio_context_t* _handle;
};

namespace custom {

template <>
struct encoder_stream_traits<stream_t*> {
    typedef char value_type;

    static constexpr bool value = true;
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

template <>
struct encoder_stream_traits<basic_stream> {
    typedef byte_t value_type;

    static constexpr bool value = true;
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

}  // namespace custom

}  // namespace hotplace

#endif
