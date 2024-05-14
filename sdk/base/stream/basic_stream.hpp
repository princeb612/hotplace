/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_BASICSTREAM__
#define __HOTPLACE_SDK_BASE_STREAM_BASICSTREAM__

#include <stdarg.h>
#include <string.h>

#include <iostream>
#include <ostream>
#include <sdk/base/stream.hpp>
#include <sdk/base/stream/bufferio.hpp>

namespace hotplace {

/**
 * @brief   basic_stream null-padded
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
     * @brief   constructor
     * @param   const basic_stream& rhs [in]
     */
    basic_stream(const basic_stream& rhs);
    basic_stream(basic_stream&& rhs);
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
    byte_t* data() const;
    /**
     * @brief   size
     */
    uint64 size() const;
    /**
     * @brief   write
     * @param   void* data [in]
     * @param   size_t size [in]
     */
    return_t write(const void* data, size_t size);
    return_t cut(uint32 begin_pos, uint32 length);
    return_t insert(size_t begin, const void* data, size_t data_size);
    /**
     * @brief   fill
     * @param   size_t l [in]
     * @param   char c [in]
     */
    return_t fill(size_t l, char c);
    /**
     * @brief   clear
     */
    return_t clear();

    /**
     * @brief   printf
     * @param   const char* buf [in]
     */
    return_t printf(const char* buf, ...);
    /**
     * @brief   vprintf
     * @param   const char* buf [in]
     */
    return_t vprintf(const char* buf, va_list ap);
#if defined _WIN32 || defined _WIN64
    return_t printf(const wchar_t* buf, ...);
    return_t vprintf(const wchar_t* buf, va_list ap);
#endif

    basic_stream& operator<<(const char* str);
    basic_stream& operator<<(char value);
    basic_stream& operator<<(int value);
    basic_stream& operator<<(unsigned int value);
    basic_stream& operator<<(long value);
    basic_stream& operator<<(unsigned long value);
    basic_stream& operator<<(long long value);
    basic_stream& operator<<(unsigned long long value);
    basic_stream& operator<<(int128 value);
    basic_stream& operator<<(uint128 value);
    basic_stream& operator<<(const basic_stream& value);
    basic_stream& operator<<(const std::string& value);

    /**
     * @brief   operator =
     * @param   basic_stream obj [in]
     */
    basic_stream& operator=(const basic_stream& rhs);
    basic_stream& operator=(basic_stream&& rhs);
    basic_stream& operator=(const std::string& str);
    basic_stream& operator=(const char* str);

    /**
     * @brief   compare
     * @param   basic_stream rhs [in]
     */
    int compare(const basic_stream& rhs);
    /**
     * @brief   compare
     * @param   basic_stream lhs [in]
     * @param   basic_stream rhs [in]
     */
    static int compare(const basic_stream& lhs, const basic_stream& rhs);
    /**
     * @brief   operator <
     * @param   basic_stream rhs [in]
     */
    bool operator<(const basic_stream& rhs) const;
    /**
     * @brief   operator <
     * @param   basic_stream rhs [in]
     */
    bool operator>(const basic_stream& rhs) const;

    bool operator==(const basic_stream& rhs) const;

    friend std::string& operator+=(std::string& lhs, const basic_stream& rhs);
    friend std::string& operator<<(std::string& lhs, const basic_stream& rhs);
    friend std::ostream& operator<<(std::ostream& lhs, const basic_stream& rhs);

   protected:
    bufferio _bio;
    bufferio_context_t* _handle;
};

/**
 * @remarks
 *          stream_policy* pol = stream_policy::get_instance();
 *          pol->set_allocsize(1 << 5);
 *
 *          basic_stream bs;
 *          bs << "hello world";
 */
class stream_policy {
   public:
    static stream_policy* get_instance();
    stream_policy& set_allocsize(size_t allocsize);
    size_t get_allocsize();

   private:
    static stream_policy _instance;
    stream_policy();

    typedef std::map<std::string, uint32> basic_stream_policy_map_t;
    basic_stream_policy_map_t _config;
};

}  // namespace hotplace

#endif
