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
#include <sdk/base/stream.hpp>
#include <sdk/base/stream/bufferio.hpp>

namespace hotplace {

/**
 * @brief   basic_stream null-padded
 */
class basic_stream : public stream_t {
   public:
    /**
     * @brief   constructor
     * @param   size_t allocsize [inopt] default 4K
     * @param   uint32 flags [inopt] default 0
     */
    basic_stream(size_t allocsize = (1 << 12), uint32 flags = 0);
    /**
     * @brief   constructor
     * @param   const char* data [in]
     */
    basic_stream(const char* data);
    /**
     * @brief   constructor
     * @param   const basic_stream& stream [in]
     */
    basic_stream(const basic_stream& stream);
    /**
     * @brief   destructor
     */
    virtual ~basic_stream();

    /**
     * @brief   c-style string
     */
    const char* c_str() const;
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
    return_t write(void* data, size_t size);
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
    basic_stream& operator<<(int value);
    basic_stream& operator<<(unsigned int value);
    basic_stream& operator<<(long value);
    basic_stream& operator<<(unsigned long value);
    basic_stream& operator<<(basic_stream const& value);
    basic_stream& operator<<(std::string const& value);

    /**
     * @brief   operator =
     * @param   basic_stream obj [in]
     */
    basic_stream& operator=(basic_stream const& obj);
    basic_stream& operator=(std::string const& str);
    basic_stream& operator=(const char* str);

    /**
     * @brief   compare
     * @param   basic_stream obj [in]
     */
    int compare(basic_stream const& obj);
    /**
     * @brief   compare
     * @param   basic_stream lhs [in]
     * @param   basic_stream rhs [in]
     */
    static int compare(basic_stream& lhs, basic_stream& rhs);
    /**
     * @brief   operator <
     * @param   basic_stream obj [in]
     */
    bool operator<(basic_stream& obj);
    /**
     * @brief   operator <
     * @param   basic_stream obj [in]
     */
    bool operator>(basic_stream& obj);

   protected:
    bufferio _bio;
    bufferio_context_t* _handle;
};

}  // namespace hotplace

#endif
